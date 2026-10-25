package himalaya

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Concurrency is the number of Himalaya processes that may run at once.
const Concurrency = 4

// Runner runs Himalaya with a fixed environment, explicit stdin, its own
// process group, bounded output and the caller's deadline (DESIGN section 6).
type Runner struct {
	bin    string
	state  string
	guard  Guard
	sem    chan struct{}
	log    *slog.Logger
	active sync.WaitGroup
}

// NewRunner returns a Runner for the binary at bin, using stateDir for HOME
// and TMPDIR and accepting only the given account names.
func NewRunner(bin, stateDir string, accounts []string, log *slog.Logger) *Runner {
	return &Runner{
		bin:   bin,
		state: stateDir,
		guard: Guard{StateDir: stateDir, Accounts: slices.Clone(accounts)},
		sem:   make(chan struct{}, Concurrency),
		log:   log,
	}
}

// Env is the complete environment every Himalaya process gets. Nothing is
// inherited, so SSL_CERT_*, *_proxy, RUST_LOG and HIMALAYA_CONFIG never apply.
func Env(stateDir string) []string {
	home := filepath.Join(stateDir, "home")
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"TMPDIR=" + filepath.Join(stateDir, "tmp"),
	}
}

type toolKey struct{}

// WithTool tags ctx with the tool name for the runner's log lines.
func WithTool(ctx context.Context, tool string) context.Context {
	return context.WithValue(ctx, toolKey{}, tool)
}

func toolOf(ctx context.Context) string {
	t, _ := ctx.Value(toolKey{}).(string)
	return t
}

// Run checks c against the guard, runs it and returns stdout on exit 0.
// Failures are *Error values; a failed mutating command is outcome_uncertain
// unless it provably failed before any mutation could be sent.
func (r *Runner) Run(ctx context.Context, c Command) ([]byte, error) {
	path, s, err := r.guard.check(c.Args)
	if err != nil {
		r.log.Error("himalaya argv refused", "tool", toolOf(ctx), "account", c.Account, "reason", err.Error())
		return nil, Errorf(CodeInternal, "")
	}
	start := time.Now()
	res := r.exec(ctx, c.Args, c.Stdin, s.stdoutCap)
	err = res.err(s)
	r.log.Info("himalaya",
		"tool", toolOf(ctx), "account", c.Account, "command", path,
		"exit", res.exit, "class", classOf(err), "duration", time.Since(start).Round(time.Millisecond))
	if err != nil {
		return nil, err
	}
	return res.stdout, nil
}

func classOf(err error) string {
	if err == nil {
		return "ok"
	}
	return string(CodeOf(err))
}

// result is what one process run produced.
type result struct {
	started  bool
	stdout   []byte
	exit     int // -1 when killed or not started
	overflow bool
	ctxErr   error
	startErr error
}

// err maps a result of a command with spec s onto the error a caller sees.
func (res result) err(s spec) error {
	switch {
	case res.startErr != nil:
		return Errorf(CodeInternal, "")
	case !res.started:
		return outcome(classification{ctxCode(res.ctxErr), true}, s.mutating)
	case res.overflow:
		return outcome(classification{CodeTooLarge, false}, s.mutating)
	case res.ctxErr != nil:
		return outcome(classification{ctxCode(res.ctxErr), false}, s.mutating)
	case res.exit == 0:
		return nil
	case res.exit == 1:
		return outcome(classifyOutput(res.stdout, s.selectFirst), s.mutating)
	case res.exit == 2:
		// A clap usage error is a wrapper bug and happens before any IMAP traffic.
		return Errorf(CodeInternal, "")
	}
	return outcome(classification{CodeMailError, false}, s.mutating)
}

func ctxCode(err error) Code {
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeTimeout
	}
	return CodeCancelled
}

// exec runs the binary once. The process group is killed when ctx ends or
// stdout overflows, and once more after the leader exits but before it is
// reaped, so an orphaned secret command dies too and a reused PGID is never
// targeted.
func (r *Runner) exec(ctx context.Context, args []string, stdin []byte, stdoutCap int64) result {
	select {
	case r.sem <- struct{}{}:
		r.active.Add(1)
		defer func() {
			<-r.sem
			r.active.Done()
		}()
	case <-ctx.Done():
		return result{exit: -1, ctxErr: ctx.Err()}
	}
	if ctx.Err() != nil {
		return result{exit: -1, ctxErr: ctx.Err()}
	}

	overflow := make(chan struct{})
	stdout := &cappedBuffer{limit: stdoutCap, onOverflow: sync.OnceFunc(func() { close(overflow) })}
	cmd := exec.Command(r.bin, args...)
	cmd.Env = Env(r.state)
	cmd.Dir = filepath.Join(r.state, "home")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = stdout
	cmd.Stderr = &cappedBuffer{limit: capStderr}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return result{exit: -1, startErr: err}
	}
	pid := cmd.Process.Pid
	exited := make(chan struct{})
	go func() {
		waitExited(pid)
		close(exited)
	}()

	res := result{started: true}
	select {
	case <-exited:
	case <-ctx.Done():
		res.ctxErr = ctx.Err()
	case <-overflow:
		res.overflow = true
	}
	// The leader is not reaped until cmd.Wait, so -pid is still our group.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	<-exited
	_ = cmd.Wait()

	res.exit = cmd.ProcessState.ExitCode()
	res.stdout = stdout.buf.Bytes()
	if stdout.overflowed {
		res.overflow = true
	}
	return res
}

// Wait blocks until every running Himalaya process has been killed or has
// exited and been reaped. Call it after cancelling all call contexts, before
// the wrapper exits, so no child outlives it.
func (r *Runner) Wait() { r.active.Wait() }

// waitExited blocks until pid has exited, without reaping it
// (waitid with WEXITED|WNOWAIT, as os/exec does internally).
func waitExited(pid int) {
	const pPID = 1
	var info [128]byte // siginfo_t
	for {
		_, _, e := syscall.Syscall6(syscall.SYS_WAITID, pPID, uintptr(pid),
			uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if e != syscall.EINTR {
			return
		}
	}
}

// cappedBuffer keeps at most limit bytes and reports the first overflow.
// Extra bytes are discarded so the child never blocks on a full pipe.
type cappedBuffer struct {
	mu         sync.Mutex
	buf        bytes.Buffer
	limit      int64
	overflowed bool
	onOverflow func()
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	room := w.limit - int64(w.buf.Len())
	if int64(len(p)) > room {
		w.buf.Write(p[:max(room, 0)])
		if !w.overflowed && w.onOverflow != nil {
			w.onOverflow()
		}
		w.overflowed = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

// Version runs "<bin> --version" with the fixed environment and returns its output.
func (r *Runner) Version(ctx context.Context) (string, error) {
	res := r.exec(ctx, []string{"--version"}, nil, capDefault)
	if err := res.err(spec{}); err != nil {
		return "", err
	}
	return string(res.stdout), nil
}

// Pinned release facts checked at startup (DESIGN section 4, L5).
const (
	PinnedVersion = "v2.2.1"
	PinnedRev     = "5b12b2a8c2c253b98f15c46610ad74cba2a182bc"
)

// IMAPOnlyFeatures is the feature set of the production build.
var IMAPOnlyFeatures = []string{"imap", "rustls-ring"}

// CheckVersion verifies "--version" output: v2.2.1, the pinned rev and,
// unless allowSendCapable, exactly the IMAP-only feature set (compared as a set).
func CheckVersion(out string, allowSendCapable bool) error {
	lines := strings.Split(out, "\n")
	fields := strings.Fields(lines[0])
	if len(fields) < 2 || fields[0] != "himalaya" || fields[1] != PinnedVersion {
		return fmt.Errorf("binary is not himalaya %s", PinnedVersion)
	}
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "git: ") && slices.Contains(strings.Fields(l), PinnedRev)
	}) {
		return fmt.Errorf("binary does not report rev %s", PinnedRev)
	}
	var features []string
	for _, f := range fields[2:] {
		name, ok := strings.CutPrefix(f, "+")
		if !ok {
			return fmt.Errorf("unexpected token in --version")
		}
		features = append(features, name)
	}
	slices.Sort(features)
	if !allowSendCapable && !slices.Equal(features, IMAPOnlyFeatures) {
		return fmt.Errorf("binary features %v are not exactly %v; set allow_send_capable_build only for tests", features, IMAPOnlyFeatures)
	}
	return nil
}

// FileSHA256 returns the hex sha256 of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
