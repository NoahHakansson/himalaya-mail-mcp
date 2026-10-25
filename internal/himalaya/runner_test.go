package himalaya

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as a fake Himalaya: when the runner execs this test
// binary with the himalaya prefix, the account name picks a behaviour.
func TestMain(m *testing.M) {
	switch {
	case len(os.Args) == 2 && os.Args[1] == "--version":
		os.Exit(fakeHimalaya("version"))
	case len(os.Args) > 4 && os.Args[1] == "-c":
		os.Exit(fakeHimalaya(os.Args[4]))
	}
	os.Exit(m.Run())
}

func fakeHimalaya(behaviour string) int {
	switch behaviour {
	case "env":
		wd, _ := os.Getwd()
		json.NewEncoder(os.Stdout).Encode(map[string]any{"env": os.Environ(), "wd": wd})
	case "stdin":
		io.Copy(os.Stdout, os.Stdin)
	case "big":
		os.Stdout.Write(bytes.Repeat([]byte("x"), capDefault+1))
		time.Sleep(10 * time.Second)
	case "sleep":
		child := exec.Command("/bin/sleep", "60")
		child.Start()
		os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "grandchild.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		time.Sleep(60 * time.Second)
	case "fail":
		os.Stdout.WriteString(`{"error":"IMAP SELECT failed: NO Mailbox doesn't exist: X","sources":[],"backtrace":null}`)
		return 1
	case "reset":
		os.Stdout.WriteString(`{"error":"IMAP APPEND failed","sources":["Connection reset by peer (os error 104)"],"backtrace":null}`)
		return 1
	case "usage":
		os.Stderr.WriteString("error: unexpected argument\n")
		return 2
	case "version":
		os.Stdout.WriteString("himalaya v2.2.1 +rustls-ring +imap\nbuild: linux musl x86_64\ngit: v2.2.1, rev " + PinnedRev + "\n")
	}
	return 0
}

func testRunner(t *testing.T, accounts ...string) (*Runner, string) {
	t.Helper()
	state := t.TempDir()
	for _, d := range []string{"home", "tmp", "himalaya"} {
		if err := os.Mkdir(filepath.Join(state, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return NewRunner(self, state, accounts, slog.New(slog.NewTextHandler(io.Discard, nil))), state
}

func acct(state, name string) Account { return Account{Name: name, Config: ConfigPath(state, name)} }

func TestRunnerEnvAndDir(t *testing.T) {
	r, state := testRunner(t, "env")
	t.Setenv("SSL_CERT_FILE", "/tmp/evil.pem")
	t.Setenv("HIMALAYA_CONFIG", "/tmp/evil.toml")
	out, err := r.Run(context.Background(), acct(state, "env").MailboxList())
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Env []string
		WD  string
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if want := Env(state); !slices.Equal(got.Env, want) {
		t.Errorf("env = %q, want %q", got.Env, want)
	}
	if got.WD != filepath.Join(state, "home") {
		t.Errorf("wd = %s", got.WD)
	}
}

func TestRunnerStdin(t *testing.T) {
	r, state := testRunner(t, "stdin")
	body := []byte("line 1\nü $(id)\n")
	out, err := r.Run(context.Background(), acct(state, "stdin").Compose(Draft{}, body))
	if err != nil || !bytes.Equal(out, body) {
		t.Errorf("stdin echo: %q %v", out, err)
	}
	// nil stdin is /dev/null, never the wrapper's own stdin.
	out, err = r.Run(context.Background(), acct(state, "stdin").Compose(Draft{}, nil))
	if err != nil || len(out) != 0 {
		t.Errorf("nil stdin: %q %v", out, err)
	}
}

func TestRunnerExitCodes(t *testing.T) {
	r, state := testRunner(t, "fail", "reset", "usage")
	ctx := context.Background()
	tests := []struct {
		name string
		cmd  Command
		want Code
	}{
		{"exit 1 read", acct(state, "fail").Status("X"), CodeMailboxNotFound},
		{"exit 1 select failure on a mutation is definite", acct(state, "fail").Move("X", "Y", []uint32{1}), CodeMailboxNotFound},
		// message add SELECTs only after its APPEND, to find the UID.
		{"exit 1 select failure on message add", acct(state, "fail").AddDraft("Drafts", []byte("m")), CodeOutcomeUncertain},
		{"exit 1 reset on a mutation", acct(state, "reset").AddDraft("Drafts", []byte("m")), CodeOutcomeUncertain},
		{"exit 1 reset on a read", acct(state, "reset").Status("INBOX"), CodeAccountUnavailable},
		{"exit 2", acct(state, "usage").Move("X", "Y", []uint32{1}), CodeInternal},
	}
	for _, tt := range tests {
		_, err := r.Run(ctx, tt.cmd)
		if CodeOf(err) != tt.want {
			t.Errorf("%s: %v, want %s", tt.name, err, tt.want)
		}
	}
}

func TestRunnerRefusesBadArgv(t *testing.T) {
	r, state := testRunner(t, "env")
	c := acct(state, "env").MailboxList()
	c.Args = append(c.Args, "--send")
	if _, err := r.Run(context.Background(), c); CodeOf(err) != CodeInternal {
		t.Errorf("got %v", err)
	}
}

func TestRunnerStdoutCap(t *testing.T) {
	r, state := testRunner(t, "big")
	start := time.Now()
	_, err := r.Run(context.Background(), acct(state, "big").Status("INBOX"))
	if CodeOf(err) != CodeTooLarge {
		t.Errorf("got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("overflow did not kill the process promptly: %v", time.Since(start))
	}
}

func TestRunnerDeadlineKillsGroup(t *testing.T) {
	r, state := testRunner(t, "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.Run(ctx, acct(state, "sleep").Status("INBOX"))
	if CodeOf(err) != CodeTimeout {
		t.Errorf("got %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
	raw, err := os.ReadFile(filepath.Join(state, "tmp", "grandchild.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(string(raw))
	deadline := time.Now().Add(3 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d survived the deadline", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.Wait()
}

// alive reports whether pid exists and is not a zombie.
func alive(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	return len(fields) > 0 && fields[0] != "Z"
}

func TestRunnerCancelledBeforeStart(t *testing.T) {
	r, state := testRunner(t, "env")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Run(ctx, acct(state, "env").Move("A", "B", []uint32{1})); CodeOf(err) != CodeCancelled {
		t.Errorf("a mutation that never started must be a definite cancel, got %v", err)
	}
}

func TestVersion(t *testing.T) {
	r, _ := testRunner(t)
	out, err := r.Version(context.Background())
	if err != nil || CheckVersion(out, false) != nil {
		t.Fatalf("version %q: %v", out, err)
	}
	official := "himalaya v2.2.1 +msgraph +imap +sieve +rustls-ring +gmail +jmap +pimdir +smtp +mbox +maildir\nbuild: linux musl x86_64\ngit: nix-flake-20261002111922, rev " + PinnedRev + "\n"
	imapOnly := "himalaya v2.2.1 +imap +rustls-ring\nbuild: linux musl x86_64\ngit: v2.2.1, rev " + PinnedRev + "\n"
	reordered := "himalaya v2.2.1 +rustls-ring +imap\nbuild: linux musl x86_64\ngit: v2.2.1, rev " + PinnedRev + "\n"
	tests := []struct {
		name      string
		out       string
		allowSend bool
		ok        bool
	}{
		{"imap-only", imapOnly, false, true},
		{"imap-only, other feature order", reordered, false, true},
		{"official refused", official, false, false},
		{"official allowed for tests", official, true, true},
		{"other version", strings.Replace(imapOnly, "v2.2.1 +", "v2.2.0 +", 1), false, false},
		{"other rev", strings.ReplaceAll(imapOnly, PinnedRev, strings.Repeat("0", 40)), true, false},
		{"extra feature", strings.Replace(imapOnly, "+imap", "+imap +smtp", 1), false, false},
		{"empty", "", true, false},
	}
	for _, tt := range tests {
		if err := CheckVersion(tt.out, tt.allowSend); (err == nil) != tt.ok {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}
