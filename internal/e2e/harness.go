//go:build integration

// Package e2e is the integration harness for himalaya-mail-mcp: throwaway
// certificates, a disposable Dovecot fixture driven through docker, an argv
// shim in front of the real Himalaya binary, and helpers that build, configure
// and connect to the server. Everything here needs the integration build tag.
package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TempDir returns a fresh 0700 directory removed at cleanup. Unlike t.TempDir
// its name does not come from the test name, so it never contains the
// characters the server's path rule refuses ($ ~ : " \).
func TempDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hmcp-e2e-")
	if err == nil {
		// Canonical, so paths match what /proc and os.Executable report.
		dir, err = filepath.EvalSymlinks(dir)
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(dir, "$~:\"\\") {
		t.Fatalf("temp dir %q contains a character the server's path rule refuses; set TMPDIR to a plain path", dir)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove %s: %v", dir, err)
		}
	})
	return dir
}

// moduleRoot is the repository root. Tests run in internal/e2e.
var moduleRoot = sync.OnceValue(func() string {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		panic(err)
	}
	return root
})

var dockerCheck = sync.OnceValue(func() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := dockerCmd(ctx, nil, "version", "--format", "{{.Server.Version}}")
	return err
})

// RequireDocker skips the test when the docker CLI or daemon is unavailable.
func RequireDocker(t testing.TB) {
	t.Helper()
	if err := dockerCheck(); err != nil {
		t.Skipf("docker is unavailable (%v); the integration tests need it", err)
	}
}

// HimalayaPath returns the absolute path of the Himalaya binary under test:
// $HMCP_HIMALAYA (relative paths are taken from the repository root), else
// .cache/himalaya-imap-only/himalaya. It skips the test when the binary is
// missing.
func HimalayaPath(t testing.TB) string {
	t.Helper()
	root := moduleRoot()
	candidates := []string{
		filepath.Join(root, ".cache", "himalaya-imap-only", "himalaya"),
	}
	if env := os.Getenv("HMCP_HIMALAYA"); env != "" {
		if !filepath.IsAbs(env) {
			env = filepath.Join(root, env)
		}
		candidates = []string{env}
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	t.Skipf("no Himalaya binary at %s; build it with scripts/build-himalaya-imap-only.sh or set HMCP_HIMALAYA", strings.Join(candidates, " or "))
	return ""
}

// HimalayaFeatures returns the cargo features that `bin --version` reports,
// sorted: [imap rustls-ring] for the IMAP-only build.
func HimalayaFeatures(t testing.TB, bin string) []string {
	t.Helper()
	cmd := exec.Command(bin, "--version")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s --version: %v", bin, err)
	}
	first, _, _ := strings.Cut(string(out), "\n")
	var features []string
	for f := range strings.FieldsSeq(first) {
		if name, ok := strings.CutPrefix(f, "+"); ok {
			features = append(features, name)
		}
	}
	slices.Sort(features)
	return features
}

// sendCapable reports whether bin is anything but the IMAP-only build.
func sendCapable(t testing.TB, bin string) bool {
	return !slices.Equal(HimalayaFeatures(t, bin), []string{"imap", "rustls-ring"})
}

// ServerEnv is the exact environment the server gives every Himalaya child
// (DESIGN.md section 6), sorted.
func ServerEnv(stateDir string) []string {
	home := filepath.Join(stateDir, "home")
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"TMPDIR=" + filepath.Join(stateDir, "tmp"),
	}
	slices.Sort(env)
	return env
}

// AssertNoProcs fails the test if any process other than this one has dir in
// its command line. Processes get up to 3 s to exit, which covers the
// server's kill-and-reap path. Call it after the server under test stopped,
// or pass a dir only its children use (the state dir).
func AssertNoProcs(t testing.TB, dir string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		left := procsReferencing(dir)
		if len(left) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("processes still reference %s:\n%s", dir, strings.Join(left, "\n"))
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func procsReferencing(dir string) []string {
	self := os.Getpid()
	paths, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	var found []string
	for _, p := range paths {
		pid, err := strconv.Atoi(filepath.Base(filepath.Dir(p)))
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		// Appending "/" matches dir itself and paths below it, not /tmp/x1 for /tmp/x.
		if slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a+"/", dir+"/") }) {
			found = append(found, fmt.Sprintf("pid %d: %s", pid, strings.Join(args, " ")))
		}
	}
	return found
}

// SilentListener listens on 127.0.0.1, accepts connections and never writes
// to them, so an IMAP client waits for a greeting until its deadline. It
// returns the port; the listener and every accepted connection close at
// cleanup.
func SilentListener(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}
