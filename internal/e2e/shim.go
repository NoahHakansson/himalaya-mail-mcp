//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Shim is an installed copy of the argv shim (internal/e2e/argvshim) in front
// of a real Himalaya binary. Point the server's himalaya.path at Path.
type Shim struct {
	Path   string // the shim executable, named "himalaya"
	Target string // the real binary it execs
	SHA256 string // hex sha256 of Path, for himalaya.sha256
}

// ShimRecord is one logged invocation.
type ShimRecord struct {
	Argv      []string `json:"argv"` // arguments after the binary path
	Env       []string `json:"env"`
	Hook      bool     `json:"hook,omitempty"` // the hook ran before the exec
	HookError string   `json:"hook_error,omitempty"`
}

// shimRecords collects every shim's records at cleanup, for TestMain's audit.
var shimRecords struct {
	sync.Mutex
	all []ShimRecord
}

// buildDir holds binaries built once per test process; TestMain removes it.
var buildDir = sync.OnceValues(func() (string, error) {
	return os.MkdirTemp("", "hmcp-e2e-bin-")
})

var shimBinary = sync.OnceValues(func() (string, error) {
	dir, err := buildDir()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "argvshim")
	out, err := exec.Command("go", "build", "-tags", "integration", "-o", bin, "./argvshim").CombinedOutput()
	if err != nil {
		return "", errors.New("go build ./argvshim: " + err.Error() + ": " + string(out))
	}
	return bin, nil
})

// BuildShim installs a fresh shim execing target (an absolute path) in a
// private dir. The shim is compiled once per process; every copy is
// byte-identical, so SHA256 is the same for all of them.
func BuildShim(t testing.TB, target string) *Shim {
	t.Helper()
	if !filepath.IsAbs(target) {
		t.Fatalf("shim target %q is not absolute", target)
	}
	bin, err := shimBinary()
	if err != nil {
		t.Fatal(err)
	}
	data := readFile(t, bin)
	sum := sha256.Sum256(data)
	s := &Shim{Path: filepath.Join(TempDir(t), "himalaya"), Target: target, SHA256: hex.EncodeToString(sum[:])}
	// 0755 exactly: the server refuses a group- or world-writable binary.
	writeFile(t, s.Path, data, 0o755)
	writeFile(t, s.Path+".target", []byte(target+"\n"), 0o600)
	t.Cleanup(func() {
		recs, err := s.records()
		if err != nil {
			t.Errorf("read shim log: %v", err)
		}
		shimRecords.Lock()
		shimRecords.all = append(shimRecords.all, recs...)
		shimRecords.Unlock()
	})
	return s
}

// Records returns every invocation logged so far, in order.
func (s *Shim) Records(t testing.TB) []ShimRecord {
	t.Helper()
	recs, err := s.records()
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func (s *Shim) records() ([]ShimRecord, error) {
	data, err := os.ReadFile(s.Path + ".log")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var recs []ShimRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var r ShimRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

// commandPath returns the subcommand path of a recorded argv, such as
// "message move", skipping the global options before it.
func commandPath(argv []string) string {
	var path []string
	for i := 0; i < len(argv); i++ {
		switch a := argv[i]; {
		case strings.HasPrefix(a, "-") && len(path) > 0:
			return strings.Join(path, " ")
		case slices.Contains([]string{"-c", "-a", "-b", "--log-level"}, a):
			i++
		case !strings.HasPrefix(a, "-"):
			path = append(path, a)
		}
	}
	return strings.Join(path, " ")
}

// AssertEnv fails the test unless every logged invocation ran with exactly
// the environment want, compared as a set.
func (s *Shim) AssertEnv(t testing.TB, want []string) {
	t.Helper()
	want = slices.Sorted(slices.Values(want))
	for i, r := range s.Records(t) {
		if got := slices.Sorted(slices.Values(r.Env)); !slices.Equal(got, want) {
			t.Errorf("shim run %d %q: env %q, want %q", i, r.Argv, got, want)
		}
	}
}

// SetHook makes the shim run argv (absolute path first, no stdin) before
// execing any command whose path equals match, e.g. []string{"message",
// "move"}. Fixture.SetUIDValidityArgv builds a typical argv.
func (s *Shim) SetHook(t testing.TB, match, argv []string) {
	t.Helper()
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		t.Fatalf("hook argv %q must start with an absolute path", argv)
	}
	data, err := json.Marshal(map[string][]string{"match_subcommand": match, "run": argv})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, s.Path+".hook", data, 0o600)
}

// ClearHook removes the hook.
func (s *Shim) ClearHook(t testing.TB) {
	t.Helper()
	if err := os.Remove(s.Path + ".hook"); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
