//go:build integration

package e2e

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// TestMain runs the tests, audits the environment and argv of every Himalaya
// run the shims recorded, and removes any fixture container this process
// created. It fails the run if an audit fails or a container is still listed.
func TestMain(m *testing.M) {
	code := m.Run()
	for _, err := range []error{auditShimEnv(), auditShimArgv(), sweepContainers()} {
		if err != nil {
			fmt.Fprintln(os.Stderr, "e2e:", err)
			code = 1
		}
	}
	if dir, err := buildDir(); err == nil {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

// auditShimEnv requires that every recorded Himalaya run had exactly
// ServerEnv for the state dir its HOME names.
func auditShimEnv() error {
	shimRecords.Lock()
	defer shimRecords.Unlock()
	var bad []string
	for _, r := range shimRecords.all {
		home := recordHome(r)
		if home == "" || !slices.Equal(slices.Sorted(slices.Values(r.Env)), ServerEnv(filepath.Dir(home))) {
			bad = append(bad, fmt.Sprintf("argv %q env %q", r.Argv, r.Env))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d Himalaya runs had an unexpected environment:\n%s", len(bad), strings.Join(bad, "\n"))
	}
	return nil
}

// auditShimArgv requires that every Himalaya run a server made, except its
// startup "--version", passes the server's own L3 guard (DESIGN section 4)
// for the state dir its HOME names. A server always runs --version first, so
// a state dir without one belongs to a test that ran the shim directly
// (TestHarness) and is not audited. WriteServerConfig configures alice and bob.
// A started server always runs account list, so servers started with
// nothing audited fail the audit instead of passing it unchecked.
func auditShimArgv() error {
	shimRecords.Lock()
	defer shimRecords.Unlock()
	served := map[string]bool{}
	for _, r := range shimRecords.all {
		if slices.Equal(r.Argv, []string{"--version"}) {
			served[filepath.Dir(recordHome(r))] = true
		}
	}
	var bad []string
	audited := 0
	for _, r := range shimRecords.all {
		state := filepath.Dir(recordHome(r))
		if !served[state] || slices.Equal(r.Argv, []string{"--version"}) {
			continue
		}
		audited++
		guard := himalaya.Guard{StateDir: state, Accounts: []string{Alice.Name, Bob.Name}}
		if _, err := guard.Check(r.Argv); err != nil {
			bad = append(bad, fmt.Sprintf("argv %q: %v", r.Argv, err))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d of %d server Himalaya runs fail the L3 guard:\n%s", len(bad), audited, strings.Join(bad, "\n"))
	}
	if n := serverStarts.Load(); n > 0 && audited == 0 {
		return fmt.Errorf("%d servers started, but none of their Himalaya runs was audited", n)
	}
	return nil
}

// recordHome is the HOME a shim record ran with, or "".
func recordHome(r ShimRecord) string {
	var home string
	for _, kv := range r.Env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			home = v
		}
	}
	return home
}

func sweepContainers() error {
	containers.Lock()
	names := slices.Clone(containers.names)
	containers.Unlock()
	if len(names) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Most are already gone; rm reports those as errors.
	dockerCmd(ctx, nil, append([]string{"rm", "-f", "-v"}, names...)...)
	out, err := dockerCmd(ctx, nil, "ps", "-a", "--filter", "name=hmcp-it-", "--format", "{{.Names}}")
	if err != nil {
		return err
	}
	var left []string
	for name := range strings.FieldsSeq(string(out)) {
		if slices.Contains(names, name) {
			left = append(left, name)
		}
	}
	if len(left) > 0 {
		return errors.New("fixture containers left behind: " + strings.Join(left, " "))
	}
	return nil
}
