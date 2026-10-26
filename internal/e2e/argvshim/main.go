//go:build integration

// Command argvshim stands in for the Himalaya binary in the integration
// tests. Next to its own path it reads and writes:
//
//	<self>.log     one JSON line {argv, env, hook, hook_error, child_exit}
//	               appended per run
//	<self>.hook    optional JSON rule {match_subcommand, run, fail_after}: when
//	               the command path equals match_subcommand, run is executed
//	               first; with fail_after the real command then runs as a
//	               child and the shim reports a connection reset instead of
//	               its result
//	<self>.target  absolute path of the real binary, exec'd with the same argv
//	               and environment
//
// The hook gets no stdin and its output never reaches stdout, which belongs
// to Himalaya.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
)

type record struct {
	Argv      []string `json:"argv"`
	Env       []string `json:"env"`
	Hook      bool     `json:"hook,omitempty"`
	HookError string   `json:"hook_error,omitempty"`
	ChildExit *int     `json:"child_exit,omitempty"` // exit status of the real command under fail_after
}

type hookRule struct {
	MatchSubcommand []string `json:"match_subcommand"`
	Run             []string `json:"run"`
	FailAfter       bool     `json:"fail_after"`
}

// failAfterOutput is what fail_after prints, the failure Himalaya reported
// in the design review after a server had stored a complete APPEND. It must
// match e2e.FailAfterOutput.
const failAfterOutput = `{"error":"cannot complete IMAP command","sources":["Connection reset by peer (os error 104)"]}` + "\n"

// Himalaya's global options that take a separate value.
var valueOptions = []string{"-c", "--config", "-a", "--account", "-b", "--backend", "--log-level", "--log-file"}

func main() {
	self, err := os.Executable()
	if err != nil {
		fail(err)
	}
	args := os.Args[1:]
	rec := record{Argv: args, Env: os.Environ()}
	rule, err := runHook(self+".hook", commandPath(args))
	rec.Hook = rule != nil
	if err != nil {
		rec.HookError = err.Error()
	}
	if rec.HookError == "" && rule != nil && rule.FailAfter {
		failAfter(self, args, rec)
	}
	if err := appendRecord(self+".log", rec); err != nil {
		fail(err)
	}
	if rec.HookError != "" {
		fail(fmt.Errorf("hook: %s", rec.HookError))
	}
	bin := target(self)
	fail(syscall.Exec(bin, append([]string{bin}, args...), os.Environ()))
}

// target returns the real binary named in <self>.target.
func target(self string) string {
	data, err := os.ReadFile(self + ".target")
	if err != nil {
		fail(err)
	}
	return strings.TrimSpace(string(data))
}

// failAfter runs the real command to completion with its stdout discarded,
// logs its exit status, then reports a connection reset and exits 1: a
// write that took effect and still failed.
func failAfter(self string, args []string, rec record) {
	cmd := exec.Command(target(self), args...)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	if err := cmd.Run(); cmd.ProcessState == nil {
		fail(err)
	}
	exit := cmd.ProcessState.ExitCode()
	rec.ChildExit = &exit
	if err := appendRecord(self+".log", rec); err != nil {
		fail(err)
	}
	os.Stdout.WriteString(failAfterOutput)
	os.Exit(1)
}

// commandPath returns the subcommand words, e.g. [message move], skipping
// global options before them and stopping at the first option or "--" after.
func commandPath(args []string) []string {
	var path []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return path
		case strings.HasPrefix(a, "-"):
			if len(path) > 0 {
				return path
			}
			if slices.Contains(valueOptions, a) {
				i++
			}
		default:
			path = append(path, a)
		}
	}
	return path
}

// runHook returns the rule in path if it exists and matches cmdPath, after
// running its run command, if any.
func runHook(path string, cmdPath []string) (*hookRule, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rule hookRule
	if err := json.Unmarshal(data, &rule); err != nil {
		return nil, err
	}
	if !slices.Equal(rule.MatchSubcommand, cmdPath) {
		return nil, nil
	}
	if len(rule.Run) == 0 {
		return &rule, nil
	}
	var out bytes.Buffer
	cmd := exec.Command(rule.Run[0], rule.Run[1:]...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return &rule, fmt.Errorf("%v: %s", err, bytes.TrimSpace(out.Bytes()))
	}
	return &rule, nil
}

// appendRecord appends one JSON line under an exclusive lock, because the
// server runs several Himalaya processes at once.
func appendRecord(path string, rec record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Close()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "argvshim:", err)
	os.Exit(97)
}
