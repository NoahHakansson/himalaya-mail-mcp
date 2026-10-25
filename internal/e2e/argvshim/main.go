//go:build integration

// Command argvshim stands in for the Himalaya binary in the integration
// tests. Next to its own path it reads and writes:
//
//	<self>.log     one JSON line {argv, env, hook, hook_error} appended per run
//	<self>.hook    optional JSON rule {match_subcommand, run}: when the command
//	               path equals match_subcommand, run is executed first
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
}

type hookRule struct {
	MatchSubcommand []string `json:"match_subcommand"`
	Run             []string `json:"run"`
}

// Himalaya's global options that take a separate value.
var valueOptions = []string{"-c", "--config", "-a", "--account", "-b", "--backend", "--log-level", "--log-file"}

func main() {
	self, err := os.Executable()
	if err != nil {
		fail(err)
	}
	args := os.Args[1:]
	rec := record{Argv: args, Env: os.Environ()}
	rec.Hook, err = runHook(self+".hook", commandPath(args))
	if err != nil {
		rec.HookError = err.Error()
	}
	if err := appendRecord(self+".log", rec); err != nil {
		fail(err)
	}
	if rec.HookError != "" {
		fail(fmt.Errorf("hook: %s", rec.HookError))
	}
	target, err := os.ReadFile(self + ".target")
	if err != nil {
		fail(err)
	}
	bin := strings.TrimSpace(string(target))
	fail(syscall.Exec(bin, append([]string{bin}, args...), os.Environ()))
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

// runHook runs the rule in path if it exists and matches cmdPath.
func runHook(path string, cmdPath []string) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var rule hookRule
	if err := json.Unmarshal(data, &rule); err != nil {
		return false, err
	}
	if len(rule.Run) == 0 || !slices.Equal(rule.MatchSubcommand, cmdPath) {
		return false, nil
	}
	var out bytes.Buffer
	cmd := exec.Command(rule.Run[0], rule.Run[1:]...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("%v: %s", err, bytes.TrimSpace(out.Bytes()))
	}
	return true, nil
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
