package himalaya

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// optKind says how an allowlisted long option may appear.
type optKind int

const (
	optFlag   optKind = iota // --name
	optValue                 // --name=value
	optDlDir                 // --name=<state>/tmp/dl-*, a fresh download directory
	optStaged                // --name=<state>/tmp/att-*/<file>, a staged attachment
)

// posKind says what may follow "--".
type posKind int

const (
	posNone    posKind = iota
	posOne             // exactly one value (a mailbox name or a search query)
	posUID             // exactly one UID
	posUIDs            // one or more UIDs as separate values
	posUIDCSV          // one value: UIDs joined by commas
	posUIDPart         // a UID and an attachment part id
)

// spec is one entry of the positive command table (DESIGN section 4, L3).
type spec struct {
	json        bool // --json present (true) or absent (false)
	opts        map[string]optKind
	pos         posKind
	mutating    bool // a failure after start is outcome_uncertain unless definite
	selectFirst bool // SELECTs before its first mutating command, so a refused SELECT changed nothing
	stdoutCap   int64
	labelConfig bool // runs with the per-call remove_label config
}

const (
	capDefault = 4 << 20
	capRead    = 48 << 20
	capCompose = 40 << 20
	capStderr  = 64 << 10
)

// CapabilityProbe is the only argv imap raw may carry after "--".
const CapabilityProbe = "A1 CAPABILITY"

var commands = map[string]spec{
	"account list":        {json: true, stdoutCap: capDefault},
	"mailbox list":        {json: true, opts: map[string]optKind{"counts": optFlag}, stdoutCap: capDefault},
	"envelope list":       {json: true, opts: pagedOpts, stdoutCap: capDefault},
	"envelope search":     {json: true, opts: pagedOpts, pos: posOne, stdoutCap: capDefault},
	"message read":        {json: true, opts: mailboxOpt, pos: posUID, stdoutCap: capRead},
	"message move":        {json: true, opts: fromToOpts, pos: posUIDs, mutating: true, selectFirst: true, stdoutCap: capDefault},
	"message copy":        {json: true, opts: fromToOpts, pos: posUIDs, mutating: true, selectFirst: true, stdoutCap: capDefault},
	"message compose":     {opts: composeOpts, stdoutCap: capCompose},
	"message reply":       {opts: replyOpts, pos: posUID, stdoutCap: capCompose},
	"message forward":     {opts: replyOpts, pos: posUID, stdoutCap: capCompose},
	"message add":         {json: true, opts: flagOpts, mutating: true, stdoutCap: capDefault},
	"message delete":      {json: true, opts: mailboxOpt, pos: posUIDs, mutating: true, selectFirst: true, stdoutCap: capDefault, labelConfig: true},
	"attachment list":     {json: true, opts: mailboxOpt, pos: posUID, stdoutCap: capDefault},
	"attachment download": {json: true, opts: map[string]optKind{"mailbox": optValue, "dir": optDlDir}, pos: posUIDPart, stdoutCap: capDefault},
	"flag add":            {json: true, opts: flagOpts, pos: posUIDs, mutating: true, selectFirst: true, stdoutCap: capDefault},
	"flag remove":         {json: true, opts: flagOpts, pos: posUIDs, mutating: true, selectFirst: true, stdoutCap: capDefault},
	"imap status":         {json: true, pos: posOne, stdoutCap: capDefault},
	"imap fetch":          {json: true, opts: map[string]optKind{"mailbox": optValue, "flags": optFlag, "size": optFlag}, pos: posUIDCSV, stdoutCap: capDefault},
	"imap raw":            {json: true, pos: posOne, stdoutCap: capDefault},
}

// flagValues are the only values --flag may carry, per command.
var flagValues = map[string][]string{
	"flag add":    {"seen", "flagged"},
	"flag remove": {"seen", "flagged"},
	"message add": {"draft", "seen"},
}

var (
	mailboxOpt  = map[string]optKind{"mailbox": optValue}
	pagedOpts   = map[string]optKind{"mailbox": optValue, "page": optValue, "page-size": optValue, "has-attachment": optFlag}
	fromToOpts  = map[string]optKind{"from": optValue, "to": optValue}
	flagOpts    = map[string]optKind{"mailbox": optValue, "flag": optValue}
	composeOpts = map[string]optKind{"to": optValue, "cc": optValue, "bcc": optValue, "subject": optValue, "attach": optStaged}
	replyOpts   = map[string]optKind{"mailbox": optValue, "to": optValue, "cc": optValue, "attach": optStaged}
)

// Guard is the runner's last check on argv (DESIGN section 4, L3): the fixed
// global prefix, then a positive table of command paths with the exact long
// options each may carry. Everything else is refused.
type Guard struct {
	StateDir string
	Accounts []string
}

// Check validates argv (everything after the binary path) and returns the
// command path, such as "envelope list".
func (g Guard) Check(argv []string) (string, error) {
	path, _, err := g.check(argv)
	return path, err
}

func (g Guard) check(argv []string) (string, spec, error) {
	refuse := func(format string, a ...any) (string, spec, error) {
		return "", spec{}, fmt.Errorf("guard: "+format, a...)
	}
	if len(argv) < 8 || argv[0] != "-c" || argv[2] != "-a" || argv[4] != "-b" || argv[5] != "imap" ||
		argv[6] != "--log-level" || argv[7] != "off" {
		return refuse("bad global prefix")
	}
	cfg, acct := argv[1], argv[3]
	if !slices.Contains(g.Accounts, acct) {
		return refuse("unknown account")
	}
	rest := argv[8:]
	hasJSON := len(rest) > 0 && rest[0] == "--json"
	if hasJSON {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return refuse("missing command")
	}
	path := rest[0] + " " + rest[1]
	s, ok := commands[path]
	if !ok {
		return refuse("command %q is not allowlisted", path)
	}
	if hasJSON != s.json {
		return refuse("--json placement for %q", path)
	}
	if s.labelConfig {
		dir := filepath.Dir(cfg)
		if filepath.Dir(dir) != filepath.Join(g.StateDir, "tmp") || !strings.HasPrefix(filepath.Base(dir), "label-") ||
			filepath.Base(cfg) != acct+".toml" || filepath.Clean(cfg) != cfg {
			return refuse("%q needs a per-call label config", path)
		}
	} else if cfg != filepath.Join(g.StateDir, "himalaya", acct+".toml") {
		return refuse("bad config path")
	}

	args := rest[2:]
	var positionals []string
	for i, a := range args {
		if a == "--" {
			positionals = args[i+1:]
			break
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		kind, ok := s.opts[name]
		if !strings.HasPrefix(a, "--") || !ok {
			return refuse("token %d of %q is not an allowed option", i, path)
		}
		switch {
		case kind == optFlag && hasValue, kind != optFlag && !hasValue:
			return refuse("option --%s has the wrong form", name)
		case kind == optDlDir && !g.inTmp(value, "dl-", 1), kind == optStaged && !g.inTmp(value, "att-", 2):
			return refuse("option --%s must name a path the wrapper staged", name)
		case name == "flag" && !slices.Contains(flagValues[path], value):
			return refuse("option --flag has a value outside the allowlist")
		}
	}
	if !positionalsOK(s.pos, positionals) {
		return refuse("positionals do not fit %q", path)
	}
	if path == "imap raw" && positionals[0] != CapabilityProbe {
		return refuse("imap raw is limited to the capability probe")
	}
	return path, s, nil
}

func positionalsOK(kind posKind, p []string) bool {
	switch kind {
	case posNone:
		return len(p) == 0
	case posOne:
		return len(p) == 1
	case posUID:
		return len(p) == 1 && isUID(p[0])
	case posUIDs:
		return len(p) > 0 && !slices.ContainsFunc(p, func(u string) bool { return !isUID(u) })
	case posUIDCSV:
		return len(p) == 1 && !slices.ContainsFunc(strings.Split(p[0], ","), func(u string) bool { return !isUID(u) })
	case posUIDPart:
		return len(p) == 2 && isUID(p[0]) && isUID(p[1])
	}
	return false
}

// isUID accepts canonical decimals 1..MaxUID. 4294967295 would mean "*".
func isUID(s string) bool {
	if s == "" || len(s) > 10 || s[0] == '0' {
		return false
	}
	var n uint64
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + uint64(c-'0')
	}
	return n <= MaxUID
}

// inTmp accepts a clean path <state>/tmp/<prefix>*[/<name>] with exactly depth elements below tmp.
func (g Guard) inTmp(p, prefix string, depth int) bool {
	rel, ok := strings.CutPrefix(p, filepath.Join(g.StateDir, "tmp")+"/")
	parts := strings.Split(rel, "/")
	return ok && filepath.Clean(p) == p && len(parts) == depth && strings.HasPrefix(parts[0], prefix) &&
		!slices.Contains(parts, "") && !slices.Contains(parts, "..")
}
