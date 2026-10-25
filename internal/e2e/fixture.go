//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// FixtureImage is the pinned Dovecot image (multi-arch index digest for 2.4.5).
const FixtureImage = "dovecot/dovecot:2.4.5@sha256:43c14def08a57f25107593cbcf64a0a6fbae84a7b9de7aa038513c9b21e91914"

// Profile selects the post-login CAPABILITY list the fixture advertises.
type Profile string

const (
	// ProfileBridge advertises what Proton Bridge (Gluon) does: no SORT, so
	// Himalaya takes its client-side sort path.
	ProfileBridge Profile = "bridge"
	// ProfileNoMove is ProfileBridge without MOVE and UIDPLUS.
	ProfileNoMove Profile = "nomove"
	// ProfileFull keeps Dovecot's own list, SORT included.
	ProfileFull Profile = "full"
)

var capabilities = map[Profile]string{
	ProfileBridge: "IMAP4rev1 IDLE UNSELECT UIDPLUS MOVE ID",
	ProfileNoMove: "IMAP4rev1 IDLE UNSELECT ID",
	ProfileFull:   "",
}

// User is a fixture IMAP account. Name doubles as the server account name.
type User struct {
	Name     string
	Login    string
	Password string
}

// Alice and Bob are the fixture's accounts.
var (
	Alice = User{Name: "alice", Login: "alice@example.test", Password: "alice-fixture-pass"}
	// Bob's password carries shell metacharacters that must stay literal.
	Bob = User{Name: "bob", Login: "bob@example.test", Password: "bob fixture pass $(not-run) ;|&"}
)

// The seed corpus, in UID order per mailbox. Files are in testdata/messages.
//
// alice INBOX: 1 plain unseen, 2 plain \Seen, 3 HTML with remote tracking
// images, 4 adversarial attachment names, 5 RFC 2047 subject \Seen \Flagged,
// 6 prompt injection. Every other mailbox holds one message.
var seedCorpus = []struct {
	user    User
	mailbox string
	flags   string
	file    string
}{
	{Alice, "INBOX", "", "alice-01-plain-unseen.eml"},
	{Alice, "INBOX", `\Seen`, "alice-02-plain-seen.eml"},
	{Alice, "INBOX", "", "alice-03-html-tracker.eml"},
	{Alice, "INBOX", "", "alice-04-adversarial-attachments.eml"},
	{Alice, "INBOX", `\Seen \Flagged`, "alice-05-unicode-subject.eml"},
	{Alice, "INBOX", "", "alice-06-prompt-injection.eml"},
	{Alice, "Archive", `\Seen`, "alice-07-archive.eml"},
	{Alice, "Drafts", `\Seen \Draft`, "alice-08-draft.eml"},
	{Alice, "Sent", `\Seen`, "alice-09-sent.eml"},
	{Alice, "Trash", `\Seen`, "alice-10-trash.eml"},
	{Alice, "Junk", "", "alice-11-junk.eml"},
	{Alice, "Résumé/Ünïcødé 📬", "", "alice-12-unicode-folder.eml"},
	{Alice, "Folders/Projects", `\Seen`, "alice-13-project.eml"},
	{Alice, "Labels/Work", "", "alice-14-label-work.eml"},
	{Bob, "INBOX", "", "bob-01-private-unseen.eml"},
	{Bob, "INBOX", `\Seen`, "bob-02-private-seen.eml"},
	{Bob, "Sent", `\Seen`, "bob-03-sent.eml"},
}

// StrayMailboxes are alice's mailboxes that get a pre-flagged \Deleted
// message (stray-deleted.eml, the last UID) with FixtureOptions.StrayDeleted.
var StrayMailboxes = []string{"INBOX", "Trash", "Labels/Work"}

// FixtureOptions configures StartFixture. The zero value starts the bridge
// profile serving PKI.Leaf from a fresh PKI.
type FixtureOptions struct {
	Profile      Profile
	PKI          *PKI
	ServerCert   *KeyPair // certificate Dovecot presents; default &PKI.Leaf
	StrayDeleted bool     // seed stray-deleted.eml with \Deleted into StrayMailboxes
}

// Fixture is a running, seeded Dovecot container bound to 127.0.0.1.
type Fixture struct {
	Name         string // container name, hmcp-it-<hex>
	Profile      Profile
	PKI          *PKI
	ServerCert   KeyPair
	Host         string // always 127.0.0.1
	STARTTLSPort int    // cleartext greeting, STARTTLS required before login
	TLSPort      int    // implicit TLS
}

// MailboxStatus is a mailbox's state as doveadm reports it.
type MailboxStatus struct {
	Messages    int
	Unseen      int
	UIDNext     uint32
	UIDValidity uint32
}

// MailEvent is one mail_log line from an IMAP session (docker logs). Events
// caused by doveadm (seeding, the state helpers) never appear here.
type MailEvent struct {
	User    string // login, e.g. alice@example.test
	Event   string // save, copy, expunge, flag_change, delete, undelete, mailbox_create, ...
	Mailbox string // box=: the mailbox the event happened in (the target of a copy)
	From    string // source mailbox of a copy, else empty
	UID     uint32 // uid= in Mailbox
	MsgID   string
	Flags   string
	Line    string
}

// containers records every fixture this process created, for TestMain's sweep.
var containers struct {
	sync.Mutex
	names []string
}

// StartFixture starts and seeds a fresh fixture, removed at cleanup.
func StartFixture(t testing.TB, opts FixtureOptions) *Fixture {
	t.Helper()
	RequireDocker(t)
	if opts.Profile == "" {
		opts.Profile = ProfileBridge
	}
	capability, ok := capabilities[opts.Profile]
	if !ok {
		t.Fatalf("unknown fixture profile %q", opts.Profile)
	}
	if opts.PKI == nil {
		opts.PKI = NewPKI(t)
	}
	if opts.ServerCert == nil {
		opts.ServerCert = &opts.PKI.Leaf
	}
	f := &Fixture{
		Name:       "hmcp-it-" + randomHex(t, 6),
		Profile:    opts.Profile,
		PKI:        opts.PKI,
		ServerCert: *opts.ServerCert,
		Host:       "127.0.0.1",
	}

	// Mounted read-only into the container, which runs as its own vmail
	// user, so these are world-readable inside a private temp dir.
	dc := filepath.Join(TempDir(t), "dovecot")
	if err := os.Mkdir(dc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dc, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dc, "dovecot.conf"), readFile(t, filepath.Join("testdata", "dovecot.conf")), 0o644)
	writeFile(t, filepath.Join(dc, "server.pem"), readFile(t, f.ServerCert.CertFile), 0o644)
	writeFile(t, filepath.Join(dc, "server.key"), readFile(t, f.ServerCert.KeyFile), 0o644)
	var users strings.Builder
	for _, u := range []User{Alice, Bob} {
		fmt.Fprintf(&users, "%s:{PLAIN}%s::::::\n", u.Login, u.Password)
	}
	writeFile(t, filepath.Join(dc, "users"), []byte(users.String()), 0o644)
	profile := ""
	if capability != "" {
		profile = "imap_capability = " + capability + "\n"
	}
	writeFile(t, filepath.Join(dc, "profile.conf"), []byte(profile), 0o644)

	containers.Lock()
	containers.names = append(containers.names, f.Name)
	containers.Unlock()
	t.Cleanup(func() { f.remove(t) })

	// Hardened and disposable: no capabilities beyond chroot, no privilege
	// gain, and mail on a tmpfs that replaces the image's VOLUME, so no
	// anonymous volume is left behind.
	runDocker(t, nil, "run", "-d", "--name", f.Name, "--label", "hmcp-fixture=1",
		"--cap-drop", "ALL", "--cap-add", "SYS_CHROOT", "--security-opt", "no-new-privileges",
		"--mount", "type=tmpfs,destination=/srv/vmail,tmpfs-mode=1777",
		"-v", filepath.Join(dc, "dovecot.conf")+":/etc/dovecot/dovecot.conf:ro",
		"-v", dc+":/etc/dovecot/fixture:ro",
		"-p", "127.0.0.1::31143", "-p", "127.0.0.1::31993",
		FixtureImage)
	f.STARTTLSPort = f.hostPort(t, 31143)
	f.TLSPort = f.hostPort(t, 31993)
	f.waitReady(t)
	f.seed(t, opts.StrayDeleted)
	return f
}

func (f *Fixture) remove(t testing.TB) {
	if t.Failed() {
		if out, err := dockerCmd(context.Background(), nil, "logs", "--tail", "40", f.Name); err == nil {
			t.Logf("last fixture log lines of %s:\n%s", f.Name, out)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := dockerCmd(ctx, nil, "rm", "-f", "-v", f.Name); err != nil && !strings.Contains(err.Error(), "No such container") {
		t.Errorf("remove fixture: %v", err)
	}
}

// hostPort returns the 127.0.0.1 port docker mapped to the container port.
func (f *Fixture) hostPort(t testing.TB, port int) int {
	t.Helper()
	out := runDocker(t, nil, "port", f.Name, fmt.Sprintf("%d/tcp", port))
	first, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	host, p, err := net.SplitHostPort(first)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("docker port %d: unexpected %q", port, out)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// waitReady waits for a real greeting: docker-proxy accepts connections
// before Dovecot listens.
func (f *Fixture) waitReady(t testing.TB) {
	t.Helper()
	addr := net.JoinHostPort(f.Host, strconv.Itoa(f.STARTTLSPort))
	deadline := time.Now().Add(30 * time.Second)
	for {
		if greeting(addr) == "* OK" {
			return
		}
		state, _ := dockerCmd(context.Background(), nil, "inspect", "-f", "{{.State.Running}}", f.Name)
		if strings.TrimSpace(string(state)) != "true" || time.Now().After(deadline) {
			logs, _ := dockerCmd(context.Background(), nil, "logs", "--tail", "40", f.Name)
			t.Fatalf("fixture %s did not become ready:\n%s", f.Name, logs)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func greeting(addr string) string {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return ""
	}
	return string(buf)
}

func (f *Fixture) seed(t testing.TB, strays bool) {
	t.Helper()
	nextUID := map[string]uint32{}
	existing := map[string]bool{}
	for _, u := range []User{Alice, Bob} {
		// Listing also auto-creates the special-use mailboxes, so no IMAP
		// session logs a mailbox_create later.
		for box := range strings.Lines(string(f.Doveadm(t, "mailbox", "list", "-u", u.Login))) {
			existing[u.Login+"\x00"+strings.TrimSpace(box)] = true
		}
	}
	add := func(u User, box, flags, file string) {
		key := u.Login + "\x00" + box
		if !existing[key] {
			f.Doveadm(t, "mailbox", "create", "-s", "-u", u.Login, box)
			existing[key] = true
		}
		f.save(t, u, box, Message(t, file))
		nextUID[key]++
		if flags != "" {
			f.addFlags(t, u, box, nextUID[key], flags)
		}
	}
	for _, m := range seedCorpus {
		add(m.user, m.mailbox, m.flags, m.file)
	}
	if strays {
		for _, box := range StrayMailboxes {
			add(Alice, box, `\Deleted`, "stray-deleted.eml")
		}
	}
}

// Seed appends eml to an existing mailbox, adds flags (IMAP spelling, e.g.
// `\Deleted`) and returns the new message's UID.
func (f *Fixture) Seed(t testing.TB, u User, mailbox string, eml []byte, flags ...string) uint32 {
	t.Helper()
	uid := f.Status(t, u, mailbox).UIDNext
	f.save(t, u, mailbox, eml)
	if len(flags) > 0 {
		f.addFlags(t, u, mailbox, uid, strings.Join(flags, " "))
	}
	return uid
}

func (f *Fixture) save(t testing.TB, u User, mailbox string, eml []byte) {
	t.Helper()
	f.doveadm(t, eml, "save", "-u", u.Login, "-m", mailbox)
}

func (f *Fixture) addFlags(t testing.TB, u User, mailbox string, uid uint32, flags string) {
	t.Helper()
	f.Doveadm(t, "flags", "add", "-u", u.Login, flags, "mailbox", mailbox, "uid", strconv.FormatUint(uint64(uid), 10))
}

// Message returns testdata/messages/<name>.
func Message(t testing.TB, name string) []byte {
	t.Helper()
	return readFile(t, filepath.Join("testdata", "messages", name))
}

// Flags returns every message's flags by UID, each list sorted and without
// the session-local \Recent.
func (f *Fixture) Flags(t testing.TB, u User, mailbox string) map[uint32][]string {
	t.Helper()
	flags := map[uint32][]string{}
	for _, row := range f.tab(t, "fetch", "-u", u.Login, "uid flags", "mailbox", mailbox, "all") {
		uid, err := strconv.ParseUint(row["uid"], 10, 32)
		if err != nil {
			t.Fatalf("doveadm fetch: bad uid %q", row["uid"])
		}
		list := []string{}
		for fl := range strings.FieldsSeq(row["flags"]) {
			if fl != `\Recent` {
				list = append(list, fl)
			}
		}
		slices.Sort(list)
		flags[uint32(uid)] = list
	}
	return flags
}

// RawMessage returns the stored message (headers and body) with that UID.
func (f *Fixture) RawMessage(t testing.TB, u User, mailbox string, uid uint32) []byte {
	t.Helper()
	out := f.Doveadm(t, "fetch", "-u", u.Login, "text", "mailbox", mailbox, "uid", strconv.FormatUint(uint64(uid), 10))
	msg, ok := bytes.CutPrefix(out, []byte("text:\n"))
	if !ok {
		t.Fatalf("no message with UID %d in %s", uid, mailbox)
	}
	return msg
}

// UIDs returns the mailbox's UIDs in ascending order.
func (f *Fixture) UIDs(t testing.TB, u User, mailbox string) []uint32 {
	t.Helper()
	var uids []uint32
	for uid := range f.Flags(t, u, mailbox) {
		uids = append(uids, uid)
	}
	slices.Sort(uids)
	return uids
}

// Status returns the mailbox's message count, unseen count, UIDNEXT and
// UIDVALIDITY.
func (f *Fixture) Status(t testing.TB, u User, mailbox string) MailboxStatus {
	t.Helper()
	rows := f.tab(t, "mailbox", "status", "-u", u.Login, "messages unseen uidnext uidvalidity", mailbox)
	if len(rows) != 1 {
		t.Fatalf("doveadm mailbox status %q: %d rows", mailbox, len(rows))
	}
	num := func(k string) uint64 {
		n, err := strconv.ParseUint(rows[0][k], 10, 32)
		if err != nil {
			t.Fatalf("doveadm mailbox status %q: bad %s %q", mailbox, k, rows[0][k])
		}
		return n
	}
	return MailboxStatus{
		Messages:    int(num("messages")),
		Unseen:      int(num("unseen")),
		UIDNext:     uint32(num("uidnext")),
		UIDValidity: uint32(num("uidvalidity")),
	}
}

// SetUIDValidity changes the mailbox's UIDVALIDITY, which invalidates every
// reference into it.
func (f *Fixture) SetUIDValidity(t testing.TB, u User, mailbox string, v uint32) {
	t.Helper()
	f.Doveadm(t, f.uidValidityArgs(u, mailbox, v)...)
}

// SetUIDValidityArgv is the absolute argv of SetUIDValidity, for Shim.SetHook.
func (f *Fixture) SetUIDValidityArgv(u User, mailbox string, v uint32) []string {
	return f.DoveadmArgv(f.uidValidityArgs(u, mailbox, v)...)
}

func (f *Fixture) uidValidityArgs(u User, mailbox string, v uint32) []string {
	return []string{"mailbox", "update", "-u", u.Login, "--uid-validity", strconv.FormatUint(uint64(v), 10), mailbox}
}

// MailLog returns every mail_log event IMAP sessions produced so far, in
// order. It still works after StopIMAP.
func (f *Fixture) MailLog(t testing.TB) []MailEvent {
	t.Helper()
	out := runDocker(t, nil, "logs", f.Name)
	var events []MailEvent
	for line := range strings.Lines(string(out)) {
		if e, ok := parseMailEvent(strings.TrimRight(line, "\r\n")); ok {
			events = append(events, e)
		}
	}
	return events
}

// mail_log lines look like
//
//	imap(alice@example.test)<282><YoBE7I>: Info: Mailbox INBOX: flag_change: box=INBOX, uid=1, msgid=<a@b>, flags=(\Seen \Recent)
//	imap(alice@example.test)<284><asVE7I>: Info: Mailbox Archive: copy from INBOX: box=Archive, uid=2, msgid=<a@b>, flags=()
//	imap(alice@example.test)<286><4Q9F7I>: Info: Mailbox Foo: Mailbox created
var (
	mailLogMessage = regexp.MustCompile(`\bimap\(([^)]*)\)<[^>]*><[^>]*>: Info: Mailbox .*?: ([a-z_]+)(?: from (.*?))?: (box=.*)$`)
	mailLogMailbox = regexp.MustCompile(`\bimap\(([^)]*)\)<[^>]*><[^>]*>: Info: Mailbox (.*): Mailbox (created|deleted|renamed)\b`)
	mailLogField   = regexp.MustCompile(`(box|uid|msgid|flags)=(\([^)]*\)|<[^>]*>|[^,]*)`)
	mailboxEvents  = map[string]string{"created": "mailbox_create", "deleted": "mailbox_delete", "renamed": "mailbox_rename"}
)

func parseMailEvent(line string) (MailEvent, bool) {
	if m := mailLogMailbox.FindStringSubmatch(line); m != nil {
		return MailEvent{User: m[1], Event: mailboxEvents[m[3]], Mailbox: m[2], Line: line}, true
	}
	m := mailLogMessage.FindStringSubmatch(line)
	if m == nil {
		return MailEvent{}, false
	}
	e := MailEvent{User: m[1], Event: m[2], From: m[3], Line: line}
	for _, kv := range mailLogField.FindAllStringSubmatch(m[4], -1) {
		switch v := kv[2]; kv[1] {
		case "box":
			e.Mailbox = v
		case "uid":
			n, _ := strconv.ParseUint(v, 10, 32)
			e.UID = uint32(n)
		case "msgid":
			e.MsgID = v
		case "flags":
			e.Flags = strings.Trim(v, "()")
		}
	}
	return e, true
}

// StopIMAP stops the container, so connections are refused as for an
// unreachable account. The doveadm helpers stop working; MailLog does not.
func (f *Fixture) StopIMAP(t testing.TB) {
	t.Helper()
	runDocker(t, nil, "stop", "-t", "1", f.Name)
}

// Doveadm runs doveadm in the container and returns its stdout. doveadm's
// own log goes to stderr, so stdout is only the command's output.
func (f *Fixture) Doveadm(t testing.TB, args ...string) []byte {
	t.Helper()
	return f.doveadm(t, nil, args...)
}

// DoveadmArgv is the absolute argv that runs doveadm args in the container.
func (f *Fixture) DoveadmArgv(args ...string) []string {
	return append([]string{dockerPath(), "exec", f.Name, "doveadm", "-o", "log_path=/dev/stderr"}, args...)
}

func (f *Fixture) doveadm(t testing.TB, stdin []byte, args ...string) []byte {
	t.Helper()
	argv := f.DoveadmArgv(args...)[1:]
	if stdin != nil {
		argv = slices.Insert(argv, 1, "-i")
	}
	return runDocker(t, stdin, argv...)
}

// tab runs doveadm with the tab formatter and returns its rows keyed by the
// header line.
func (f *Fixture) tab(t testing.TB, args ...string) []map[string]string {
	t.Helper()
	out := f.Doveadm(t, append([]string{"-f", "tab"}, args...)...)
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil
	}
	header := strings.Split(lines[0], "\t")
	var rows []map[string]string
	for _, l := range lines[1:] {
		vals := strings.Split(l, "\t")
		if len(vals) != len(header) {
			t.Fatalf("doveadm %v: row %q does not match header %q", args, l, lines[0])
		}
		row := map[string]string{}
		for i, h := range header {
			row[h] = vals[i]
		}
		rows = append(rows, row)
	}
	return rows
}

var dockerPath = sync.OnceValue(func() string {
	if p, err := exec.LookPath("docker"); err == nil {
		return p
	}
	return "docker"
})

// runDocker runs the docker CLI and fails the test on error.
func runDocker(t testing.TB, stdin []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := dockerCmd(ctx, stdin, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func dockerCmd(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, dockerPath(), args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("docker %s: %v", strings.Join(args, " "), err)
		if msg := bytes.TrimSpace(stderr.Bytes()); len(msg) > 0 {
			err = fmt.Errorf("%w: %s", err, msg)
		}
	}
	return out, err
}

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func randomHex(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
