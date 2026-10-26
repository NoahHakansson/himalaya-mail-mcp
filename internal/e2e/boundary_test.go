//go:build integration

package e2e

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The no-send, no-arbitrary-command boundary: adversarial tool inputs,
// Himalaya's send paths, startup refusals, failures and cancellation, and
// the HTTP front door.

// bdOptionValues look like Himalaya options. Every string field either
// rejects them or passes them on literally.
var bdOptionValues = []string{"--save=Sent", "-a", "--", "--json"}

// TestAdversarialInputs sends option-looking, shell-looking,
// control-character, over-long and unknown inputs to every tool. Each is
// rejected before any Himalaya run or kept literal. TestMain's argv audit
// then checks every run against the server's L3 guard.
func TestAdversarialInputs(t *testing.T) {
	f := StartFixture(t, FixtureOptions{})
	shim := BuildShim(t, HimalayaPath(t))
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	cs := StartStdio(t, BuildServer(t), files)

	// listed returns the uidvalidity and the first tagged uid of mailbox, as list_messages gives them.
	listed := func(mailbox string) (uint32, string) {
		var out struct {
			UIDValidity uint32
			Messages    []struct{ UID string }
		}
		bdOK(t, bdCall(t, cs, "list_messages", map[string]any{"account": "alice", "mailbox": mailbox}), &out)
		if len(out.Messages) == 0 {
			t.Fatalf("%s is empty", mailbox)
		}
		return out.UIDValidity, out.Messages[0].UID
	}
	inbox, inboxUID := listed("INBOX")
	trash, trashUID := listed("Trash")
	work, workUID := listed("Labels/Work")
	drafts, draftUID := listed("Drafts")
	ref := map[string]any{"account": "alice", "mailbox": "INBOX", "uidvalidity": inbox, "uid": inboxUID}
	batch := map[string]any{"account": "alice", "mailbox": "INBOX", "uidvalidity": inbox, "uids": []any{inboxUID}}
	with := func(base map[string]any, kv ...any) map[string]any {
		m := maps.Clone(base)
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	// Valid arguments per tool, so that the field under test is the only fault.
	tools := []struct {
		name                               string
		base                               map[string]any
		mailboxes, addresses, files, dates []string
	}{
		{name: "list_mailboxes", base: map[string]any{"account": "alice"}},
		{name: "list_messages", base: map[string]any{"account": "alice", "mailbox": "INBOX"}, mailboxes: []string{"mailbox"}},
		{name: "search_messages", base: map[string]any{"account": "alice", "mailbox": "INBOX", "subject": "x"},
			mailboxes: []string{"mailbox"}, dates: []string{"since", "before", "on"}},
		{name: "read_message", base: ref, mailboxes: []string{"mailbox"}},
		{name: "list_attachments", base: ref, mailboxes: []string{"mailbox"}},
		{name: "download_attachment", base: with(ref, "part_id", 1), mailboxes: []string{"mailbox"}},
		{name: "update_flags", base: with(batch, "seen", true), mailboxes: []string{"mailbox"}},
		{name: "move_messages", base: with(batch, "to", "Archive"), mailboxes: []string{"mailbox", "to"}},
		{name: "archive_messages", base: batch, mailboxes: []string{"mailbox"}},
		{name: "trash_messages", base: batch, mailboxes: []string{"mailbox"}},
		{name: "restore_messages", base: map[string]any{"account": "alice", "uidvalidity": trash, "uids": []any{trashUID}, "to": "INBOX"},
			mailboxes: []string{"to"}},
		{name: "add_label", base: with(batch, "label", "Labels/Work"), mailboxes: []string{"mailbox", "label"}},
		{name: "remove_label", base: map[string]any{"account": "alice", "label": "Labels/Work", "uidvalidity": work, "uids": []any{workUID}},
			mailboxes: []string{"label"}},
		{name: "create_draft", base: map[string]any{"account": "alice", "to": []any{"carol@example.test"}, "subject": "x"},
			addresses: []string{"to", "cc", "bcc"}, files: []string{"attachments"}},
		{name: "update_draft", base: map[string]any{"account": "alice", "uidvalidity": drafts, "uid": draftUID, "subject": "x"},
			addresses: []string{"to", "cc", "bcc"}, files: []string{"attachments"}},
		{name: "reply_draft", base: with(ref, "body", "x"), mailboxes: []string{"mailbox"}, addresses: []string{"to", "cc"}, files: []string{"attachments"}},
		{name: "forward_draft", base: with(ref, "to", []any{"carol@example.test"}), mailboxes: []string{"mailbox"}, addresses: []string{"to", "cc"}, files: []string{"attachments"}},
	}

	type rejection struct {
		tool, field string
		args        map[string]any
		handler     bool // the schema allows it, so the handler's own check must refuse it
	}
	var rejections []rejection
	reject := func(tool, field string, args map[string]any) {
		rejections = append(rejections, rejection{tool: tool, field: field, args: args})
	}
	rejectInHandler := func(tool, field string, args map[string]any) {
		rejections = append(rejections, rejection{tool: tool, field: field, args: args, handler: true})
	}
	for _, tl := range tools {
		for _, v := range bdOptionValues {
			reject(tl.name, "account", with(tl.base, "account", v))
		}
		for _, field := range tl.mailboxes {
			for _, v := range append([]string{"-c/etc/passwd", "INBOX\r\nA1 LOGOUT"}, bdOptionValues...) {
				reject(tl.name, field, with(tl.base, field, v))
			}
			// The schema allows invisible characters; the mailbox rule refuses them.
			rejectInHandler(tl.name, field, with(tl.base, field, "Labels/Work\u200b"))
		}
		for _, field := range tl.addresses {
			for _, v := range append([]string{"--send"}, bdOptionValues...) {
				reject(tl.name, field, with(tl.base, field, []any{v}))
			}
		}
		for _, field := range tl.files {
			for _, v := range append([]string{"../x"}, bdOptionValues...) {
				reject(tl.name, field, with(tl.base, field, []any{v}))
			}
		}
		for _, field := range tl.dates {
			for _, v := range bdOptionValues {
				reject(tl.name, field, with(tl.base, field, v))
			}
		}
	}
	draft := map[string]any{"account": "alice", "to": []any{"carol@example.test"}}
	reject("read_message", "uid", with(ref, "uid", "1,2"))
	reject("update_flags", "uids", with(batch, "seen", true, "uids", []any{"1,2"}))
	// A bare number, without the tag that ties it to its mailbox.
	reject("read_message", "uid", with(ref, "uid", 1))
	reject("update_flags", "uids", with(batch, "seen", true, "uids", []any{1}))
	// Over-long values: the schema counts code points, the handlers also count bytes.
	reject("create_draft", "subject", with(draft, "subject", strings.Repeat("a", 256)))
	rejectInHandler("create_draft", "subject", with(draft, "subject", strings.Repeat("𝄞", 255)))
	reject("create_draft", "body", with(draft, "body", strings.Repeat("a", 256<<10+1)))
	rejectInHandler("create_draft", "body", with(draft, "body", strings.Repeat("€", 90000)))
	reject("search_messages", "subject", with(tools[2].base, "subject", strings.Repeat("a", 201)))
	reject("list_messages", "mailbox", with(tools[1].base, "mailbox", strings.Repeat("a", 256)))
	rejectInHandler("list_messages", "mailbox", with(tools[1].base, "mailbox", strings.Repeat("𝄞", 255)))
	// Unknown fields, named after Himalaya options DESIGN section 2.3 keeps unreachable.
	reject("list_messages", "cmd", with(tools[1].base, "cmd", "id"))
	reject("create_draft", "send", with(draft, "send", true))
	reject("create_draft", "from", with(draft, "from", "mallory@example.test"))
	reject("create_draft", "save", with(draft, "save", "Sent"))
	reject("read_message", "seen", with(ref, "seen", true))
	reject("read_message", "raw", with(ref, "raw", true))

	for _, r := range rejections {
		before := len(shim.Records(t))
		res := bdCall(t, cs, r.tool, r.args)
		text := resultText(res)
		switch {
		case !res.IsError:
			t.Errorf("%s with %s = %s was accepted: %s", r.tool, r.field, bdShort(r.args[r.field]), bdShort(text))
		case !strings.HasPrefix(text, "invalid_argument: ") && (r.handler || !strings.HasPrefix(text, `validating "arguments"`)):
			t.Errorf("%s with %s = %s: not the expected validation error: %s", r.tool, r.field, bdShort(r.args[r.field]), bdShort(text))
		case !strings.Contains(text, "/properties/"+r.field) && !strings.Contains(text, "("+r.field+" ") && !strings.Contains(text, `"`+r.field+`"`):
			// The error names a different field: the base arguments are wrong, not the field under test.
			t.Errorf("%s with %s = %s: rejected for another field: %s", r.tool, r.field, bdShort(r.args[r.field]), bdShort(text))
		}
		if n := len(shim.Records(t)); n != before {
			t.Errorf("%s with %s = %s ran Himalaya %d times", r.tool, r.field, bdShort(r.args[r.field]), n-before)
		}
	}
	t.Logf("%d adversarial inputs rejected before any Himalaya run", len(rejections))

	// Kept literal: option-looking and shell-looking text in search terms,
	// subjects and bodies. Search patterns are quoted inside the one query
	// value after "--"; subjects travel as one --subject= token; bodies go
	// on stdin and never into argv.
	marker := Message(t, "alice-01-plain-unseen.eml")
	marker = regexp.MustCompile(`(?m)^Subject: .*$`).ReplaceAll(marker, []byte("Subject: $(id) --save=Sent"))
	marker = append(marker, "\r\n$(id) -a --json\r\n"...)
	markerUID := f.Seed(t, Alice, "INBOX", marker)

	type search struct {
		args  map[string]any
		query string // the one argv value after "--"
		want  []uint32
	}
	searches := []search{
		{map[string]any{"subject": "$(id)"}, `subject "$(id)" order by date desc`, []uint32{markerUID}},
		{map[string]any{"body": "$(id) -a"}, `body "$(id) -a" order by date desc`, []uint32{markerUID}},
	}
	for _, v := range bdOptionValues {
		searches = append(searches, search{
			map[string]any{"from": v, "to": v, "subject": v, "body": v},
			fmt.Sprintf(`from "%s" and to "%s" and subject "%s" and body "%s" order by date desc`, v, v, v, v),
			[]uint32{},
		})
	}
	for _, s := range searches {
		before := len(shim.Records(t))
		var out struct{ Messages []struct{ UID string } }
		bdOK(t, bdCall(t, cs, "search_messages", bdMerge(map[string]any{"account": "alice", "mailbox": "INBOX"}, s.args)), &out)
		got := []uint32{}
		for _, m := range out.Messages {
			got = append(got, uidNumber(t, m.UID))
		}
		if !slices.Equal(got, s.want) {
			t.Errorf("search %v found UIDs %v, want %v", s.args, got, s.want)
		}
		r := bdRecord(t, shim.Records(t)[before:], "envelope search")
		if n := len(r.Argv); n < 2 || r.Argv[n-2] != "--" || r.Argv[n-1] != s.query {
			t.Errorf("search %v ran %q, want the single query %q after --", s.args, r.Argv, s.query)
		}
	}

	sentBefore := f.Status(t, Alice, "Sent")
	inboxBefore := f.Status(t, Alice, "INBOX")
	for _, v := range bdOptionValues {
		before := len(shim.Records(t))
		body := "$(id)\n" + v + "\n"
		var d struct{ UID string }
		bdOK(t, bdCall(t, cs, "create_draft", with(draft, "subject", v, "body", body)), &d)
		r := bdRecord(t, shim.Records(t)[before:], "message compose")
		// After the fixed global prefix, which carries -a itself.
		if args := r.Argv[8:]; !slices.Contains(args, "--subject="+v) || slices.Contains(args, v) {
			t.Errorf("subject %q: compose ran %q, want it only inside --subject=", v, r.Argv)
		}
		raw := string(f.RawMessage(t, Alice, "Drafts", uidNumber(t, d.UID)))
		if !regexp.MustCompile(`(?m)^Subject: `+regexp.QuoteMeta(v)+"\r?$").MatchString(raw) || !strings.Contains(raw, "$(id)") {
			t.Errorf("draft %s for subject %q is not literal:\n%s", d.UID, v, raw)
		}
	}
	for _, r := range shim.Records(t) {
		for _, a := range r.Argv {
			if strings.Contains(a, "$(id)") && !strings.HasPrefix(a, "subject ") && !strings.HasPrefix(a, "body ") {
				t.Errorf("argv %q carries shell-looking input outside a search query", r.Argv)
			}
		}
	}
	if got := f.Status(t, Alice, "Sent"); got != sentBefore {
		t.Errorf("Sent changed from %+v to %+v; --save=Sent must stay a subject", sentBefore, got)
	}
	if got := f.Status(t, Alice, "INBOX"); got.Messages != inboxBefore.Messages || got.UIDNext != inboxBefore.UIDNext {
		t.Errorf("INBOX changed from %+v to %+v", inboxBefore, got)
	}
	for _, e := range f.MailLog(t) {
		if e.Event != "save" || e.Mailbox != "Drafts" {
			t.Errorf("unexpected mail event %s", e.Line)
		}
	}
}

// TestSendPathsFailClosed runs Himalaya's send paths with the
// server-generated config and the real binaries, inside a container with no
// network that also runs the Dovecot fixture, so reply and forward reach
// their send step. Every path must stop with "No send-capable backend"
// before anything is appended. The binary under test is the IMAP-only
// build (L5 plus L4); the official asset, when present, shows that the
// generated config alone (L4) fails closed too.
func TestSendPathsFailClosed(t *testing.T) {
	underTest := HimalayaPath(t)
	RequireDocker(t)
	bins := []string{underTest}
	if official := bdOfficialAsset(); official != "" && official != underTest {
		bins = append(bins, official)
	}

	pki := NewPKI(t)
	// Inside the container the fixture listens on its own ports.
	f := &Fixture{Name: "hmcp-it-" + randomHex(t, 6), Profile: ProfileBridge, PKI: pki, ServerCert: pki.Leaf,
		Host: "127.0.0.1", STARTTLSPort: 31143, TLSPort: 31993}
	shim := BuildShim(t, underTest)
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	// Startup writes <state>/himalaya/alice.toml and makes no connection.
	StartStdio(t, BuildServer(t), files)
	toml := filepath.Join(files.StateDir, "himalaya", "alice.toml")

	dc := bdDovecotDir(t, pki)
	args := []string{"run", "-d", "--rm", "--network", "none", "--name", f.Name, "--label", "hmcp-fixture=1",
		"--cap-drop", "ALL", "--cap-add", "SYS_CHROOT", "--security-opt", "no-new-privileges",
		"--mount", "type=tmpfs,destination=/srv/vmail,tmpfs-mode=1777",
		"-v", filepath.Join(dc, "dovecot.conf") + ":/etc/dovecot/dovecot.conf:ro",
		"-v", dc + ":/etc/dovecot/fixture:ro",
		// The image has no /bin/cat, which the generated password command runs.
		"-v", bdStaticCat(t) + ":/bin/cat:ro"}
	for _, p := range []string{toml, files.PasswordFiles[Alice.Name], pki.CA.CertFile} {
		args = append(args, "-v", p+":"+p+":ro")
	}
	inContainer := map[string]string{}
	for i, b := range bins {
		inContainer[b] = fmt.Sprintf("/hmcp/himalaya-%d", i)
		args = append(args, "-v", b+":"+inContainer[b]+":ro")
	}
	containers.Lock()
	containers.names = append(containers.names, f.Name)
	containers.Unlock()
	t.Cleanup(func() {
		if t.Failed() {
			if out, err := dockerCmd(context.Background(), nil, "logs", "--tail", "40", f.Name); err == nil {
				t.Logf("last log lines of %s:\n%s", f.Name, out)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dockerCmd(ctx, nil, "rm", "-f", "-v", f.Name)
	})
	runDocker(t, nil, append(args, FixtureImage)...)
	if mode := strings.TrimSpace(string(runDocker(t, nil, "inspect", "-f", "{{.HostConfig.NetworkMode}}", f.Name))); mode != "none" {
		t.Fatalf("probe container network mode %q, want none", mode)
	}

	prefix := []string{"-c", toml, "-a", Alice.Name, "-b", "imap", "--log-level", "off"}
	bdWaitFor(t, "doveadm in "+f.Name, func() bool {
		_, err := dockerCmd(context.Background(), nil, f.DoveadmArgv("mailbox", "status", "-u", Alice.Login, "messages", "INBOX")[1:]...)
		return err == nil
	})
	uid := fmt.Sprint(f.Seed(t, Alice, "INBOX", Message(t, "alice-01-plain-unseen.eml")))
	// The generated config works in there: login over TLS with the CA and /bin/cat.
	bdWaitFor(t, "an IMAP login from "+f.Name, func() bool {
		code, _ := bdExecIn(t, f.Name, nil, append([]string{inContainer[underTest]}, append(prefix, "--json", "imap", "status", "--", "INBOX")...)...)
		return code == 0
	})

	boxes := []string{"INBOX", "Drafts", "Sent"}
	before := map[string]MailboxStatus{}
	for _, b := range boxes {
		before[b] = f.Status(t, Alice, b)
	}
	flagsBefore := f.Flags(t, Alice, "INBOX")

	raw := []byte("From: alice@example.test\r\nTo: nobody@example.invalid\r\nSubject: no-send probe\r\n\r\nThis must never be sent.\r\n")
	body := []byte("This must never be sent.\n")
	probes := []struct {
		args  []string
		stdin []byte
	}{
		{[]string{"message", "send"}, raw},
		{[]string{"message", "compose", "--to=nobody@example.invalid", "--subject=no-send probe", "--send"}, body},
		{[]string{"message", "add", "--mailbox=Drafts", "--send"}, raw},
		{[]string{"message", "reply", "--mailbox=INBOX", "--send", "--", uid}, body},
		{[]string{"message", "forward", "--mailbox=INBOX", "--to=nobody@example.invalid", "--send", "--", uid}, body},
	}
	for _, bin := range bins {
		label := filepath.Base(filepath.Dir(bin)) + "/" + filepath.Base(bin)
		for _, p := range probes {
			code, out := bdExecIn(t, f.Name, p.stdin, append([]string{inContainer[bin]}, append(prefix, p.args...)...)...)
			t.Logf("%s %q: exit %d: %s", label, p.args, code, strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
			if code != 1 || !strings.Contains(out, "No send-capable backend") {
				t.Errorf("%s %q: exit %d, output %q; want exit 1 with No send-capable backend", label, p.args, code, out)
			}
		}
		if sendCapable(t, bin) {
			continue
		}
		for _, cmd := range []string{"smtp", "sieve"} {
			code, out := bdExecIn(t, f.Name, nil, append([]string{inContainer[bin]}, append(prefix, cmd)...)...)
			t.Logf("%s %s: exit %d: %s", label, cmd, code, strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
			if code != 2 || !strings.Contains(out, "unrecognized subcommand") {
				t.Errorf("%s %s: exit %d, output %q; want exit 2, unrecognized subcommand", label, cmd, code, out)
			}
		}
	}

	for _, b := range boxes {
		if got := f.Status(t, Alice, b); got.Messages != before[b].Messages || got.UIDNext != before[b].UIDNext {
			t.Errorf("%s changed from %+v to %+v: a send path appended", b, before[b], got)
		}
	}
	if got := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(got, flagsBefore, slices.Equal) {
		t.Errorf("INBOX flags changed from %v to %v", flagsBefore, got)
	}
	if events := f.MailLog(t); len(events) != 0 {
		t.Errorf("send probes caused mail events: %+v", events)
	}
}

// TestStartupRefusals starts check and stdio with one fault each.
// Every start exits 1 naming the fault, before any Himalaya run (the shim
// records nothing) and before any IMAP connection (the fixture logs none).
// A clean check afterwards logs in, which shows both detectors work.
func TestStartupRefusals(t *testing.T) {
	f := StartFixture(t, FixtureOptions{})
	shim := BuildShim(t, HimalayaPath(t))
	bin := BuildServer(t)
	sessions := len(bdIMAPLogLines(t, f))

	cases := []struct {
		name   string
		edit   func(*testing.T, *ServerConfig)
		after  func(*testing.T, *ServerFiles)
		reason string
		// tree, when set, is what <root>/real must hold after both refused starts.
		tree []string
	}{
		{
			name:   "wrong sha256",
			edit:   func(_ *testing.T, c *ServerConfig) { c.Himalaya.SHA256 = strings.Repeat("0", 64) },
			reason: "does not match himalaya.sha256",
		},
		{
			name: "official build without allow_send_capable_build",
			edit: func(t *testing.T, c *ServerConfig) {
				official := bdOfficialAsset()
				if official == "" {
					t.Skip("the official asset is not in .cache/dl-v2.2.1")
				}
				c.Himalaya = HimalayaConfig{Path: official, SHA256: bdSHA256(t, official)}
				c.AllowSendCapableBuild = false
			},
			reason: "are not exactly [imap rustls-ring]",
		},
		{
			name: "unknown config field",
			after: func(t *testing.T, files *ServerFiles) {
				var doc map[string]any
				if err := json.Unmarshal(readFile(t, files.ConfigPath), &doc); err != nil {
					t.Fatal(err)
				}
				doc["accounts"].(map[string]any)[Alice.Name].(map[string]any)["smtp"] = map[string]any{"host": "127.0.0.1", "port": 25}
				data, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, files.ConfigPath, data, 0o600)
			},
			reason: `unknown field \"smtp\"`, // as slog quotes it
		},
		{
			name:   "0644 password file",
			after:  func(t *testing.T, files *ServerFiles) { bdChmod(t, files.PasswordFiles[Bob.Name], 0o644) },
			reason: "must not be accessible by group or others",
		},
		{
			name: "password file symlink",
			edit: func(t *testing.T, c *ServerConfig) {
				real := c.Accounts[Alice.Name].IMAP.PasswordFile
				link := real + ".link"
				if err := os.Symlink(real, link); err != nil {
					t.Fatal(err)
				}
				c.Accounts[Alice.Name].IMAP.PasswordFile = link
			},
			reason: "must be a regular file, not a symlink",
		},
		{
			// os.OpenRoot would follow the alias and expose the password files by name.
			name: "files_dir through a symlink to the secrets",
			edit: func(t *testing.T, c *ServerConfig) {
				secrets := filepath.Dir(c.Accounts[Alice.Name].IMAP.PasswordFile)
				alias := filepath.Join(filepath.Dir(secrets), "alias")
				if err := os.Symlink(secrets, alias); err != nil {
					t.Fatal(err)
				}
				c.Accounts[Alice.Name].FilesDir = alias
			},
			reason: "accounts.alice.files_dir must not contain symlinks",
		},
		{
			// The refusal must come before tmp/ is emptied or anything is written through the alias.
			name: "state_dir through a symlinked ancestor",
			edit: func(t *testing.T, c *ServerConfig) {
				root := filepath.Dir(c.StateDir)
				bdMkdirAll(t, filepath.Join(root, "real", "state", "tmp"))
				writeFile(t, filepath.Join(root, "real", "state", "tmp", "marker"), []byte("keep\n"), 0o600)
				if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				c.StateDir = filepath.Join(root, "alias", "state")
			},
			reason: "state_dir must not contain symlinks",
			tree:   []string{"state", "state/tmp", "state/tmp/marker"},
		},
		{
			name: "files_dir to be created through a symlinked ancestor",
			edit: func(t *testing.T, c *ServerConfig) {
				root := filepath.Dir(c.StateDir)
				bdMkdirAll(t, filepath.Join(root, "real"))
				if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
				c.Accounts[Alice.Name].FilesDir = filepath.Join(root, "alias", "files")
			},
			reason: "accounts.alice.files_dir must not contain symlinks",
			tree:   []string{},
		},
		{
			name: "$ in a path",
			edit: func(t *testing.T, c *ServerConfig) {
				real := c.Accounts[Alice.Name].IMAP.PasswordFile
				dir := filepath.Join(filepath.Dir(real), "$HOME")
				mkdirPrivate(t, dir)
				moved := filepath.Join(dir, filepath.Base(real))
				writeFile(t, moved, readFile(t, real), 0o600)
				c.Accounts[Alice.Name].IMAP.PasswordFile = moved
			},
			reason: "must not contain $",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := ServerOptions{Fixture: f, Shim: shim}
			if c.edit != nil {
				opts.Edit = func(cfg *ServerConfig) { c.edit(t, cfg) }
			}
			files := WriteServerConfig(t, opts)
			if c.after != nil {
				c.after(t, files)
			}
			for _, mode := range []string{"check", "stdio"} {
				code, stdout, stderr := bdRunServer(t, bin, files.ConfigPath, mode)
				if code != 1 || !strings.Contains(stderr, c.reason) || stdout != "" {
					t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 1 naming %q", mode, code, stdout, stderr, c.reason)
				}
			}
			if c.tree != nil {
				if got := bdTree(t, filepath.Join(files.Root, "real")); !slices.Equal(got, c.tree) {
					t.Errorf("the alias target holds %q after the refused starts, want %q", got, c.tree)
				}
			}
		})
	}
	if recs := shim.Records(t); len(recs) != 0 {
		t.Errorf("refused starts ran Himalaya: %+v", recs)
	}
	if got := bdIMAPLogLines(t, f); len(got) != sessions {
		t.Errorf("refused starts reached IMAP:\n%s", strings.Join(got[sessions:], "\n"))
	}

	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	if code, stdout, stderr := bdRunServer(t, bin, files.ConfigPath, "check"); code != 0 || stdout != "alice: ok\nbob: ok\n" {
		t.Fatalf("clean check: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !slices.ContainsFunc(bdIMAPLogLines(t, f)[sessions:], func(l string) bool { return strings.Contains(l, "Logged in: user=<"+Alice.Login+">") }) {
		t.Errorf("the clean check logged no IMAP login, so the no-traffic assertion above proves nothing")
	}
}

// TestFailuresAndCancellation covers an unreachable server, a silent one, client
// cancellation over both transports, and a mutation cancelled mid-flight.
// No Himalaya process or secret command may outlive its call.
func TestFailuresAndCancellation(t *testing.T) {
	himalayaBin := HimalayaPath(t)
	bin := BuildServer(t)
	f := StartFixture(t, FixtureOptions{})

	t.Run("silent server times out", func(t *testing.T) {
		pki := NewPKI(t)
		port := SilentListener(t)
		silent := &Fixture{Name: "silent", PKI: pki, Host: "127.0.0.1", STARTTLSPort: port, TLSPort: port}
		files := WriteServerConfig(t, ServerOptions{Fixture: silent, Shim: BuildShim(t, himalayaBin),
			Edit: func(c *ServerConfig) { c.CallTimeoutSeconds = 2 }})
		cs := StartStdio(t, bin, files)
		start := time.Now()
		res := bdCall(t, cs, "list_mailboxes", map[string]any{"account": "alice"})
		elapsed := time.Since(start)
		if code := bdErrCode(res); code != "timeout" {
			t.Errorf("list_mailboxes against a silent server: %q, want timeout", resultText(res))
		}
		if elapsed < 2*time.Second || elapsed > 4*time.Second {
			t.Errorf("timeout after %v, want about 2 s", elapsed)
		}
		t.Logf("timeout after %v", elapsed.Round(time.Millisecond))
		AssertNoProcs(t, files.StateDir)
	})

	// cancelRead blocks alice's secret command (/bin/cat on a FIFO, which
	// waits for a writer forever) and cancels list_mailboxes once it is
	// stuck there.
	cancelRead := func(t *testing.T, files *ServerFiles, cs *mcp.ClientSession) {
		pw := files.PasswordFiles[Alice.Name]
		if err := os.Remove(pw); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(pw, 0o600); err != nil {
			t.Fatal(err)
		}
		before := bdToolClasses(t, files, "list_mailboxes")
		took := bdCancelMidCall(t, cs, "list_mailboxes", map[string]any{"account": "alice"}, pw)
		if took > time.Second {
			t.Errorf("CallTool returned %v after the cancel", took)
		}
		t.Logf("CallTool returned %v after the cancel", took.Round(time.Microsecond))
		AssertNoProcs(t, filepath.Dir(pw)) // the secret command, orphaned if only Himalaya died
		AssertNoProcs(t, files.StateDir)
		if class := bdWaitToolClass(t, files, "list_mailboxes", before); class != "cancelled" {
			t.Errorf("server classified the cancelled list_mailboxes as %q, want cancelled", class)
		}
	}
	t.Run("cancel over stdio", func(t *testing.T) {
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalayaBin)})
		cancelRead(t, files, StartStdio(t, bin, files))
	})
	t.Run("cancel over http", func(t *testing.T) {
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalayaBin)})
		_, cs := StartHTTP(t, bin, files)
		if v := cs.InitializeResult().ProtocolVersion; v != "2026-07-28" {
			t.Fatalf("http session negotiated %s; cancellation propagates from 2026-07-28 on", v)
		}
		cancelRead(t, files, cs)
	})

	t.Run("cancel a mutation mid-flight", func(t *testing.T) {
		shim := BuildShim(t, himalayaBin)
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
		cs := StartStdio(t, bin, files)
		// The hook blocks inside the started flag add process, before it execs Himalaya.
		hookDir := TempDir(t)
		fifo := filepath.Join(hookDir, "block")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		shim.SetHook(t, []string{"flag", "add"}, []string{"/bin/cat", fifo})
		flagsBefore := f.Flags(t, Alice, "INBOX")
		var list struct {
			UIDValidity uint32
			Messages    []struct{ UID string }
		}
		bdOK(t, bdCall(t, cs, "list_messages", map[string]any{"account": "alice", "mailbox": "INBOX"}), &list)
		args := map[string]any{"account": "alice", "mailbox": "INBOX", "uidvalidity": list.UIDValidity, "uids": []any{list.Messages[0].UID}, "seen": true}
		before := bdToolClasses(t, files, "update_flags")
		bdCancelMidCall(t, cs, "update_flags", args, fifo)
		AssertNoProcs(t, hookDir)
		AssertNoProcs(t, files.StateDir)
		// DESIGN section 6: a mutating subprocess killed after it started has an unknown outcome.
		if class := bdWaitToolClass(t, files, "update_flags", before); class != "outcome_uncertain" {
			t.Errorf("server classified the cancelled update_flags as %q, want outcome_uncertain", class)
		}
		// Never retried: the runner started flag add once and the flags are
		// untouched. (The shim logs a run only after its hook, so count the
		// runner's log lines.)
		if adds := strings.Count(string(readFile(t, files.ServerLog)), `command="flag add"`); adds != 1 {
			t.Errorf("flag add ran %d times, want exactly once", adds)
		}
		if got := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(got, flagsBefore, slices.Equal) {
			t.Errorf("INBOX flags changed from %v to %v after the cancel", flagsBefore, got)
		}
	})

	// Last: it stops the shared fixture.
	t.Run("stopped server is account_unavailable", func(t *testing.T) {
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalayaBin)})
		cs := StartStdio(t, bin, files)
		f.StopIMAP(t)
		res := bdCall(t, cs, "list_mailboxes", map[string]any{"account": "alice"})
		if code := bdErrCode(res); code != "account_unavailable" {
			t.Errorf("list_mailboxes on a stopped server: %q, want account_unavailable", resultText(res))
		}
		AssertNoProcs(t, files.StateDir)
	})
}

// TestHTTP checks the HTTP front door with raw requests (Host
// allowlist, cross-origin protection, bearer token, methods, body limit,
// paths), that none of them reaches Himalaya, and then real SDK sessions at
// protocol 2025-06-18 and the latest.
func TestHTTP(t *testing.T) {
	f := StartFixture(t, FixtureOptions{})
	shim := BuildShim(t, HimalayaPath(t))
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	base, latest := StartHTTP(t, BuildServer(t), files)
	_, port, err := net.SplitHostPort(strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	uv := f.Status(t, Alice, "INBOX").UIDValidity
	flagsBefore := f.Flags(t, Alice, "INBOX")
	recsBefore := len(shim.Records(t))

	token := files.Token
	wrong := []byte(token)
	wrong[0] ^= 1
	call := fmt.Appendf(nil, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"update_flags","arguments":{"account":"alice","mailbox":"INBOX","uidvalidity":%d,"uids":[1],"seen":true}}}`, uv)
	initialize := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}`)
	huge := fmt.Appendf(nil, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_accounts","arguments":{"pad":"%s"}}}`, strings.Repeat("x", 4<<20))

	bearer := "Bearer " + token
	cases := []struct {
		name, method, path, host, auth string
		header                         map[string]string
		body                           []byte
		want                           int
	}{
		{name: "authenticated initialize", auth: bearer, body: initialize, want: http.StatusOK},
		{name: "no token initialize", body: initialize, want: http.StatusUnauthorized},
		{name: "no token tools/call", body: call, want: http.StatusUnauthorized},
		{name: "wrong token", auth: "Bearer " + string(wrong), body: call, want: http.StatusUnauthorized},
		{name: "longer token", auth: bearer + "0", body: call, want: http.StatusUnauthorized},
		{name: "shorter token", auth: bearer[:len(bearer)-1], body: call, want: http.StatusUnauthorized},
		{name: "basic auth", auth: "Basic " + base64.StdEncoding.EncodeToString([]byte("client:"+token)), body: call, want: http.StatusUnauthorized},
		{name: "bad host", host: "evil.example:" + port, auth: bearer, body: call, want: http.StatusForbidden},
		{name: "localhost host", host: "localhost:" + port, auth: bearer, body: call, want: http.StatusForbidden},
		{name: "cross-site origin", auth: bearer, header: map[string]string{"Origin": "https://evil.example"}, body: call, want: http.StatusForbidden},
		{name: "cross-site fetch", auth: bearer, header: map[string]string{"Sec-Fetch-Site": "cross-site"}, body: call, want: http.StatusForbidden},
		{name: "authenticated GET", method: http.MethodGet, auth: bearer, want: http.StatusMethodNotAllowed},
		{name: "authenticated DELETE", method: http.MethodDelete, auth: bearer, want: http.StatusMethodNotAllowed},
		{name: "oversized authenticated body", auth: bearer, body: huge, want: http.StatusRequestEntityTooLarge},
		{name: "oversized unauthenticated body", body: huge, want: http.StatusUnauthorized},
		{name: "other path", path: "/other", auth: bearer, body: call, want: http.StatusNotFound},
		{name: "subpath", path: "/mcp/x", auth: bearer, body: call, want: http.StatusNotFound},
	}
	for _, c := range cases {
		method, path := cmp.Or(c.method, http.MethodPost), cmp.Or(c.path, "/mcp")
		req, err := http.NewRequestWithContext(t.Context(), method, base+path, bytes.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		for k, v := range c.header {
			req.Header.Set(k, v)
		}
		if c.host != "" {
			req.Host = c.host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d", c.name, resp.StatusCode, c.want)
		}
	}
	if recs := shim.Records(t); len(recs) != recsBefore {
		t.Errorf("raw requests reached Himalaya: %+v", recs[recsBefore:])
	}
	if got := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(got, flagsBefore, slices.Equal) {
		t.Errorf("raw requests changed INBOX flags from %v to %v", flagsBefore, got)
	}

	legacy, err := ConnectHTTP(t, base, token, "2025-06-18")
	if err != nil {
		t.Fatalf("connect at 2025-06-18: %v", err)
	}
	sessions := []struct {
		cs      *mcp.ClientSession
		version string
		uid     uint32
		flag    string
		args    map[string]any
	}{
		{legacy, "2025-06-18", 1, `\Seen`, map[string]any{"seen": true}},
		{latest, "2026-07-28", 3, `\Flagged`, map[string]any{"flagged": true}},
	}
	want := maps.Clone(flagsBefore)
	for _, s := range sessions {
		if v := s.cs.InitializeResult().ProtocolVersion; v != s.version {
			t.Errorf("negotiated %s, want %s", v, s.version)
		}
		var list struct {
			UIDValidity uint32
			Messages    []struct{ UID string }
		}
		bdOK(t, bdCall(t, s.cs, "list_messages", map[string]any{"account": "alice", "mailbox": "INBOX"}), &list)
		if list.UIDValidity != uv || len(list.Messages) != 6 {
			t.Errorf("%s list_messages: uidvalidity %d and %d messages, want %d and 6", s.version, list.UIDValidity, len(list.Messages), uv)
		}
		i := slices.IndexFunc(list.Messages, func(m struct{ UID string }) bool { return uidNumber(t, m.UID) == s.uid })
		if i < 0 {
			t.Fatalf("%s list_messages has no uid %d", s.version, s.uid)
		}
		var upd struct{ Updated int }
		bdOK(t, bdCall(t, s.cs, "update_flags", bdMerge(map[string]any{"account": "alice", "mailbox": "INBOX", "uidvalidity": uv, "uids": []any{list.Messages[i].UID}}, s.args)), &upd)
		if upd.Updated != 1 {
			t.Errorf("%s update_flags updated %d, want 1", s.version, upd.Updated)
		}
		want[s.uid] = slices.Sorted(slices.Values(append(slices.Clone(want[s.uid]), s.flag)))
	}
	if got := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("INBOX flags = %v, want %v", got, want)
	}

	// list_accounts is served from the config, which also holds the secret
	// paths; none of them, nor any secret, may come back.
	res := bdCall(t, latest, "list_accounts", map[string]any{})
	var accounts struct {
		Accounts []struct{ Name, Email string }
	}
	bdOK(t, res, &accounts)
	if len(accounts.Accounts) != 2 {
		t.Errorf("list_accounts returned %+v, want alice and bob", accounts.Accounts)
	}
	structured, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{files.Root, f.PKI.Dir, Alice.Password, Bob.Password, token} {
		if strings.Contains(resultText(res), secret) || strings.Contains(string(structured), secret) {
			t.Errorf("list_accounts output contains %q: %s", secret, structured)
		}
	}
}

// --- helpers ------------------------------------------------------------------

// bdCall calls a tool and fails the test on a protocol or transport error.
func bdCall(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

// bdErrCode is the code of a server tool error ("<code>: ..."), or "" on success.
func bdErrCode(res *mcp.CallToolResult) string {
	if !res.IsError {
		return ""
	}
	code, _, _ := strings.Cut(resultText(res), ": ")
	return code
}

// bdOK requires a successful result and decodes its structured content into out.
func bdOK(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", bdShort(resultText(res)))
	}
	data, err := json.Marshal(res.StructuredContent)
	if err == nil {
		err = json.Unmarshal(data, out)
	}
	if err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

// bdShort quotes v, cut to 120 bytes for messages.
func bdShort(v any) string {
	s := fmt.Sprintf("%q", fmt.Sprint(v))
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// bdMerge returns a copy of base with extra's keys set.
func bdMerge(base, extra map[string]any) map[string]any {
	m := maps.Clone(base)
	maps.Copy(m, extra)
	return m
}

// bdRecord returns the only record among recs with the given command path.
func bdRecord(t *testing.T, recs []ShimRecord, path string) ShimRecord {
	t.Helper()
	var found []ShimRecord
	for _, r := range recs {
		if commandPath(r.Argv) == path {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d %q runs among %+v", len(found), path, recs)
	}
	return found[0]
}

var bdToolLine = regexp.MustCompile(`\bmsg=tool tool=(\S+) class=(\S+)`)

// bdToolClasses returns the classes the server logged for finished calls of tool.
func bdToolClasses(t *testing.T, files *ServerFiles, tool string) []string {
	t.Helper()
	data, err := os.ReadFile(files.ServerLog)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var classes []string
	for _, m := range bdToolLine.FindAllStringSubmatch(string(data), -1) {
		if m[1] == tool {
			classes = append(classes, m[2])
		}
	}
	return classes
}

// bdWaitToolClass waits for the server to log one more finished call of
// tool than before and returns its class.
func bdWaitToolClass(t *testing.T, files *ServerFiles, tool string, before []string) string {
	t.Helper()
	var classes []string
	bdWaitFor(t, "the server's log line for "+tool, func() bool {
		classes = bdToolClasses(t, files, tool)
		return len(classes) > len(before)
	})
	return classes[len(classes)-1]
}

// bdCancelMidCall starts a call, waits until a process references blockedIn
// and at least 300 ms have passed, cancels the client context, and returns
// how long CallTool took to return after the cancel.
func bdCancelMidCall(t *testing.T, cs *mcp.ClientSession, tool string, args map[string]any, blockedIn string) time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		done <- err
	}()
	bdWaitFor(t, "a process blocked in "+blockedIn, func() bool { return len(procsReferencing(blockedIn)) > 0 })
	time.Sleep(time.Until(start.Add(300 * time.Millisecond)))
	cancel()
	cancelled := time.Now()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s after the cancel returned %v, want context.Canceled", tool, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s still running 10 s after the cancel", tool)
	}
	return time.Since(cancelled)
}

// bdWaitFor polls cond every 50 ms for up to 30 s.
func bdWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// bdRunServer runs the server in mode with stdin at EOF, so a stdio server
// that did start exits at once, and returns its exit code and output.
func bdRunServer(t *testing.T, bin, config, mode string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-config", config, mode)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("%s %s: %v", bin, mode, err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

// bdIMAPLogLines returns the fixture's imap-login log lines: one or more
// per connection, whether or not it logged in.
func bdIMAPLogLines(t *testing.T, f *Fixture) []string {
	t.Helper()
	var lines []string
	for line := range strings.Lines(string(runDocker(t, nil, "logs", f.Name))) {
		if strings.Contains(line, "imap-login:") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

// bdOfficialAsset is the official v2.2.1 binary fetched into .cache, or "".
func bdOfficialAsset() string {
	p := filepath.Join(moduleRoot(), ".cache", "dl-v2.2.1", "extract", "himalaya")
	if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	return p
}

func bdSHA256(t *testing.T, path string) string {
	t.Helper()
	sum := sha256.Sum256(readFile(t, path))
	return hex.EncodeToString(sum[:])
}

func bdMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// bdTree lists every path below dir, relative to it, in lexical order.
func bdTree(t *testing.T, dir string) []string {
	t.Helper()
	tree := []string{}
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		tree = append(tree, rel)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func bdChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// bdDovecotDir writes the fixture's Dovecot files (bridge profile, serving
// pki.Leaf) into a world-readable directory, as StartFixture does.
func bdDovecotDir(t *testing.T, pki *PKI) string {
	t.Helper()
	dc := filepath.Join(TempDir(t), "dovecot")
	if err := os.Mkdir(dc, 0o755); err != nil {
		t.Fatal(err)
	}
	bdChmod(t, dc, 0o755)
	writeFile(t, filepath.Join(dc, "dovecot.conf"), readFile(t, filepath.Join("testdata", "dovecot.conf")), 0o644)
	writeFile(t, filepath.Join(dc, "server.pem"), readFile(t, pki.Leaf.CertFile), 0o644)
	writeFile(t, filepath.Join(dc, "server.key"), readFile(t, pki.Leaf.KeyFile), 0o644)
	var users strings.Builder
	for _, u := range []User{Alice, Bob} {
		fmt.Fprintf(&users, "%s:{PLAIN}%s::::::\n", u.Login, u.Password)
	}
	writeFile(t, filepath.Join(dc, "users"), []byte(users.String()), 0o644)
	writeFile(t, filepath.Join(dc, "profile.conf"), []byte("imap_capability = "+capabilities[ProfileBridge]+"\n"), 0o644)
	return dc
}

const bdCatSource = `package main

import (
	"io"
	"os"
)

// cat copies each named file to stdout.
func main() {
	for _, p := range os.Args[1:] {
		f, err := os.Open(p)
		if err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		io.Copy(os.Stdout, f)
		f.Close()
	}
}
`

// bdStaticCat builds a static cat for images that lack one.
func bdStaticCat(t *testing.T) string {
	t.Helper()
	dir := TempDir(t)
	writeFile(t, filepath.Join(dir, "go.mod"), []byte("module bdcat\n\ngo 1.26\n"), 0o644)
	writeFile(t, filepath.Join(dir, "main.go"), []byte(bdCatSource), 0o644)
	cmd := exec.Command("go", "build", "-o", "cat", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build static cat: %v\n%s", err, out)
	}
	return filepath.Join(dir, "cat")
}

// bdExecIn runs argv in the container as the test's uid with a fixed
// environment and returns the exit code and combined output.
func bdExecIn(t *testing.T, container string, stdin []byte, argv ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	args := []string{"exec", "-i", "-u", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-w", "/tmp",
		"-e", "PATH=/usr/bin:/bin", "-e", "HOME=/tmp", "-e", "XDG_CONFIG_HOME=/tmp/.config", "-e", "TMPDIR=/tmp", container}
	cmd := exec.CommandContext(ctx, dockerPath(), append(args, argv...)...)
	cmd.Stdin = bytes.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatalf("docker exec %q: %v", argv, err)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}
