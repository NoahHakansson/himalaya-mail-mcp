//go:build integration

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The read-path tests: the tool list and its hints, every read tool against
// the seeded fixture with unread preservation checked through doveadm,
// account isolation, mailbox identity, and TLS certificate validation. Tools
// are called with plain JSON arguments and decoded into the wire shapes of
// DESIGN.md section 2, so a renamed field fails here even when the server's
// own types agree.

// rdArgs are a tool call's JSON arguments.
type rdArgs = map[string]any

type rdAddress struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type rdSummary struct {
	UID           uint32      `json:"uid"`
	MessageID     string      `json:"message_id"`
	From          []rdAddress `json:"from"`
	Subject       string      `json:"subject"`
	Flags         []string    `json:"flags"`
	HasAttachment bool        `json:"has_attachment"`
}

type rdList struct {
	Account     string      `json:"account"`
	Mailbox     string      `json:"mailbox"`
	UIDValidity uint32      `json:"uidvalidity"`
	Total       int         `json:"total"`
	Unseen      int         `json:"unseen"`
	Page        int         `json:"page"`
	PageSize    int         `json:"page_size"`
	Messages    []rdSummary `json:"messages"`
}

type rdMailbox struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Kind    string `json:"kind"`
	Total   int    `json:"total"`
	Unread  int    `json:"unread"`
	Movable bool   `json:"movable"`
}

type rdMailboxes struct {
	Account            string      `json:"account"`
	Mailboxes          []rdMailbox `json:"mailboxes"`
	OmittedUnsafeNames int         `json:"omitted_unsafe_names"`
}

type rdRead struct {
	MessageID  string      `json:"message_id"`
	Date       string      `json:"date"`
	From       []rdAddress `json:"from"`
	Cc         []rdAddress `json:"cc"`
	ReplyTo    []rdAddress `json:"reply_to"`
	Subject    string      `json:"subject"`
	Body       string      `json:"body"`
	BodyFormat string      `json:"body_format"`
}

type rdAttachment struct {
	PartID   int    `json:"part_id"`
	Filename string `json:"filename"`
	MIME     string `json:"mime"`
}

type rdDraft struct {
	Mailbox   string `json:"mailbox"`
	UID       uint32 `json:"uid"`
	MessageID string `json:"message_id"`
}

// rdCall calls a tool and fails the test on a protocol-level error.
func rdCall(t *testing.T, cs *mcp.ClientSession, name string, args rdArgs) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
	return res
}

// rdOut calls a tool that must succeed and decodes its structured output.
func rdOut[T any](t *testing.T, cs *mcp.ClientSession, name string, args rdArgs) T {
	t.Helper()
	res := rdCall(t, cs, name, args)
	if res.IsError {
		t.Fatalf("%s %v failed: %s", name, args, resultText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: decode %s: %v", name, raw, err)
	}
	return out
}

// rdFail calls a tool that must return a tool error and returns its text.
func rdFail(t *testing.T, cs *mcp.ClientSession, name string, args rdArgs) string {
	t.Helper()
	res := rdCall(t, cs, name, args)
	if !res.IsError {
		raw, _ := json.Marshal(res.StructuredContent)
		t.Fatalf("%s %v succeeded with %s, want an error", name, args, raw)
	}
	return resultText(res)
}

// rdCode returns the error code of a server tool error ("<code>: ...").
func rdCode(text string) string {
	code, _, _ := strings.Cut(text, ":")
	return code
}

func rdUIDs(msgs []rdSummary) []uint32 {
	uids := []uint32{}
	for _, m := range msgs {
		uids = append(uids, m.UID)
	}
	return uids
}

// rdHints are the four annotations of one tool. openWorld is always false.
type rdHints struct{ ReadOnly, Destructive, Idempotent, OpenWorld bool }

// rdWantHints is the hint column of DESIGN.md section 2. R is read-only,
// not destructive and idempotent; W is additive; D is destructive.
var rdWantHints = map[string]rdHints{
	"list_accounts":       {ReadOnly: true, Idempotent: true},
	"list_mailboxes":      {ReadOnly: true, Idempotent: true},
	"list_messages":       {ReadOnly: true, Idempotent: true},
	"search_messages":     {ReadOnly: true, Idempotent: true},
	"read_message":        {ReadOnly: true, Idempotent: true},
	"list_attachments":    {ReadOnly: true, Idempotent: true},
	"download_attachment": {},
	"update_flags":        {Destructive: true, Idempotent: true},
	"move_messages":       {Destructive: true, Idempotent: true},
	"archive_messages":    {Destructive: true, Idempotent: true},
	"trash_messages":      {Destructive: true, Idempotent: true},
	"restore_messages":    {Destructive: true, Idempotent: true},
	"add_label":           {Idempotent: true},
	"remove_label":        {Destructive: true, Idempotent: true},
	"create_draft":        {},
	"update_draft":        {Destructive: true},
	"reply_draft":         {},
	"forward_draft":       {},
}

// rdOpenObjects returns the path of every object schema under s that does
// not set additionalProperties to false.
func rdOpenObjects(path string, s any) []string {
	var open []string
	switch v := s.(type) {
	case map[string]any:
		if v["type"] == "object" && v["additionalProperties"] != false {
			open = append(open, path)
		}
		for _, k := range slices.Sorted(maps.Keys(v)) {
			open = append(open, rdOpenObjects(path+"/"+k, v[k])...)
		}
	case []any:
		for _, child := range v {
			open = append(open, rdOpenObjects(path+"/[]", child)...)
		}
	}
	return open
}

// TestToolList proves the L1 tool boundary (DESIGN.md section 4): exactly
// the 18 tools, each with all four hints as section 2 specifies, closed input
// schemas, and calls with an unknown tool or an extra argument rejected
// before any Himalaya process runs. It needs no IMAP server: the accounts
// point at a closed port, and the shim log shows whether anything ran.
func TestToolList(t *testing.T) {
	himalaya := HimalayaPath(t)
	bin := BuildServer(t)
	shim := BuildShim(t, himalaya)
	closed := rdClosedPort(t)
	f := &Fixture{Host: "127.0.0.1", PKI: NewPKI(t), TLSPort: closed, STARTTLSPort: closed}
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	cs := StartStdio(t, bin, files)

	seen := map[string]bool{}
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tool.Name] = true
		want, ok := rdWantHints[tool.Name]
		if !ok {
			t.Errorf("unexpected tool %q", tool.Name)
			continue
		}
		a := tool.Annotations
		if a == nil || a.DestructiveHint == nil || a.OpenWorldHint == nil {
			t.Errorf("%s: annotations %+v do not set destructiveHint and openWorldHint explicitly", tool.Name, a)
			continue
		}
		got := rdHints{ReadOnly: a.ReadOnlyHint, Destructive: *a.DestructiveHint, Idempotent: a.IdempotentHint, OpenWorld: *a.OpenWorldHint}
		if got != want {
			t.Errorf("%s: hints %+v, want %+v", tool.Name, got, want)
		}
		if open := rdOpenObjects("#", tool.InputSchema); len(open) > 0 {
			t.Errorf("%s: object schemas without additionalProperties:false at %v", tool.Name, open)
		}
	}
	if missing := slices.DeleteFunc(slices.Sorted(maps.Keys(rdWantHints)), func(n string) bool { return seen[n] }); len(missing) > 0 {
		t.Errorf("missing tools %v", missing)
	}

	runs := len(shim.Records(t))

	_, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "send_message", Arguments: rdArgs{"account": "alice"}})
	var rpcErr *jsonrpc.Error
	if !errors.As(err, &rpcErr) || rpcErr.Code != jsonrpc.CodeInvalidParams {
		t.Errorf("unknown tool: error %v, want JSON-RPC %d", err, jsonrpc.CodeInvalidParams)
	}

	// list_accounts is served from config, so it runs nothing either.
	accounts := rdOut[struct {
		Accounts []struct {
			Name      string            `json:"name"`
			Email     string            `json:"email"`
			Mailboxes map[string]string `json:"mailboxes"`
			Labels    struct {
				Enabled bool   `json:"enabled"`
				Prefix  string `json:"prefix"`
			} `json:"labels"`
		} `json:"accounts"`
	}](t, cs, "list_accounts", rdArgs{})
	roles := map[string]string{"inbox": "INBOX", "drafts": "Drafts", "sent": "Sent", "trash": "Trash", "archive": "Archive", "junk": "Junk"}
	if len(accounts.Accounts) != 2 {
		t.Fatalf("list_accounts returned %+v, want alice and bob", accounts)
	}
	for i, u := range []User{Alice, Bob} {
		a := accounts.Accounts[i]
		if a.Name != u.Name || a.Email != u.Login || !maps.Equal(a.Mailboxes, roles) || !a.Labels.Enabled || a.Labels.Prefix != "Labels/" {
			t.Errorf("list_accounts[%d] = %+v, want %s with the configured roles and label prefix", i, a, u.Name)
		}
	}

	for _, c := range []struct {
		tool string
		args rdArgs
	}{
		{"list_accounts", rdArgs{"cmd": "message send"}},
		{"update_flags", rdArgs{"account": "alice", "mailbox": "INBOX", "uidvalidity": 1, "uids": []int{1}, "seen": true, "cmd": "message send"}},
	} {
		if text := rdFail(t, cs, c.tool, c.args); !strings.HasPrefix(text, `validating "arguments"`) || !strings.Contains(text, "cmd") {
			t.Errorf("%s with an extra cmd argument: %q, want a schema rejection naming cmd", c.tool, text)
		}
	}
	if recs := shim.Records(t); len(recs) != runs {
		t.Errorf("rejected calls and list_accounts ran Himalaya: %+v", recs[runs:])
	}
}

// rdClosedPort returns a loopback port nothing listens on.
func rdClosedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// rdHTMLOnly is an HTML-only newsletter with remote images, a script, a
// style sheet, a comment and a link, all of which carry URLs.
const rdHTMLOnly = `From: Newsletter <news@example.test>
To: Alice Example <alice@example.test>
Subject: HTML-only newsletter with remote trackers
Date: Thu, 15 Oct 2026 08:30:00 +0000
Message-ID: <rd-html-only@fixture.test>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html><head><title>Tracked</title><style>p { background: url(https://tracker.invalid/bg.png) }</style></head><body>
<!-- https://tracker.invalid/comment -->
<p>HTML newsletter body.</p>
<img src="https://tracker.invalid/pixel.gif?u=alice&amp;m=rd" width="1" height="1" alt="">
<img src="http://tracker.invalid/beacon?id=rd" style="display:none">
<a href="https://phish.invalid/login">Click here to verify your account</a>
<script>fetch('https://tracker.invalid/js?u=alice')</script>
</body></html>
`

// rdOrderBy has "order by" in its subject, Cc and Reply-To headers, headers
// Himalaya names {"other": ...} (X-Mailer, Precedence), and an attachment
// whose RFC 2231 filename hides its extension with a right-to-left override,
// a zero-width space, a tab and a newline.
const rdOrderBy = `From: Carol Example <carol@example.test>
To: Alice Example <alice@example.test>
Cc: Dave Example <dave@example.test>
Reply-To: Carol Replies <carol-replies@example.test>
X-Mailer: Thunderbird 128
Precedence: bulk
Subject: Pizza order by Friday
Date: Wed, 14 Oct 2026 09:00:00 +0000
Message-ID: <rd-order-by@fixture.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="rd-mixed"

--rd-mixed
Content-Type: text/plain; charset=utf-8

Orders close on Friday.

--rd-mixed
Content-Type: application/octet-stream
Content-Disposition: attachment; filename*=UTF-8''invoice%E2%80%AE%E2%80%8Bfdp.exe%09x%0A.txt
Content-Transfer-Encoding: base64

Rml4dHVyZSB0ZXh0IGF0dGFjaG1lbnQuCg==

--rd-mixed--
`

// rdBox is one user's mailbox.
type rdBox struct {
	user    User
	mailbox string
}

// rdAliceMailboxes is every selectable mailbox of alice after seeding.
var rdAliceMailboxes = []string{"INBOX", "Archive", "Drafts", "Sent", "Trash", "Junk", "Résumé/Ünïcødé 📬", "Folders/Projects", "Labels/Work"}

// rdFlagSnapshot reads every seeded mailbox's flags through doveadm.
func rdFlagSnapshot(t *testing.T, f *Fixture) map[rdBox]map[uint32][]string {
	t.Helper()
	snap := map[rdBox]map[uint32][]string{}
	for _, mb := range rdAliceMailboxes {
		snap[rdBox{Alice, mb}] = f.Flags(t, Alice, mb)
	}
	for _, mb := range []string{"INBOX", "Sent"} {
		snap[rdBox{Bob, mb}] = f.Flags(t, Bob, mb)
	}
	return snap
}

// TestReadPath runs every read tool against one shared fixture, then proves
// unread preservation: doveadm shows every flag unchanged and mail_log has
// no flag_change or expunge. reply_draft and forward_draft are included for
// their sources; their drafts are the only change allowed.
func TestReadPath(t *testing.T) {
	himalaya := HimalayaPath(t)
	bin := BuildServer(t)
	f := StartFixture(t, FixtureOptions{})
	// Outside INBOX, so INBOX keeps the six messages the paging rows assume.
	htmlUID := f.Seed(t, Alice, "Archive", []byte(rdHTMLOnly))
	orderUID := f.Seed(t, Alice, "Folders/Projects", []byte(rdOrderBy))
	before := rdFlagSnapshot(t, f)
	shim := BuildShim(t, himalaya)
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	cs := StartStdio(t, bin, files)

	inbox := f.Status(t, Alice, "INBOX")
	ref := func(mailbox string, uid uint32) rdArgs {
		return rdArgs{"account": "alice", "mailbox": mailbox, "uidvalidity": f.Status(t, Alice, mailbox).UIDValidity, "uid": uid}
	}

	t.Run("mailboxes", func(t *testing.T) {
		// Himalaya reports a role only for INBOX (the generated config has no
		// aliases) and lists it as "Inbox"; roles, kinds and movability come
		// from the wrapper config, which names the junk role "Junk" rather
		// than the Bridge default "Spam".
		want := map[string]rdMailbox{
			"INBOX":            {Role: "inbox", Kind: "system", Movable: true},
			"Archive":          {Role: "archive", Kind: "system", Movable: true},
			"Drafts":           {Role: "drafts", Kind: "system"},
			"Sent":             {Role: "sent", Kind: "system"},
			"Trash":            {Role: "trash", Kind: "system", Movable: true},
			"Junk":             {Role: "junk", Kind: "system", Movable: true},
			"Résumé/Ünïcødé 📬": {Kind: "folder", Movable: true},
			"Folders/Projects": {Kind: "folder", Movable: true},
			"Labels/Work":      {Kind: "label"},
		}
		out := rdOut[rdMailboxes](t, cs, "list_mailboxes", rdArgs{"account": "alice"})
		got := map[string]rdMailbox{}
		for _, m := range out.Mailboxes {
			got[m.Name] = m
		}
		for name, w := range want {
			st := f.Status(t, Alice, name)
			w.Name, w.Total, w.Unread = name, st.Messages, st.Unseen
			want[name] = w
		}
		if out.Account != "alice" || !maps.Equal(got, want) {
			t.Errorf("list_mailboxes = %+v\nwant %+v", out, want)
		}
	})

	t.Run("paging", func(t *testing.T) {
		for i, want := range [][]uint32{{6, 5}, {4, 3}, {2, 1}, {}} {
			page := i + 1
			out := rdOut[rdList](t, cs, "list_messages", rdArgs{"account": "alice", "mailbox": "inbox", "page": page, "page_size": 2})
			if got := rdUIDs(out.Messages); !slices.Equal(got, want) {
				t.Errorf("page %d: uids %v, want %v", page, got, want)
			}
			if out.Mailbox != "INBOX" || out.UIDValidity != inbox.UIDValidity || out.Total != 6 || out.Unseen != 4 || out.Page != page || out.PageSize != 2 {
				t.Errorf("page %d: %+v, want INBOX with uidvalidity %d, total 6, unseen 4", page, out, inbox.UIDValidity)
			}
			for _, m := range out.Messages {
				switch m.UID {
				case 5:
					if m.Subject != "Grüße – 日本語 📬" || len(m.From) != 1 || m.From[0] != (rdAddress{"Björn Åström", "bjorn@example.test"}) ||
						!slices.Equal(m.Flags, []string{"seen", "flagged"}) || m.MessageID != "alice-05@fixture.test" {
						t.Errorf("summary of uid 5 = %+v", m)
					}
				case 4:
					if !m.HasAttachment {
						t.Errorf("summary of uid 4 = %+v, want has_attachment", m)
					}
				case 1:
					if m.HasAttachment || len(m.Flags) != 0 {
						t.Errorf("summary of uid 1 = %+v, want unseen without attachment", m)
					}
				}
			}
		}
	})

	t.Run("unicode folder", func(t *testing.T) {
		const box = "Résumé/Ünïcødé 📬"
		out := rdOut[rdList](t, cs, "list_messages", rdArgs{"account": "alice", "mailbox": box})
		if got := rdUIDs(out.Messages); out.Mailbox != box || !slices.Equal(got, []uint32{1}) || out.Messages[0].Subject != "In the Résumé folder" {
			t.Fatalf("list_messages %q = %+v", box, out)
		}
		msg := rdOut[rdRead](t, cs, "read_message", ref(box, 1))
		if len(msg.From) != 1 || msg.From[0].Name != "Zoë" || !strings.Contains(msg.Body, "Message stored under a Unicode mailbox name.") {
			t.Errorf("read_message %q 1 = %+v", box, msg)
		}
	})

	t.Run("search", func(t *testing.T) {
		for _, c := range []struct {
			name    string
			mailbox string
			args    rdArgs
			want    []uint32
		}{
			{"unicode subject", "INBOX", rdArgs{"subject": "日本語"}, []uint32{5}},
			{"unicode from", "INBOX", rdArgs{"from": "Åström"}, []uint32{5}},
			{"from", "INBOX", rdArgs{"from": "carol"}, []uint32{1}},
			{"unseen", "INBOX", rdArgs{"unseen": true}, []uint32{6, 4, 3, 1}},
			{"seen", "INBOX", rdArgs{"unseen": false}, []uint32{5, 2}},
			{"since is inclusive", "INBOX", rdArgs{"since": "2026-10-08"}, []uint32{6, 5, 4}},
			{"before is exclusive", "INBOX", rdArgs{"before": "2026-10-08"}, []uint32{3, 2, 1}},
			{"since and before", "INBOX", rdArgs{"since": "2026-10-06", "before": "2026-10-08"}, []uint32{3, 2}},
			{"on", "INBOX", rdArgs{"on": "2026-10-09"}, []uint32{5}},
			// Escaped, this is one literal pattern; unescaped it would add "or from bjorn" and match uid 5.
			{"quote injection", "INBOX", rdArgs{"subject": `a" or from bjorn`}, []uint32{}},
			// Himalaya splits a query at its last "order by"; the appended sort clause keeps the pattern whole.
			{"order by in pattern", "Folders/Projects", rdArgs{"subject": "order by friday"}, []uint32{orderUID}},
		} {
			t.Run(c.name, func(t *testing.T) {
				args := maps.Clone(c.args)
				args["account"], args["mailbox"] = "alice", c.mailbox
				if got := rdUIDs(rdOut[rdList](t, cs, "search_messages", args).Messages); !slices.Equal(got, c.want) {
					t.Errorf("uids %v, want %v", got, c.want)
				}
			})
		}
		// The injected text stayed inside one quoted pattern: no clause was added.
		const want = `subject "a\" or from bjorn" order by date desc`
		var queries []string
		for _, r := range shim.Records(t) {
			if i := slices.Index(r.Argv, "search"); i > 0 && r.Argv[i-1] == "envelope" && strings.Contains(r.Argv[len(r.Argv)-1], "bjorn") {
				queries = append(queries, r.Argv[len(r.Argv)-1])
			}
		}
		if !slices.Equal(queries, []string{want}) {
			t.Errorf("quote injection reached Himalaya as %q, want [%q]", queries, want)
		}
	})

	t.Run("read", func(t *testing.T) {
		plain := rdOut[rdRead](t, cs, "read_message", ref("INBOX", 1))
		if plain.BodyFormat != "text" || plain.MessageID != "alice-01@fixture.test" || plain.Subject != "Plain hello (unseen)" || plain.Date != "2026-10-05T09:00:00Z" ||
			!strings.Contains(plain.Body, "This is a plain text message that starts unseen.") {
			t.Errorf("read_message INBOX 1 = %+v", plain)
		}

		headers := rdOut[rdRead](t, cs, "read_message", ref("Folders/Projects", orderUID))
		if !slices.Equal(headers.Cc, []rdAddress{{"Dave Example", "dave@example.test"}}) ||
			!slices.Equal(headers.ReplyTo, []rdAddress{{"Carol Replies", "carol-replies@example.test"}}) {
			t.Errorf("read_message cc %+v, reply_to %+v", headers.Cc, headers.ReplyTo)
		}

		// multipart/alternative: the text part is the body; nothing from the HTML part leaks.
		alt := rdOut[rdRead](t, cs, "read_message", ref("INBOX", 3))
		if alt.BodyFormat != "text" || !strings.Contains(alt.Body, "Plain alternative of the newsletter.") ||
			strings.ContainsAny(alt.Body, "<>") || strings.Contains(alt.Body, "tracker.invalid") || strings.Contains(alt.Body, "phish.invalid") {
			t.Errorf("read_message INBOX 3 = %+v", alt)
		}

		html := rdOut[rdRead](t, cs, "read_message", ref("Archive", htmlUID))
		if html.BodyFormat != "html_stripped" || !strings.Contains(html.Body, "HTML newsletter body.") || !strings.Contains(html.Body, "Click here to verify your account") {
			t.Errorf("read_message of the HTML-only newsletter = %+v", html)
		}
		for _, banned := range []string{"<", ">", "http", ".invalid", "src", "Tracked", "background", "fetch"} {
			if strings.Contains(html.Body, banned) {
				t.Errorf("stripped HTML body contains %q:\n%s", banned, html.Body)
			}
		}

		// The prompt injection is returned verbatim as data.
		eml := Message(t, "alice-06-prompt-injection.eml")
		_, body, _ := bytes.Cut(eml, []byte("\n\n"))
		inj := rdOut[rdRead](t, cs, "read_message", ref("INBOX", 6))
		if inj.BodyFormat != "text" || strings.TrimRight(inj.Body, "\n") != strings.TrimRight(string(body), "\n") {
			t.Errorf("read_message INBOX 6 body %q (%s), want %q", inj.Body, inj.BodyFormat, body)
		}
	})

	t.Run("attachments", func(t *testing.T) {
		long := regexp.MustCompile(`very-long-x+\.txt`).Find(Message(t, "alice-04-adversarial-attachments.eml"))
		// Names are untrusted data and are listed as decoded; the inline image is excluded.
		want := []rdAttachment{
			{3, "../../evil.sh", "application/x-sh"},
			{4, "a/b.txt", "text/plain"},
			{5, string(long), "text/plain"},
			{6, "résumé 📎 файл.pdf", "application/pdf"},
			{7, "Отчёт 2026 ✓.txt", "text/plain"},
			{8, "-rf.txt", "text/plain"},
			{9, "/etc/passwd", "text/plain"},
			{10, `..\..\windows.bat`, "application/octet-stream"},
			{11, "", "application/octet-stream"},
		}
		got := rdOut[struct {
			Attachments []rdAttachment `json:"attachments"`
		}](t, cs, "list_attachments", ref("INBOX", 4))
		if !slices.Equal(got.Attachments, want) {
			t.Errorf("list_attachments INBOX 4 =\n%+v\nwant\n%+v", got.Attachments, want)
		}

		// The bidi override and zero-width space are dropped; tab and newline become spaces.
		hostile := rdOut[struct {
			Attachments []rdAttachment `json:"attachments"`
		}](t, cs, "list_attachments", ref("Folders/Projects", orderUID))
		if wantH := []rdAttachment{{3, "invoicefdp.exe x .txt", "application/octet-stream"}}; !slices.Equal(hostile.Attachments, wantH) {
			t.Errorf("list_attachments of the hidden-extension name = %+v, want %+v", hostile.Attachments, wantH)
		}

		args := ref("INBOX", 4)
		args["part_id"] = 3
		rdOut[struct {
			File string `json:"file"`
		}](t, cs, "download_attachment", args)
	})

	var drafts []rdDraft
	t.Run("reply and forward sources", func(t *testing.T) {
		reply := ref("INBOX", 1)
		reply["body"] = "Thanks, Carol."
		forward := ref("INBOX", 3)
		forward["to"] = []string{"carol@example.test"}
		for _, c := range []struct {
			tool string
			args rdArgs
		}{{"reply_draft", reply}, {"forward_draft", forward}} {
			d := rdOut[rdDraft](t, cs, c.tool, c.args)
			if d.Mailbox != "Drafts" || d.UID == 0 || d.MessageID == "" {
				t.Errorf("%s = %+v, want a reference into Drafts", c.tool, d)
			}
			drafts = append(drafts, d)
		}
	})

	after := rdFlagSnapshot(t, f)
	newDrafts := map[uint32][]string{}
	for _, d := range drafts {
		newDrafts[d.UID] = []string{`\Draft`, `\Seen`}
	}
	for box, want := range before {
		got := after[box]
		if box == (rdBox{Alice, "Drafts"}) {
			// The new drafts must carry exactly \Draft \Seen; anything else stays and fails the comparison.
			got = maps.Clone(got)
			maps.DeleteFunc(got, func(uid uint32, flags []string) bool {
				want, isNew := newDrafts[uid]
				return isNew && slices.Equal(flags, want)
			})
		}
		if !maps.EqualFunc(got, want, slices.Equal) {
			t.Errorf("%s %s flags changed: %v, want %v", box.user.Name, box.mailbox, got, want)
		}
	}
	var saves []string
	for _, e := range f.MailLog(t) {
		if e.Event != "save" || e.Mailbox != "Drafts" || e.User != Alice.Login {
			t.Errorf("unexpected mail event %s", e.Line)
			continue
		}
		saves = append(saves, strings.Trim(e.MsgID, "<>"))
	}
	var wantSaves []string
	for _, d := range drafts {
		wantSaves = append(wantSaves, d.MessageID)
	}
	if !slices.Equal(saves, wantSaves) {
		t.Errorf("mail_log saves %q, want the drafts %q", saves, wantSaves)
	}
}

// TestAccountIsolation proves that accounts stay apart: bob sees none of
// alice's mailboxes or mail, alice's reference used with account bob is
// stale, each generated config names only its own account and secret, and
// losing bob's credential does not affect alice.
func TestAccountIsolation(t *testing.T) {
	himalaya := HimalayaPath(t)
	bin := BuildServer(t)
	f := StartFixture(t, FixtureOptions{})
	shim := BuildShim(t, himalaya)
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim})
	cs := StartStdio(t, bin, files)

	mbs := rdOut[rdMailboxes](t, cs, "list_mailboxes", rdArgs{"account": "bob"})
	var names []string
	for _, m := range mbs.Mailboxes {
		names = append(names, m.Name)
	}
	if !slices.Contains(names, "INBOX") || slices.ContainsFunc(names, func(n string) bool {
		return slices.Contains([]string{"Résumé/Ünïcødé 📬", "Folders/Projects", "Labels/Work"}, n)
	}) {
		t.Errorf("bob's mailboxes %q include alice's folders or lack INBOX", names)
	}
	bobInbox := rdOut[rdList](t, cs, "list_messages", rdArgs{"account": "bob", "mailbox": "INBOX"})
	var ids []string
	for _, m := range bobInbox.Messages {
		ids = append(ids, m.MessageID)
	}
	if !slices.Equal(ids, []string{"bob-02@fixture.test", "bob-01@fixture.test"}) || bobInbox.Total != 2 {
		t.Errorf("bob's INBOX holds %q (total %d), want only bob's two messages", ids, bobInbox.Total)
	}

	// Dovecot derives UIDVALIDITY from the clock, so the two INBOXes may match; make them differ.
	aliceInbox := rdOut[rdList](t, cs, "list_messages", rdArgs{"account": "alice", "mailbox": "INBOX"})
	f.SetUIDValidity(t, Bob, "INBOX", aliceInbox.UIDValidity+1)
	bobFlags := f.Flags(t, Bob, "INBOX")
	events := len(f.MailLog(t))
	aliceRef := rdArgs{"account": "bob", "mailbox": "INBOX", "uidvalidity": aliceInbox.UIDValidity}
	for _, c := range []struct {
		tool string
		args rdArgs
	}{
		{"read_message", rdArgs{"uid": 1}},
		{"update_flags", rdArgs{"uids": []int{1}, "seen": true}},
	} {
		args := maps.Clone(aliceRef)
		maps.Copy(args, c.args)
		if text := rdFail(t, cs, c.tool, args); rdCode(text) != "stale_reference" {
			t.Errorf("%s with alice's reference on bob: %q, want stale_reference", c.tool, text)
		}
	}
	if got := f.Flags(t, Bob, "INBOX"); !maps.EqualFunc(got, bobFlags, slices.Equal) {
		t.Errorf("bob's INBOX flags changed from %v to %v", bobFlags, got)
	}
	if evs := f.MailLog(t); len(evs) != events {
		t.Errorf("stale references caused mail events: %+v", evs[events:])
	}

	// Each generated config names only its own account, login and secret.
	for _, c := range []struct{ own, other User }{{Alice, Bob}, {Bob, Alice}} {
		toml := string(readFile(t, filepath.Join(files.StateDir, "himalaya", c.own.Name+".toml")))
		if !strings.Contains(toml, files.PasswordFiles[c.own.Name]) {
			t.Fatalf("%s.toml does not reference its own password file:\n%s", c.own.Name, toml)
		}
		for _, leak := range []string{files.PasswordFiles[c.other.Name], files.FilesDirs[c.other.Name], c.other.Login, "accounts." + c.other.Name} {
			if strings.Contains(toml, leak) {
				t.Errorf("%s.toml contains %q:\n%s", c.own.Name, leak, toml)
			}
		}
	}

	if err := os.Remove(files.PasswordFiles["bob"]); err != nil {
		t.Fatal(err)
	}
	if text := rdFail(t, cs, "list_mailboxes", rdArgs{"account": "bob"}); !slices.Contains([]string{"credential_unavailable", "auth_failed"}, rdCode(text)) ||
		strings.Contains(text, files.PasswordFiles["bob"]) {
		t.Errorf("bob without a password file: %q, want credential_unavailable or auth_failed without the path", text)
	}
	rdOut[rdMailboxes](t, cs, "list_mailboxes", rdArgs{"account": "alice"})
}

// TestMailboxIdentity proves that list_mailboxes names are exact: of two
// folders that differ only by a zero-width space, only the plain one is
// listed and the other is counted as omitted. Its exact name is refused
// before any Himalaya run, and the listed name addresses the plain folder.
func TestMailboxIdentity(t *testing.T) {
	himalaya := HimalayaPath(t)
	bin := BuildServer(t)
	f := StartFixture(t, FixtureOptions{})
	plain, hidden := "Folders/Review", "Folders/Review\u200b"
	for _, box := range []string{plain, hidden} {
		f.Doveadm(t, "mailbox", "create", "-u", Alice.Login, box)
	}
	f.Seed(t, Alice, hidden, []byte("From: h@example.test\r\nTo: alice@example.test\r\nSubject: hidden\r\nMessage-ID: <hidden@review.test>\r\n\r\nhidden\r\n"))
	shim := BuildShim(t, himalaya)
	cs := StartStdio(t, bin, WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim}))

	out := rdOut[rdMailboxes](t, cs, "list_mailboxes", rdArgs{"account": "alice"})
	var reviews []rdMailbox
	for _, m := range out.Mailboxes {
		if strings.HasPrefix(m.Name, plain) {
			reviews = append(reviews, m)
		}
	}
	if len(reviews) != 1 || reviews[0].Name != plain || reviews[0].Total != 0 || out.OmittedUnsafeNames != 1 {
		t.Errorf("list_mailboxes lists %+v and omits %d, want only the empty %q and 1 omitted", reviews, out.OmittedUnsafeNames, plain)
	}

	runs := len(shim.Records(t))
	if text := rdFail(t, cs, "list_messages", rdArgs{"account": "alice", "mailbox": hidden}); rdCode(text) != "invalid_argument" {
		t.Errorf("list_messages on the hidden folder: %q, want invalid_argument", text)
	}
	if n := len(shim.Records(t)); n != runs {
		t.Errorf("the refused name ran Himalaya %d times", n-runs)
	}
	if l := rdOut[rdList](t, cs, "list_messages", rdArgs{"account": "alice", "mailbox": plain}); l.Total != 0 {
		t.Errorf("list_messages on %q found %d messages, want the empty plain folder", plain, l.Total)
	}
}

// TestTLS proves certificate validation over implicit TLS (alice) and
// STARTTLS (bob): the CA and a pinned Bridge-style leaf are accepted; a rogue
// CA, a wrong SAN through the CA and an account without a certificate fail
// as tls_failed without the password in the result or the server log. The
// account without a certificate is tested on a server that itself runs with
// SSL_CERT_FILE=<CA>, which Himalaya would honour if the server passed it on.
func TestTLS(t *testing.T) {
	himalaya := HimalayaPath(t)
	bin := BuildServer(t)
	RequireDocker(t)
	pki := NewPKI(t)

	t.Run("ca", func(t *testing.T) {
		t.Parallel()
		f := StartFixture(t, FixtureOptions{PKI: pki})
		// The audit in TestMain knows only alice and bob, so each server pairs a good and a bad account.
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalaya), Edit: func(c *ServerConfig) {
			c.Accounts["bob"].IMAP.TLSCertFile = pki.RogueCA.CertFile
		}})
		cs := StartStdio(t, bin, files)
		rdTLSOK(t, cs, "alice")
		rdTLSFailed(t, cs, files, "bob")

		// The server's own environment must not widen the child's trust.
		envFiles := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalaya), Edit: func(c *ServerConfig) {
			c.Accounts["alice"].IMAP.TLSCertFile = ""
		}})
		envCS := StartStdio(t, bin, envFiles, "SSL_CERT_FILE="+pki.CA.CertFile)
		rdTLSFailed(t, envCS, envFiles, "alice")
		rdTLSOK(t, envCS, "bob")
		// Premise: the same generated config connects when Himalaya does inherit SSL_CERT_FILE.
		cmd := exec.Command(himalaya, "-c", filepath.Join(envFiles.StateDir, "himalaya", "alice.toml"), "-a", "alice", "-b", "imap", "--log-level", "off", "--json", "mailbox", "list")
		cmd.Env = append(ServerEnv(envFiles.StateDir), "SSL_CERT_FILE="+pki.CA.CertFile)
		if out, err := cmd.Output(); err != nil {
			t.Errorf("premise failed: Himalaya with SSL_CERT_FILE and no imap.tls.cert: %v %s", err, out)
		}
	})

	t.Run("pinned bridge leaf", func(t *testing.T) {
		t.Parallel()
		f := StartFixture(t, FixtureOptions{PKI: pki, ServerCert: &pki.Bridge})
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalaya), Edit: func(c *ServerConfig) {
			for _, a := range c.Accounts {
				a.IMAP.TLSCertFile = pki.Bridge.CertFile
			}
		}})
		rdTLSOK(t, StartStdio(t, bin, files), "alice", "bob")
	})

	t.Run("wrong SAN through the CA", func(t *testing.T) {
		t.Parallel()
		f := StartFixture(t, FixtureOptions{PKI: pki, ServerCert: &pki.WrongSAN})
		files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: BuildShim(t, himalaya)})
		cs := StartStdio(t, bin, files)
		rdTLSFailed(t, cs, files, "alice")
		rdTLSFailed(t, cs, files, "bob")
	})
}

// rdTLSOK requires that each account can list its mailboxes.
func rdTLSOK(t *testing.T, cs *mcp.ClientSession, accounts ...string) {
	t.Helper()
	for _, a := range accounts {
		rdOut[rdMailboxes](t, cs, "list_mailboxes", rdArgs{"account": a})
	}
}

// rdTLSFailed requires tls_failed for account, with no password and no
// Himalaya text in the result and no password in the server log.
func rdTLSFailed(t *testing.T, cs *mcp.ClientSession, files *ServerFiles, account string) {
	t.Helper()
	text := rdFail(t, cs, "list_mailboxes", rdArgs{"account": account})
	if rdCode(text) != "tls_failed" || strings.Contains(text, "peer certificate") {
		t.Errorf("%s: %q, want tls_failed without Himalaya's error text", account, text)
	}
	log := readFile(t, files.ServerLog)
	for _, u := range []User{Alice, Bob} {
		if strings.Contains(text, u.Password) || bytes.Contains(log, []byte(u.Password)) {
			t.Errorf("%s: %s's password appears in the result or the server log", account, u.Name)
		}
	}
}
