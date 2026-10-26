package mailmcp

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// fakeRunner answers by command path from per-path queues (the last answer
// repeats) and checks every argv against the real guard.
type fakeRunner struct {
	t       *testing.T
	guard   himalaya.Guard
	calls   []string
	answers map[string][]answer
}

type answer struct {
	out string
	err error
}

func (f *fakeRunner) Run(_ context.Context, c himalaya.Command) ([]byte, error) {
	path, err := f.guard.Check(c.Args)
	if err != nil {
		f.t.Fatalf("argv refused by the guard: %v: %q", err, c.Args)
	}
	f.calls = append(f.calls, path)
	q := f.answers[path]
	if len(q) == 0 {
		f.t.Fatalf("unexpected call %q", path)
	}
	a := q[0]
	if len(q) > 1 {
		f.answers[path] = q[1:]
	}
	return []byte(a.out), a.err
}

const (
	statusOK      = `{"messages":3,"recent":0,"uid_next":10,"uid_validity":77,"unseen":1}`
	statusChanged = `{"messages":3,"recent":0,"uid_next":10,"uid_validity":78,"unseen":1}`
	fetch12       = `{"messages":[{"seq":1,"uid":1,"flags":[],"size":100},{"seq":2,"uid":2,"flags":["\\Seen"],"size":100}]}`
	fetch1        = `{"messages":[{"seq":1,"uid":1,"flags":[],"size":100}]}`
	capsOK        = `{"message":"* CAPABILITY IMAP4rev1 IDLE UNSELECT UIDPLUS MOVE ID\r\nA1 OK done\r\n"}`
	composed      = "From: <you@proton.me>\r\nTo: <bob@example.test>\r\nSubject: s\r\nMessage-ID: <abc.123@mail-mcp>\r\n\r\nbody\r\n"
)

func uncertainErr() error { return himalaya.Errorf(himalaya.CodeOutcomeUncertain, "") }

func newTestServer(t *testing.T, answers map[string][]answer) (*Server, *fakeRunner) {
	t.Helper()
	state := t.TempDir()
	if err := os.Mkdir(filepath.Join(state, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := bridgeAccount()
	a.Email = "you@proton.me"
	cfg := &config.Config{
		StateDir: state, CallTimeoutSeconds: 5,
		Limits:   config.Limits{MaxAttachmentBytes: 1 << 20, MaxMessageBytes: 1000},
		Accounts: map[string]*config.Account{"proton": a},
	}
	files, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.Close() })
	f := &fakeRunner{t: t, guard: himalaya.Guard{StateDir: state, Accounts: []string{"proton"}}, answers: answers}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(context.Background(), cfg, f, map[string]*os.Root{"proton": files}, nil, log), f
}

// tagged returns UIDs of account proton's mailbox mb at UIDVALIDITY uv as s returns them.
func tagged(s *Server, mb string, uv uint32, nums ...uint32) UIDs {
	out := make(UIDs, len(nums))
	for i, n := range nums {
		out[i] = s.tagUID("proton", mb, uv, n)
	}
	return out
}

func wantCode(t *testing.T, err error, code himalaya.Code, detail string) {
	t.Helper()
	if himalaya.CodeOf(err) != code || !strings.Contains(err.Error(), detail) {
		t.Fatalf("err = %v, want %s containing %q", err, code, detail)
	}
}

func wantCalls(t *testing.T, f *fakeRunner, want ...string) {
	t.Helper()
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls = %q\nwant    %q", f.calls, want)
	}
}

func moveIn(s *Server) MoveIn {
	return MoveIn{Account: "proton", Mailbox: "inbox", UIDValidity: 77, UIDs: tagged(s, "INBOX", 77, 1, 2), To: "Archive"}
}

func TestMoveFlow(t *testing.T) {
	tests := []struct {
		name    string
		answers map[string][]answer
		code    himalaya.Code
		detail  string
		calls   []string
	}{
		{"moved", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}}, "imap fetch": {{out: fetch12}},
			"message move": {{out: `{"message":"2 messages successfully moved"}`}},
		}, "", "", []string{"imap raw", "imap status", "imap fetch", "imap status", "message move", "imap status"}},
		{"partial count", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}}, "imap fetch": {{out: fetch12}},
			"message move": {{out: `{"message":"1 message successfully moved"}`}},
		}, himalaya.CodePartial, "1 of 2 messages moved", nil},
		{"uidvalidity changed afterwards", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}, {out: statusOK}, {out: statusChanged}}, "imap fetch": {{out: fetch12}},
			"message move": {{out: `{"message":"2 messages successfully moved"}`}},
		}, himalaya.CodeOutcomeUncertain, `could not be confirmed`, nil},
		{"connection reset during move", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}}, "imap fetch": {{out: fetch12}},
			"message move": {{err: uncertainErr()}},
		}, himalaya.CodeOutcomeUncertain, `move from "INBOX" to "Archive"`, nil},
		{"missing uid stops before the move", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}}, "imap fetch": {{out: fetch1}},
		}, himalaya.CodeNotFound, "missing uids [2]", []string{"imap raw", "imap status", "imap fetch", "imap status"}},
		// The UIDVALIDITY check runs last before the move, after the fetch.
		{"stale reference", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}, {out: statusChanged}}, "imap fetch": {{out: fetch12}},
		}, himalaya.CodeStaleReference, `mailbox "INBOX"`, []string{"imap raw", "imap status", "imap fetch", "imap status"}},
		// UIDs the fetch missed because of a reset are stale, not missing.
		{"reset hides a uid", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}, {out: statusChanged}}, "imap fetch": {{out: fetch1}},
		}, himalaya.CodeStaleReference, `mailbox "INBOX"`, []string{"imap raw", "imap status", "imap fetch", "imap status"}},
		// Status of the target first: MOVE to a missing mailbox would be outcome_uncertain.
		{"missing target", map[string][]answer{
			"imap raw": {{out: capsOK}}, "imap status": {{err: himalaya.Errorf(himalaya.CodeMailboxNotFound, "")}},
		}, himalaya.CodeMailboxNotFound, `mailbox "Archive"`, []string{"imap raw", "imap status"}},
		{"server without MOVE", map[string][]answer{
			"imap raw": {{out: `{"message":"* CAPABILITY IMAP4rev1 UIDPLUS\r\nA1 OK\r\n"}`}},
		}, himalaya.CodeServerUnsupported, "", []string{"imap raw"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := newTestServer(t, tt.answers)
			out, err := s.moveMessages(context.Background(), moveIn(s))
			if tt.code == "" {
				if err != nil || out.Moved != 2 || out.From != "INBOX" || out.To != "Archive" {
					t.Fatalf("%+v %v", out, err)
				}
			} else {
				wantCode(t, err, tt.code, tt.detail)
			}
			if tt.calls != nil {
				wantCalls(t, f, tt.calls...)
			}
		})
	}
}

// update_flags reports the steps that completed, and confirms UIDVALIDITY
// after each one so that a reset during the first stops the second.
func TestUpdateFlagsSteps(t *testing.T) {
	added := answer{out: `{"flags":["seen"]}`}
	tests := []struct {
		name   string
		status []answer
		remove []answer
		detail string
		calls  []string
	}{
		{"second step fails", []answer{{out: statusOK}}, []answer{{err: uncertainErr()}},
			"completed before the failure: added seen",
			[]string{"imap raw", "imap fetch", "imap status", "flag add", "imap status", "flag remove"}},
		{"reset during the first step", []answer{{out: statusOK}, {out: statusChanged}}, nil,
			`flags added seen, but the UIDVALIDITY of "INBOX" could not be confirmed`,
			[]string{"imap raw", "imap fetch", "imap status", "flag add", "imap status"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := newTestServer(t, map[string][]answer{
				"imap raw": {{out: capsOK}}, "imap status": tt.status, "imap fetch": {{out: fetch12}},
				"flag add": {added}, "flag remove": tt.remove,
			})
			_, err := s.updateFlags(context.Background(), FlagsIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 77,
				UIDs: tagged(s, "INBOX", 77, 1, 2), Seen: new(true), Flagged: new(false)})
			wantCode(t, err, himalaya.CodeOutcomeUncertain, tt.detail)
			wantCalls(t, f, tt.calls...)
		})
	}
}

func TestUpdateDraftTrashStep(t *testing.T) {
	moved := answer{out: `{"message":"1 message successfully moved"}`}
	tests := []struct {
		name     string
		recheck  answer // Drafts status after the new version was added
		move     answer
		trashed  string
		errorHas string
	}{
		{"trashed", answer{out: statusOK}, moved, "yes", ""},
		{"move uncertain", answer{out: statusOK}, answer{err: uncertainErr()}, "uncertain", "outcome_uncertain"},
		{"move failed before connecting", answer{out: statusOK}, answer{err: himalaya.Errorf(himalaya.CodeAccountUnavailable, "")}, "no", "account_unavailable"},
		// The old uid may now be another message, so it is not moved.
		{"drafts reset meanwhile", answer{out: statusChanged}, moved, "no", "stale_reference"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := newTestServer(t, map[string][]answer{
				"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}, tt.recheck}, "imap fetch": {{out: fetch1}},
				"message compose": {{out: composed}}, "message add": {{out: `{"id":"12","sent":false}`}},
				"message move": {tt.move},
			})
			out, err := s.updateDraft(context.Background(), UpdateDraftIn{Account: "proton", UIDValidity: 77, UID: s.tagUID("proton", "Drafts", 77, 1),
				To: Addresses{"bob@example.test"}, Subject: "s", Body: "body"})
			if err != nil || out.UID != s.tagUID("proton", "Drafts", 77, 12) || out.UIDValidity != 77 || out.Mailbox != "Drafts" || out.MessageID != "abc.123@mail-mcp" ||
				out.PreviousTrashed != tt.trashed || !strings.Contains(out.Error, tt.errorHas) {
				t.Fatalf("%+v %v", out, err)
			}
			checked := []string{"imap raw", "imap fetch", "imap status", "message compose", "message add", "imap status"}
			switch tt.name {
			case "trashed":
				wantCalls(t, f, append(checked, "message move", "imap status")...)
			case "drafts reset meanwhile":
				wantCalls(t, f, checked...)
			}
		})
	}
}

// Once message add has run, the draft may exist whatever add reported, so
// the error is outcome_uncertain with the message_id to look for in Drafts,
// and update_draft leaves the previous draft alone.
func TestDraftAddUncertainNamesMessageID(t *testing.T) {
	const look = `look for message_id "abc.123@mail-mcp" in "Drafts"`
	adds := []struct {
		name string
		add  answer
	}{
		{"add failed", answer{err: uncertainErr()}},
		{"add result unrecognized", answer{out: `{"id":"","sent":false}`}},
	}
	for _, tt := range adds {
		t.Run("create_draft "+tt.name, func(t *testing.T) {
			s, f := newTestServer(t, map[string][]answer{
				"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}},
				"message compose": {{out: composed}}, "message add": {tt.add},
			})
			_, err := s.createDraft(context.Background(), DraftIn{Account: "proton", To: Addresses{"bob@example.test"}})
			wantCode(t, err, himalaya.CodeOutcomeUncertain, look)
			// Drafts status runs before the append so a UIDVALIDITY reset makes the reference stale, never wrong.
			wantCalls(t, f, "imap raw", "imap status", "message compose", "message add")
		})
		t.Run("update_draft "+tt.name, func(t *testing.T) {
			s, f := newTestServer(t, map[string][]answer{
				"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}}, "imap fetch": {{out: fetch1}},
				"message compose": {{out: composed}}, "message add": {tt.add},
			})
			_, err := s.updateDraft(context.Background(), UpdateDraftIn{Account: "proton", UIDValidity: 77, UID: s.tagUID("proton", "Drafts", 77, 1), Subject: "s"})
			wantCode(t, err, himalaya.CodeOutcomeUncertain, look)
			wantCode(t, err, himalaya.CodeOutcomeUncertain, "the previous draft was left in place")
			wantCalls(t, f, "imap raw", "imap fetch", "imap status", "message compose", "message add")
		})
	}
}

// message add would silently store only the lines before the first invalid
// byte, so compose output that is not UTF-8 never reaches it.
func TestCreateDraftRefusesComposeOutputThatIsNotUTF8(t *testing.T) {
	s, f := newTestServer(t, map[string][]answer{
		"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}},
		"message compose": {{out: composed + "caf\xe9\r\n"}},
	})
	_, err := s.createDraft(context.Background(), DraftIn{Account: "proton", To: Addresses{"bob@example.test"}})
	wantCode(t, err, himalaya.CodeMailError, "")
	wantCalls(t, f, "imap raw", "imap status", "message compose")
}

// A reset between the checks and the download would fetch another
// message's attachment, so download_attachment checks again before saving.
func TestDownloadRechecksBeforeSaving(t *testing.T) {
	s, f := newTestServer(t, map[string][]answer{
		"imap status": {{out: statusOK}, {out: statusChanged}}, "imap fetch": {{out: fetch1}},
		"attachment download": {{out: `{"attachments":[{"id":"3","filename":"a.txt","mime":"text/plain","size":5,"inline":false}]}`}},
	})
	_, err := s.downloadAttachment(context.Background(), DownloadIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 77, UID: s.tagUID("proton", "INBOX", 77, 1), PartID: 3})
	wantCode(t, err, himalaya.CodeStaleReference, `mailbox "INBOX"`)
	wantCalls(t, f, "imap status", "imap fetch", "attachment download", "imap status")
	if names, _ := fs.ReadDir(s.roots["proton"].FS(), "."); len(names) != 0 {
		t.Errorf("files_dir holds %v", names)
	}
	if names, _ := os.ReadDir(s.tmpDir()); len(names) != 0 {
		t.Errorf("<state>/tmp holds %v", names)
	}
}

func TestReadChecksSizeBeforeFetchingTheBody(t *testing.T) {
	s, f := newTestServer(t, map[string][]answer{
		"imap status": {{out: statusOK}},
		"imap fetch":  {{out: `{"messages":[{"seq":1,"uid":1,"flags":[],"size":1001}]}`}},
	})
	_, err := s.readMessage(context.Background(), ReadIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 77, UID: s.tagUID("proton", "INBOX", 77, 1)})
	wantCode(t, err, himalaya.CodeTooLarge, "max_message_bytes")
	wantCalls(t, f, "imap status", "imap fetch")
}

// imap fetch lists unsolicited FETCH responses as rows too, so the size must
// come from the one row of the requested UID that carries RFC822.SIZE.
func TestCheckSizeUsesTheRequestedUIDsRow(t *testing.T) {
	row := func(uid int, size string) string {
		return fmt.Sprintf(`{"seq":%d,"uid":%d,"flags":[],"internal_date":null,"size":%s,"envelope":null,"structure":null,"body":null}`, uid, uid, size)
	}
	tests := []struct {
		name  string
		fetch string
		code  himalaya.Code
	}{
		{"unsolicited FLAGS-only row first", `{"messages":[` + row(2, "null") + `,` + row(4, "1001") + `]}`, himalaya.CodeTooLarge},
		{"size absent", `{"messages":[` + row(4, "null") + `]}`, himalaya.CodeMailError},
		{"size twice", `{"messages":[` + row(4, "100") + `,` + row(4, "100") + `]}`, himalaya.CodeMailError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := newTestServer(t, map[string][]answer{"imap status": {{out: statusOK}}, "imap fetch": {{out: tt.fetch}}})
			_, err := s.readMessage(context.Background(), ReadIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 77, UID: s.tagUID("proton", "INBOX", 77, 4)})
			wantCode(t, err, tt.code, "")
			wantCalls(t, f, "imap status", "imap fetch")
		})
	}
}

// reply_draft and forward_draft recheck the source after Himalaya rendered
// it: a UIDVALIDITY reset in between means the draft may quote another
// message, so nothing is added.
func TestReplyDraftRechecksTheSource(t *testing.T) {
	added := answer{out: `{"id":"12","sent":false}`}
	tests := []struct {
		name    string
		recheck answer
		add     answer
		code    himalaya.Code
		detail  string
	}{
		{"saved", answer{out: statusOK}, added, "", ""},
		{"source reset while rendering", answer{out: statusChanged}, added, himalaya.CodeStaleReference, `mailbox "INBOX"`},
		{"source unconfirmed", answer{err: himalaya.Errorf(himalaya.CodeAccountUnavailable, "")}, added, himalaya.CodeAccountUnavailable, ""},
		{"add uncertain", answer{out: statusOK}, answer{err: uncertainErr()}, himalaya.CodeOutcomeUncertain, `look for message_id "abc.123@mail-mcp" in "Drafts"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := newTestServer(t, map[string][]answer{
				"imap raw": {{out: capsOK}}, "imap fetch": {{out: fetch1}}, "message reply": {{out: composed}},
				// source, drafts, then the source again
				"imap status": {{out: statusOK}, {out: statusOK}, tt.recheck},
				"message add": {tt.add},
			})
			out, err := s.replyDraft(context.Background(), ReplyIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 77, UID: s.tagUID("proton", "INBOX", 77, 1), Body: "ok"})
			checks := []string{"imap raw", "imap status", "imap fetch", "imap status", "message reply", "imap status"}
			if tt.code == "" {
				if err != nil || out.UID != s.tagUID("proton", "Drafts", 77, 12) || out.MessageID != "abc.123@mail-mcp" {
					t.Fatalf("%+v %v", out, err)
				}
				wantCalls(t, f, append(checks, "message add")...)
				return
			}
			wantCode(t, err, tt.code, tt.detail)
			if tt.code != himalaya.CodeOutcomeUncertain {
				wantCalls(t, f, checks...)
			}
		})
	}
}

func TestReadMessageSanitizes(t *testing.T) {
	read := `{"html_body":[0],"text_body":[0],"attachments":[],"parts":[{"headers":[` +
		`{"name":"subject","value":{"Text":"Hi\u202e\r\nthere"}},{"name":"message_id","value":{"Text":"m@x"}},` +
		`{"name":"from","value":{"Address":{"List":[{"name":"Eve\u200b","address":"eve@x.test"}]}}},` +
		`{"name":"mime_version","value":"Empty"}],` +
		`"body":{"Html":"<p>Hello</p><img src=\"https://tracker.invalid/p.gif\"><script>x()</script>` + strings.Repeat("é", 1000) + `"}}]}`
	s, _ := newTestServer(t, map[string][]answer{
		"imap status": {{out: statusOK}}, "imap fetch": {{out: fetch1}}, "message read": {{out: read}},
	})
	out, err := s.readMessage(context.Background(), ReadIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 77, UID: s.tagUID("proton", "INBOX", 77, 1), MaxBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "Hi there" || out.From[0].Name != "Eve" || out.BodyFormat != "html_stripped" || !out.Truncated ||
		len(out.Body) > 1024 || strings.Contains(out.Body, "tracker") || !strings.HasPrefix(out.Body, "Hello") {
		t.Errorf("%+v", out)
	}
}

func TestRemoveLabelRequiresDeletedResult(t *testing.T) {
	s, f := newTestServer(t, map[string][]answer{
		"imap raw": {{out: capsOK}}, "imap status": {{out: statusOK}}, "imap fetch": {{out: fetch1}},
		"message delete": {{out: `{"action":"moved-to-trash","count":1}`}},
	})
	_, err := s.removeLabel(context.Background(), RemoveLabelIn{Account: "proton", Label: "Labels/Work", UIDValidity: 77, UIDs: tagged(s, "Labels/Work", 77, 1)})
	wantCode(t, err, himalaya.CodeOutcomeUncertain, `removing label "Labels/Work"`)
	wantCalls(t, f, "imap raw", "imap fetch", "imap status", "message delete")
	if left, _ := os.ReadDir(s.tmpDir()); len(left) != 0 {
		t.Errorf("per-call config left behind: %v", left)
	}
}

// list_mailboxes shows server names exactly. Names the mailbox rule refuses
// are left out and counted rather than shown cleaned, which would make
// Folders/Review and Folders/Review<ZWSP> look like one folder.
func TestListMailboxesOmitsUnsafeNames(t *testing.T) {
	row := func(id string) string {
		return fmt.Sprintf(`{"id":%q,"name":%[1]q,"role":null,"total":1,"unread":0}`, id)
	}
	rows := []string{row("Folders/Review"), row("Folders/Review\u200b"), row("Inbox"), row("Invoice\u202efdp.exe"), row("-x"), row("Résumé/Ünïcødé 📬")}
	s, _ := newTestServer(t, map[string][]answer{"mailbox list": {{out: `{"mailboxes":[` + strings.Join(rows, ",") + `]}`}}})
	out, err := s.listMailboxes(context.Background(), AccountIn{Account: "proton"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range out.Mailboxes {
		names = append(names, m.Name)
	}
	if want := []string{"Folders/Review", "INBOX", "Résumé/Ünïcødé 📬"}; !slices.Equal(names, want) || out.OmittedUnsafeNames != 3 {
		t.Errorf("names %q, omitted %d; want %q, omitted 3", names, out.OmittedUnsafeNames, want)
	}
}

// A name list_mailboxes shows must be usable as input exactly as shown, so
// the mailbox rule alone must refuse every name the sanitizer would change.
func TestAddressable(t *testing.T) {
	for _, name := range []string{"INBOX", "Folders/Review", "Résumé/Ünïcødé 📬", strings.Repeat("日", 255)} {
		if !addressable(name) {
			t.Errorf("%q is not addressable", name)
		}
	}
	for _, name := range []string{"", "-x", "a\xffb", "a\tb", strings.Repeat("x", 256)} {
		if addressable(name) {
			t.Errorf("%q is addressable", name)
		}
	}
	for r := rune(0); r <= 0xe00ff; r++ {
		if name := "Folders/Review" + string(r); sanitizeLine(name) != name && config.CheckMailboxName(name) == nil {
			t.Errorf("the mailbox rule accepts U+%04X, which the sanitizer changes", r)
		}
	}
}

// TestHandlersValidate calls handlers directly, as a client that bypasses
// the schema would: every bad value is refused before any subprocess. Rows
// that test a later check pass correctly tagged UIDs.
func TestHandlersValidate(t *testing.T) {
	ctx := context.Background()
	ref := func(mb Mailbox, uid UID) ReadIn {
		return ReadIn{Account: "proton", Mailbox: mb, UIDValidity: 77, UID: uid}
	}
	const anyTag = "AAAAAAAAAAA"
	tests := []struct {
		name string
		call func(s *Server) error
		code himalaya.Code
	}{
		{"unknown account", func(s *Server) error { _, err := s.listMailboxes(ctx, AccountIn{Account: "bob"}); return err }, himalaya.CodeInvalidArgument},
		{"uid without its tag", func(s *Server) error { _, err := s.readMessage(ctx, ref("INBOX", "1")); return err }, himalaya.CodeInvalidArgument},
		{"uid 0", func(s *Server) error { _, err := s.readMessage(ctx, ref("INBOX", "0."+anyTag)); return err }, himalaya.CodeInvalidArgument},
		{"uid star", func(s *Server) error { _, err := s.readMessage(ctx, ref("INBOX", "4294967295."+anyTag)); return err }, himalaya.CodeInvalidArgument},
		{"uid from another mailbox", func(s *Server) error {
			_, err := s.readMessage(ctx, ref("INBOX", s.tagUID("proton", "Trash", 77, 1)))
			return err
		}, himalaya.CodeStaleReference},
		// The undo-a-trash mistake: the UID the message had before it moved.
		{"restore with an inbox uid", func(s *Server) error {
			_, err := s.restoreMessages(ctx, RestoreIn{Account: "proton", UIDValidity: 77, UIDs: tagged(s, "INBOX", 77, 1)})
			return err
		}, himalaya.CodeStaleReference},
		{"mailbox option", func(s *Server) error { _, err := s.readMessage(ctx, ref("-c/etc/passwd", "1."+anyTag)); return err }, himalaya.CodeInvalidArgument},
		{"mailbox crlf", func(s *Server) error { _, err := s.readMessage(ctx, ref("a\r\nb", "1."+anyTag)); return err }, himalaya.CodeInvalidArgument},
		{"mailbox zero-width", func(s *Server) error {
			_, err := s.readMessage(ctx, ref("Folders/Review\u200b", "1."+anyTag))
			return err
		}, himalaya.CodeInvalidArgument},
		{"move target bidi", func(s *Server) error {
			_, err := s.moveMessages(ctx, MoveIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, 1), To: "Archive\u202e"})
			return err
		}, himalaya.CodeInvalidArgument},
		{"label tag character", func(s *Server) error {
			_, err := s.addLabel(ctx, AddLabelIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, 1), Label: "Labels/Work\U000E0041"})
			return err
		}, himalaya.CodeInvalidArgument},
		{"uidvalidity 0", func(s *Server) error {
			_, err := s.readMessage(ctx, ReadIn{Account: "proton", Mailbox: "INBOX", UID: s.tagUID("proton", "INBOX", 1, 1)})
			return err
		}, himalaya.CodeInvalidArgument},
		{"max_bytes too small", func(s *Server) error {
			_, err := s.readMessage(ctx, ReadIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UID: s.tagUID("proton", "INBOX", 1, 1), MaxBytes: 10})
			return err
		}, himalaya.CodeInvalidArgument},
		{"duplicate uids", func(s *Server) error {
			_, err := s.trashMessages(ctx, BatchIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, 1, 1)})
			return err
		}, himalaya.CodeInvalidArgument},
		{"51 uids", func(s *Server) error {
			nums := make([]uint32, 51)
			for i := range nums {
				nums[i] = uint32(i + 1)
			}
			_, err := s.trashMessages(ctx, BatchIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, nums...)})
			return err
		}, himalaya.CodeInvalidArgument},
		{"display name", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", To: Addresses{"Bob <bob@x.test>"}})
			return err
		}, himalaya.CodeInvalidArgument},
		{"address option", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", Cc: Addresses{"--send"}})
			return err
		}, himalaya.CodeInvalidArgument},
		{"subject crlf", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", Subject: "a\r\nBcc: e@x.test"})
			return err
		}, himalaya.CodeInvalidArgument},
		{"body nul", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", Body: "a\x00b"})
			return err
		}, himalaya.CodeInvalidArgument},
		{"body too big", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", Body: Body(strings.Repeat("é", maxBody/2+1))})
			return err
		}, himalaya.CodeInvalidArgument},
		{"attachment path", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", Attachments: FileNames{"../x"}})
			return err
		}, himalaya.CodeInvalidArgument},
		{"hidden attachment", func(s *Server) error {
			_, err := s.createDraft(ctx, DraftIn{Account: "proton", Attachments: FileNames{".ssh"}})
			return err
		}, himalaya.CodeInvalidArgument},
		{"search term control", func(s *Server) error {
			_, err := s.searchMessages(ctx, SearchIn{Account: "proton", Mailbox: "INBOX", Subject: "a\nb"})
			return err
		}, himalaya.CodeInvalidArgument},
		{"bad date", func(s *Server) error {
			_, err := s.searchMessages(ctx, SearchIn{Account: "proton", Mailbox: "INBOX", Since: "2026-13-01"})
			return err
		}, himalaya.CodeInvalidArgument},
		{"page too high", func(s *Server) error {
			_, err := s.listMessages(ctx, ListMessagesIn{Account: "proton", Mailbox: "INBOX", Page: 10001})
			return err
		}, himalaya.CodeInvalidArgument},
		{"flags without a change", func(s *Server) error {
			_, err := s.updateFlags(ctx, FlagsIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, 1)})
			return err
		}, himalaya.CodeInvalidArgument},
		{"label outside the prefix", func(s *Server) error {
			_, err := s.addLabel(ctx, AddLabelIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, 1), Label: "Trash"})
			return err
		}, himalaya.CodeForbidden},
		{"move into a label", func(s *Server) error {
			_, err := s.moveMessages(ctx, MoveIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UIDs: tagged(s, "INBOX", 1, 1), To: "Labels/Work"})
			return err
		}, himalaya.CodeForbidden},
		{"trash from trash", func(s *Server) error {
			_, err := s.trashMessages(ctx, BatchIn{Account: "proton", Mailbox: "trash", UIDValidity: 1, UIDs: tagged(s, "trash", 1, 1)})
			return err
		}, himalaya.CodeForbidden},
		{"restore into trash", func(s *Server) error {
			_, err := s.restoreMessages(ctx, RestoreIn{Account: "proton", UIDValidity: 1, UIDs: tagged(s, "Trash", 1, 1), To: "Trash"})
			return err
		}, himalaya.CodeForbidden},
		{"part id 0", func(s *Server) error {
			_, err := s.downloadAttachment(ctx, DownloadIn{Account: "proton", Mailbox: "INBOX", UIDValidity: 1, UID: s.tagUID("proton", "INBOX", 1, 1)})
			return err
		}, himalaya.CodeInvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, f := newTestServer(t, nil)
			wantCode(t, tt.call(s), tt.code, "")
			wantCalls(t, f)
		})
	}
}

// A tagged UID works only with the account, mailbox and UIDVALIDITY it was
// listed with, and only in the process that listed it.
func TestTaggedUIDs(t *testing.T) {
	s, _ := newTestServer(t, nil)
	u := s.tagUID("proton", "INBOX", 77, 5)
	if n, err := s.checkUID("uid", "proton", "INBOX", 77, u); err != nil || n != 5 {
		t.Fatalf("round trip of %q: %d %v", u, n, err)
	}
	_, tag, _ := strings.Cut(string(u), ".")
	// The last base64url character carries two padding bits, so flipping the
	// lowest one keeps the decoded bytes and changes the text.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	alias := UID("5." + tag[:tagLen-1] + string(alphabet[strings.IndexByte(alphabet, tag[tagLen-1])^1]))
	other, _ := newTestServer(t, nil)
	for _, tt := range []struct {
		name, account, mb string
		uv                uint32
		u                 UID
		code              himalaya.Code
	}{
		{"another account", "bob", "INBOX", 77, u, himalaya.CodeStaleReference},
		{"another mailbox", "proton", "Trash", 77, u, himalaya.CodeStaleReference},
		{"another uidvalidity", "proton", "INBOX", 78, u, himalaya.CodeStaleReference},
		{"another uid", "proton", "INBOX", 77, UID("6." + tag), himalaya.CodeStaleReference},
		{"another process", "proton", "INBOX", 77, other.tagUID("proton", "INBOX", 77, 5), himalaya.CodeStaleReference},
		{"alias spelling", "proton", "INBOX", 77, alias, himalaya.CodeStaleReference},
		{"bare number", "proton", "INBOX", 77, "5", himalaya.CodeInvalidArgument},
		{"empty tag", "proton", "INBOX", 77, "5.", himalaya.CodeInvalidArgument},
		{"leading zero", "proton", "INBOX", 77, UID("05." + tag), himalaya.CodeInvalidArgument},
		{"signed", "proton", "INBOX", 77, UID("+5." + tag), himalaya.CodeInvalidArgument},
		{"past MaxUID", "proton", "INBOX", 77, UID("4294967295." + tag), himalaya.CodeInvalidArgument},
		{"long tag", "proton", "INBOX", 77, u + "A", himalaya.CodeInvalidArgument},
		{"not base64url", "proton", "INBOX", 77, "5.!!!!!!!!!!!", himalaya.CodeInvalidArgument},
		{"empty", "proton", "INBOX", 77, "", himalaya.CodeInvalidArgument},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.checkUID("uid", tt.account, tt.mb, tt.uv, tt.u)
			wantCode(t, err, tt.code, "")
		})
	}
	// The same UID under its alias spelling is a duplicate, not a stale reference.
	_, err := s.checkUIDs("proton", "INBOX", 77, UIDs{u, alias})
	wantCode(t, err, himalaya.CodeInvalidArgument, "must be unique")
}

func TestGuardRecoversPanics(t *testing.T) {
	s, _ := newTestServer(t, nil)
	h := guard(s, "boom", func(context.Context, NoInput) (ListAccountsOut, error) {
		var m map[string]int
		m["x"] = 1 // panics
		return ListAccountsOut{}, nil
	})
	_, _, err := h(context.Background(), nil, NoInput{})
	wantCode(t, err, himalaya.CodeInternal, "")
	h2 := guard(s, "plain", func(context.Context, NoInput) (ListAccountsOut, error) {
		return ListAccountsOut{}, io.ErrUnexpectedEOF // not an *Error: must not reach the client verbatim
	})
	_, _, err = h2(context.Background(), nil, NoInput{})
	if err.Error() != "internal: internal error" {
		t.Errorf("got %q", err)
	}
}
