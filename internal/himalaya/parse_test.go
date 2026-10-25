package himalaya

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testdata holds output captured from the IMAP-only v2.2.1 build against the
// Dovecot dev fixture (synthetic messages only).
func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseListings(t *testing.T) {
	accts, err := ParseAccountList(sample(t, "account_list.json"))
	if err != nil || len(accts) != 1 || accts[0].Name != "alice" || !slices.Equal(accts[0].Backends, []string{"imap"}) {
		t.Errorf("account list: %+v %v", accts, err)
	}

	boxes, err := ParseMailboxList(sample(t, "mailbox_list.json"))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(boxes, func(m MailboxEntry) bool { return m.ID == "Résumé/Ünïcødé 📬" })
	inbox := slices.IndexFunc(boxes, func(m MailboxEntry) bool { return m.ID == "Inbox" })
	if i < 0 || inbox < 0 || boxes[inbox].Total != 6 || boxes[inbox].Unread != 4 {
		t.Errorf("mailbox list: %+v", boxes)
	}

	st, err := ParseStatus(sample(t, "status_inbox.json"))
	if err != nil || st != (Status{Messages: 6, UIDNext: 7, UIDValidity: 1792770252, Unseen: 4}) {
		t.Errorf("status: %+v %v", st, err)
	}
	if _, err := ParseStatus([]byte(`{"messages":1}`)); err == nil {
		t.Error("status without uid_validity accepted")
	}

	rows, err := ParseFetch(sample(t, "fetch.json"))
	if err != nil || len(rows) != 2 || rows[0].UID != 1 || rows[0].Size == nil || *rows[0].Size != 356 || rows[1].UID != 3 {
		t.Errorf("fetch: %+v %v", rows, err)
	}

	envs, err := ParseEnvelopes(sample(t, "envelope_list.json"))
	if err != nil || len(envs) != 6 {
		t.Fatalf("envelopes: %d %v", len(envs), err)
	}
	e5 := envs[1]
	if e5.UID != 5 || e5.MessageID != "alice-05@fixture.test" || e5.Subject != "Grüße – 日本語 📬" ||
		!slices.Equal(e5.Flags, []string{"seen", "flagged"}) || e5.From[0] != (Address{"Björn Åström", "bjorn@example.test"}) ||
		e5.Date != "2026-10-09T16:45:00+02:00" || e5.Size != 399 {
		t.Errorf("envelope 5: %+v", e5)
	}
	if !envs[2].HasAttachment || envs[2].UID != 4 || envs[0].HasAttachment {
		t.Errorf("has-attachment: %+v %+v", envs[2], envs[0])
	}
}

func TestParseGroupEnvelope(t *testing.T) {
	// Himalaya renders IMAP group markers as addresses without '@'.
	out := []byte(`{"queued":0,"envelopes":[{"id":"7","message-id":"x","in-reply-to":[],"flags":[],"subject":"s",` +
		`"from":[{"name":null,"email":"a@x.test"}],"to":[{"name":"","email":"Team"},{"name":"","email":"d@x.test"},{"name":"","email":""}],` +
		`"date":null,"size":1,"has-attachment":null}]}`)
	envs, err := ParseEnvelopes(out)
	if err != nil || len(envs[0].To) != 1 || envs[0].To[0].Email != "d@x.test" || envs[0].Date != "" {
		t.Errorf("%+v %v", envs, err)
	}
}

func TestParseMessage(t *testing.T) {
	tests := []struct {
		file    string
		kind    BodyKind
		bodyHas string
		subject string
		date    string
		replyTo []Address
		toCount int
		ccCount int
	}{
		{"read_plain.json", BodyText, "plain text message that starts unseen", "Plain hello (unseen)", "2026-10-05T09:00:00Z", nil, 1, 0},
		{"read_html.json", BodyText, "Plain alternative of the newsletter", "Newsletter with a remote tracking pixel", "2026-10-07T08:30:00Z", nil, 1, 0},
		{"read_html_only.json", BodyHTML, "<script>alert(1)</script>", "HTML only \u202e bidi", "2026-10-12T08:15:00-07:00",
			[]Address{{"", "replies@example.test"}}, 3, 1},
		{"read_attach.json", BodyText, "Ten attachments follow", "Attachments with adversarial filenames", "2026-10-08T12:00:00Z", nil, 1, 0},
		// X-Mailer, Precedence and X-Priority are named {"other": ...}.
		{"read_other_headers.json", BodyText, "Body with custom headers", "Custom headers", "2026-10-05T09:00:00Z", nil, 1, 0},
	}
	for _, tt := range tests {
		m, err := ParseMessage(sample(t, tt.file))
		if err != nil {
			t.Fatalf("%s: %v", tt.file, err)
		}
		if m.BodyKind != tt.kind || !strings.Contains(m.Body, tt.bodyHas) || m.Subject != tt.subject || m.Date != tt.date ||
			!slices.Equal(m.ReplyTo, tt.replyTo) || len(m.To) != tt.toCount || len(m.Cc) != tt.ccCount || len(m.From) != 1 || m.MessageID == "" {
			t.Errorf("%s: %+v", tt.file, m)
		}
	}
	if _, err := ParseMessage([]byte(`{"parts":[]}`)); err == nil {
		t.Error("message without parts accepted")
	}
}

func TestParseAttachments(t *testing.T) {
	atts, err := ParseAttachments(sample(t, "attachment_list.json"))
	if err != nil || len(atts) != 9 {
		t.Fatalf("%d %v", len(atts), err)
	}
	if atts[0] != (Attachment{PartID: 3, Filename: "../../evil.sh", MIME: "application/x-sh", Size: 72}) || atts[8].Filename != "" || atts[8].PartID != 11 {
		t.Errorf("%+v", atts)
	}
	none, err := ParseAttachments(sample(t, "attachment_list_none.json"))
	if err != nil || len(none) != 0 {
		t.Errorf("none: %+v %v", none, err)
	}
	dl, err := ParseAttachments(sample(t, "download.json"))
	if err != nil || len(dl) != 1 || dl[0].PartID != 3 {
		t.Errorf("download: %+v %v", dl, err)
	}
}

func TestParseResults(t *testing.T) {
	counts := []struct {
		file, verb string
		want       int
		wantErr    bool
	}{
		{"move_one.json", "moved", 1, false},
		{"move_none.json", "moved", 0, false},
		{"copy_two.json", "copied", 2, false},
		{"copy_two.json", "moved", 0, true},
		{"add.json", "moved", 0, true},
	}
	for _, tt := range counts {
		n, err := ParseCount(sample(t, tt.file), tt.verb)
		if n != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("%s/%s: %d %v", tt.file, tt.verb, n, err)
		}
	}
	if uid, err := ParseAdd(sample(t, "add.json")); err != nil || uid != 2 {
		t.Errorf("add: %d %v", uid, err)
	}
	if _, err := ParseAdd([]byte(`{"id":"2","sent":true}`)); err == nil {
		t.Error("sent=true accepted")
	}
	if d, err := ParseDelete(sample(t, "delete_label.json")); err != nil || d != (DeleteResult{"deleted", 2}) {
		t.Errorf("delete: %+v %v", d, err)
	}
	caps, err := ParseCapability(sample(t, "capability.json"))
	if err != nil || !slices.Contains(caps, "MOVE") || !slices.Contains(caps, "UIDPLUS") {
		t.Errorf("capability: %v %v", caps, err)
	}
	if _, err := ParseCapability([]byte(`{"message":"A1 BAD nope\r\n"}`)); err == nil {
		t.Error("capability without CAPABILITY line accepted")
	}
}
