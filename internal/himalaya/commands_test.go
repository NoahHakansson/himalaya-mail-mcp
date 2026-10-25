package himalaya

import (
	"slices"
	"strings"
	"testing"
	"time"
)

const testState = "/var/lib/hmcp"

var testHX = Account{Name: "proton", Config: ConfigPath(testState, "proton")}

var testGuard = Guard{StateDir: testState, Accounts: []string{"proton"}}

// builderCases is every argv builder with the argv it must produce after the global prefix.
func builderCases() []struct {
	name string
	cmd  Command
	want string
} {
	draft := Draft{To: []string{"a@x.test", "b@x.test"}, Cc: []string{"c@x.test"}, Bcc: []string{"d@x.test"},
		Subject: "Hi -- there", Attach: []string{testState + "/tmp/att-1/report.pdf"}}
	return []struct {
		name string
		cmd  Command
		want string
	}{
		{"account list", testHX.AccountList(), "--json account list"},
		{"mailbox list", testHX.MailboxList(), "--json mailbox list --counts"},
		{"status", testHX.Status("-weird"), "--json imap status -- -weird"},
		{"fetch", testHX.Fetch("INBOX", []uint32{1, 3, 4294967294}), "--json imap fetch --mailbox=INBOX --flags --size -- 1,3,4294967294"},
		{"envelope list", testHX.EnvelopeList("Résumé/Ü 📬", 2, 50), "--json envelope list --mailbox=Résumé/Ü 📬 --page=2 --page-size=50 --has-attachment"},
		{"envelope search", testHX.EnvelopeSearch("INBOX", 1, 20, `subject "x" order by date desc`), `--json envelope search --mailbox=INBOX --page=1 --page-size=20 --has-attachment -- subject "x" order by date desc`},
		{"message read", testHX.MessageRead("INBOX", 7), "--json message read --mailbox=INBOX -- 7"},
		{"attachment list", testHX.AttachmentList("INBOX", 7), "--json attachment list --mailbox=INBOX -- 7"},
		{"attachment download", testHX.AttachmentDownload("INBOX", testState+"/tmp/dl-1", 7, 3), "--json attachment download --mailbox=INBOX --dir=" + testState + "/tmp/dl-1 -- 7 3"},
		{"flag add", testHX.FlagChange(true, "INBOX", []Flag{FlagSeen, FlagFlagged}, []uint32{1, 2}), "--json flag add --mailbox=INBOX --flag=seen --flag=flagged -- 1 2"},
		{"flag remove", testHX.FlagChange(false, "INBOX", []Flag{FlagSeen}, []uint32{9}), "--json flag remove --mailbox=INBOX --flag=seen -- 9"},
		{"move", testHX.Move("INBOX", "Trash", []uint32{1, 2}), "--json message move --from=INBOX --to=Trash -- 1 2"},
		{"copy", testHX.Copy("INBOX", "Labels/Work", []uint32{5}), "--json message copy --from=INBOX --to=Labels/Work -- 5"},
		{"compose", testHX.Compose(draft, []byte("body")), "message compose --to=a@x.test --to=b@x.test --cc=c@x.test --bcc=d@x.test --subject=Hi -- there --attach=" + testState + "/tmp/att-1/report.pdf"},
		{"compose empty", testHX.Compose(Draft{}, nil), "message compose"},
		{"reply", testHX.Reply("INBOX", 4, draft, []byte("b")), "message reply --mailbox=INBOX --to=a@x.test --to=b@x.test --cc=c@x.test --attach=" + testState + "/tmp/att-1/report.pdf -- 4"},
		{"forward", testHX.Forward("INBOX", 4, Draft{}, nil), "message forward --mailbox=INBOX -- 4"},
		{"add draft", testHX.AddDraft("Drafts", []byte("raw")), "--json message add --mailbox=Drafts --flag=draft --flag=seen"},
		{"capability", testHX.Capability(), "--json imap raw -- A1 CAPABILITY"},
	}
}

func TestBuilders(t *testing.T) {
	prefix := []string{"-c", testState + "/himalaya/proton.toml", "-a", "proton", "-b", "imap", "--log-level", "off"}
	for _, tt := range builderCases() {
		if !slices.Equal(tt.cmd.Args[:8], prefix) {
			t.Errorf("%s: prefix %q", tt.name, tt.cmd.Args[:8])
			continue
		}
		if got := strings.Join(tt.cmd.Args[8:], " "); got != tt.want {
			t.Errorf("%s:\n got %s\nwant %s", tt.name, got, tt.want)
		}
	}
	// Each value is a single argv element, never split or joined.
	c := testHX.Compose(Draft{Subject: "a b --send"}, nil)
	if !slices.Contains(c.Args, "--subject=a b --send") {
		t.Errorf("subject split: %q", c.Args)
	}
	if string(testHX.Compose(Draft{}, []byte("body")).Stdin) != "body" || testHX.Status("INBOX").Stdin != nil {
		t.Error("stdin not carried")
	}
}

func TestDeleteFromLabel(t *testing.T) {
	cfg := testState + "/tmp/label-abc/proton.toml"
	c := testHX.DeleteFromLabel(cfg, "Labels/Work", []uint32{3, 4})
	want := "-c " + cfg + " -a proton -b imap --log-level off --json message delete --mailbox=Labels/Work -- 3 4"
	if got := strings.Join(c.Args, " "); got != want {
		t.Errorf("got %s", got)
	}
}

func TestSearchQuery(t *testing.T) {
	day := func(s string) *time.Time {
		d, _ := time.Parse("2006-01-02", s)
		return &d
	}
	yes, no := true, false
	tests := []struct {
		name string
		in   Search
		want string
	}{
		{"subject", Search{Subject: "Grüße"}, `subject "Grüße" order by date desc`},
		{"quote injection stays literal", Search{Subject: `a" or from bjorn`}, `subject "a\" or from bjorn" order by date desc`},
		{"backslash", Search{From: `a\`}, `from "a\\" order by date desc`},
		{"order by inside a pattern", Search{Body: "x order by date"}, `body "x order by date" order by date desc`},
		{"shell text stays literal", Search{To: "$(id)"}, `to "$(id)" order by date desc`},
		{"since and before", Search{Since: day("2026-10-08"), Before: day("2026-10-09")}, `after 2026-10-07 and not after 2026-10-08 order by date desc`},
		{"since crosses a month", Search{Since: day("2026-03-01")}, `after 2026-02-28 order by date desc`},
		{"on", Search{On: day("2026-10-08")}, `date 2026-10-08 order by date desc`},
		{"unseen", Search{Unseen: &yes}, `not flag seen order by date desc`},
		{"seen", Search{Unseen: &no}, `flag seen order by date desc`},
		{"flagged", Search{Flagged: &yes}, `flag flagged order by date desc`},
		{"not flagged", Search{Flagged: &no}, `not flag flagged order by date desc`},
		{"all joined with and", Search{From: "a", To: "b", Subject: "c", Body: "d", Unseen: &yes},
			`from "a" and to "b" and subject "c" and body "d" and not flag seen order by date desc`},
	}
	for _, tt := range tests {
		got, err := tt.in.Query()
		if err != nil || got != tt.want {
			t.Errorf("%s: got %q, %v\nwant %q", tt.name, got, err, tt.want)
		}
	}
	if _, err := (Search{}).Query(); err == nil {
		t.Error("empty search accepted")
	}
}
