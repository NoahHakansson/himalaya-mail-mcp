package himalaya

import (
	"strings"
	"testing"
)

func TestGuardAcceptsEveryBuilder(t *testing.T) {
	for _, tt := range builderCases() {
		if _, err := testGuard.Check(tt.cmd.Args); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
	c := testHX.DeleteFromLabel(testState+"/tmp/label-abc/proton.toml", "Labels/Work", []uint32{3})
	if _, err := testGuard.Check(c.Args); err != nil {
		t.Errorf("label delete: %v", err)
	}
}

func TestGuardRefuses(t *testing.T) {
	cfg := testState + "/himalaya/proton.toml"
	p := "-c " + cfg + " -a proton -b imap --log-level off "
	tests := []struct{ name, argv string }{
		{"message send", p + "--json message send"},
		{"compose --send", p + "message compose --to=a@x.test --send"},
		{"compose --save", p + "message compose --save=Drafts"},
		{"compose --no-save", p + "message compose --no-save"},
		{"compose --from", p + "message compose --from=m@evil.test"},
		{"compose --body", p + "message compose --body=x"},
		{"compose --body-file", p + "message compose --body-file=/etc/passwd"},
		{"compose --signature", p + "message compose --signature=x"},
		{"compose --json", p + "--json message compose"},
		{"add --send", p + "--json message add --mailbox=Drafts --send"},
		{"reply --send", p + "message reply --mailbox=INBOX --send -- 1"},
		{"read --seen", p + "--json message read --mailbox=INBOX --seen -- 1"},
		{"read --raw", p + "--json message read --mailbox=INBOX --raw -- 1"},
		{"log file", p + "--json --log-file=/tmp/x mailbox list"},
		{"short option", p + "--json message read -m INBOX -- 1"},
		{"subcommand prefix", p + "--json mess read --mailbox=INBOX -- 1"},
		{"flag set", p + "--json flag set --mailbox=INBOX --flag=seen -- 1"},
		{"flag deleted", p + "--json flag add --mailbox=INBOX --flag=deleted -- 1"},
		{"flag draft", p + "--json flag add --mailbox=INBOX --flag=draft -- 1"},
		{"add flagged", p + "--json message add --mailbox=Drafts --flag=flagged"},
		{"read two uids", p + "--json message read --mailbox=INBOX -- 1 2"},
		{"imap expunge", p + "--json imap expunge INBOX"},
		{"imap raw other", p + "--json imap raw -- A1 LOGOUT"},
		{"imap raw two lines", p + "--json imap raw -- A1 CAPABILITY extra"},
		{"imap fetch --body", p + "--json imap fetch --mailbox=INBOX --body -- 1"},
		{"smtp", p + "--json smtp send"},
		{"sieve", p + "--json sieve put"},
		{"configure", p + "configure"},
		{"account check", p + "--json account check"},
		{"delete with main config", p + "--json message delete --mailbox=Labels/Work -- 1"},
		{"move with label config", "-c " + testState + "/tmp/label-x/proton.toml -a proton -b imap --log-level off --json message move --from=INBOX --to=Trash -- 1"},
		{"unknown account", "-c " + testState + "/himalaya/bob.toml -a bob -b imap --log-level off --json mailbox list --counts"},
		{"wrong config path", "-c /etc/other.toml -a proton -b imap --log-level off --json mailbox list --counts"},
		{"merged config path", "-c " + cfg + ":/etc/x.toml -a proton -b imap --log-level off --json mailbox list --counts"},
		{"backend auto", "-c " + cfg + " -a proton -b auto --log-level off --json mailbox list --counts"},
		{"log level trace", "-c " + cfg + " -a proton -b imap --log-level trace --json mailbox list --counts"},
		{"missing --json", p + "mailbox list --counts"},
		{"positional before --", p + "--json message read --mailbox=INBOX 1"},
		{"positionals on list", p + "--json envelope list --mailbox=INBOX -- x"},
		{"uid star", p + "--json message read --mailbox=INBOX -- 4294967295"},
		{"uid range", p + "--json flag add --mailbox=INBOX --flag=seen -- 1:*"},
		{"uid zero", p + "--json message move --from=INBOX --to=Trash -- 0"},
		{"uid leading zero", p + "--json message move --from=INBOX --to=Trash -- 01"},
		{"fetch range", p + "--json imap fetch --mailbox=INBOX --flags --size -- 1:*"},
		{"attach outside tmp", p + "message compose --attach=/etc/passwd"},
		{"attach traversal", p + "message compose --attach=" + testState + "/tmp/att-1/../../himalaya/proton.toml"},
		{"download dir outside tmp", p + "--json attachment download --mailbox=INBOX --dir=/tmp -- 1 2"},
		{"flag option without value", p + "--json mailbox list --counts=yes"},
		{"valued option without value", p + "--json envelope list --mailbox"},
		{"two searches", p + "--json envelope search --mailbox=INBOX -- a b"},
	}
	for _, tt := range tests {
		if path, err := testGuard.Check(strings.Fields(tt.argv)); err == nil {
			t.Errorf("%s: accepted as %q", tt.name, path)
		}
	}
}
