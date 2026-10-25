package mailmcp

import (
	"slices"
	"testing"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

func bridgeAccount() *config.Account {
	return &config.Account{
		Name: "proton", Mailboxes: config.DefaultMailboxes, LabelPrefix: "Labels/",
		ProtectedMailboxes: slices.Clone(config.DefaultProtectedMailboxes),
	}
}

func TestCheckMove(t *testing.T) {
	a := bridgeAccount()
	tests := []struct {
		from, to string
		ok       bool
	}{
		{"INBOX", "Archive", true},
		{"INBOX", "Folders/Projects", true},
		{"INBOX", "Résumé/Ünïcødé 📬", true},
		{"Labels/Work", "Archive", true}, // removes the label on Bridge
		{"Trash", "INBOX", true},
		{"Drafts", "Trash", true},
		{"Sent", "Trash", true},
		{"INBOX", "INBOX", false},
		{"INBOX", "inbox", false},
		{"INBOX", "Labels/Work", false},
		{"INBOX", "labels/work", false},
		{"INBOX", "Drafts", false},
		{"INBOX", "sent", false},
		{"INBOX", "All Mail", false},
		{"INBOX", "starred", false},
		{"All Mail", "INBOX", false},
		{"Scheduled", "Trash", false},
		{"Drafts", "Archive", false},
		{"Sent", "INBOX", false},
	}
	for _, tt := range tests {
		err := checkMove(a, tt.from, tt.to)
		if (err == nil) != tt.ok || (err != nil && himalaya.CodeOf(err) != himalaya.CodeForbidden) {
			t.Errorf("%s -> %s: %v", tt.from, tt.to, err)
		}
	}
}

func TestCheckLabel(t *testing.T) {
	a := bridgeAccount()
	tests := map[string]bool{
		"Labels/Work":  true,
		"Labels/a/b":   true,
		"Labels/":      false,
		"labels/Work":  false,
		"Folders/Work": false,
		"Trash":        false,
		"Labels":       false,
		"Labels/Ünï 📬": true,
	}
	for label, ok := range tests {
		if err := checkLabel(a, label); (err == nil) != ok {
			t.Errorf("%q: %v", label, err)
		}
	}
	a.LabelPrefix = ""
	if err := checkLabel(a, "Labels/Work"); err == nil {
		t.Error("labels accepted while disabled")
	}
	b := bridgeAccount()
	b.ProtectedMailboxes = append(b.ProtectedMailboxes, "Labels/Secret")
	if checkLabel(b, "Labels/Secret") == nil {
		t.Error("protected label accepted")
	}
	if checkLabelSource(b, "All Mail", "Labels/Work") == nil || checkLabelSource(b, "Labels/Work", "Labels/Work") == nil ||
		checkLabelSource(b, "INBOX", "Labels/Work") != nil {
		t.Error("label source rules")
	}
}

func TestKinds(t *testing.T) {
	a := bridgeAccount()
	tests := []struct {
		name, kind, role string
		movable          bool
	}{
		{"INBOX", "system", "inbox", true},
		{"Drafts", "system", "drafts", false},
		{"Spam", "system", "junk", true},
		{"All Mail", "system", "", false},
		{"Labels/Work", "label", "", false},
		{"Folders/Projects", "folder", "", true},
	}
	for _, tt := range tests {
		if k, r, m := kindOf(a, tt.name), roleOf(a, tt.name), movableTarget(a, tt.name); k != tt.kind || r != tt.role || m != tt.movable {
			t.Errorf("%s: kind %s role %q movable %v", tt.name, k, r, m)
		}
	}
}
