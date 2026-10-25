package mailmcp

import (
	"fmt"
	"strings"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// Policy (DESIGN section 2.1), enforced before any subprocess runs. Roles
// come from the wrapper config; protected names and roles compare case-insensitively.

func forbidden(format string, a ...any) error {
	return himalaya.Errorf(himalaya.CodeForbidden, fmt.Sprintf(format, a...))
}

// roleOf returns the role name of mailbox mb, or "".
func roleOf(a *config.Account, mb string) string {
	for _, r := range a.Mailboxes.Roles() {
		if strings.EqualFold(r.Name, mb) {
			return r.Role
		}
	}
	return ""
}

// underLabelPrefix reports whether mb lies under the account's label prefix, ignoring case.
func underLabelPrefix(a *config.Account, mb string) bool {
	p := a.LabelPrefix
	return p != "" && len(mb) >= len(p) && strings.EqualFold(mb[:len(p)], p)
}

// kindOf classifies a mailbox for list_mailboxes.
func kindOf(a *config.Account, mb string) string {
	switch {
	case roleOf(a, mb) != "" || a.IsProtected(mb):
		return "system"
	case underLabelPrefix(a, mb):
		return "label"
	}
	return "folder"
}

// movableTarget reports whether mb may be the target of a move from some source.
func movableTarget(a *config.Account, mb string) bool {
	role := roleOf(a, mb)
	return !a.IsProtected(mb) && role != "drafts" && role != "sent" && !underLabelPrefix(a, mb)
}

// checkMove applies the move rules: no protected source or target, no
// drafts, sent or label target, from != to, and drafts or sent sources may
// only go to trash. On Bridge a move into a label would only copy.
func checkMove(a *config.Account, from, to string) error {
	switch {
	case strings.EqualFold(from, to):
		return forbidden("source and target are the same mailbox")
	case a.IsProtected(from):
		return forbidden("mailbox %q is protected", from)
	case !movableTarget(a, to):
		return forbidden("mailbox %q is not a move target", to)
	}
	if r := roleOf(a, from); (r == "drafts" || r == "sent") && roleOf(a, to) != "trash" {
		return forbidden("messages in %q can only go to trash", from)
	}
	return nil
}

// checkLabel requires labels to be enabled and label to be a proper label
// mailbox: the exact prefix followed by at least one more character.
func checkLabel(a *config.Account, label string) error {
	p := a.LabelPrefix
	switch {
	case p == "":
		return forbidden("labels are disabled for this account")
	case !strings.HasPrefix(label, p) || len(label) == len(p):
		return forbidden("label must start with %q", p)
	case a.IsProtected(label):
		return forbidden("mailbox %q is protected", label)
	}
	return nil
}

// checkLabelSource rejects protected sources and copying a label onto itself.
func checkLabelSource(a *config.Account, from, label string) error {
	switch {
	case a.IsProtected(from):
		return forbidden("mailbox %q is protected", from)
	case strings.EqualFold(from, label):
		return forbidden("source and label are the same mailbox")
	}
	return nil
}
