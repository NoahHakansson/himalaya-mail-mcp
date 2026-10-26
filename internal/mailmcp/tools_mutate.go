package mailmcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// BatchIn is the input of tools that act on UIDs in one mailbox.
type BatchIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UIDs        UIDs        `json:"uids"`
}

func (s *Server) batchIn(acct Account, mailbox Mailbox, v UIDValidity, us UIDs) (*account, string, uint32, []uint32, error) {
	a, err := s.account(acct)
	if err != nil {
		return nil, "", 0, nil, err
	}
	mb, err := checkMailbox("mailbox", mailbox)
	if err != nil {
		return nil, "", 0, nil, err
	}
	uv, err := checkUIDValidity(v)
	if err != nil {
		return nil, "", 0, nil, err
	}
	uids, err := s.checkUIDs(a.cfg.Name, mb, uv, us)
	if err != nil {
		return nil, "", 0, nil, err
	}
	return a, mb, uv, uids, nil
}

// --- update_flags -------------------------------------------------------------

// FlagsIn is the input of update_flags. At least one of seen and flagged is required.
type FlagsIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UIDs        UIDs        `json:"uids"`
	Seen        *bool       `json:"seen,omitempty" jsonschema:"true marks read, false marks unread"`
	Flagged     *bool       `json:"flagged,omitempty" jsonschema:"true stars, false unstars"`
}

// FlagsOut is the output of update_flags.
type FlagsOut struct {
	Updated int `json:"updated"`
}

func (s *Server) updateFlags(ctx context.Context, in FlagsIn) (FlagsOut, error) {
	a, mb, uv, uids, err := s.batchIn(in.Account, in.Mailbox, in.UIDValidity, in.UIDs)
	if err != nil {
		return FlagsOut{}, err
	}
	if in.Seen == nil && in.Flagged == nil {
		return FlagsOut{}, invalid("seen or flagged", "is required")
	}
	var add, remove []himalaya.Flag
	for _, f := range []struct {
		v    *bool
		flag himalaya.Flag
	}{{in.Seen, himalaya.FlagSeen}, {in.Flagged, himalaya.FlagFlagged}} {
		switch {
		case f.v == nil:
		case *f.v:
			add = append(add, f.flag)
		default:
			remove = append(remove, f.flag)
		}
	}
	if err := s.mutateRef(ctx, a, mb, uv, uids); err != nil {
		return FlagsOut{}, err
	}
	var done []string
	for _, step := range []struct {
		add   bool
		flags []himalaya.Flag
	}{{true, add}, {false, remove}} {
		if len(step.flags) == 0 {
			continue
		}
		verb := map[bool]string{true: "added", false: "removed"}[step.add]
		if _, err := s.run.Run(ctx, a.hx.FlagChange(step.add, mb, step.flags, uids)); err != nil {
			return FlagsOut{}, withSteps(err, done)
		}
		done = append(done, fmt.Sprintf("%s %s", verb, flagList(step.flags)))
		// After each step, so a reset during the first stops the second.
		if err := s.postCheck(ctx, a, mb, uv, "flags "+strings.Join(done, " and ")); err != nil {
			return FlagsOut{}, err
		}
	}
	return FlagsOut{Updated: len(uids)}, nil
}

func flagList(fs []himalaya.Flag) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		parts[i] = string(f)
	}
	return strings.Join(parts, "+")
}

// withSteps reports the steps that completed before a later step failed.
func withSteps(err error, done []string) error {
	e, ok := err.(*himalaya.Error)
	if !ok || len(done) == 0 {
		return err
	}
	detail := "completed before the failure: " + strings.Join(done, ", ")
	if e.Detail != "" {
		detail = e.Detail + "; " + detail
	}
	return himalaya.Errorf(e.Code, detail)
}

// --- moves: move, archive, trash, restore ---------------------------------------

// MoveIn is the input of move_messages.
type MoveIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UIDs        UIDs        `json:"uids"`
	To          Mailbox     `json:"to"`
}

// RestoreIn is the input of restore_messages. The source is always the trash role.
type RestoreIn struct {
	Account     Account     `json:"account"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UIDs        UIDs        `json:"uids"`
	To          Mailbox     `json:"to,omitempty" jsonschema:"target mailbox; defaults to the inbox"`
}

// MoveOut is the output of the move tools.
type MoveOut struct {
	Moved int    `json:"moved"`
	From  string `json:"from"`
	To    string `json:"to"`
	Note  string `json:"note"`
}

const moveNote = "moved messages get new UIDs in the target mailbox; list it and match by message_id to find them"

func (s *Server) moveMessages(ctx context.Context, in MoveIn) (MoveOut, error) {
	a, mb, uv, uids, err := s.batchIn(in.Account, in.Mailbox, in.UIDValidity, in.UIDs)
	if err != nil {
		return MoveOut{}, err
	}
	to, err := checkMailbox("to", in.To)
	if err != nil {
		return MoveOut{}, err
	}
	return s.move(ctx, a, mb, to, uv, uids)
}

func (s *Server) archiveMessages(ctx context.Context, in BatchIn) (MoveOut, error) {
	a, mb, uv, uids, err := s.batchIn(in.Account, in.Mailbox, in.UIDValidity, in.UIDs)
	if err != nil {
		return MoveOut{}, err
	}
	return s.move(ctx, a, mb, a.cfg.Mailboxes.Archive, uv, uids)
}

func (s *Server) trashMessages(ctx context.Context, in BatchIn) (MoveOut, error) {
	a, mb, uv, uids, err := s.batchIn(in.Account, in.Mailbox, in.UIDValidity, in.UIDs)
	if err != nil {
		return MoveOut{}, err
	}
	if roleOf(a.cfg, mb) == "trash" {
		return MoveOut{}, forbidden("messages are already in trash")
	}
	return s.move(ctx, a, mb, a.cfg.Mailboxes.Trash, uv, uids)
}

func (s *Server) restoreMessages(ctx context.Context, in RestoreIn) (MoveOut, error) {
	a, err := s.account(in.Account)
	if err != nil {
		return MoveOut{}, err
	}
	to := a.cfg.Mailboxes.Inbox
	if in.To != "" {
		if to, err = checkMailbox("to", in.To); err != nil {
			return MoveOut{}, err
		}
	}
	uv, err := checkUIDValidity(in.UIDValidity)
	if err != nil {
		return MoveOut{}, err
	}
	uids, err := s.checkUIDs(a.cfg.Name, a.cfg.Mailboxes.Trash, uv, in.UIDs)
	if err != nil {
		return MoveOut{}, err
	}
	if roleOf(a.cfg, to) == "trash" {
		return MoveOut{}, forbidden("restore needs a target other than trash")
	}
	return s.move(ctx, a, a.cfg.Mailboxes.Trash, to, uv, uids)
}

// move runs policy, the capability gate, a status of the target, the source
// reference checks, one message move and the count and UIDVALIDITY checks.
// A MOVE into a missing mailbox fails as outcome_uncertain; the target
// status makes it a definite mailbox_not_found. It runs before the source
// checks so that the window between them and the move does not grow.
func (s *Server) move(ctx context.Context, a *account, from, to string, uv uint32, uids []uint32) (MoveOut, error) {
	if err := checkMove(a.cfg, from, to); err != nil {
		return MoveOut{}, err
	}
	if err := s.requireCapable(ctx, a); err != nil {
		return MoveOut{}, err
	}
	if _, err := s.status(ctx, a, to); err != nil {
		return MoveOut{}, err
	}
	if err := s.mutateRef(ctx, a, from, uv, uids); err != nil {
		return MoveOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.Move(from, to, uids))
	if err != nil {
		return MoveOut{}, withMailbox(uncertain(err, fmt.Sprintf("move from %q to %q", from, to)), from)
	}
	n, err := himalaya.ParseCount(raw, "moved")
	if err != nil {
		return MoveOut{}, himalaya.Errorf(himalaya.CodeOutcomeUncertain, "unrecognized move result")
	}
	if err := s.postCheck(ctx, a, from, uv, fmt.Sprintf("%d of %d messages moved to %q", n, len(uids), to)); err != nil {
		return MoveOut{}, err
	}
	if n != len(uids) {
		return MoveOut{}, himalaya.Errorf(himalaya.CodePartial, fmt.Sprintf("%d of %d messages moved from %q to %q", n, len(uids), from, to))
	}
	return MoveOut{Moved: n, From: from, To: to, Note: moveNote}, nil
}

// --- labels ---------------------------------------------------------------------

// AddLabelIn is the input of add_label.
type AddLabelIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UIDs        UIDs        `json:"uids"`
	Label       Label       `json:"label"`
}

// AddLabelOut is the output of add_label.
type AddLabelOut struct {
	Labeled int `json:"labeled"`
}

func (s *Server) addLabel(ctx context.Context, in AddLabelIn) (AddLabelOut, error) {
	a, mb, uv, uids, err := s.batchIn(in.Account, in.Mailbox, in.UIDValidity, in.UIDs)
	if err != nil {
		return AddLabelOut{}, err
	}
	label, err := checkMailbox("label", Mailbox(in.Label))
	if err != nil {
		return AddLabelOut{}, err
	}
	if err := checkLabel(a.cfg, label); err != nil {
		return AddLabelOut{}, err
	}
	if err := checkLabelSource(a.cfg, mb, label); err != nil {
		return AddLabelOut{}, err
	}
	if err := s.mutateRef(ctx, a, mb, uv, uids); err != nil {
		return AddLabelOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.Copy(mb, label, uids))
	if err != nil {
		return AddLabelOut{}, withMailbox(uncertain(err, fmt.Sprintf("copy from %q to %q", mb, label)), mb)
	}
	n, err := himalaya.ParseCount(raw, "copied")
	if err != nil {
		return AddLabelOut{}, himalaya.Errorf(himalaya.CodeOutcomeUncertain, "unrecognized copy result")
	}
	if err := s.postCheck(ctx, a, mb, uv, fmt.Sprintf("%d of %d messages labeled %q", n, len(uids), label)); err != nil {
		return AddLabelOut{}, err
	}
	if n != len(uids) {
		return AddLabelOut{}, himalaya.Errorf(himalaya.CodePartial, fmt.Sprintf("%d of %d messages labeled %q", n, len(uids), label))
	}
	return AddLabelOut{Labeled: n}, nil
}

// RemoveLabelIn is the input of remove_label. UIDs and uidvalidity belong to the label mailbox.
type RemoveLabelIn struct {
	Account     Account     `json:"account"`
	Label       Label       `json:"label"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UIDs        UIDs        `json:"uids"`
}

// RemoveLabelOut is the output of remove_label.
type RemoveLabelOut struct {
	Unlabeled int `json:"unlabeled"`
}

// removeLabel runs message delete inside the label mailbox with a per-call
// config that aliases trash to the label, so Himalaya sends UID STORE
// +\Deleted and UID EXPUNGE for just these UIDs (DESIGN section 2.2).
func (s *Server) removeLabel(ctx context.Context, in RemoveLabelIn) (RemoveLabelOut, error) {
	a, label, uv, uids, err := s.batchIn(in.Account, Mailbox(in.Label), in.UIDValidity, in.UIDs)
	if err != nil {
		return RemoveLabelOut{}, invalidLabel(err)
	}
	if err := checkLabel(a.cfg, label); err != nil {
		return RemoveLabelOut{}, err
	}
	if err := s.mutateRef(ctx, a, label, uv, uids); err != nil {
		return RemoveLabelOut{}, err
	}
	cfgPath, dir, err := himalaya.WriteLabelConfig(s.cfg.StateDir, a.cfg, label)
	if err != nil {
		return RemoveLabelOut{}, err
	}
	defer os.RemoveAll(dir)
	raw, err := s.run.Run(ctx, a.hx.DeleteFromLabel(cfgPath, label, uids))
	if err != nil {
		return RemoveLabelOut{}, withMailbox(uncertain(err, fmt.Sprintf("remove label %q", label)), label)
	}
	res, err := himalaya.ParseDelete(raw)
	if err != nil || res.Action != "deleted" || res.Count != len(uids) {
		return RemoveLabelOut{}, himalaya.Errorf(himalaya.CodeOutcomeUncertain, fmt.Sprintf("unexpected result removing label %q", label))
	}
	if err := s.postCheck(ctx, a, label, uv, fmt.Sprintf("label %q removed from %d messages", label, len(uids))); err != nil {
		return RemoveLabelOut{}, err
	}
	return RemoveLabelOut{Unlabeled: len(uids)}, nil
}

// invalidLabel renames the mailbox field in validation errors to label.
func invalidLabel(err error) error {
	if e, ok := err.(*himalaya.Error); ok && strings.HasPrefix(e.Detail, "mailbox ") {
		return himalaya.Errorf(e.Code, "label"+strings.TrimPrefix(e.Detail, "mailbox"))
	}
	return err
}
