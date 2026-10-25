package mailmcp

import (
	"bytes"
	"context"
	"fmt"
	"net/mail"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// Drafts are composed by Himalaya (compose, reply or forward print RFC 5322
// on stdout) and appended with message add to the drafts role only, which
// returns a UID and sets \Draft. Nothing is ever sent.

// DraftOut is the reference of a newly saved draft.
type DraftOut struct {
	Account     string `json:"account"`
	Mailbox     string `json:"mailbox"`
	UIDValidity uint32 `json:"uidvalidity"`
	UID         uint32 `json:"uid"`
	MessageID   string `json:"message_id"`
}

// DraftIn is the input of create_draft.
type DraftIn struct {
	Account     Account   `json:"account"`
	To          Addresses `json:"to,omitempty"`
	Cc          Addresses `json:"cc,omitempty"`
	Bcc         Addresses `json:"bcc,omitempty"`
	Subject     Subject   `json:"subject,omitempty"`
	Body        Body      `json:"body,omitempty"`
	Attachments FileNames `json:"attachments,omitempty"`
}

// UpdateDraftIn is the input of update_draft: the draft to replace, then the new content.
type UpdateDraftIn struct {
	Account     Account     `json:"account"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UID         UID         `json:"uid"`
	To          Addresses   `json:"to,omitempty"`
	Cc          Addresses   `json:"cc,omitempty"`
	Bcc         Addresses   `json:"bcc,omitempty"`
	Subject     Subject     `json:"subject,omitempty"`
	Body        Body        `json:"body,omitempty"`
	Attachments FileNames   `json:"attachments,omitempty"`
}

// UpdateDraftOut is the new draft's reference plus what happened to the previous version.
type UpdateDraftOut struct {
	Account         string `json:"account"`
	Mailbox         string `json:"mailbox"`
	UIDValidity     uint32 `json:"uidvalidity"`
	UID             uint32 `json:"uid"`
	MessageID       string `json:"message_id"`
	PreviousTrashed string `json:"previous_trashed" jsonschema:"yes, no or uncertain"`
	Error           string `json:"error,omitempty" jsonschema:"why the previous draft was not confirmed in trash"`
}

// ReplyIn is the input of reply_draft.
type ReplyIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UID         UID         `json:"uid"`
	Body        Body        `json:"body"`
	To          Addresses   `json:"to,omitempty"`
	Cc          Addresses   `json:"cc,omitempty"`
	Attachments FileNames   `json:"attachments,omitempty"`
}

// ForwardIn is the input of forward_draft. It matches ReplyIn except that the body is optional.
type ForwardIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UID         UID         `json:"uid"`
	Body        Body        `json:"body,omitempty"`
	To          Addresses   `json:"to,omitempty"`
	Cc          Addresses   `json:"cc,omitempty"`
	Attachments FileNames   `json:"attachments,omitempty"`
}

// content is validated draft input.
type content struct {
	draft himalaya.Draft
	body  []byte
	files []string
}

func checkContent(to, cc, bcc Addresses, subject Subject, body Body, files FileNames) (c content, err error) {
	if c.draft.To, err = checkAddresses("to", to); err != nil {
		return c, err
	}
	if c.draft.Cc, err = checkAddresses("cc", cc); err != nil {
		return c, err
	}
	if c.draft.Bcc, err = checkAddresses("bcc", bcc); err != nil {
		return c, err
	}
	if c.draft.Subject, err = checkSubject(subject); err != nil {
		return c, err
	}
	if c.body, err = checkBody(body); err != nil {
		return c, err
	}
	c.files, err = checkFileNames(files)
	return c, err
}

// compose stages attachments, runs the given compose-like command and
// returns the RFC 5322 output with its Message-ID.
func (s *Server) compose(ctx context.Context, a *account, c content, build func(himalaya.Draft) himalaya.Command) ([]byte, string, error) {
	dir, paths, err := stageAttachments(a.files, s.secrets, s.tmpDir(), c.files, s.cfg.Limits.MaxAttachmentBytes)
	if err != nil {
		return nil, "", err
	}
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	d := c.draft
	d.Attach = paths
	raw, err := s.run.Run(ctx, build(d))
	if err != nil {
		return nil, "", err
	}
	// message add silently stops at the first line that is not UTF-8.
	if !utf8.Valid(raw) {
		return nil, "", mailError()
	}
	return raw, messageID(raw), nil
}

// messageID reads the Message-ID header that compose generated, without angle brackets.
func messageID(raw []byte) string {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	id := strings.TrimSpace(m.Header.Get("Message-Id"))
	return sanitizeLine(strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">"))
}

// saveDraft appends raw to the drafts mailbox. uv is the UIDVALIDITY read
// before the append, so a reset in between makes the reference stale rather than wrong.
func (s *Server) saveDraft(ctx context.Context, a *account, uv uint32, raw []byte, msgID string) (DraftOut, error) {
	drafts := a.cfg.Mailboxes.Drafts
	check := fmt.Sprintf("look for message_id %q in %q before retrying", msgID, drafts)
	out, err := s.run.Run(ctx, a.hx.AddDraft(drafts, raw))
	if err != nil {
		return DraftOut{}, uncertain(err, check)
	}
	uid, err := himalaya.ParseAdd(out)
	if err != nil {
		return DraftOut{}, himalaya.Errorf(himalaya.CodeOutcomeUncertain, check)
	}
	return DraftOut{Account: a.cfg.Name, Mailbox: drafts, UIDValidity: uv, UID: uid, MessageID: msgID}, nil
}

func (s *Server) createDraft(ctx context.Context, in DraftIn) (DraftOut, error) {
	a, err := s.account(in.Account)
	if err != nil {
		return DraftOut{}, err
	}
	c, err := checkContent(in.To, in.Cc, in.Bcc, in.Subject, in.Body, in.Attachments)
	if err != nil {
		return DraftOut{}, err
	}
	if err := s.requireCapable(ctx, a); err != nil {
		return DraftOut{}, err
	}
	st, err := s.status(ctx, a, a.cfg.Mailboxes.Drafts)
	if err != nil {
		return DraftOut{}, err
	}
	raw, id, err := s.compose(ctx, a, c, func(d himalaya.Draft) himalaya.Command { return a.hx.Compose(d, c.body) })
	if err != nil {
		return DraftOut{}, err
	}
	return s.saveDraft(ctx, a, st.UIDValidity, raw, id)
}

// updateDraft adds the new version, then moves the old one to trash, where
// it stays recoverable. There is no in-place edit over IMAP.
func (s *Server) updateDraft(ctx context.Context, in UpdateDraftIn) (UpdateDraftOut, error) {
	a, err := s.account(in.Account)
	if err != nil {
		return UpdateDraftOut{}, err
	}
	uv, err := checkUIDValidity(in.UIDValidity)
	if err != nil {
		return UpdateDraftOut{}, err
	}
	old, err := checkUID(in.UID)
	if err != nil {
		return UpdateDraftOut{}, err
	}
	c, err := checkContent(in.To, in.Cc, in.Bcc, in.Subject, in.Body, in.Attachments)
	if err != nil {
		return UpdateDraftOut{}, err
	}
	drafts, trash := a.cfg.Mailboxes.Drafts, a.cfg.Mailboxes.Trash
	if err := checkMove(a.cfg, drafts, trash); err != nil {
		return UpdateDraftOut{}, err
	}
	if err := s.mutateRef(ctx, a, drafts, uv, []uint32{old}); err != nil {
		return UpdateDraftOut{}, err
	}
	raw, id, err := s.compose(ctx, a, c, func(d himalaya.Draft) himalaya.Command { return a.hx.Compose(d, c.body) })
	if err != nil {
		return UpdateDraftOut{}, err
	}
	d, err := s.saveDraft(ctx, a, uv, raw, id)
	if err != nil {
		return UpdateDraftOut{}, withSteps(err, []string{"the previous draft was left in place"})
	}
	out := UpdateDraftOut{
		Account: d.Account, Mailbox: d.Mailbox, UIDValidity: d.UIDValidity, UID: d.UID, MessageID: d.MessageID,
		PreviousTrashed: "yes",
	}
	if err := s.trashOld(ctx, a, uv, old); err != nil {
		out.PreviousTrashed = "no"
		if himalaya.CodeOf(err) == himalaya.CodeOutcomeUncertain {
			out.PreviousTrashed = "uncertain"
		}
		out.Error = err.Error()
	}
	return out, nil
}

// trashOld moves the previous draft to trash and confirms UIDVALIDITY afterwards.
func (s *Server) trashOld(ctx context.Context, a *account, uv, uid uint32) error {
	drafts, trash := a.cfg.Mailboxes.Drafts, a.cfg.Mailboxes.Trash
	raw, err := s.run.Run(ctx, a.hx.Move(drafts, trash, []uint32{uid}))
	if err != nil {
		return uncertain(err, fmt.Sprintf("move of draft %d to %q", uid, trash))
	}
	n, err := himalaya.ParseCount(raw, "moved")
	if err != nil {
		return himalaya.Errorf(himalaya.CodeOutcomeUncertain, "unrecognized move result")
	}
	if n != 1 {
		return himalaya.Errorf(himalaya.CodeNotFound, fmt.Sprintf("draft %d was no longer in %q", uid, drafts))
	}
	return s.postCheck(ctx, a, drafts, uv, fmt.Sprintf("draft %d moved to %q", uid, trash))
}

func (s *Server) replyDraft(ctx context.Context, in ReplyIn) (DraftOut, error) {
	return s.replyLike(ctx, in, func(a *account, mb string, uid uint32, d himalaya.Draft, body []byte) himalaya.Command {
		return a.hx.Reply(mb, uid, d, body)
	})
}

func (s *Server) forwardDraft(ctx context.Context, in ForwardIn) (DraftOut, error) {
	return s.replyLike(ctx, ReplyIn(in), func(a *account, mb string, uid uint32, d himalaya.Draft, body []byte) himalaya.Command {
		return a.hx.Forward(mb, uid, d, body)
	})
}

// replyLike is reply_draft and forward_draft: check the source reference
// and size, read the drafts UIDVALIDITY, render with Himalaya, check the
// source reference again, then add. The second check catches a UIDVALIDITY
// reset before Himalaya's own SELECT, which would render another message.
func (s *Server) replyLike(ctx context.Context, in ReplyIn, build func(*account, string, uint32, himalaya.Draft, []byte) himalaya.Command) (DraftOut, error) {
	a, mb, uv, uid, err := s.refIn(in.Account, in.Mailbox, in.UIDValidity, in.UID)
	if err != nil {
		return DraftOut{}, err
	}
	c, err := checkContent(in.To, in.Cc, nil, "", in.Body, in.Attachments)
	if err != nil {
		return DraftOut{}, err
	}
	if err := s.requireCapable(ctx, a); err != nil {
		return DraftOut{}, err
	}
	if err := s.readRef(ctx, a, mb, uv, uid); err != nil {
		return DraftOut{}, err
	}
	st, err := s.status(ctx, a, a.cfg.Mailboxes.Drafts)
	if err != nil {
		return DraftOut{}, err
	}
	raw, id, err := s.compose(ctx, a, c, func(d himalaya.Draft) himalaya.Command { return build(a, mb, uid, d, c.body) })
	if err != nil {
		return DraftOut{}, withMailbox(err, mb)
	}
	if _, err := s.checkRef(ctx, a, mb, uv, []uint32{uid}); err != nil {
		return DraftOut{}, err
	}
	return s.saveDraft(ctx, a, st.UIDValidity, raw, id)
}
