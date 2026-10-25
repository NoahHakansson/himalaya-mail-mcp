package mailmcp

import (
	"context"
	"slices"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// --- shared output types ---------------------------------------------------

// AddressOut is a sanitized mail address.
type AddressOut struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// Summary is one row of list_messages or search_messages.
type Summary struct {
	UID           uint32       `json:"uid"`
	MessageID     string       `json:"message_id"`
	Date          string       `json:"date"`
	From          []AddressOut `json:"from"`
	To            []AddressOut `json:"to"`
	Subject       string       `json:"subject"`
	Flags         []string     `json:"flags"`
	HasAttachment bool         `json:"has_attachment"`
	Size          int64        `json:"size"`
}

var summaryFlags = []string{"seen", "answered", "flagged", "draft", "deleted"}

func addressesOut(in []himalaya.Address) []AddressOut {
	out := make([]AddressOut, 0, len(in))
	for _, a := range in {
		out = append(out, AddressOut{Name: sanitizeLine(a.Name), Email: sanitizeLine(a.Email)})
	}
	return out
}

func summaries(envs []himalaya.Envelope) []Summary {
	out := make([]Summary, 0, len(envs))
	for _, e := range envs {
		flags := []string{}
		for _, f := range e.Flags {
			if slices.Contains(summaryFlags, f) && !slices.Contains(flags, f) {
				flags = append(flags, f)
			}
		}
		out = append(out, Summary{
			UID: e.UID, MessageID: sanitizeLine(e.MessageID), Date: sanitizeLine(e.Date),
			From: addressesOut(e.From), To: addressesOut(e.To), Subject: sanitizeLine(e.Subject),
			Flags: flags, HasAttachment: e.HasAttachment, Size: e.Size,
		})
	}
	return out
}

func mailError() error { return himalaya.Errorf(himalaya.CodeMailError, "") }

// --- list_accounts ----------------------------------------------------------

// NoInput is the input of tools without parameters.
type NoInput struct{}

// AccountInfo describes one configured account.
type AccountInfo struct {
	Name      string           `json:"name"`
	Email     string           `json:"email"`
	Mailboxes config.Mailboxes `json:"mailboxes"`
	Labels    LabelInfo        `json:"labels"`
}

// LabelInfo says whether the label tools work for an account and which prefix labels use.
type LabelInfo struct {
	Enabled bool   `json:"enabled"`
	Prefix  string `json:"prefix"`
}

// ListAccountsOut is the output of list_accounts.
type ListAccountsOut struct {
	Accounts []AccountInfo `json:"accounts"`
}

func (s *Server) listAccounts(_ context.Context, _ NoInput) (ListAccountsOut, error) {
	out := ListAccountsOut{Accounts: []AccountInfo{}}
	for _, n := range s.cfg.AccountNames() {
		a := s.cfg.Accounts[n]
		out.Accounts = append(out.Accounts, AccountInfo{
			Name: n, Email: a.Email, Mailboxes: a.Mailboxes,
			Labels: LabelInfo{Enabled: a.LabelPrefix != "", Prefix: a.LabelPrefix},
		})
	}
	return out, nil
}

// --- list_mailboxes ---------------------------------------------------------

// AccountIn is the input of tools that take only an account.
type AccountIn struct {
	Account Account `json:"account"`
}

// MailboxInfo is one mailbox with its role, kind and counts.
type MailboxInfo struct {
	Name    string `json:"name"`
	Role    string `json:"role,omitempty"`
	Kind    string `json:"kind"`
	Total   int64  `json:"total"`
	Unread  int64  `json:"unread"`
	Movable bool   `json:"movable"`
}

// ListMailboxesOut is the output of list_mailboxes. Mailboxes whose names
// are not addressable are left out and only counted.
type ListMailboxesOut struct {
	Account            string        `json:"account"`
	Mailboxes          []MailboxInfo `json:"mailboxes"`
	OmittedUnsafeNames int           `json:"omitted_unsafe_names"`
}

func (s *Server) listMailboxes(ctx context.Context, in AccountIn) (ListMailboxesOut, error) {
	a, err := s.account(in.Account)
	if err != nil {
		return ListMailboxesOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.MailboxList())
	if err != nil {
		return ListMailboxesOut{}, err
	}
	entries, err := himalaya.ParseMailboxList(raw)
	if err != nil {
		return ListMailboxesOut{}, mailError()
	}
	out := ListMailboxesOut{Account: a.cfg.Name, Mailboxes: []MailboxInfo{}}
	for _, e := range entries {
		if !addressable(e.ID) {
			out.OmittedUnsafeNames++
			continue
		}
		name := config.NormalizeMailbox(e.ID)
		out.Mailboxes = append(out.Mailboxes, MailboxInfo{
			Name: name, Role: roleOf(a.cfg, name), Kind: kindOf(a.cfg, name),
			Total: e.Total, Unread: e.Unread, Movable: movableTarget(a.cfg, name),
		})
	}
	return out, nil
}

// --- list_messages and search_messages --------------------------------------

// ListMessagesIn is the input of list_messages.
type ListMessagesIn struct {
	Account  Account  `json:"account"`
	Mailbox  Mailbox  `json:"mailbox"`
	Page     Page     `json:"page,omitempty"`
	PageSize PageSize `json:"page_size,omitempty"`
}

// ListMessagesOut is the output of list_messages.
type ListMessagesOut struct {
	Account     string    `json:"account"`
	Mailbox     string    `json:"mailbox"`
	UIDValidity uint32    `json:"uidvalidity"`
	Total       int64     `json:"total"`
	Unseen      int64     `json:"unseen"`
	Page        int       `json:"page"`
	PageSize    int       `json:"page_size"`
	Messages    []Summary `json:"messages"`
}

func paging(p Page, ps PageSize) (int, int, error) {
	page, err := bounded("page", p, 1, maxPage, defaultPage)
	if err != nil {
		return 0, 0, err
	}
	size, err := bounded("page_size", ps, 1, maxPageSize, defaultPageSize)
	return page, size, err
}

func (s *Server) listMessages(ctx context.Context, in ListMessagesIn) (ListMessagesOut, error) {
	a, err := s.account(in.Account)
	if err != nil {
		return ListMessagesOut{}, err
	}
	mb, err := checkMailbox("mailbox", in.Mailbox)
	if err != nil {
		return ListMessagesOut{}, err
	}
	page, size, err := paging(in.Page, in.PageSize)
	if err != nil {
		return ListMessagesOut{}, err
	}
	// Status first: if UIDVALIDITY changes in between, the references carry the old value and fail later checks.
	st, err := s.status(ctx, a, mb)
	if err != nil {
		return ListMessagesOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.EnvelopeList(mb, page, size))
	if err != nil {
		return ListMessagesOut{}, withMailbox(err, mb)
	}
	envs, err := himalaya.ParseEnvelopes(raw)
	if err != nil {
		return ListMessagesOut{}, mailError()
	}
	return ListMessagesOut{
		Account: a.cfg.Name, Mailbox: mb, UIDValidity: st.UIDValidity, Total: st.Messages, Unseen: st.Unseen,
		Page: page, PageSize: size, Messages: summaries(envs),
	}, nil
}

// SearchIn is the input of search_messages. At least one criterion is required.
type SearchIn struct {
	Account  Account    `json:"account"`
	Mailbox  Mailbox    `json:"mailbox"`
	From     SearchTerm `json:"from,omitempty"`
	To       SearchTerm `json:"to,omitempty"`
	Subject  SearchTerm `json:"subject,omitempty"`
	Body     SearchTerm `json:"body,omitempty"`
	Since    Date       `json:"since,omitempty" jsonschema:"on or after this date (Date header)"`
	Before   Date       `json:"before,omitempty" jsonschema:"strictly before this date (Date header)"`
	On       Date       `json:"on,omitempty" jsonschema:"on this date (Date header)"`
	Unseen   *bool      `json:"unseen,omitempty" jsonschema:"true for unread messages, false for read ones"`
	Flagged  *bool      `json:"flagged,omitempty" jsonschema:"true for starred messages, false for the rest"`
	Page     Page       `json:"page,omitempty"`
	PageSize PageSize   `json:"page_size,omitempty"`
}

// SearchOut is the output of search_messages.
type SearchOut struct {
	Account     string    `json:"account"`
	Mailbox     string    `json:"mailbox"`
	UIDValidity uint32    `json:"uidvalidity"`
	Page        int       `json:"page"`
	PageSize    int       `json:"page_size"`
	Messages    []Summary `json:"messages"`
}

func (in SearchIn) search() (q himalaya.Search, err error) {
	if q.From, err = checkTerm("from", in.From); err != nil {
		return q, err
	}
	if q.To, err = checkTerm("to", in.To); err != nil {
		return q, err
	}
	if q.Subject, err = checkTerm("subject", in.Subject); err != nil {
		return q, err
	}
	if q.Body, err = checkTerm("body", in.Body); err != nil {
		return q, err
	}
	if q.Since, err = checkDate("since", in.Since); err != nil {
		return q, err
	}
	if q.Before, err = checkDate("before", in.Before); err != nil {
		return q, err
	}
	if q.On, err = checkDate("on", in.On); err != nil {
		return q, err
	}
	q.Unseen, q.Flagged = in.Unseen, in.Flagged
	return q, nil
}

func (s *Server) searchMessages(ctx context.Context, in SearchIn) (SearchOut, error) {
	a, err := s.account(in.Account)
	if err != nil {
		return SearchOut{}, err
	}
	mb, err := checkMailbox("mailbox", in.Mailbox)
	if err != nil {
		return SearchOut{}, err
	}
	page, size, err := paging(in.Page, in.PageSize)
	if err != nil {
		return SearchOut{}, err
	}
	q, err := in.search()
	if err != nil {
		return SearchOut{}, err
	}
	query, err := q.Query()
	if err != nil {
		return SearchOut{}, invalid("search", "needs at least one criterion")
	}
	st, err := s.status(ctx, a, mb)
	if err != nil {
		return SearchOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.EnvelopeSearch(mb, page, size, query))
	if err != nil {
		return SearchOut{}, withMailbox(err, mb)
	}
	envs, err := himalaya.ParseEnvelopes(raw)
	if err != nil {
		return SearchOut{}, mailError()
	}
	return SearchOut{
		Account: a.cfg.Name, Mailbox: mb, UIDValidity: st.UIDValidity,
		Page: page, PageSize: size, Messages: summaries(envs),
	}, nil
}

// --- read_message -------------------------------------------------------------

// ReadIn is the input of read_message.
type ReadIn struct {
	Account     Account     `json:"account"`
	Mailbox     Mailbox     `json:"mailbox"`
	UIDValidity UIDValidity `json:"uidvalidity"`
	UID         UID         `json:"uid"`
	MaxBytes    MaxBytes    `json:"max_bytes,omitempty"`
}

// ReadOut is the output of read_message. Body is sanitized plain text; raw HTML is never returned.
type ReadOut struct {
	Account     string       `json:"account"`
	Mailbox     string       `json:"mailbox"`
	UIDValidity uint32       `json:"uidvalidity"`
	UID         uint32       `json:"uid"`
	MessageID   string       `json:"message_id"`
	Date        string       `json:"date"`
	From        []AddressOut `json:"from"`
	To          []AddressOut `json:"to"`
	Cc          []AddressOut `json:"cc"`
	ReplyTo     []AddressOut `json:"reply_to"`
	Subject     string       `json:"subject"`
	Body        string       `json:"body"`
	BodyFormat  string       `json:"body_format" jsonschema:"text, html_stripped or none"`
	Truncated   bool         `json:"truncated"`
}

// refIn validates the common reference fields.
func (s *Server) refIn(acct Account, mailbox Mailbox, v UIDValidity, u UID) (*account, string, uint32, uint32, error) {
	a, err := s.account(acct)
	if err != nil {
		return nil, "", 0, 0, err
	}
	mb, err := checkMailbox("mailbox", mailbox)
	if err != nil {
		return nil, "", 0, 0, err
	}
	uv, err := checkUIDValidity(v)
	if err != nil {
		return nil, "", 0, 0, err
	}
	uid, err := checkUID(u)
	if err != nil {
		return nil, "", 0, 0, err
	}
	return a, mb, uv, uid, nil
}

func (s *Server) readMessage(ctx context.Context, in ReadIn) (ReadOut, error) {
	a, mb, uv, uid, err := s.refIn(in.Account, in.Mailbox, in.UIDValidity, in.UID)
	if err != nil {
		return ReadOut{}, err
	}
	limit, err := bounded("max_bytes", in.MaxBytes, minReadBytes, maxReadBytes, defaultReadBytes)
	if err != nil {
		return ReadOut{}, err
	}
	if err := s.readRef(ctx, a, mb, uv, uid); err != nil {
		return ReadOut{}, err
	}
	raw, err := s.run.Run(ctx, a.hx.MessageRead(mb, uid))
	if err != nil {
		return ReadOut{}, withMailbox(err, mb)
	}
	m, err := himalaya.ParseMessage(raw)
	if err != nil {
		return ReadOut{}, mailError()
	}
	out := ReadOut{
		Account: a.cfg.Name, Mailbox: mb, UIDValidity: uv, UID: uid,
		MessageID: sanitizeLine(m.MessageID), Date: m.Date, Subject: sanitizeLine(m.Subject),
		From: addressesOut(m.From), To: addressesOut(m.To), Cc: addressesOut(m.Cc), ReplyTo: addressesOut(m.ReplyTo),
		BodyFormat: "none",
	}
	switch m.BodyKind {
	case himalaya.BodyText:
		out.Body, out.BodyFormat = sanitize(m.Body), "text"
	case himalaya.BodyHTML:
		out.Body, out.BodyFormat = sanitize(stripHTML(m.Body)), "html_stripped"
	}
	out.Body, out.Truncated = truncate(out.Body, limit)
	return out, nil
}
