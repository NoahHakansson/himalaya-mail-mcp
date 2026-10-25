package himalaya

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// MaxUID is the largest UID the wrapper passes. Himalaya reads 4294967295 as "*".
const MaxUID = 4294967294

// Command is one fully built Himalaya invocation: argv after the binary path,
// plus the bytes given on stdin (nil means /dev/null).
type Command struct {
	Account string
	Args    []string
	Stdin   []byte
}

// Account builds the argv for one configured account. Config is the path of
// the generated per-account TOML file.
type Account struct {
	Name   string
	Config string
}

// Flag is a writable message flag.
type Flag string

// Writable flags. \Answered and \Draft are local to Bridge, so only these two are exposed.
const (
	FlagSeen    Flag = "seen"
	FlagFlagged Flag = "flagged"
)

// Draft holds the header fields and staged attachment paths of a composed message.
type Draft struct {
	To, Cc, Bcc []string
	Subject     string
	Attach      []string
}

func (a Account) cmd(json bool, stdin []byte, args ...string) Command {
	return a.cmdWith(a.Config, json, stdin, args...)
}

func (a Account) cmdWith(config string, json bool, stdin []byte, args ...string) Command {
	argv := []string{"-c", config, "-a", a.Name, "-b", "imap", "--log-level", "off"}
	if json {
		argv = append(argv, "--json")
	}
	return Command{Account: a.Name, Args: append(argv, args...), Stdin: stdin}
}

func opt(name, value string) string { return "--" + name + "=" + value }

func uidArgs(uids []uint32) []string {
	out := make([]string, len(uids))
	for i, u := range uids {
		out[i] = strconv.FormatUint(uint64(u), 10)
	}
	return out
}

// AccountList lists the accounts in the generated config. It makes no connection.
func (a Account) AccountList() Command { return a.cmd(true, nil, "account", "list") }

// MailboxList lists mailboxes with message counts.
func (a Account) MailboxList() Command { return a.cmd(true, nil, "mailbox", "list", "--counts") }

// Status reads UIDVALIDITY, UIDNEXT and counts of one mailbox.
func (a Account) Status(mailbox string) Command {
	return a.cmd(true, nil, "imap", "status", "--", mailbox)
}

// Fetch reads only UID, FLAGS and RFC822.SIZE of the given UIDs. Missing UIDs are absent from the output.
func (a Account) Fetch(mailbox string, uids []uint32) Command {
	return a.cmd(true, nil, "imap", "fetch", opt("mailbox", mailbox), "--flags", "--size", "--",
		strings.Join(uidArgs(uids), ","))
}

// EnvelopeList lists one page of envelopes in arrival order, newest first.
func (a Account) EnvelopeList(mailbox string, page, pageSize int) Command {
	return a.cmd(true, nil, "envelope", "list", opt("mailbox", mailbox), opt("page", strconv.Itoa(page)),
		opt("page-size", strconv.Itoa(pageSize)), "--has-attachment")
}

// EnvelopeSearch lists one page of envelopes matching a query built by Search.Query.
func (a Account) EnvelopeSearch(mailbox string, page, pageSize int, query string) Command {
	return a.cmd(true, nil, "envelope", "search", opt("mailbox", mailbox), opt("page", strconv.Itoa(page)),
		opt("page-size", strconv.Itoa(pageSize)), "--has-attachment", "--", query)
}

// MessageRead fetches one message with BODY.PEEK[], leaving \Seen unchanged.
func (a Account) MessageRead(mailbox string, uid uint32) Command {
	return a.cmd(true, nil, "message", "read", opt("mailbox", mailbox), "--", uidArgs([]uint32{uid})[0])
}

// AttachmentList lists the non-inline attachments of one message.
func (a Account) AttachmentList(mailbox string, uid uint32) Command {
	return a.cmd(true, nil, "attachment", "list", opt("mailbox", mailbox), "--", uidArgs([]uint32{uid})[0])
}

// AttachmentDownload writes one attachment part into dir, a fresh directory under <state>/tmp.
func (a Account) AttachmentDownload(mailbox, dir string, uid uint32, part int) Command {
	return a.cmd(true, nil, "attachment", "download", opt("mailbox", mailbox), opt("dir", dir), "--",
		uidArgs([]uint32{uid})[0], strconv.Itoa(part))
}

// FlagChange adds or removes flags on the given UIDs.
func (a Account) FlagChange(add bool, mailbox string, flags []Flag, uids []uint32) Command {
	verb := "remove"
	if add {
		verb = "add"
	}
	args := []string{"flag", verb, opt("mailbox", mailbox)}
	for _, f := range flags {
		args = append(args, opt("flag", string(f)))
	}
	return a.cmd(true, nil, append(append(args, "--"), uidArgs(uids)...)...)
}

// Move moves UIDs between mailboxes (UID MOVE when the server has MOVE).
func (a Account) Move(from, to string, uids []uint32) Command {
	return a.cmd(true, nil, append([]string{"message", "move", opt("from", from), opt("to", to), "--"}, uidArgs(uids)...)...)
}

// Copy copies UIDs into another mailbox, which adds a label on Bridge.
func (a Account) Copy(from, to string, uids []uint32) Command {
	return a.cmd(true, nil, append([]string{"message", "copy", opt("from", from), opt("to", to), "--"}, uidArgs(uids)...)...)
}

func recipientArgs(d Draft) []string {
	var args []string
	for _, r := range d.To {
		args = append(args, opt("to", r))
	}
	for _, r := range d.Cc {
		args = append(args, opt("cc", r))
	}
	for _, r := range d.Bcc {
		args = append(args, opt("bcc", r))
	}
	return args
}

// Compose renders a new message as RFC 5322 on stdout. The body goes on stdin.
func (a Account) Compose(d Draft, body []byte) Command {
	args := append([]string{"message", "compose"}, recipientArgs(d)...)
	if d.Subject != "" {
		args = append(args, opt("subject", d.Subject))
	}
	for _, p := range d.Attach {
		args = append(args, opt("attach", p))
	}
	return a.cmd(false, body, args...)
}

// Reply renders a reply to uid as RFC 5322 on stdout. Only To, Cc and Attach of d are used.
func (a Account) Reply(mailbox string, uid uint32, d Draft, body []byte) Command {
	return a.replyLike("reply", mailbox, uid, d, body)
}

// Forward renders a forward of uid as RFC 5322 on stdout. Only To, Cc and Attach of d are used.
func (a Account) Forward(mailbox string, uid uint32, d Draft, body []byte) Command {
	return a.replyLike("forward", mailbox, uid, d, body)
}

func (a Account) replyLike(verb, mailbox string, uid uint32, d Draft, body []byte) Command {
	args := append([]string{"message", verb, opt("mailbox", mailbox)}, recipientArgs(Draft{To: d.To, Cc: d.Cc})...)
	for _, p := range d.Attach {
		args = append(args, opt("attach", p))
	}
	return a.cmd(false, body, append(args, "--", uidArgs([]uint32{uid})[0])...)
}

// AddDraft appends raw (from Compose, Reply or Forward) to the drafts mailbox with \Draft and \Seen.
func (a Account) AddDraft(drafts string, raw []byte) Command {
	return a.cmd(true, raw, "message", "add", opt("mailbox", drafts), opt("flag", "draft"), opt("flag", "seen"))
}

// DeleteFromLabel removes UIDs from a label mailbox with UID STORE +\Deleted
// and UID EXPUNGE of just those UIDs. labelConfig must be the per-call config
// that aliases trash to label (LabelTOML).
func (a Account) DeleteFromLabel(labelConfig, label string, uids []uint32) Command {
	return a.cmdWith(labelConfig, true, nil,
		append([]string{"message", "delete", opt("mailbox", label), "--"}, uidArgs(uids)...)...)
}

// Capability runs the fixed CAPABILITY probe after login.
func (a Account) Capability() Command {
	return a.cmd(true, nil, "imap", "raw", "--", CapabilityProbe)
}

// --- output parsers -------------------------------------------------------

func decode[T any](out []byte) (T, error) {
	var v T
	if err := json.Unmarshal(out, &v); err != nil {
		return v, fmt.Errorf("decode himalaya output: %w", err)
	}
	return v, nil
}

// AccountEntry is one row of account list.
type AccountEntry struct {
	Name     string   `json:"name"`
	Default  bool     `json:"default"`
	Backends []string `json:"backends"`
}

// ParseAccountList decodes account list output.
func ParseAccountList(out []byte) ([]AccountEntry, error) {
	v, err := decode[struct {
		Accounts []AccountEntry `json:"accounts"`
	}](out)
	return v.Accounts, err
}

// MailboxEntry is one row of mailbox list --counts.
type MailboxEntry struct {
	ID     string `json:"id"`
	Total  int64  `json:"total"`
	Unread int64  `json:"unread"`
}

// ParseMailboxList decodes mailbox list output.
func ParseMailboxList(out []byte) ([]MailboxEntry, error) {
	v, err := decode[struct {
		Mailboxes []MailboxEntry `json:"mailboxes"`
	}](out)
	return v.Mailboxes, err
}

// Status is the imap status of one mailbox.
type Status struct {
	Messages    int64  `json:"messages"`
	UIDNext     uint32 `json:"uid_next"`
	UIDValidity uint32 `json:"uid_validity"`
	Unseen      int64  `json:"unseen"`
}

// ParseStatus decodes imap status output and requires a non-zero UIDVALIDITY.
func ParseStatus(out []byte) (Status, error) {
	s, err := decode[Status](out)
	if err == nil && s.UIDValidity == 0 {
		err = errors.New("status without uid_validity")
	}
	return s, err
}

// FetchRow is one message of imap fetch --flags --size. Unsolicited FETCH
// responses appear as rows too, possibly for other UIDs and without a size.
type FetchRow struct {
	UID   uint32   `json:"uid"`
	Flags []string `json:"flags"`
	Size  *int64   `json:"size"` // nil when the row carries no RFC822.SIZE
}

// ParseFetch decodes imap fetch output.
func ParseFetch(out []byte) ([]FetchRow, error) {
	v, err := decode[struct {
		Messages []FetchRow `json:"messages"`
	}](out)
	return v.Messages, err
}

// Address is a decoded mailbox address. Name may be empty.
type Address struct {
	Name  string
	Email string
}

// Envelope is one row of envelope list or search.
type Envelope struct {
	UID           uint32
	MessageID     string
	Date          string
	From, To      []Address
	Subject       string
	Flags         []string // IANA names only: seen, answered, flagged, draft, deleted, ...
	HasAttachment bool
	Size          int64
}

type rawEnvelope struct {
	ID        string `json:"id"`
	MessageID string `json:"message-id"`
	Flags     []struct {
		IANA *string `json:"iana"`
	} `json:"flags"`
	Subject       string       `json:"subject"`
	From          []rawAddress `json:"from"`
	To            []rawAddress `json:"to"`
	Date          *string      `json:"date"`
	Size          int64        `json:"size"`
	HasAttachment *bool        `json:"has-attachment"`
}

type rawAddress struct {
	Name  *string `json:"name"`
	Email string  `json:"email"`
}

// ParseEnvelopes decodes envelope list and envelope search output.
func ParseEnvelopes(out []byte) ([]Envelope, error) {
	v, err := decode[struct {
		Envelopes []rawEnvelope `json:"envelopes"`
	}](out)
	if err != nil {
		return nil, err
	}
	envs := make([]Envelope, 0, len(v.Envelopes))
	for _, r := range v.Envelopes {
		uid, err := strconv.ParseUint(r.ID, 10, 32)
		if err != nil || uid == 0 {
			return nil, fmt.Errorf("envelope id %q is not a UID", r.ID)
		}
		e := Envelope{
			UID: uint32(uid), MessageID: r.MessageID, Subject: r.Subject, Size: r.Size,
			From: addresses(r.From), To: addresses(r.To),
			HasAttachment: r.HasAttachment != nil && *r.HasAttachment,
		}
		if r.Date != nil {
			e.Date = *r.Date
		}
		for _, f := range r.Flags {
			if f.IANA != nil {
				e.Flags = append(e.Flags, *f.IANA)
			}
		}
		envs = append(envs, e)
	}
	return envs, nil
}

// addresses converts envelope addresses. IMAP group markers, which arrive
// as entries whose email is empty or lacks '@', are dropped, flattening groups.
func addresses(raw []rawAddress) []Address {
	out := make([]Address, 0, len(raw))
	for _, r := range raw {
		if !strings.Contains(r.Email, "@") {
			continue
		}
		a := Address{Email: r.Email}
		if r.Name != nil {
			a.Name = *r.Name
		}
		out = append(out, a)
	}
	return out
}

// Attachment is one row of attachment list or download.
type Attachment struct {
	PartID   int
	Filename string // empty when the part has no name
	MIME     string
	Size     int64
	Inline   bool
}

// ParseAttachments decodes attachment list and attachment download output.
func ParseAttachments(out []byte) ([]Attachment, error) {
	v, err := decode[struct {
		Attachments []struct {
			ID       string  `json:"id"`
			Filename *string `json:"filename"`
			MIME     string  `json:"mime"`
			Size     int64   `json:"size"`
			Inline   bool    `json:"inline"`
		} `json:"attachments"`
	}](out)
	if err != nil {
		return nil, err
	}
	atts := make([]Attachment, 0, len(v.Attachments))
	for _, r := range v.Attachments {
		id, err := strconv.Atoi(r.ID)
		if err != nil || id < 1 {
			return nil, fmt.Errorf("attachment id %q is not a part id", r.ID)
		}
		a := Attachment{PartID: id, MIME: r.MIME, Size: r.Size, Inline: r.Inline}
		if r.Filename != nil {
			a.Filename = *r.Filename
		}
		atts = append(atts, a)
	}
	return atts, nil
}

var countRe = regexp.MustCompile(`^(\d+) messages? successfully (moved|copied)$`)

// ParseCount reads the count from move ("moved") or copy ("copied") output.
// "No message moved: ..." is a count of zero.
func ParseCount(out []byte, verb string) (int, error) {
	v, err := decode[struct {
		Message string `json:"message"`
	}](out)
	if err != nil {
		return 0, err
	}
	if strings.HasPrefix(v.Message, "No message ") {
		return 0, nil
	}
	m := countRe.FindStringSubmatch(v.Message)
	if m == nil || m[2] != verb {
		return 0, errors.New("unexpected move or copy result")
	}
	return strconv.Atoi(m[1])
}

// ParseAdd reads the UID that message add returns.
func ParseAdd(out []byte) (uint32, error) {
	v, err := decode[struct {
		ID   string `json:"id"`
		Sent bool   `json:"sent"`
	}](out)
	if err != nil {
		return 0, err
	}
	uid, err := strconv.ParseUint(v.ID, 10, 32)
	if err != nil || uid == 0 || v.Sent {
		return 0, errors.New("unexpected message add result")
	}
	return uint32(uid), nil
}

// DeleteResult is the output of message delete.
type DeleteResult struct {
	Action string `json:"action"`
	Count  int    `json:"count"`
}

// ParseDelete decodes message delete output.
func ParseDelete(out []byte) (DeleteResult, error) { return decode[DeleteResult](out) }

// ParseCapability returns the capabilities from the CAPABILITY probe, uppercased.
func ParseCapability(out []byte) ([]string, error) {
	v, err := decode[struct {
		Message string `json:"message"`
	}](out)
	if err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(v.Message, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "* CAPABILITY "); ok {
			return strings.Fields(strings.ToUpper(rest)), nil
		}
	}
	return nil, errors.New("no CAPABILITY line")
}
