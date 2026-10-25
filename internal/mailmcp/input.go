package mailmcp

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// Named input types. Their JSON Schema constraints come from schemaOptions,
// so every tool gets them; handlers re-validate every value because the
// schema is documentation, not the boundary.
type (
	Account     string
	Mailbox     string
	Label       string
	UIDValidity int64
	UID         int64
	UIDs        []UID
	Address     string
	Addresses   []Address
	FileName    string
	FileNames   []FileName
	Date        string
	Subject     string
	Body        string
	SearchTerm  string
	Page        int
	PageSize    int
	MaxBytes    int
	PartID      int
)

// Input limits (DESIGN section 2).
const (
	maxUIDs        = 50
	maxRecipients  = 50
	maxAttachments = 10
	maxFileName    = 200
	maxSubject     = 255
	maxSubjectB    = 998
	maxBody        = 256 << 10
	maxTerm        = 200
	maxPage        = 10000
	maxPageSize    = 50
	minReadBytes   = 1024
	maxReadBytes   = 256 << 10
	maxPartID      = 100000

	defaultPage      = 1
	defaultPageSize  = 20
	defaultReadBytes = 32 << 10
)

const (
	noControl     = `^[^\x00-\x1f\x7f-\x9f]*$`
	mailboxSchema = `^[^\-\x00-\x1f\x7f-\x9f][^\x00-\x1f\x7f-\x9f]*$`
)

func ptr[T any](v T) *T { return &v }

func schemaOptions(accounts []string) *jsonschema.ForOptions {
	names := make([]any, len(accounts))
	for i, a := range accounts {
		names[i] = a
	}
	str := func(desc string, minLen, maxLen int, pattern string) *jsonschema.Schema {
		return &jsonschema.Schema{Type: "string", Description: desc, MinLength: ptr(minLen), MaxLength: ptr(maxLen), Pattern: pattern}
	}
	integer := func(desc string, lo, hi, def int) *jsonschema.Schema {
		s := &jsonschema.Schema{Type: "integer", Description: desc, Minimum: ptr(float64(lo)), Maximum: ptr(float64(hi))}
		if def != 0 {
			s.Default = json.RawMessage(fmt.Sprint(def))
		}
		return s
	}
	uid := integer("message UID within the mailbox's UIDVALIDITY epoch", 1, himalaya.MaxUID, 0)
	addr := str("bare address such as user@example.com, no display name", 3, 254, `^[^\-\s"(),:;<>\[\\\]][^\s"(),:;<>\[\\\]]*$`)
	file := str("file name in the account's files directory, as returned by download_attachment", 1, maxFileName, `^[^.\-/\\\x00-\x1f\x7f][^/\\\x00-\x1f\x7f]*$`)
	return &jsonschema.ForOptions{TypeSchemas: map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[Account]():     {Type: "string", Description: "configured account name", Enum: names},
		reflect.TypeFor[Mailbox]():     str("mailbox name as listed by list_mailboxes; any case of inbox means INBOX", 1, 255, mailboxSchema),
		reflect.TypeFor[Label]():       str("label mailbox name, starting with the account's label prefix", 1, 255, mailboxSchema),
		reflect.TypeFor[UIDValidity](): integer("UIDVALIDITY returned with the reference", 1, 4294967295, 0),
		reflect.TypeFor[UID]():         uid,
		reflect.TypeFor[UIDs]():        {Type: "array", Items: uid, MinItems: ptr(1), MaxItems: ptr(maxUIDs), UniqueItems: true},
		reflect.TypeFor[Address]():     addr,
		reflect.TypeFor[Addresses]():   {Type: "array", Items: addr, MaxItems: ptr(maxRecipients)},
		reflect.TypeFor[FileName]():    file,
		reflect.TypeFor[FileNames]():   {Type: "array", Items: file, MaxItems: ptr(maxAttachments), UniqueItems: true},
		reflect.TypeFor[Date]():        {Type: "string", Description: "date as YYYY-MM-DD, matched against the Date header", Pattern: `^[0-9]{4}-[0-9]{2}-[0-9]{2}$`},
		reflect.TypeFor[Subject]():     str("subject line", 0, maxSubject, noControl),
		reflect.TypeFor[Body]():        str("plain text body", 0, maxBody, ""),
		reflect.TypeFor[SearchTerm]():  str("case-insensitive substring", 1, maxTerm, noControl),
		reflect.TypeFor[Page]():        integer("page number, 1 is the newest arrivals", 1, maxPage, defaultPage),
		reflect.TypeFor[PageSize]():    integer("messages per page", 1, maxPageSize, defaultPageSize),
		reflect.TypeFor[MaxBytes]():    integer("maximum body bytes returned", minReadBytes, maxReadBytes, defaultReadBytes),
		reflect.TypeFor[PartID]():      integer("attachment part_id from list_attachments", 1, maxPartID, 0),
	}}
}

func invalid(field, why string) error {
	return himalaya.Errorf(himalaya.CodeInvalidArgument, field+" "+why)
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}

func checkMailbox(field string, m Mailbox) (string, error) {
	if !addressable(string(m)) {
		return "", invalid(field, "is not a valid mailbox name")
	}
	return config.NormalizeMailbox(string(m)), nil
}

// addressable is the one rule for mailbox names in both directions: a name
// passes the mailbox rule and the sanitizer leaves it unchanged. Inputs must
// be addressable, and list_mailboxes omits server names that are not, since
// showing a cleaned name would make distinct mailboxes look alike.
func addressable(name string) bool {
	return config.CheckMailboxName(name) == nil && sanitizeLine(name) == name
}

func checkUIDValidity(v UIDValidity) (uint32, error) {
	if v < 1 || v > 4294967295 {
		return 0, invalid("uidvalidity", "must be 1..4294967295")
	}
	return uint32(v), nil
}

func checkUID(u UID) (uint32, error) {
	if u < 1 || u > himalaya.MaxUID {
		return 0, invalid("uid", fmt.Sprintf("must be 1..%d", himalaya.MaxUID))
	}
	return uint32(u), nil
}

func checkUIDs(us UIDs) ([]uint32, error) {
	if len(us) < 1 || len(us) > maxUIDs {
		return nil, invalid("uids", fmt.Sprintf("must hold 1..%d UIDs", maxUIDs))
	}
	out := make([]uint32, 0, len(us))
	seen := map[UID]bool{}
	for _, u := range us {
		v, err := checkUID(u)
		if err != nil {
			return nil, err
		}
		if seen[u] {
			return nil, invalid("uids", "must be unique")
		}
		seen[u] = true
		out = append(out, v)
	}
	return out, nil
}

func checkAddresses(field string, as Addresses) ([]string, error) {
	if len(as) > maxRecipients {
		return nil, invalid(field, fmt.Sprintf("must hold at most %d addresses", maxRecipients))
	}
	out := make([]string, 0, len(as))
	for _, a := range as {
		if !config.IsBareAddress(string(a)) {
			return nil, invalid(field, "must hold bare addresses such as user@example.com")
		}
		out = append(out, string(a))
	}
	return out, nil
}

func checkFileNames(fs FileNames) ([]string, error) {
	if len(fs) > maxAttachments {
		return nil, invalid("attachments", fmt.Sprintf("must hold at most %d files", maxAttachments))
	}
	out := make([]string, 0, len(fs))
	seen := map[FileName]bool{}
	for _, f := range fs {
		s := string(f)
		if s == "" || len(s) > maxFileName || !utf8.ValidString(s) || strings.ContainsAny(s, "/\\") ||
			s[0] == '.' || s[0] == '-' || hasControl(s) {
			return nil, invalid("attachments", "must hold plain file names from the files directory")
		}
		if seen[f] {
			return nil, invalid("attachments", "must be unique")
		}
		seen[f] = true
		out = append(out, s)
	}
	return out, nil
}

func checkDate(field string, d Date) (*time.Time, error) {
	if d == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", string(d))
	if err != nil {
		return nil, invalid(field, "must be a date as YYYY-MM-DD")
	}
	return &t, nil
}

func checkSubject(s Subject) (string, error) {
	if !utf8.ValidString(string(s)) || utf8.RuneCountInString(string(s)) > maxSubject || len(s) > maxSubjectB || hasControl(string(s)) {
		return "", invalid("subject", fmt.Sprintf("must be at most %d characters without control characters", maxSubject))
	}
	return string(s), nil
}

// checkBody allows tab, LF and CR among the C0 characters and returns nil for an empty body.
func checkBody(b Body) ([]byte, error) {
	s := string(b)
	if len(s) > maxBody || !utf8.ValidString(s) ||
		strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 && r != '\t' && r != '\n' && r != '\r' }) {
		return nil, invalid("body", "must be at most 256 KiB of text without NUL or control characters")
	}
	if s == "" {
		return nil, nil
	}
	return []byte(s), nil
}

func checkTerm(field string, t SearchTerm) (string, error) {
	s := string(t)
	if s == "" {
		return "", nil
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxTerm || hasControl(s) {
		return "", invalid(field, fmt.Sprintf("must be 1..%d characters without control characters", maxTerm))
	}
	return s, nil
}

// bounded returns v, def when v is zero, or an error outside lo..hi.
func bounded[T ~int](field string, v T, lo, hi, def int) (int, error) {
	if v == 0 {
		return def, nil
	}
	if int(v) < lo || int(v) > hi {
		return 0, invalid(field, fmt.Sprintf("must be %d..%d", lo, hi))
	}
	return int(v), nil
}
