package mailmcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// Message references and stale-reference safety (DESIGN section 3). A
// reference is {account, mailbox, uidvalidity, uid}; every tool that takes
// one checks it against imap status before using it. Mutations also check
// that every UID exists, run that status check last before each mutating
// command, and recheck UIDVALIDITY afterwards.

// Tagged UIDs. Every UID the wrapper returns reads "<uid>.<tag>", where tag
// is an HMAC over the account, mailbox, UIDVALIDITY and UID under a key that
// lives as long as the process. A UID copied to another mailbox, another
// UIDVALIDITY or another account, or kept across a restart, fails checkUID
// before any IMAP command runs. Himalaya only ever sees the number.

const (
	tagLen      = 11 // base64url of 8 bytes, without padding
	tagAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

// tagUID returns uid as clients see it.
func (s *Server) tagUID(account, mb string, uv, uid uint32) UID {
	return UID(strconv.FormatUint(uint64(uid), 10) + "." + s.tag(account, mb, uv, uid))
}

func (s *Server) tag(account, mb string, uv, uid uint32) string {
	h := hmac.New(sha256.New, s.key)
	fmt.Fprintf(h, "v1\x00%s\x00%s\x00%d\x00%d", account, mb, uv, uid)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:8])
}

// parseUID splits a tagged uid into a canonical decimal UID in 1..MaxUID
// and an 11-character base64url tag, or reports that u is malformed.
func parseUID(u UID) (uint32, string, bool) {
	num, tag, _ := strings.Cut(string(u), ".")
	n, err := strconv.ParseUint(num, 10, 32)
	ok := err == nil && num[0] != '0' && n <= himalaya.MaxUID && len(tag) == tagLen &&
		!strings.ContainsFunc(tag, func(r rune) bool { return !strings.ContainsRune(tagAlphabet, r) })
	return uint32(n), tag, ok
}

// verifyTag requires tag to be the one tagUID gives uid in mailbox mb of
// account at UIDVALIDITY uv, else stale_reference. It compares text and
// never decodes the tag, because the base64 decoder accepts more than one
// spelling of the same bytes.
func (s *Server) verifyTag(account, mb string, uv, uid uint32, tag string) error {
	if !hmac.Equal([]byte(tag), []byte(s.tag(account, mb, uv, uid))) {
		return himalaya.Errorf(himalaya.CodeStaleReference, fmt.Sprintf("uid %d was not listed in mailbox %q at uidvalidity %d", uid, mb, uv))
	}
	return nil
}

// checkUID returns the UID that u tags in mailbox mb of account at
// UIDVALIDITY uv. A malformed u is invalid_argument; a tag for anything
// else is stale_reference.
func (s *Server) checkUID(field, account, mb string, uv uint32, u UID) (uint32, error) {
	n, tag, ok := parseUID(u)
	if !ok {
		return 0, invalid(field, "must be copied exactly from a tool result")
	}
	return n, s.verifyTag(account, mb, uv, n, tag)
}

// checkUIDs is checkUID for a batch of 1..50 distinct UIDs. Form and
// uniqueness come first, so the same UID under two spellings is a duplicate.
func (s *Server) checkUIDs(account, mb string, uv uint32, us UIDs) ([]uint32, error) {
	if len(us) < 1 || len(us) > maxUIDs {
		return nil, invalid("uids", fmt.Sprintf("must hold 1..%d UIDs", maxUIDs))
	}
	nums := make([]uint32, len(us))
	tags := make([]string, len(us))
	for i, u := range us {
		n, tag, ok := parseUID(u)
		if !ok {
			return nil, invalid("uids", "must be copied exactly from a tool result")
		}
		if slices.Contains(nums[:i], n) {
			return nil, invalid("uids", "must be unique")
		}
		nums[i], tags[i] = n, tag
	}
	for i, n := range nums {
		if err := s.verifyTag(account, mb, uv, n, tags[i]); err != nil {
			return nil, err
		}
	}
	return nums, nil
}

func (s *Server) status(ctx context.Context, a *account, mb string) (himalaya.Status, error) {
	out, err := s.run.Run(ctx, a.hx.Status(mb))
	if err != nil {
		return himalaya.Status{}, withMailbox(err, mb)
	}
	st, err := himalaya.ParseStatus(out)
	if err != nil {
		return himalaya.Status{}, himalaya.Errorf(himalaya.CodeMailError, "")
	}
	return st, nil
}

// withMailbox names the mailbox in a mailbox_not_found error.
func withMailbox(err error, mb string) error {
	if e, ok := err.(*himalaya.Error); ok && e.Code == himalaya.CodeMailboxNotFound && e.Detail == "" {
		return himalaya.Errorf(e.Code, fmt.Sprintf("mailbox %q", mb))
	}
	return err
}

// checkRef runs status and rejects a different UIDVALIDITY (stale_reference)
// and any UID at or past UIDNEXT (not_found).
func (s *Server) checkRef(ctx context.Context, a *account, mb string, uidvalidity uint32, uids []uint32) (himalaya.Status, error) {
	st, err := s.status(ctx, a, mb)
	if err != nil {
		return st, err
	}
	if st.UIDValidity != uidvalidity {
		return st, himalaya.Errorf(himalaya.CodeStaleReference, fmt.Sprintf("mailbox %q", mb))
	}
	var missing []uint32
	for _, u := range uids {
		if u >= st.UIDNext {
			missing = append(missing, u)
		}
	}
	if len(missing) > 0 {
		return st, notFound(mb, missing)
	}
	return st, nil
}

func notFound(mb string, uids []uint32) error {
	return himalaya.Errorf(himalaya.CodeNotFound, fmt.Sprintf("mailbox %q, missing uids %s", mb, joinUIDs(uids)))
}

func joinUIDs(uids []uint32) string {
	parts := make([]string, len(uids))
	for i, u := range uids {
		parts[i] = fmt.Sprint(u)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// fetch reads UID, FLAGS and RFC822.SIZE and fails with not_found, listing
// every absent UID, unless all of them exist. It is all or nothing because
// flag and move commands report success for missing UIDs.
func (s *Server) fetch(ctx context.Context, a *account, mb string, uids []uint32) ([]himalaya.FetchRow, error) {
	out, err := s.run.Run(ctx, a.hx.Fetch(mb, uids))
	if err != nil {
		return nil, withMailbox(err, mb)
	}
	rows, err := himalaya.ParseFetch(out)
	if err != nil {
		return nil, himalaya.Errorf(himalaya.CodeMailError, "")
	}
	var missing []uint32
	for _, u := range uids {
		if !slices.ContainsFunc(rows, func(r himalaya.FetchRow) bool { return r.UID == u }) {
			missing = append(missing, u)
		}
	}
	if len(missing) > 0 {
		return nil, notFound(mb, missing)
	}
	return rows, nil
}

// checkSize is the size step before every body fetch: the UID must exist
// and its RFC822.SIZE must be within limits.max_message_bytes, because
// Himalaya loads whole messages into memory. The size comes from the one row
// of that UID that carries it; any other row may be an unsolicited FETCH. A
// UID's content never changes within one UIDVALIDITY epoch, so the check
// cannot go stale.
func (s *Server) checkSize(ctx context.Context, a *account, mb string, uid uint32) error {
	rows, err := s.fetch(ctx, a, mb, []uint32{uid})
	if err != nil {
		return err
	}
	var sizes []int64
	for _, r := range rows {
		if r.UID == uid && r.Size != nil {
			sizes = append(sizes, *r.Size)
		}
	}
	if len(sizes) != 1 {
		return mailError()
	}
	if sizes[0] > s.cfg.Limits.MaxMessageBytes {
		return tooLarge("message exceeds limits.max_message_bytes")
	}
	return nil
}

// readRef is checkRef followed by checkSize, for tools that fetch one body.
func (s *Server) readRef(ctx context.Context, a *account, mb string, uidvalidity, uid uint32) error {
	if _, err := s.checkRef(ctx, a, mb, uidvalidity, []uint32{uid}); err != nil {
		return err
	}
	return s.checkSize(ctx, a, mb, uid)
}

// mutateRef prepares a mutation: the capability gate, fetch, then checkRef,
// so that the UIDVALIDITY check is the last command before the mutation.
// UIDs the fetch missed because of a reset still read stale_reference.
func (s *Server) mutateRef(ctx context.Context, a *account, mb string, uidvalidity uint32, uids []uint32) error {
	if err := s.requireCapable(ctx, a); err != nil {
		return err
	}
	_, ferr := s.fetch(ctx, a, mb, uids)
	if ferr != nil && himalaya.CodeOf(ferr) != himalaya.CodeNotFound {
		return ferr
	}
	if _, err := s.checkRef(ctx, a, mb, uidvalidity, uids); err != nil {
		return err
	}
	return ferr
}

// postCheck reruns status after a mutation. A changed UIDVALIDITY, or a
// status that fails, means the mutation may have hit other messages.
func (s *Server) postCheck(ctx context.Context, a *account, mb string, uidvalidity uint32, done string) error {
	st, err := s.status(ctx, a, mb)
	if err != nil || st.UIDValidity != uidvalidity {
		return himalaya.Errorf(himalaya.CodeOutcomeUncertain,
			fmt.Sprintf("%s, but the UIDVALIDITY of %q could not be confirmed afterwards", done, mb))
	}
	return nil
}

// uncertain adds context to an outcome_uncertain error and passes others through.
func uncertain(err error, detail string) error {
	if e, ok := err.(*himalaya.Error); ok && e.Code == himalaya.CodeOutcomeUncertain {
		return himalaya.Errorf(e.Code, detail)
	}
	return err
}
