package mailmcp

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// Message references and stale-reference safety (DESIGN section 3). A
// reference is {account, mailbox, uidvalidity, uid}; every tool that takes
// one checks it against imap status before using it. Mutations also check
// that every UID exists, run that status check last before each mutating
// command, and recheck UIDVALIDITY afterwards.

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
