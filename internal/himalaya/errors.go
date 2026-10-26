package himalaya

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
)

// Code is a stable error category. Tool errors read "<code>: <sentence>".
type Code string

// Error codes. The runner produces the IMAP and process codes; the tool
// layer adds the policy and reference codes.
const (
	CodeInvalidArgument       Code = "invalid_argument"
	CodeForbidden             Code = "forbidden"
	CodeStaleReference        Code = "stale_reference"
	CodeNotFound              Code = "not_found"
	CodeMailboxNotFound       Code = "mailbox_not_found"
	CodeTooLarge              Code = "too_large"
	CodePartial               Code = "partial"
	CodeOutcomeUncertain      Code = "outcome_uncertain"
	CodeServerUnsupported     Code = "server_unsupported"
	CodeTLSFailed             Code = "tls_failed"
	CodeCredentialUnavailable Code = "credential_unavailable"
	CodeAuthFailed            Code = "auth_failed"
	CodeAccountUnavailable    Code = "account_unavailable"
	CodeTimeout               Code = "timeout"
	CodeCancelled             Code = "cancelled"
	CodeAttachmentUnsupported Code = "attachment_unsupported"
	CodeMailError             Code = "mail_error"
	CodeInternal              Code = "internal"
)

var sentences = map[Code]string{
	CodeInvalidArgument:       "the input is not valid",
	CodeForbidden:             "the operation is not allowed by the server policy",
	CodeStaleReference:        "the uidvalidity does not match the mailbox, which was reset or is not the reference's mailbox; list the mailbox again for fresh references",
	CodeNotFound:              "the message or attachment does not exist",
	CodeMailboxNotFound:       "the mailbox does not exist",
	CodeTooLarge:              "the message or output exceeds the configured size limit",
	CodePartial:               "only some of the messages were changed",
	CodeOutcomeUncertain:      "the change may or may not have been applied; check the mailbox before retrying",
	CodeServerUnsupported:     "the mail server lacks MOVE or UIDPLUS, which mutations require",
	CodeTLSFailed:             "the mail server certificate was not accepted",
	CodeCredentialUnavailable: "the account credential could not be read",
	CodeAuthFailed:            "the mail server rejected the login",
	CodeAccountUnavailable:    "the mail server could not be reached",
	CodeTimeout:               "the call exceeded its time limit",
	CodeCancelled:             "the call was cancelled",
	CodeAttachmentUnsupported: "the attachment cannot be downloaded, for example because its filename is too long",
	CodeMailError:             "the mail operation failed",
	CodeInternal:              "internal error",
}

// Error is the only error type tools return. Detail is safe context written
// by the wrapper itself (mailbox names, UIDs, counts); it never holds
// Himalaya or server text.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string {
	s := string(e.Code) + ": " + sentences[e.Code]
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

// Errorf is a shorthand for an *Error with the given code and detail.
func Errorf(code Code, detail string) *Error { return &Error{Code: code, Detail: detail} }

// CodeOf returns the code of an *Error, or internal for anything else.
func CodeOf(err error) Code {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return CodeInternal
}

// classification is the result of reading a Himalaya failure.
type classification struct {
	code Code
	// definite is true when the failure happened before any mutating IMAP
	// command could have been sent.
	definite bool
}

// classifyOutput reads an exit-1 failure: the JSON error document, or the
// plain-text "Error:" report that commands without --json print on stdout.
//
// Server text appears in these reports (after "IMAP APPEND failed: NO ", for
// example), so only the start of Himalaya's own top-level message can make
// a failure definite. Each trusted prefix names a stage that ends before the
// first mutating command. A refused SELECT is definite only for commands that
// select first; message add selects after its APPEND, to look up the new UID.
// Every other failure gets a best-effort code from the full text and is never
// definite.
func classifyOutput(stdout []byte, selectFirst bool) classification {
	r, ok := parseReport(stdout)
	if !ok {
		return classification{CodeMailError, false}
	}
	switch {
	case strings.HasPrefix(r.top, "invalid peer certificate"):
		return classification{CodeTLSFailed, true}
	case strings.HasPrefix(r.top, "Secret command error"):
		return classification{CodeCredentialUnavailable, true}
	case strings.HasPrefix(r.top, "IMAP AUTHENTICATE "), strings.HasPrefix(r.top, "IMAP LOGIN "):
		return classification{CodeAuthFailed, true}
	case strings.HasPrefix(r.top, "connect "):
		refused := slices.ContainsFunc(r.sources, func(s string) bool { return strings.HasPrefix(s, "Connection refused") })
		return classification{CodeAccountUnavailable, refused}
	case strings.HasPrefix(r.top, "IMAP SELECT failed"):
		return classification{CodeMailboxNotFound, selectFirst}
	}
	text := strings.ToLower(r.top + "\n" + strings.Join(r.sources, "\n"))
	switch {
	case strings.Contains(text, "stream stopped responding"):
		return classification{CodeTimeout, false}
	case strings.Contains(text, "mailbox doesn't exist"):
		return classification{CodeMailboxNotFound, false}
	case strings.Contains(text, "fetch returned no body") || strings.Contains(text, "no attachment with id"):
		return classification{CodeNotFound, false}
	case strings.Contains(text, "filename too long"):
		return classification{CodeAttachmentUnsupported, false}
	case strings.Contains(text, "connect") || strings.Contains(text, "unexpected end of file") ||
		strings.Contains(text, "broken pipe"):
		return classification{CodeAccountUnavailable, false}
	}
	return classification{CodeMailError, false}
}

// report is a failure report: Himalaya's top-level message and its causes.
type report struct {
	top     string
	sources []string
}

// parseReport reads {"error","sources"} or the plain-text form,
// "Error: <top>" followed by an optional "Caused by:" list of " - <source>".
func parseReport(stdout []byte) (report, bool) {
	var doc struct {
		Error   string   `json:"error"`
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(stdout, &doc); err == nil && doc.Error != "" {
		return report{doc.Error, doc.Sources}, true
	}
	text, ok := strings.CutPrefix(string(bytes.TrimSpace(stdout)), "Error: ")
	if !ok {
		return report{}, false
	}
	top, rest, _ := strings.Cut(text, "\n")
	r := report{top: top}
	if _, causes, ok := strings.Cut(rest, "Caused by:\n"); ok {
		for _, line := range strings.Split(causes, "\n") {
			source, ok := strings.CutPrefix(line, " - ")
			if !ok {
				break
			}
			r.sources = append(r.sources, source)
		}
	}
	return r, true
}

// outcome turns a classification into the error a caller sees. A failed
// mutating command is outcome_uncertain unless the failure was definite.
func outcome(c classification, mutating bool) *Error {
	if mutating && !c.definite {
		return Errorf(CodeOutcomeUncertain, "")
	}
	return Errorf(c.code, "")
}
