package himalaya

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	reset := []byte(`{"error":"IMAP APPEND failed","sources":["Connection reset by peer (os error 104)"],"backtrace":null}`)
	eof := []byte(`{"error":"cannot read IMAP response","sources":["unexpected end of file"],"backtrace":null}`)
	stall := []byte(`{"error":"stream stopped responding after 60s","sources":[],"backtrace":null}`)
	timedOut := []byte(`{"error":"connect 192.0.2.1:993","sources":["Connection timed out (os error 110)"],"backtrace":null}`)
	plainRefused := []byte("Error: connect 127.0.0.1:1\n\nCaused by:\n - Connection refused (os error 111)\n\nSuggestions:\n - Run with --log-level to enable more verbose logs\n")
	U := CodeOutcomeUncertain
	tests := []struct {
		name string
		out  []byte
		read Code // a read-only command
		mut  Code // the same failure on a command that selects before it mutates
		add  Code // the same failure on message add, which selects after its APPEND
	}{
		{"tls", sample(t, "err_tls.json"), CodeTLSFailed, CodeTLSFailed, CodeTLSFailed},
		{"auth", sample(t, "err_auth.json"), CodeAuthFailed, CodeAuthFailed, CodeAuthFailed},
		{"secret command", sample(t, "err_secret.json"), CodeCredentialUnavailable, CodeCredentialUnavailable, CodeCredentialUnavailable},
		{"connection refused", sample(t, "err_refused.json"), CodeAccountUnavailable, CodeAccountUnavailable, CodeAccountUnavailable},
		{"plain-text connection refused", plainRefused, CodeAccountUnavailable, CodeAccountUnavailable, CodeAccountUnavailable},
		{"connect timeout", timedOut, CodeAccountUnavailable, U, U},
		{"connection reset", reset, CodeAccountUnavailable, U, U},
		{"unexpected eof", eof, CodeAccountUnavailable, U, U},
		{"read stall", stall, CodeTimeout, U, U},
		{"select failed", sample(t, "err_envelope_missing_mb.json"), CodeMailboxNotFound, CodeMailboxNotFound, U},
		{"status on missing mailbox", sample(t, "err_status_missing.json"), CodeMailboxNotFound, U, U},
		{"move to missing target", sample(t, "err_move_missing_target.json"), CodeMailboxNotFound, U, U},
		{"missing uid", sample(t, "err_read_missing.json"), CodeNotFound, U, U},
		{"missing part", sample(t, "err_attach_missing.json"), CodeNotFound, U, U},
		{"filename too long", sample(t, "err_download_long.json"), CodeAttachmentUnsupported, U, U},
		{"plain-text Error:", sample(t, "err_compose_bad_addr.txt"), CodeMailError, U, U},
		{"unparsable", []byte("garbage"), CodeMailError, U, U},
	}
	for _, tt := range tests {
		for _, c := range []struct {
			path string
			want Code
		}{{"imap status", tt.read}, {"message move", tt.mut}, {"message add", tt.add}} {
			err := result{started: true, exit: 1, stdout: tt.out}.err(commands[c.path])
			if CodeOf(err) != c.want {
				t.Errorf("%s (%s): %v, want %s", tt.name, c.path, err, c.want)
			}
			if strings.Contains(err.Error(), "secs") || strings.Contains(err.Error(), "os error") {
				t.Errorf("%s: Himalaya text leaked: %v", tt.name, err)
			}
		}
	}
}

// Server text can hold every word the stage rules look for. Only the start of
// Himalaya's own top-level message counts, so a failure after a mutating
// command may have been sent stays outcome_uncertain and a read gets no
// login, TLS or credential code.
func TestClassifyHostileServerText(t *testing.T) {
	doc := func(top string, sources ...string) []byte {
		b, err := json.Marshal(map[string]any{"error": top, "sources": sources, "backtrace": nil})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	mutating := []string{"message add", "message move", "message copy", "flag add", "flag remove", "message delete"}
	for _, word := range []string{"Authentication failed", "invalid peer certificate", "Secret command error", "Connection refused", "IMAP SELECT failed", "IMAP LOGIN failed"} {
		for _, out := range [][]byte{
			doc("IMAP APPEND failed: NO " + word),
			doc("IMAP MOVE failed: NO " + word),
			doc("IMAP COPY failed: BAD " + word),
			doc("IMAP STORE failed: NO " + word),
			doc("IMAP EXPUNGE failed: NO " + word),
			doc("IMAP MOVE failed", word),
			[]byte("Error: IMAP APPEND failed: NO " + word + "\n\nCaused by:\n - " + word + "\n"),
		} {
			for _, path := range mutating {
				if err := (result{started: true, exit: 1, stdout: out}).err(commands[path]); CodeOf(err) != CodeOutcomeUncertain {
					t.Errorf("%s on %q: %v, want outcome_uncertain", path, out, err)
				}
			}
			switch code := CodeOf((result{started: true, exit: 1, stdout: out}).err(commands["imap status"])); code {
			case CodeTLSFailed, CodeCredentialUnavailable, CodeAuthFailed:
				t.Errorf("imap status on %q: %s from server text", out, code)
			}
		}
	}
	// Captured from Himalaya after a server accepted the APPEND and refused the SELECT that looks up the UID.
	selectAfterAppend := []byte(`{"error":"IMAP SELECT failed: NO Mailbox doesn't exist: Drafts-authentication","sources":[],"backtrace":null}`)
	if err := (result{started: true, exit: 1, stdout: selectAfterAppend}).err(commands["message add"]); CodeOf(err) != CodeOutcomeUncertain {
		t.Errorf("message add with SELECT refused after APPEND: %v, want outcome_uncertain", err)
	}
}

func TestResultErr(t *testing.T) {
	tests := []struct {
		name     string
		res      result
		mutating bool
		want     Code
	}{
		{"ok", result{started: true, exit: 0}, true, ""},
		{"usage error", result{started: true, exit: 2}, true, CodeInternal},
		{"abort signal", result{started: true, exit: -1}, false, CodeMailError},
		{"abort signal while mutating", result{started: true, exit: -1}, true, CodeOutcomeUncertain},
		{"deadline", result{started: true, exit: -1, ctxErr: context.DeadlineExceeded}, false, CodeTimeout},
		{"deadline while mutating", result{started: true, exit: -1, ctxErr: context.DeadlineExceeded}, true, CodeOutcomeUncertain},
		{"cancel before start", result{exit: -1, ctxErr: context.Canceled}, true, CodeCancelled},
		{"deadline before start", result{exit: -1, ctxErr: context.DeadlineExceeded}, true, CodeTimeout},
		{"stdout overflow", result{started: true, exit: -1, overflow: true}, false, CodeTooLarge},
		{"stdout overflow while mutating", result{started: true, exit: -1, overflow: true}, true, CodeOutcomeUncertain},
	}
	for _, tt := range tests {
		err := tt.res.err(spec{mutating: tt.mutating})
		if got := Code(""); err != nil {
			got = CodeOf(err)
			if got != tt.want {
				t.Errorf("%s: %v, want %s", tt.name, err, tt.want)
			}
		} else if tt.want != "" {
			t.Errorf("%s: nil, want %s", tt.name, tt.want)
		}
	}
}

func TestErrorText(t *testing.T) {
	err := Errorf(CodeNotFound, `mailbox "INBOX", missing uids [9]`)
	if got := err.Error(); got != `not_found: the message or attachment does not exist (mailbox "INBOX", missing uids [9])` {
		t.Errorf("got %q", got)
	}
	if CodeOf(context.Canceled) != CodeInternal {
		t.Error("foreign errors must map to internal")
	}
}
