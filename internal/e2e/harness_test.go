//go:build integration

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestHarness checks the harness itself with the real Himalaya binary run
// through the shim: fixture seed data and profile, the doveadm helpers, the
// shim log and hook, certificate rejection, and cleanup.
func TestHarness(t *testing.T) {
	himalaya := HimalayaPath(t)
	RequireDocker(t)

	var container, root string
	t.Run("fixture", func(t *testing.T) {
		f := StartFixture(t, FixtureOptions{})
		container = f.Name
		shim := BuildShim(t, himalaya)
		root = TempDir(t)
		state := filepath.Join(root, "state")
		for _, dir := range []string{state, filepath.Join(state, "home"), filepath.Join(state, "tmp")} {
			mkdirPrivate(t, dir)
		}
		pw := filepath.Join(root, "alice.password")
		writeFile(t, pw, []byte(Alice.Password+"\n"), 0o600)
		writeConfig := func(name, server, tlsLine, cert string) string {
			path := filepath.Join(root, name+".toml")
			writeFile(t, path, fmt.Appendf(nil, `[accounts.alice]
default = true
email = %q
imap.server = %q
%simap.tls.cert = %q
imap.sasl.plain.username = %q
imap.sasl.plain.password.command = ["/bin/cat", %q]
`, Alice.Login, server, tlsLine, cert, Alice.Login, pw), 0o600)
			return path
		}
		good := writeConfig("good", fmt.Sprintf("imap://%s:%d", f.Host, f.STARTTLSPort), "imap.starttls = true\n", f.PKI.CA.CertFile)
		rogue := writeConfig("rogue", fmt.Sprintf("imaps://%s:%d", f.Host, f.TLSPort), "", f.PKI.RogueCA.CertFile)

		env := ServerEnv(state)
		run := func(config string, out any, args ...string) (int, string) {
			t.Helper()
			cmd := exec.Command(shim.Path, append([]string{"-c", config, "-a", "alice", "-b", "imap", "--log-level", "off", "--json"}, args...)...)
			cmd.Env = env
			stdout, err := cmd.Output()
			var exit *exec.ExitError
			switch {
			case err != nil && !errors.As(err, &exit):
				t.Fatalf("%q: %v", args, err)
			case exit != nil && out != nil:
				t.Fatalf("%q: exit %d: %s", args, exit.ExitCode(), stdout)
			case out != nil:
				if err := json.Unmarshal(stdout, out); err != nil {
					t.Fatalf("%q: %v: %s", args, err, stdout)
				}
			}
			return cmd.ProcessState.ExitCode(), string(stdout)
		}

		var raw struct{ Message string }
		run(good, &raw, "imap", "raw", "--", "A1 CAPABILITY")
		if !strings.HasPrefix(raw.Message, "* CAPABILITY IMAP4rev1 IDLE UNSELECT UIDPLUS MOVE ID\r\n") {
			t.Errorf("bridge profile CAPABILITY = %q", raw.Message)
		}

		var mailboxes struct{ Mailboxes []struct{ Name string } }
		run(good, &mailboxes, "mailbox", "list")
		var names []string
		for _, m := range mailboxes.Mailboxes {
			names = append(names, m.Name)
		}
		for _, want := range []string{"Inbox", "Archive", "Drafts", "Sent", "Trash", "Junk", "Résumé/Ünïcødé 📬", "Folders/Projects", "Labels/Work"} {
			if !slices.Contains(names, want) {
				t.Errorf("mailbox list %q lacks %q", names, want)
			}
		}

		var envelopes struct {
			Envelopes []struct {
				ID    string
				Flags []struct{ Raw string }
			}
		}
		run(good, &envelopes, "envelope", "list", "--mailbox=INBOX", "--page-size=50")
		var unseen []string
		for _, e := range envelopes.Envelopes {
			if !slices.ContainsFunc(e.Flags, func(f struct{ Raw string }) bool { return f.Raw == `\Seen` }) {
				unseen = append(unseen, e.ID)
			}
		}
		slices.Sort(unseen)
		if len(envelopes.Envelopes) != 6 || !slices.Equal(unseen, []string{"1", "3", "4", "6"}) {
			t.Errorf("INBOX has %d envelopes, unseen %q; want 6 and [1 3 4 6]", len(envelopes.Envelopes), unseen)
		}

		wantFlags := map[uint32][]string{1: {}, 2: {`\Seen`}, 3: {}, 4: {}, 5: {`\Flagged`, `\Seen`}, 6: {}}
		if got := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(got, wantFlags, slices.Equal) {
			t.Errorf("INBOX flags after the reads = %v, want %v", got, wantFlags)
		}
		if st := f.Status(t, Alice, "INBOX"); st.Messages != 6 || st.Unseen != 4 || st.UIDNext != 7 || st.UIDValidity == 0 {
			t.Errorf("INBOX status = %+v", st)
		}
		if got := f.UIDs(t, Alice, "Résumé/Ünïcødé 📬"); !slices.Equal(got, []uint32{1}) {
			t.Errorf("Unicode folder UIDs = %v", got)
		}
		if got, want := f.RawMessage(t, Alice, "INBOX", 4), Message(t, "alice-04-adversarial-attachments.eml"); !bytes.Equal(got, want) {
			t.Errorf("RawMessage(INBOX, 4) differs from the seeded file:\n%s", got)
		}
		if events := f.MailLog(t); len(events) != 0 {
			t.Errorf("reads logged mail events: %+v", events)
		}

		// The hook runs before the exec, so the status already sees the new value.
		shim.SetHook(t, []string{"imap", "status"}, f.SetUIDValidityArgv(Alice, "INBOX", 4242))
		var status struct {
			UIDValidity uint32 `json:"uid_validity"`
		}
		run(good, &status, "imap", "status", "--", "INBOX")
		shim.ClearHook(t)
		if status.UIDValidity != 4242 {
			t.Errorf("uid_validity after the hook = %d, want 4242", status.UIDValidity)
		}

		if code, out := run(rogue, nil, "mailbox", "list"); code != 1 || !strings.Contains(out, "invalid peer certificate") {
			t.Errorf("rogue CA: exit %d, output %s", code, out)
		}

		recs := shim.Records(t)
		var hooked []bool
		for _, r := range recs {
			hooked = append(hooked, r.Hook)
		}
		if !slices.Equal(hooked, []bool{false, false, false, true, false}) || recs[3].Argv[len(recs[3].Argv)-1] != "INBOX" {
			t.Errorf("shim recorded %d runs with hook flags %v", len(recs), hooked)
		}
		shim.AssertEnv(t, env)

		uid := f.Seed(t, Alice, "Labels/Work", Message(t, "stray-deleted.eml"), `\Deleted`)
		if got := f.Flags(t, Alice, "Labels/Work"); uid != 2 || !slices.Equal(got[uid], []string{`\Deleted`}) {
			t.Errorf("seeded stray uid %d, Labels/Work flags %v", uid, got)
		}
	})

	if out := runDocker(t, nil, "ps", "-a", "--filter", "name=^"+container+"$", "--format", "{{.Names}}"); len(out) != 0 {
		t.Errorf("fixture container survived its test: %s", out)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temp dir %s survived its test: %v", root, err)
	}
	AssertNoProcs(t, root)
}
