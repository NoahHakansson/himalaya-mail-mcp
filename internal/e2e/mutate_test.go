//go:build integration

package e2e

// Mutating tool tests from DESIGN.md section 11 (TestAttachments, TestDrafts,
// TestMovesAndTrash, TestStaleAndInvalidRefs). Each test starts its own
// fixture and checks mailbox state through doveadm and mail_log, not only
// through tool results.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/mailmcp"
)

// TestAttachments: downloads land in files_dir only under generated
// names, the size limits hold before any body is fetched or any file is
// written, and draft attachments must be regular files.
func TestAttachments(t *testing.T) {
	HimalayaPath(t)
	f := StartFixture(t, FixtureOptions{})
	ref := mailmcp.RefIn{Account: "alice", Mailbox: "INBOX", UIDValidity: mailmcp.UIDValidity(f.Status(t, Alice, "INBOX").UIDValidity), UID: 4}
	source := muParse(t, Message(t, "alice-04-adversarial-attachments.eml")).attachments
	evil := source["../../evil.sh"]
	download := func(part int) mailmcp.DownloadIn {
		return mailmcp.DownloadIn{Account: ref.Account, Mailbox: ref.Mailbox, UIDValidity: ref.UIDValidity, UID: ref.UID, PartID: mailmcp.PartID(part)}
	}

	t.Run("download", func(t *testing.T) {
		e := muStart(t, f, nil)
		dir := e.files.FilesDirs["alice"]
		parts := e.partIDs(t, ref)

		got := muDownload.call(t, e.cs, download(parts["../../evil.sh"]))
		if !regexp.MustCompile(`^[0-9]{8}-[0-9a-f]{8}-_\.\._evil\.sh$`).MatchString(got.File) {
			t.Errorf("stored name %q, want <date>-<hex>-_.._evil.sh", got.File)
		}
		if _, err := os.Lstat(filepath.Join(dir, "../../evil.sh")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("../../evil.sh exists relative to files_dir: %v", err)
		}
		fi, err := os.Lstat(filepath.Join(dir, got.File))
		if err != nil {
			t.Fatal(err)
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Errorf("stored file mode %v, want a regular 0600 file", fi.Mode())
		}
		data := readFile(t, filepath.Join(dir, got.File))
		sum := sha256.Sum256(data)
		if !bytes.Equal(data, evil) || got.Size != int64(len(evil)) || got.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("stored %q (result size %d, sha256 %s), want the attachment's %d bytes %q", data, got.Size, got.SHA256, len(evil), evil)
		}

		var long string
		for name := range parts {
			if len(name) > 255 {
				long = name
			}
		}
		if long == "" {
			t.Fatal("alice-04 lists no attachment with a name over 255 bytes")
		}
		muDownload.wantCode(t, e.cs, download(parts[long]), himalaya.CodeAttachmentUnsupported)
		if names := muDirNames(t, dir); !slices.Equal(names, []string{got.File}) {
			t.Errorf("files_dir holds %q, want only %q", names, got.File)
		}
		e.assertTmpEmpty(t)
	})

	t.Run("draft attachments must be regular files", func(t *testing.T) {
		e := muStart(t, f, nil)
		dir := e.files.FilesDirs["alice"]
		// The link targets are FIFOs, so muOpened can tell whether anything opened them.
		outside := filepath.Join(TempDir(t), "secret.fifo")
		fifos := []string{outside, filepath.Join(dir, "inside.fifo")}
		for _, p := range fifos {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		links := map[string]string{
			"inside-link.txt":   "inside.fifo", // os.Root alone would follow this one
			"outside-link.txt":  outside,
			"dangling-link.txt": filepath.Join(dir, "missing.txt"),
		}
		for name, target := range links {
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		drafts := f.UIDs(t, Alice, "Drafts")
		m := e.mark(t)
		for name := range links {
			if muOpened(fifos, func() {
				muCreateDraft.wantCode(t, e.cs, mailmcp.DraftIn{
					Account: "alice", To: mailmcp.Addresses{"carol@example.test"}, Subject: mailmcp.Subject("attach " + name),
					Attachments: mailmcp.FileNames{mailmcp.FileName(name)},
				}, himalaya.CodeInvalidArgument)
			}) {
				t.Errorf("attaching %s opened a link target", name)
			}
		}
		if cmds := e.commandsSince(t, m); slices.Contains(cmds, "message compose") || slices.Contains(cmds, "message add") {
			t.Errorf("refused attachments still reached Himalaya: %q", cmds)
		}
		if got := f.UIDs(t, Alice, "Drafts"); !slices.Equal(got, drafts) {
			t.Errorf("Drafts UIDs %v, want unchanged %v", got, drafts)
		}
		if ev := e.eventsSince(t, m); len(ev) != 0 {
			t.Errorf("refused drafts logged mail events: %+v", ev)
		}
		e.assertTmpEmpty(t)
	})

	t.Run("message over max_message_bytes", func(t *testing.T) {
		const limit = 2000
		if size := len(Message(t, "alice-04-adversarial-attachments.eml")); size <= limit {
			t.Fatalf("alice-04 has %d bytes, want more than %d", size, limit)
		}
		e := muStart(t, f, func(c *ServerConfig) { c.Limits.MaxMessageBytes = limit })
		read := mailmcp.ReadIn{Account: ref.Account, Mailbox: ref.Mailbox, UIDValidity: ref.UIDValidity, UID: ref.UID}
		to := mailmcp.Addresses{"carol@example.test"}
		for _, c := range []struct {
			tool string
			call func()
		}{
			{"read_message", func() { muReadMessage.wantCode(t, e.cs, read, himalaya.CodeTooLarge) }},
			{"list_attachments", func() { muListAttachments.wantCode(t, e.cs, ref, himalaya.CodeTooLarge) }},
			// Any part ID: the size check comes first.
			{"download_attachment", func() { muDownload.wantCode(t, e.cs, download(3), himalaya.CodeTooLarge) }},
			{"reply_draft", func() {
				muReplyDraft.wantCode(t, e.cs, mailmcp.ReplyIn{Account: ref.Account, Mailbox: ref.Mailbox, UIDValidity: ref.UIDValidity, UID: ref.UID, Body: "ok"}, himalaya.CodeTooLarge)
			}},
			{"forward_draft", func() {
				muForwardDraft.wantCode(t, e.cs, mailmcp.ForwardIn{Account: ref.Account, Mailbox: ref.Mailbox, UIDValidity: ref.UIDValidity, UID: ref.UID, To: to}, himalaya.CodeTooLarge)
			}},
		} {
			m := e.mark(t)
			c.call()
			// Only the checks ran, and the size fetch was the last of them.
			cmds := e.commandsSince(t, m)
			checksOnly := !slices.ContainsFunc(cmds, func(c string) bool { return !slices.Contains(muCheckCommands, c) })
			if !checksOnly || len(cmds) == 0 || cmds[len(cmds)-1] != "imap fetch" {
				t.Errorf("%s ran %q, want no body fetch after the size fetch", c.tool, cmds)
			}
		}
		// The limit is a threshold: a small message is still readable.
		read.UID = 1
		muReadMessage.call(t, e.cs, read)
		if names := muDirNames(t, e.files.FilesDirs["alice"]); len(names) != 0 {
			t.Errorf("files_dir holds %q, want nothing", names)
		}
		e.assertTmpEmpty(t)
	})

	t.Run("attachment over max_attachment_bytes", func(t *testing.T) {
		const limit = 64
		small := source["a/b.txt"]
		if len(evil) <= limit || len(small) > limit {
			t.Fatalf("evil.sh has %d and a/b.txt %d bytes, want them on either side of %d", len(evil), len(small), limit)
		}
		e := muStart(t, f, func(c *ServerConfig) { c.Limits.MaxAttachmentBytes = limit })
		dir := e.files.FilesDirs["alice"]
		parts := e.partIDs(t, ref)
		muDownload.wantCode(t, e.cs, download(parts["../../evil.sh"]), himalaya.CodeTooLarge)
		if names := muDirNames(t, dir); len(names) != 0 {
			t.Errorf("files_dir holds %q after a refused download, want nothing", names)
		}
		got := muDownload.call(t, e.cs, download(parts["a/b.txt"]))
		if names := muDirNames(t, dir); !slices.Equal(names, []string{got.File}) {
			t.Errorf("files_dir holds %q, want only %q", names, got.File)
		}
		e.assertTmpEmpty(t)
	})
}

// TestDrafts: drafts are saved only to Drafts with \Draft \Seen and the
// requested headers and attachments, update_draft keeps the old version
// recoverable in Trash, reply and forward render from the source without
// marking it read, and content that is not UTF-8 is never cut short.
func TestDrafts(t *testing.T) {
	HimalayaPath(t)
	f := StartFixture(t, FixtureOptions{StrayDeleted: true})
	e := muStart(t, f, nil)
	drafts := mailmcp.UIDValidity(f.Status(t, Alice, "Drafts").UIDValidity)
	inbox := mailmcp.UIDValidity(f.Status(t, Alice, "INBOX").UIDValidity)
	sent := f.UIDs(t, Alice, "Sent")
	// message add stops silently at the first line that is not UTF-8, so a
	// draft carrying these bytes must still arrive whole.
	blob := []byte("\xff\xfe\x00binary \xe9t\xe9\nsecond line\n")
	writeFile(t, filepath.Join(e.files.FilesDirs["alice"], "report.bin"), blob, 0o600)

	var created mailmcp.DraftOut
	t.Run("create_draft", func(t *testing.T) {
		in := mailmcp.DraftIn{
			Account:     "alice",
			To:          mailmcp.Addresses{"carol@example.test", "dave@example.test"},
			Cc:          mailmcp.Addresses{"erin@example.test"},
			Bcc:         mailmcp.Addresses{"frank@example.test"},
			Subject:     "Quarterly report: Grüße ✓",
			Body:        "Hi Carol,\n\nthe report is attached.\nlast line",
			Attachments: mailmcp.FileNames{"report.bin"},
		}
		created = muCreateDraft.call(t, e.cs, in)
		if created.Mailbox != "Drafts" || created.UIDValidity != uint32(drafts) {
			t.Errorf("draft reference %+v, want Drafts with uidvalidity %d", created, drafts)
		}
		if got := f.Flags(t, Alice, "Drafts")[created.UID]; !slices.Equal(got, []string{`\Draft`, `\Seen`}) {
			t.Errorf("draft flags %q, want [\\Draft \\Seen]", got)
		}
		msg := muParse(t, f.RawMessage(t, Alice, "Drafts", created.UID))
		for field, want := range map[string]mailmcp.Addresses{"To": in.To, "Cc": in.Cc, "Bcc": in.Bcc} {
			if got := muAddresses(t, msg.header, field); !slices.Equal(got, want) {
				t.Errorf("%s %q, want %q", field, got, want)
			}
		}
		if got := msg.subject(t); got != string(in.Subject) {
			t.Errorf("subject %q, want %q", got, in.Subject)
		}
		if got := msg.header.Get("Message-ID"); got != "<"+created.MessageID+">" {
			t.Errorf("Message-ID %q, result message_id %q", got, created.MessageID)
		}
		if got := msg.text(); got != string(in.Body) {
			t.Errorf("body %q, want %q", got, in.Body)
		}
		if got, ok := msg.attachments["report.bin"]; !ok || !bytes.Equal(got, blob) {
			t.Errorf("attachments %q, want report.bin with %q", slices.Collect(maps.Keys(msg.attachments)), blob)
		}
	})

	t.Run("CRLF subject", func(t *testing.T) {
		m := e.mark(t)
		muCreateDraft.wantRejected(t, e.cs, mailmcp.DraftIn{Account: "alice", To: mailmcp.Addresses{"carol@example.test"}, Subject: "Hi\r\nBcc: mallory@evil.test"})
		if cmds := e.commandsSince(t, m); len(cmds) != 0 {
			t.Errorf("a rejected subject ran Himalaya: %q", cmds)
		}
	})

	t.Run("update_draft", func(t *testing.T) {
		if created.UID == 0 {
			t.Skip("create_draft failed")
		}
		trash := f.UIDs(t, Alice, "Trash")
		m := e.mark(t)
		got := muUpdateDraft.call(t, e.cs, mailmcp.UpdateDraftIn{
			Account: "alice", UIDValidity: drafts, UID: mailmcp.UID(created.UID),
			To: mailmcp.Addresses{"carol@example.test"}, Subject: "Quarterly report v2", Body: "Version two.",
		})
		if got.UID <= created.UID || got.PreviousTrashed != "yes" || got.MessageID == created.MessageID {
			t.Errorf("update_draft %+v, want a new UID above %d and previous_trashed yes", got, created.UID)
		}
		if uids := f.UIDs(t, Alice, "Drafts"); !slices.Contains(uids, got.UID) || slices.Contains(uids, created.UID) {
			t.Errorf("Drafts UIDs %v, want %d and not %d", uids, got.UID, created.UID)
		}
		after := f.UIDs(t, Alice, "Trash")
		if len(after) != len(trash)+1 || !slices.Equal(after[:len(trash)], trash) {
			t.Fatalf("Trash UIDs %v, want %v plus the old draft", after, trash)
		}
		if id := muParse(t, f.RawMessage(t, Alice, "Trash", after[len(trash)])).header.Get("Message-ID"); id != "<"+created.MessageID+">" {
			t.Errorf("new Trash message has Message-ID %q, want the old draft's %q", id, created.MessageID)
		}
		muAssertStrays(t, f, "Trash")
		if got := muExpunges(e.eventsSince(t, m)); !slices.Equal(got, []string{"Drafts/" + strconv.Itoa(int(created.UID))}) {
			t.Errorf("expunges %q, want only the old draft in Drafts", got)
		}
	})

	t.Run("reply_draft", func(t *testing.T) {
		// An 8-bit ISO-8859-1 source, unseen.
		src := f.Seed(t, Alice, "INBOX", []byte("From: Old Sender <old@example.test>\r\nTo: alice@example.test\r\n"+
			"Subject: =?iso-8859-1?q?caf=E9?=\r\nMessage-ID: <latin1@fixture.test>\r\nMIME-Version: 1.0\r\n"+
			"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"+
			"caf\xe9 first\r\nend marker\r\n"))
		flags := f.Flags(t, Alice, "INBOX")
		m := e.mark(t)
		got := muReplyDraft.call(t, e.cs, mailmcp.ReplyIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UID: mailmcp.UID(src), Body: "Thanks, noted."})
		msg := muParse(t, f.RawMessage(t, Alice, "Drafts", got.UID))
		if irt := msg.header.Get("In-Reply-To"); irt != "<latin1@fixture.test>" {
			t.Errorf("In-Reply-To %q, want <latin1@fixture.test>", irt)
		}
		if to := muAddresses(t, msg.header, "To"); !slices.Equal(to, mailmcp.Addresses{"old@example.test"}) {
			t.Errorf("To %q, want the source's From", to)
		}
		if body := msg.text(); !strings.HasPrefix(body, "Thanks, noted.") || !strings.HasSuffix(body, "> café first\n> end marker") {
			t.Errorf("reply body %q, want the reply then the whole quote decoded to UTF-8", body)
		}
		if after := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(after, flags, slices.Equal) {
			t.Errorf("INBOX flags changed from %v to %v", flags, after)
		}
		if ev := e.eventsSince(t, m); len(ev) != 1 || ev[0].Event != "save" || ev[0].Mailbox != "Drafts" {
			t.Errorf("reply_draft logged %+v, want only the save in Drafts", ev)
		}
	})

	t.Run("forward_draft", func(t *testing.T) {
		ref := mailmcp.RefIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UID: 4}
		dl := muDownload.call(t, e.cs, mailmcp.DownloadIn{Account: ref.Account, Mailbox: ref.Mailbox, UIDValidity: ref.UIDValidity, UID: ref.UID,
			PartID: mailmcp.PartID(e.partIDs(t, ref)["../../evil.sh"])})
		got := muForwardDraft.call(t, e.cs, mailmcp.ForwardIn{Account: ref.Account, Mailbox: ref.Mailbox, UIDValidity: ref.UIDValidity, UID: ref.UID,
			To: mailmcp.Addresses{"carol@example.test"}, Attachments: mailmcp.FileNames{mailmcp.FileName(dl.File)}})
		msg := muParse(t, f.RawMessage(t, Alice, "Drafts", got.UID))
		if s := msg.subject(t); !strings.HasPrefix(s, "Fwd: ") {
			t.Errorf("forward subject %q, want Fwd: ...", s)
		}
		want := muParse(t, Message(t, "alice-04-adversarial-attachments.eml")).attachments["../../evil.sh"]
		if data, ok := msg.attachments[dl.File]; !ok || !bytes.Equal(data, want) {
			t.Errorf("forward attachments %q, want %s with the downloaded bytes", slices.Collect(maps.Keys(msg.attachments)), dl.File)
		}
	})

	// One APPEND per draft, all into Drafts; only update_draft moved anything (Drafts to Trash).
	saves := 0
	for _, ev := range f.MailLog(t) {
		switch {
		case ev.Event == "save" && ev.Mailbox == "Drafts":
			saves++
		case ev.Event == "save", ev.Event == "copy" && (ev.From != "Drafts" || ev.Mailbox != "Trash"):
			t.Errorf("draft tools logged %s", ev.Line)
		}
	}
	if saves != 4 {
		t.Errorf("%d saves in Drafts, want one per draft (4)", saves)
	}
	if got := f.UIDs(t, Alice, "Sent"); !slices.Equal(got, sent) {
		t.Errorf("Sent UIDs %v, want unchanged %v", got, sent)
	}
	e.assertTmpEmpty(t)
}

// TestMovesAndTrash: moves, trash, restore, flags and labels change
// exactly the messages named, never expunge stray \Deleted messages, and
// refuse forbidden targets and servers without MOVE or UIDPLUS.
func TestMovesAndTrash(t *testing.T) {
	HimalayaPath(t)

	t.Run("bridge", func(t *testing.T) {
		f := StartFixture(t, FixtureOptions{StrayDeleted: true})
		e := muStart(t, f, nil)
		status := func(mb string) mailmcp.UIDValidity { return mailmcp.UIDValidity(f.Status(t, Alice, mb).UIDValidity) }
		inbox := status("INBOX")
		const unicode = "Résumé/Ünïcødé 📬"
		m := e.mark(t)

		t.Run("forbidden", func(t *testing.T) {
			for _, to := range []mailmcp.Mailbox{"INBOX", "inbox", "Drafts", "Sent", "Labels/Work", "labels/work"} {
				muMove.wantCode(t, e.cs, mailmcp.MoveIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{1}, To: to}, himalaya.CodeForbidden)
			}
			// Drafts and Sent messages may only go to trash.
			muMove.wantCode(t, e.cs, mailmcp.MoveIn{Account: "alice", Mailbox: "Drafts", UIDValidity: status("Drafts"), UIDs: mailmcp.UIDs{1}, To: "INBOX"}, himalaya.CodeForbidden)
			if cmds := e.commandsSince(t, m); len(cmds) != 0 {
				t.Errorf("policy refusals ran Himalaya: %q", cmds)
			}
		})

		var want []string // expected expunges, as mailbox/uid
		moved := func(t *testing.T, from, to, id string, out mailmcp.MoveOut) uint32 {
			t.Helper()
			if out.Moved != 1 || out.From != from || out.To != to {
				t.Errorf("move result %+v, want 1 from %s to %s", out, from, to)
			}
			if got := muFind(t, f, from, id); len(got) != 0 {
				t.Errorf("%s still holds %s at %v", from, id, got)
			}
			got := muFind(t, f, to, id)
			if len(got) != 1 {
				t.Fatalf("%s holds %s at %v, want one copy", to, id, got)
			}
			return got[0]
		}
		expunged := func(mb string, uid uint32) { want = append(want, mb+"/"+strconv.Itoa(int(uid))) }

		t.Run("trash and restore", func(t *testing.T) {
			trashed := moved(t, "INBOX", "Trash", "alice-01@fixture.test",
				muTrash.call(t, e.cs, mailmcp.BatchIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{1}}))
			expunged("INBOX", 1)
			moved(t, "Trash", "INBOX", "alice-01@fixture.test",
				muRestore.call(t, e.cs, mailmcp.RestoreIn{Account: "alice", UIDValidity: status("Trash"), UIDs: mailmcp.UIDs{mailmcp.UID(trashed)}}))
			expunged("Trash", trashed)
		})

		t.Run("archive", func(t *testing.T) {
			moved(t, "INBOX", "Archive", "alice-02@fixture.test",
				muArchive.call(t, e.cs, mailmcp.BatchIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{2}}))
			expunged("INBOX", 2)
		})

		t.Run("move into the Unicode folder", func(t *testing.T) {
			moved(t, "INBOX", unicode, "alice-03@fixture.test",
				muMove.call(t, e.cs, mailmcp.MoveIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{3}, To: unicode}))
			expunged("INBOX", 3)
		})

		t.Run("update_flags", func(t *testing.T) {
			before := f.Flags(t, Alice, "INBOX")
			for _, step := range []struct {
				on   bool
				want []string
			}{{true, []string{`\Flagged`, `\Seen`}}, {false, []string{}}} {
				out := muUpdateFlags.call(t, e.cs, mailmcp.FlagsIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{4}, Seen: new(step.on), Flagged: new(step.on)})
				after := f.Flags(t, Alice, "INBOX")
				if out.Updated != 1 || !slices.Equal(after[4], step.want) {
					t.Errorf("seen and flagged %v: updated %d, UID 4 flags %q, want 1 and %q", step.on, out.Updated, after[4], step.want)
				}
				after[4] = before[4] // the rest must be untouched
				if !maps.EqualFunc(after, before, slices.Equal) {
					t.Errorf("other INBOX flags changed from %v to %v", before, after)
				}
			}
		})

		t.Run("labels", func(t *testing.T) {
			out := muAddLabel.call(t, e.cs, mailmcp.AddLabelIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{5}, Label: "Labels/Work"})
			copies := muFind(t, f, "Labels/Work", "alice-05@fixture.test")
			if out.Labeled != 1 || len(copies) != 1 || !slices.Equal(muFind(t, f, "INBOX", "alice-05@fixture.test"), []uint32{5}) {
				t.Fatalf("add_label: labeled %d, copies in Labels/Work %v; want 1 copy and INBOX UID 5 kept", out.Labeled, copies)
			}
			work := f.UIDs(t, Alice, "Labels/Work")
			rm := muRemoveLabel.call(t, e.cs, mailmcp.RemoveLabelIn{Account: "alice", Label: "Labels/Work", UIDValidity: status("Labels/Work"), UIDs: mailmcp.UIDs{mailmcp.UID(copies[0])}})
			expunged("Labels/Work", copies[0])
			left := slices.DeleteFunc(slices.Clone(work), func(u uint32) bool { return u == copies[0] })
			if got := f.UIDs(t, Alice, "Labels/Work"); rm.Unlabeled != 1 || !slices.Equal(got, left) {
				t.Errorf("remove_label: unlabeled %d, Labels/Work UIDs %v; want 1 and %v", rm.Unlabeled, got, left)
			}
			if got := muFind(t, f, "INBOX", "alice-05@fixture.test"); !slices.Equal(got, []uint32{5}) {
				t.Errorf("INBOX holds alice-05 at %v after remove_label, want [5]", got)
			}
		})

		muAssertStrays(t, f, StrayMailboxes...)
		if got := muExpunges(e.eventsSince(t, m)); !slices.Equal(got, want) {
			t.Errorf("expunges %q, want exactly %q", got, want)
		}
		e.assertTmpEmpty(t)
	})

	t.Run("nomove", func(t *testing.T) {
		f := StartFixture(t, FixtureOptions{Profile: ProfileNoMove})
		e := muStart(t, f, nil)
		inbox, archive := f.UIDs(t, Alice, "INBOX"), f.UIDs(t, Alice, "Archive")
		m := e.mark(t)
		muMove.wantCode(t, e.cs, mailmcp.MoveIn{Account: "alice", Mailbox: "INBOX",
			UIDValidity: mailmcp.UIDValidity(f.Status(t, Alice, "INBOX").UIDValidity), UIDs: mailmcp.UIDs{1}, To: "Archive"}, himalaya.CodeServerUnsupported)
		if cmds := e.commandsSince(t, m); !slices.Equal(cmds, []string{"imap raw"}) {
			t.Errorf("ran %q, want only the capability probe", cmds)
		}
		if got := f.UIDs(t, Alice, "INBOX"); !slices.Equal(got, inbox) {
			t.Errorf("INBOX UIDs %v, want unchanged %v", got, inbox)
		}
		if got := f.UIDs(t, Alice, "Archive"); !slices.Equal(got, archive) {
			t.Errorf("Archive UIDs %v, want unchanged %v", got, archive)
		}
		if ev := e.eventsSince(t, m); len(ev) != 0 {
			t.Errorf("mail events: %+v", ev)
		}
	})
}

// TestStaleAndInvalidRefs: references are checked against UIDVALIDITY and
// existence before anything runs, invalid input never reaches Himalaya, a
// UIDVALIDITY reset right before a mutation is reported as outcome_uncertain,
// and one while a reply renders saves no draft.
func TestStaleAndInvalidRefs(t *testing.T) {
	HimalayaPath(t)
	f := StartFixture(t, FixtureOptions{})
	e := muStart(t, f, nil)
	uv := f.Status(t, Alice, "INBOX").UIDValidity
	inbox := mailmcp.UIDValidity(uv)
	read := func(mb mailmcp.Mailbox, v mailmcp.UIDValidity, uid mailmcp.UID) mailmcp.ReadIn {
		return mailmcp.ReadIn{Account: "alice", Mailbox: mb, UIDValidity: v, UID: uid}
	}
	move := func(mb mailmcp.Mailbox, v mailmcp.UIDValidity, uids ...mailmcp.UID) mailmcp.MoveIn {
		return mailmcp.MoveIn{Account: "alice", Mailbox: mb, UIDValidity: v, UIDs: uids, To: "Archive"}
	}
	flag := func(v mailmcp.UIDValidity, uids ...mailmcp.UID) mailmcp.FlagsIn {
		return mailmcp.FlagsIn{Account: "alice", Mailbox: "INBOX", UIDValidity: v, UIDs: uids, Flagged: new(true)}
	}
	// noMutation requires that only the checks ran since m and nothing changed mail.
	noMutation := func(t *testing.T, m muMark) {
		t.Helper()
		for _, c := range e.commandsSince(t, m) {
			if !slices.Contains(muCheckCommands, c) {
				t.Errorf("ran %q after the reference check failed", c)
			}
		}
		if ev := e.eventsSince(t, m); len(ev) != 0 {
			t.Errorf("mail events: %+v", ev)
		}
	}

	t.Run("invalid input", func(t *testing.T) {
		m := e.mark(t)
		muReadMessage.wantRejected(t, e.cs, read("INBOX", inbox, 0))
		muReadMessage.wantRejected(t, e.cs, read("INBOX", inbox, 4294967295)) // Himalaya reads it as "*"
		muUpdateFlags.wantRejected(t, e.cs, flag(inbox, 1, 1))
		muReadMessage.wantRejected(t, e.cs, read("INBOX\x1b[2J", inbox, 1))
		muMove.wantRejected(t, e.cs, mailmcp.MoveIn{Account: "alice", Mailbox: "INBOX", UIDValidity: inbox, UIDs: mailmcp.UIDs{1}, To: "Archive\u0085"})
		if cmds := e.commandsSince(t, m); len(cmds) != 0 {
			t.Errorf("rejected input ran Himalaya: %q", cmds)
		}
	})

	t.Run("missing mailbox", func(t *testing.T) {
		m := e.mark(t)
		muReadMessage.wantCode(t, e.cs, read("Nope", inbox, 1), himalaya.CodeMailboxNotFound)
		muMove.wantCode(t, e.cs, move("Nope", inbox, 1), himalaya.CodeMailboxNotFound)
		// A missing target is found by status, before any MOVE could be sent.
		missingTarget := move("INBOX", inbox, 1)
		missingTarget.To = "Nope"
		if text := muMove.wantCode(t, e.cs, missingTarget, himalaya.CodeMailboxNotFound); !strings.Contains(text, `"Nope"`) {
			t.Errorf("mailbox_not_found text %q does not name Nope", text)
		}
		noMutation(t, m)
	})

	t.Run("missing UID", func(t *testing.T) {
		flags := f.Flags(t, Alice, "INBOX")
		m := e.mark(t)
		muUpdateFlags.wantCode(t, e.cs, flag(inbox, 999), himalaya.CodeNotFound)
		muMove.wantCode(t, e.cs, move("INBOX", inbox, 999), himalaya.CodeNotFound)
		// A gap below UIDNEXT, where Himalaya alone would report success.
		f.Doveadm(t, "expunge", "-u", Alice.Login, "mailbox", "INBOX", "uid", "2")
		delete(flags, 2)
		if text := muUpdateFlags.wantCode(t, e.cs, flag(inbox, 4, 2), himalaya.CodeNotFound); !strings.Contains(text, "[2]") {
			t.Errorf("not_found text %q does not name UID 2", text)
		}
		muMove.wantCode(t, e.cs, move("INBOX", inbox, 2), himalaya.CodeNotFound)
		noMutation(t, m)
		if got := f.Flags(t, Alice, "INBOX"); !maps.EqualFunc(got, flags, slices.Equal) {
			t.Errorf("INBOX flags changed from %v to %v", flags, got)
		}
	})

	t.Run("stale reference", func(t *testing.T) {
		uids := f.UIDs(t, Alice, "INBOX")
		f.SetUIDValidity(t, Alice, "INBOX", uv+1)
		m := e.mark(t)
		muReadMessage.wantCode(t, e.cs, read("INBOX", inbox, 1), himalaya.CodeStaleReference)
		muMove.wantCode(t, e.cs, move("INBOX", inbox, 1), himalaya.CodeStaleReference)
		noMutation(t, m)
		if got := f.UIDs(t, Alice, "INBOX"); !slices.Equal(got, uids) {
			t.Errorf("INBOX UIDs %v, want unchanged %v", got, uids)
		}
	})

	t.Run("UIDVALIDITY reset before the move", func(t *testing.T) {
		current := mailmcp.UIDValidity(f.Status(t, Alice, "INBOX").UIDValidity)
		e.shim.SetHook(t, []string{"message", "move"}, f.SetUIDValidityArgv(Alice, "INBOX", uint32(current)+1))
		t.Cleanup(func() { e.shim.ClearHook(t) })
		m := e.mark(t)
		if text := muMove.wantCode(t, e.cs, move("INBOX", current, 1), himalaya.CodeOutcomeUncertain); !strings.Contains(text, `"INBOX"`) {
			t.Errorf("outcome_uncertain text %q does not name INBOX", text)
		}
		recs := e.shim.Records(t)[m.runs:]
		if i := slices.IndexFunc(recs, func(r ShimRecord) bool { return commandPath(r.Argv) == "message move" }); i < 0 || !recs[i].Hook || recs[i].HookError != "" {
			t.Fatalf("the hook did not run cleanly before the move: %+v", recs)
		}
		// The residual race: the move itself went through, only the post-check caught the reset.
		if got := muFind(t, f, "Archive", "alice-01@fixture.test"); len(got) != 1 {
			t.Errorf("Archive holds alice-01 at %v, want the moved copy", got)
		}
	})

	t.Run("UIDVALIDITY reset while a reply renders", func(t *testing.T) {
		current := mailmcp.UIDValidity(f.Status(t, Alice, "INBOX").UIDValidity)
		e.shim.SetHook(t, []string{"message", "reply"}, f.SetUIDValidityArgv(Alice, "INBOX", uint32(current)+1))
		t.Cleanup(func() { e.shim.ClearHook(t) })
		drafts := f.UIDs(t, Alice, "Drafts")
		m := e.mark(t)
		muReplyDraft.wantCode(t, e.cs, mailmcp.ReplyIn{Account: "alice", Mailbox: "INBOX", UIDValidity: current, UID: 5, Body: "Noted."}, himalaya.CodeStaleReference)
		recs := e.shim.Records(t)[m.runs:]
		if i := slices.IndexFunc(recs, func(r ShimRecord) bool { return commandPath(r.Argv) == "message reply" }); i < 0 || !recs[i].Hook || recs[i].HookError != "" {
			t.Fatalf("the hook did not run cleanly before the reply: %+v", recs)
		}
		if cmds := e.commandsSince(t, m); slices.Contains(cmds, "message add") {
			t.Errorf("ran %q, want no message add after the reset", cmds)
		}
		if got := f.UIDs(t, Alice, "Drafts"); !slices.Equal(got, drafts) {
			t.Errorf("Drafts UIDs %v, want unchanged %v", got, drafts)
		}
		if ev := e.eventsSince(t, m); len(ev) != 0 {
			t.Errorf("mail events: %+v", ev)
		}
	})
}

// --- helpers --------------------------------------------------------------

// muTool pairs a tool name with its input and output types.
type muTool[In, Out any] string

var (
	muReadMessage     = muTool[mailmcp.ReadIn, mailmcp.ReadOut]("read_message")
	muListAttachments = muTool[mailmcp.RefIn, mailmcp.ListAttachmentsOut]("list_attachments")
	muDownload        = muTool[mailmcp.DownloadIn, mailmcp.DownloadOut]("download_attachment")
	muCreateDraft     = muTool[mailmcp.DraftIn, mailmcp.DraftOut]("create_draft")
	muUpdateDraft     = muTool[mailmcp.UpdateDraftIn, mailmcp.UpdateDraftOut]("update_draft")
	muReplyDraft      = muTool[mailmcp.ReplyIn, mailmcp.DraftOut]("reply_draft")
	muForwardDraft    = muTool[mailmcp.ForwardIn, mailmcp.DraftOut]("forward_draft")
	muUpdateFlags     = muTool[mailmcp.FlagsIn, mailmcp.FlagsOut]("update_flags")
	muMove            = muTool[mailmcp.MoveIn, mailmcp.MoveOut]("move_messages")
	muArchive         = muTool[mailmcp.BatchIn, mailmcp.MoveOut]("archive_messages")
	muTrash           = muTool[mailmcp.BatchIn, mailmcp.MoveOut]("trash_messages")
	muRestore         = muTool[mailmcp.RestoreIn, mailmcp.MoveOut]("restore_messages")
	muAddLabel        = muTool[mailmcp.AddLabelIn, mailmcp.AddLabelOut]("add_label")
	muRemoveLabel     = muTool[mailmcp.RemoveLabelIn, mailmcp.RemoveLabelOut]("remove_label")
)

func (tool muTool[In, Out]) result(t *testing.T, cs *mcp.ClientSession, in In) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: string(tool), Arguments: in})
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return res
}

// call runs the tool and returns its structured result; a tool error fails the test.
func (tool muTool[In, Out]) call(t *testing.T, cs *mcp.ClientSession, in In) Out {
	t.Helper()
	res := tool.result(t, cs, in)
	if res.IsError {
		t.Fatalf("%s: %s", tool, resultText(res))
	}
	data, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out Out
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("%s: decode %s: %v", tool, data, err)
	}
	return out
}

// wantCode runs the tool, requires a tool error "<code>: ..." and returns its text.
func (tool muTool[In, Out]) wantCode(t *testing.T, cs *mcp.ClientSession, in In, code himalaya.Code) string {
	t.Helper()
	res := tool.result(t, cs, in)
	text := resultText(res)
	if !res.IsError || !strings.HasPrefix(text, string(code)+": ") {
		t.Errorf("%s: error %v %q, want %s", tool, res.IsError, text, code)
	}
	return text
}

// wantRejected requires the input schema to reject in before the handler runs.
func (tool muTool[In, Out]) wantRejected(t *testing.T, cs *mcp.ClientSession, in In) {
	t.Helper()
	res := tool.result(t, cs, in)
	if text := resultText(res); !res.IsError || !strings.HasPrefix(text, `validating "arguments"`) {
		t.Errorf("%s: error %v %q, want a schema rejection", tool, res.IsError, text)
	}
}

// muEnv is one stdio server, with its own shim, in front of a fixture.
type muEnv struct {
	f     *Fixture
	shim  *Shim
	files *ServerFiles
	cs    *mcp.ClientSession
}

func muStart(t *testing.T, f *Fixture, edit func(*ServerConfig)) *muEnv {
	t.Helper()
	bin := BuildServer(t)
	shim := BuildShim(t, HimalayaPath(t))
	files := WriteServerConfig(t, ServerOptions{Fixture: f, Shim: shim, Edit: edit})
	return &muEnv{f: f, shim: shim, files: files, cs: StartStdio(t, bin, files)}
}

// muCheckCommands are the commands the wrapper runs to check a call before
// it fetches a body or mutates anything: the capability probe, status and
// the UID/FLAGS/RFC822.SIZE fetch.
var muCheckCommands = []string{"imap raw", "imap status", "imap fetch"}

// muMark is a position in the shim log and the fixture's mail log.
type muMark struct{ runs, events int }

func (e *muEnv) mark(t *testing.T) muMark {
	t.Helper()
	return muMark{len(e.shim.Records(t)), len(e.f.MailLog(t))}
}

// commandsSince returns the subcommand paths Himalaya ran since m, in order.
func (e *muEnv) commandsSince(t *testing.T, m muMark) []string {
	t.Helper()
	var cmds []string
	for _, r := range e.shim.Records(t)[m.runs:] {
		cmds = append(cmds, commandPath(r.Argv))
	}
	return cmds
}

func (e *muEnv) eventsSince(t *testing.T, m muMark) []MailEvent {
	t.Helper()
	return e.f.MailLog(t)[m.events:]
}

// partIDs maps attachment filenames to part IDs, as list_attachments reports them.
func (e *muEnv) partIDs(t *testing.T, ref mailmcp.RefIn) map[string]int {
	t.Helper()
	ids := map[string]int{}
	for _, a := range muListAttachments.call(t, e.cs, ref).Attachments {
		ids[a.Filename] = a.PartID
	}
	return ids
}

func (e *muEnv) assertTmpEmpty(t *testing.T) {
	t.Helper()
	if names := muDirNames(t, filepath.Join(e.files.StateDir, "tmp")); len(names) != 0 {
		t.Errorf("<state>/tmp holds %q, want nothing", names)
	}
}

// muOpened runs call and reports whether anything opened one of the FIFOs
// for reading meanwhile. Opening a FIFO for writing without blocking only
// succeeds while it has a reader, and it releases a reader blocked in open,
// so a regression fails here instead of hanging the call.
func muOpened(fifos []string, call func()) (opened bool) {
	done := make(chan struct{})
	var seen atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			for _, p := range fifos {
				if fd, err := syscall.Open(p, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					seen.Store(true)
					syscall.Close(fd)
				}
			}
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	// Deferred, so the poller also stops when call fails the test.
	defer func() {
		close(done)
		wg.Wait()
		opened = seen.Load()
	}()
	call()
	return
}

func muDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// muFind returns the UIDs in mailbox whose Message-ID is id (no brackets).
func muFind(t *testing.T, f *Fixture, mailbox, id string) []uint32 {
	t.Helper()
	uids := []uint32{}
	out := f.Doveadm(t, "search", "-u", Alice.Login, "mailbox", mailbox, "header", "Message-ID", id)
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		uid, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
		if err != nil {
			t.Fatalf("doveadm search: %q", line)
		}
		uids = append(uids, uint32(uid))
	}
	slices.Sort(uids)
	return uids
}

// muAssertStrays requires the stray \Deleted message, the last UID of each
// mailbox seeded with FixtureOptions.StrayDeleted, to still be there.
func muAssertStrays(t *testing.T, f *Fixture, mailboxes ...string) {
	t.Helper()
	for _, mb := range mailboxes {
		if uids := muFind(t, f, mb, "stray-deleted@fixture.test"); len(uids) != 1 || !slices.Equal(f.Flags(t, Alice, mb)[uids[0]], []string{`\Deleted`}) {
			t.Errorf("the stray \\Deleted message in %s is gone or changed (UIDs %v)", mb, uids)
		}
	}
}

// muExpunges lists the expunge events as mailbox/uid, in order.
func muExpunges(events []MailEvent) []string {
	var out []string
	for _, ev := range events {
		if ev.Event == "expunge" {
			out = append(out, ev.Mailbox+"/"+strconv.Itoa(int(ev.UID)))
		}
	}
	return out
}

// muMessage is a stored message: its header, the transfer-decoded text of
// its first inline text part, and its attachments by raw filename.
type muMessage struct {
	header      mail.Header
	body        []byte
	attachments map[string][]byte
}

func muParse(t *testing.T, raw []byte) muMessage {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v\n%s", err, raw)
	}
	m := muMessage{header: msg.Header, attachments: map[string][]byte{}}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		m.body = muDecode(t, msg.Header.Get("Content-Transfer-Encoding"), msg.Body)
		return m
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return m
		}
		if err != nil {
			t.Fatalf("parse part: %v\n%s", err, raw)
		}
		// NextPart already decodes quoted-printable and drops the header.
		data := muDecode(t, p.Header.Get("Content-Transfer-Encoding"), p)
		disposition, dp, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
		switch {
		case disposition == "attachment":
			m.attachments[dp["filename"]] = data
		case m.body == nil:
			m.body = data
		}
	}
}

func muDecode(t *testing.T, encoding string, r io.Reader) []byte {
	t.Helper()
	switch strings.ToLower(encoding) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, r)
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decode %s part: %v", encoding, err)
	}
	return data
}

// text is the body with LF line ends and no trailing newline.
func (m muMessage) text() string {
	return strings.TrimRight(strings.ReplaceAll(string(m.body), "\r\n", "\n"), "\n")
}

func (m muMessage) subject(t *testing.T) string {
	t.Helper()
	s, err := new(mime.WordDecoder).DecodeHeader(m.header.Get("Subject"))
	if err != nil {
		t.Fatalf("decode subject %q: %v", m.header.Get("Subject"), err)
	}
	return s
}

func muAddresses(t *testing.T, h mail.Header, field string) mailmcp.Addresses {
	t.Helper()
	list, err := h.AddressList(field)
	if err != nil {
		t.Fatalf("%s: %v", field, err)
	}
	var out mailmcp.Addresses
	for _, a := range list {
		out = append(out, mailmcp.Address(a.Address))
	}
	return out
}
