package mailmcp

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

func TestSafeName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"../../evil.sh", "_.._evil.sh"},
		{"/etc/passwd", "_etc_passwd"},
		{`..\..\windows.bat`, "_.._windows.bat"},
		{"-rf.txt", "rf.txt"},
		{"...hidden", "hidden"},
		{"résumé 📎 файл.pdf", "r_sum________.pdf"},
		{"a b\x00c\nd", "a_b_c_d"},
		{strings.Repeat("x", 300) + ".txt", strings.Repeat("x", 80)},
		{"", "attachment"},
		{"..", "attachment"},
		{"report-2026_v1.pdf", "report-2026_v1.pdf"},
	}
	for _, tt := range tests {
		if got := safeName(tt.in); got != tt.want {
			t.Errorf("safeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	name := storedName(time.Date(2026, 10, 23, 1, 2, 3, 0, time.UTC), "../../evil.sh")
	if !regexp.MustCompile(`^20261023-[0-9a-f]{8}-_\.\._evil\.sh$`).MatchString(name) {
		t.Errorf("storedName = %q", name)
	}
}

// fileSetup returns a download temp dir, a files_dir and its root.
func fileSetup(t *testing.T) (string, string, *os.Root) {
	t.Helper()
	tmp, files := t.TempDir(), t.TempDir()
	root, err := os.OpenRoot(files)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return tmp, files, root
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSaveDownload(t *testing.T) {
	tmp, files, root := fileSetup(t)
	write(t, filepath.Join(tmp, "_.._evil.sh"), "#!/bin/sh\n")
	size, sum, err := saveDownload(tmp, root, "20261023-00000000-_.._evil.sh", 100)
	want := sha256.Sum256([]byte("#!/bin/sh\n"))
	if err != nil || size != 10 || sum != hex.EncodeToString(want[:]) {
		t.Fatalf("size %d sum %s err %v", size, sum, err)
	}
	fi, err := os.Stat(filepath.Join(files, "20261023-00000000-_.._evil.sh"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("stored file: %v %v", fi, err)
	}
}

func TestSaveDownloadRefusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, tmp, files string)
		limit int64
		code  himalaya.Code
	}{
		{"oversize", func(t *testing.T, tmp, _ string) { write(t, filepath.Join(tmp, "a"), "12345") }, 4, himalaya.CodeTooLarge},
		{"two files", func(t *testing.T, tmp, _ string) {
			write(t, filepath.Join(tmp, "a"), "1")
			write(t, filepath.Join(tmp, "b"), "2")
		}, 10, himalaya.CodeInternal},
		{"no file", func(*testing.T, string, string) {}, 10, himalaya.CodeInternal},
		{"symlink in tmp", func(t *testing.T, tmp, _ string) { os.Symlink("/etc/hostname", filepath.Join(tmp, "a")) }, 10, himalaya.CodeInternal},
		{"directory in tmp", func(t *testing.T, tmp, _ string) { os.Mkdir(filepath.Join(tmp, "a"), 0o700) }, 10, himalaya.CodeInternal},
		{"destination exists", func(t *testing.T, tmp, files string) {
			write(t, filepath.Join(tmp, "a"), "1")
			write(t, filepath.Join(files, "dest"), "old")
		}, 10, himalaya.CodeInternal},
		{"dangling symlink at destination", func(t *testing.T, tmp, files string) {
			write(t, filepath.Join(tmp, "a"), "1")
			os.Symlink(filepath.Join(files, "..", "escaped"), filepath.Join(files, "dest"))
		}, 10, himalaya.CodeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp, files, root := fileSetup(t)
			tt.setup(t, tmp, files)
			before, _ := os.ReadDir(files)
			_, _, err := saveDownload(tmp, root, "dest", tt.limit)
			if err == nil || himalaya.CodeOf(err) != tt.code {
				t.Fatalf("err = %v, want %s", err, tt.code)
			}
			after, _ := os.ReadDir(files)
			if len(after) != len(before) {
				t.Errorf("files_dir changed: %v -> %v", before, after)
			}
			if _, err := os.Lstat(filepath.Join(files, "..", "escaped")); !os.IsNotExist(err) {
				t.Error("symlink was followed out of files_dir")
			}
		})
	}
}

func TestStageAttachments(t *testing.T) {
	stageRoot := t.TempDir()
	_, files, root := fileSetup(t)
	write(t, filepath.Join(files, "a.txt"), "aaaa")
	write(t, filepath.Join(files, "b.pdf"), "bbbbbb")
	os.Symlink("/etc/hostname", filepath.Join(files, "link.txt"))
	os.Symlink(filepath.Join(files, "missing"), filepath.Join(files, "dangling.txt"))
	os.Mkdir(filepath.Join(files, "dir"), 0o700)
	// A hard link to a credential passes every other check.
	secret := filepath.Join(t.TempDir(), "proton.password")
	write(t, secret, "hunter2")
	if err := os.Link(secret, filepath.Join(files, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(secret)
	if err != nil {
		t.Fatal(err)
	}
	secrets := []os.FileInfo{fi}

	dir, paths, err := stageAttachments(root, secrets, stageRoot, []string{"a.txt", "b.pdf"}, 10)
	if err != nil || len(paths) != 2 || filepath.Base(paths[1]) != "b.pdf" || filepath.Dir(paths[0]) != dir {
		t.Fatalf("stage: %v %v %v", dir, paths, err)
	}
	if b, _ := os.ReadFile(paths[1]); string(b) != "bbbbbb" {
		t.Errorf("staged content %q", b)
	}
	os.RemoveAll(dir)

	tests := []struct {
		name  string
		files []string
		limit int64
		code  himalaya.Code
	}{
		{"symlink", []string{"link.txt"}, 100, himalaya.CodeInvalidArgument},
		{"dangling symlink", []string{"dangling.txt"}, 100, himalaya.CodeInvalidArgument},
		{"directory", []string{"dir"}, 100, himalaya.CodeInvalidArgument},
		{"missing", []string{"nope.txt"}, 100, himalaya.CodeInvalidArgument},
		{"total over the limit", []string{"a.txt", "b.pdf"}, 9, himalaya.CodeTooLarge},
		{"hard link to a secret", []string{"a.txt", "notes.txt"}, 100, himalaya.CodeForbidden},
	}
	for _, tt := range tests {
		_, _, err := stageAttachments(root, secrets, stageRoot, tt.files, tt.limit)
		if himalaya.CodeOf(err) != tt.code {
			t.Errorf("%s: %v, want %s", tt.name, err, tt.code)
		}
	}
	if left, _ := os.ReadDir(stageRoot); len(left) != 0 {
		t.Errorf("staging left %v behind", left)
	}
}
