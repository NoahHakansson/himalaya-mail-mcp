package mailmcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
)

// Attachment files (DESIGN section 7). Every files_dir is an *os.Root, so
// names cannot escape it through "..", absolute paths or symlinks.

const maxSafeName = 80

// safeName maps an untrusted attachment filename to [A-Za-z0-9._-], strips
// leading dots and dashes, caps it at 80 bytes, and falls back to "attachment".
func safeName(name string) string {
	mapped := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, name)
	mapped = strings.TrimLeft(mapped, ".-")
	if len(mapped) > maxSafeName {
		mapped = mapped[:maxSafeName]
	}
	if mapped == "" {
		return "attachment"
	}
	return mapped
}

// storedName is the files_dir name of a download: <YYYYMMDD>-<8 hex>-<safe>.
func storedName(now time.Time, original string) string {
	return now.Format("20060102") + "-" + randomHex(4) + "-" + safeName(original)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

func tooLarge(detail string) error { return himalaya.Errorf(himalaya.CodeTooLarge, detail) }

// saveDownload moves the single regular file Himalaya wrote into tmpDir to
// dest inside files, copying at most limit bytes. It returns the size and
// sha256. On any error nothing is left behind in files.
func saveDownload(tmpDir string, files *os.Root, dest string, limit int64) (int64, string, error) {
	tmp, err := os.OpenRoot(tmpDir)
	if err != nil {
		return 0, "", err
	}
	defer tmp.Close()
	dir, err := tmp.Open(".")
	if err != nil {
		return 0, "", err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return 0, "", err
	}
	if len(entries) != 1 {
		return 0, "", errors.New("download did not produce exactly one file")
	}
	src, err := openRegular(tmp, entries[0].Name(), limit)
	if err != nil {
		return 0, "", err
	}
	defer src.Close()

	dst, err := files.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(dst, h), src, limit+1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = tooLarge("attachment exceeds limits.max_attachment_bytes")
	}
	if err != nil {
		files.Remove(dest)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// openRegular opens name in root after checking, before and after opening,
// that it is a regular file (not a symlink) of at most limit bytes.
func openRegular(root *os.Root, name string, limit int64) (*os.File, error) {
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err = f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err == nil && fi.Size() > limit {
		err = tooLarge("attachment exceeds limits.max_attachment_bytes")
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// stageAttachments copies the named files from files into a fresh 0700
// directory under tmpRoot, keeping their basenames, so Himalaya only ever
// reads paths the wrapper staged. A file that is one of secrets (a hard
// link) is refused. The total is bounded by limit even if a file grows after
// its Stat. The caller removes the returned directory.
func stageAttachments(files *os.Root, secrets []os.FileInfo, tmpRoot string, names []string, limit int64) (string, []string, error) {
	if len(names) == 0 {
		return "", nil, nil
	}
	dir, err := os.MkdirTemp(tmpRoot, "att-")
	if err != nil {
		return "", nil, err
	}
	paths, err := stageInto(files, secrets, dir, names, limit)
	if err != nil {
		os.RemoveAll(dir)
		return "", nil, err
	}
	return dir, paths, nil
}

func stageInto(files *os.Root, secrets []os.FileInfo, dir string, names []string, limit int64) ([]string, error) {
	var paths []string
	budget := limit
	for _, name := range names {
		src, err := openRegular(files, name, budget)
		if err != nil {
			if himalaya.CodeOf(err) == himalaya.CodeTooLarge {
				return nil, tooLarge("attachments exceed limits.max_attachment_bytes in total")
			}
			return nil, invalid("attachments", "must name regular files in the files directory")
		}
		fi, err := src.Stat()
		if err == nil && slices.ContainsFunc(secrets, func(s os.FileInfo) bool { return os.SameFile(fi, s) }) {
			err = forbidden("attachments must not be credential files")
		}
		if err != nil {
			src.Close()
			return nil, err
		}
		p := filepath.Join(dir, name)
		n, err := copyNew(p, src, budget)
		src.Close()
		if err != nil {
			return nil, err
		}
		budget -= n
		paths = append(paths, p)
	}
	return paths, nil
}

// copyNew creates path exclusively and copies at most limit bytes into it.
func copyNew(path string, src io.Reader, limit int64) (int64, error) {
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.CopyN(dst, src, limit+1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = tooLarge("attachments exceed limits.max_attachment_bytes in total")
	}
	return n, err
}
