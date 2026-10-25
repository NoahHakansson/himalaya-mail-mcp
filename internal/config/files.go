package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// MinTokenBytes is the shortest accepted HTTP bearer token.
const MinTokenBytes = 32

// CheckSecretFile requires a regular file (not a symlink) owned by the
// service UID with no group or other permission bits (mode&0o077 == 0).
func CheckSecretFile(path string) error {
	fi, err := regularFile(path)
	if err != nil {
		return err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s must be owned by uid %d", path, os.Getuid())
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible by group or others (mode %04o)", path, fi.Mode().Perm())
	}
	return nil
}

// CheckNotWritableByOthers requires a regular file (not a symlink) that is
// not group- or world-writable. It covers the binary and certificate files.
func CheckNotWritableByOthers(path string) error {
	fi, err := regularFile(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group- or world-writable (mode %04o)", path, fi.Mode().Perm())
	}
	return nil
}

func regularFile(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink or other type", path)
	}
	return fi, nil
}

// ReadToken checks the token file like a secret and returns its trimmed
// content, which must be at least MinTokenBytes of printable ASCII without spaces.
func ReadToken(path string) (string, error) {
	if err := CheckSecretFile(path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(raw))
	if len(tok) < MinTokenBytes {
		return "", fmt.Errorf("token in %s is shorter than %d bytes", path, MinTokenBytes)
	}
	if strings.ContainsFunc(tok, func(r rune) bool { return r <= ' ' || r > '~' }) {
		return "", errors.New("token must be printable ASCII without whitespace")
	}
	return tok, nil
}

// CheckSecrets checks every file the given mode depends on: each account's
// password file and certificate, plus the HTTP token and TLS files when
// withHTTP is set. The password, token, key and HTTP certificate files must
// also have paths without symlinks. It returns their FileInfo, so that tools
// can refuse a hard link to one of them.
func (c *Config) CheckSecrets(withHTTP bool) ([]os.FileInfo, error) {
	var secrets []os.FileInfo
	secret := func(field, path string, check func(string) error) error {
		if err := check(path); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		if err := checkNoSymlinks(field, path); err != nil {
			return err
		}
		fi, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		secrets = append(secrets, fi)
		return nil
	}
	for _, n := range c.AccountNames() {
		a := c.Accounts[n]
		if err := secret("accounts."+n+".imap.password_file", a.IMAP.PasswordFile, CheckSecretFile); err != nil {
			return nil, err
		}
		if a.IMAP.TLSCertFile != "" {
			if err := CheckNotWritableByOthers(a.IMAP.TLSCertFile); err != nil {
				return nil, fmt.Errorf("accounts.%s.imap.tls_cert_file: %w", n, err)
			}
		}
	}
	if !withHTTP {
		return secrets, nil
	}
	h := c.HTTP
	if h.TokenFile == "" {
		return nil, errors.New("http.token_file is required for the http transport")
	}
	if err := secret("http.token_file", h.TokenFile, CheckSecretFile); err != nil {
		return nil, err
	}
	if h.TLSKeyFile != "" {
		if err := secret("http.tls_key_file", h.TLSKeyFile, CheckSecretFile); err != nil {
			return nil, err
		}
		if err := secret("http.tls_cert_file", h.TLSCertFile, CheckNotWritableByOthers); err != nil {
			return nil, err
		}
	}
	return secrets, nil
}

// CheckDirs requires state_dir, which must exist, and every files_dir to
// have paths without symlinks. A files_dir that does not exist yet is checked
// up to its nearest existing ancestor, so creating it cannot go through a
// symlink. Call it before changing anything on disk and again once the
// files_dirs exist. os.OpenRoot follows symlinks, so this makes the lexical
// checks of Parse hold for the directories the wrapper opens.
func (c *Config) CheckDirs() error {
	if err := checkNoSymlinks("state_dir", c.StateDir); err != nil {
		return err
	}
	for _, n := range c.AccountNames() {
		if err := checkNoSymlinksSoFar("accounts."+n+".files_dir", c.Accounts[n].FilesDir); err != nil {
			return err
		}
	}
	return nil
}

// checkNoSymlinks requires that path resolves to itself.
func checkNoSymlinks(field, path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if resolved != path {
		return fmt.Errorf("%s must not contain symlinks: %s resolves to %s", field, path, resolved)
	}
	return nil
}

// checkNoSymlinksSoFar is checkNoSymlinks for path or, while path does not
// exist, for its nearest existing ancestor.
func checkNoSymlinksSoFar(field, path string) error {
	p := path
	for {
		_, err := os.Lstat(p)
		if err == nil || !errors.Is(err, fs.ErrNotExist) || p == filepath.Dir(p) {
			return checkNoSymlinks(field, p)
		}
		p = filepath.Dir(p)
	}
}
