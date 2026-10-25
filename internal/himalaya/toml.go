package himalaya

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
)

// AccountTOML renders the Himalaya config for one account: an imap block and
// nothing else (no smtp, sendmail, signature, downloads-dir or alias). Values
// were validated by config, so they hold no control characters.
func AccountTOML(a *config.Account) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "[accounts.%s]\n", a.Name)
	b.WriteString("default = true\n")
	fmt.Fprintf(&b, "email = %s\n", tomlString(a.Email))
	hostPort := a.IMAP.Host + ":" + strconv.Itoa(a.IMAP.Port)
	if a.IMAP.Security == config.SecurityTLS {
		fmt.Fprintf(&b, "imap.server = %s\n", tomlString("imaps://"+hostPort))
	} else {
		fmt.Fprintf(&b, "imap.server = %s\n", tomlString("imap://"+hostPort))
		b.WriteString("imap.starttls = true\n")
	}
	if a.IMAP.TLSCertFile != "" {
		fmt.Fprintf(&b, "imap.tls.cert = %s\n", tomlString(a.IMAP.TLSCertFile))
	}
	fmt.Fprintf(&b, "imap.sasl.plain.username = %s\n", tomlString(a.Email))
	fmt.Fprintf(&b, "imap.sasl.plain.password.command = [%s, %s]\n", tomlString("/bin/cat"), tomlString(a.IMAP.PasswordFile))
	return []byte(b.String())
}

// LabelTOML is AccountTOML plus mailbox.alias.trash = label. With it,
// message delete --mailbox=<label> runs UID STORE +\Deleted and UID EXPUNGE
// on just the given UIDs (DESIGN section 2.2). Alias values are not shell-expanded.
func LabelTOML(a *config.Account, label string) []byte {
	return append(AccountTOML(a), fmt.Sprintf("mailbox.alias.trash = %s\n", tomlString(label))...)
}

func tomlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// ConfigPath is where the generated config of account name lives.
func ConfigPath(stateDir, name string) string {
	return filepath.Join(stateDir, "himalaya", name+".toml")
}

// PrepareState creates <state>/{himalaya,home,tmp} with mode 0700 and
// atomically rewrites every account's config with mode 0600. state_dir must
// exist and have passed config.CheckDirs. emptyTmp also removes leftovers
// from <state>/tmp; the check subcommand skips it so it can run next to a
// live server.
func PrepareState(c *config.Config, emptyTmp bool) error {
	fi, err := os.Lstat(c.StateDir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("state_dir %s must be a directory that is not group- or world-writable", c.StateDir)
	}
	if emptyTmp {
		if err := os.RemoveAll(filepath.Join(c.StateDir, "tmp")); err != nil {
			return err
		}
	}
	for _, d := range []string{"himalaya", "home", "tmp"} {
		p := filepath.Join(c.StateDir, d)
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o700); err != nil {
			return err
		}
	}
	for _, n := range c.AccountNames() {
		if err := replaceFile(ConfigPath(c.StateDir, n), AccountTOML(c.Accounts[n])); err != nil {
			return err
		}
	}
	return nil
}

// WriteLabelConfig writes the per-call remove_label config under a fresh
// <state>/tmp/label-* directory and returns its path. The caller removes the directory.
func WriteLabelConfig(stateDir string, a *config.Account, label string) (path, dir string, err error) {
	dir, err = os.MkdirTemp(filepath.Join(stateDir, "tmp"), "label-")
	if err != nil {
		return "", "", err
	}
	path = filepath.Join(dir, a.Name+".toml")
	if err := createFile(path, LabelTOML(a, label)); err != nil {
		os.RemoveAll(dir)
		return "", "", err
	}
	return path, dir, nil
}

// replaceFile atomically replaces path with a 0600 file. rename replaces a
// planted symlink instead of following it.
func replaceFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return err
	}
	return os.Rename(f.Name(), path)
}

// createFile creates a new 0600 file and fails if anything exists at path.
func createFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
