package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// base returns a valid config document as a mutable map.
func base() map[string]any {
	return map[string]any{
		"himalaya":  map[string]any{"path": "/opt/hmcp/himalaya", "sha256": strings.Repeat("a", 64)},
		"state_dir": "/var/lib/hmcp",
		"accounts": map[string]any{
			"proton": map[string]any{
				"email": "you@proton.me",
				"imap": map[string]any{"host": "127.0.0.1", "port": 1143, "security": "starttls",
					"tls_cert_file": "/etc/hmcp/cert.pem", "password_file": "/etc/hmcp/proton.pass"},
				"label_prefix": "Labels/",
				"files_dir":    "/var/lib/hmcp/files/proton",
			},
		},
	}
}

func account(m map[string]any) map[string]any {
	return m["accounts"].(map[string]any)["proton"].(map[string]any)
}

func TestParseDefaults(t *testing.T) {
	raw, _ := json.Marshal(base())
	c, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Accounts["proton"]
	if a.Name != "proton" || a.Mailboxes != DefaultMailboxes || len(a.ProtectedMailboxes) != 4 {
		t.Errorf("account defaults: %+v", a)
	}
	if c.CallTimeoutSeconds != 25 || c.Limits.MaxAttachmentBytes != 25<<20 || c.Limits.MaxMessageBytes != 25<<20 || c.HTTP.Listen != "127.0.0.1:8765" {
		t.Errorf("defaults: %+v", c)
	}
}

func TestParseRefusals(t *testing.T) {
	tests := []struct {
		name string
		edit func(m map[string]any)
		want string
	}{
		{"unknown top-level field", func(m map[string]any) { m["himalya"] = 1 }, "unknown field"},
		{"unknown account field", func(m map[string]any) { account(m)["imapp"] = 1 }, "unknown field"},
		{"bad account name", func(m map[string]any) { renameAccount(m, "Proton") }, "name must match"},
		{"default account name", func(m map[string]any) { renameAccount(m, "default") }, "name must match"},
		{"dollar in path", func(m map[string]any) { m["state_dir"] = "/var/$HOME" }, "must not contain"},
		{"tilde in path", func(m map[string]any) { account(m)["files_dir"] = "/var/~x" }, "must not contain"},
		{"colon in path", func(m map[string]any) { setIMAP(m, "password_file", "/a:/b") }, "must not contain"},
		{"relative path", func(m map[string]any) { setIMAP(m, "password_file", "secrets/p") }, "absolute"},
		{"unclean path", func(m map[string]any) { m["state_dir"] = "/var/lib/../hmcp" }, "absolute, clean"},
		{"cleartext imap", func(m map[string]any) { setIMAP(m, "security", "none") }, "security"},
		{"bad host", func(m map[string]any) { setIMAP(m, "host", "a b") }, "imap.host"},
		{"bad port", func(m map[string]any) { setIMAP(m, "port", 0) }, "imap.port"},
		{"email with display name", func(m map[string]any) { account(m)["email"] = "You <you@proton.me>" }, "bare address"},
		{"email with dollar", func(m map[string]any) { account(m)["email"] = "$USER@proton.me" }, "email"},
		{"overlapping files_dir", func(m map[string]any) {
			second := map[string]any{}
			for k, v := range account(m) {
				second[k] = v
			}
			second["files_dir"] = "/var/lib/hmcp/files/proton/sub"
			m["accounts"].(map[string]any)["work"] = second
		}, "overlap"},
		{"files_dir in state tmp", func(m map[string]any) { account(m)["files_dir"] = "/var/lib/hmcp/tmp/x" }, "must not be inside"},
		{"secret inside files_dir", func(m map[string]any) { setIMAP(m, "password_file", "/var/lib/hmcp/files/proton/p") }, "inside accounts.proton.files_dir"},
		{"secret inside state_dir", func(m map[string]any) { setIMAP(m, "password_file", "/var/lib/hmcp/p") }, "inside state_dir"},
		{"http certificate inside files_dir", func(m map[string]any) {
			m["http"] = map[string]any{"tls_cert_file": "/var/lib/hmcp/files/proton/c.pem", "tls_key_file": "/etc/k.pem"}
		}, "inside accounts.proton.files_dir"},
		{"non-loopback without TLS", func(m map[string]any) {
			m["http"] = map[string]any{"listen": "192.0.2.10:8443", "allowed_hosts": []string{"mail:8443"}}
		}, "not loopback"},
		{"non-loopback without hosts", func(m map[string]any) {
			m["http"] = map[string]any{"listen": "0.0.0.0:8443", "tls_cert_file": "/etc/c.pem", "tls_key_file": "/etc/k.pem"}
		}, "not loopback"},
		{"cert without key", func(m map[string]any) { m["http"] = map[string]any{"tls_cert_file": "/etc/c.pem"} }, "set together"},
		{"label prefix without slash", func(m map[string]any) { account(m)["label_prefix"] = "Labels" }, `end with "/"`},
		{"role is protected", func(m map[string]any) { account(m)["mailboxes"] = map[string]any{"archive": "All Mail"} }, "protected"},
		{"duplicate roles", func(m map[string]any) { account(m)["mailboxes"] = map[string]any{"archive": "trash"} }, "must differ"},
		{"role under label prefix", func(m map[string]any) { account(m)["mailboxes"] = map[string]any{"junk": "Labels/Spam"} }, "label_prefix"},
		{"call timeout too long", func(m map[string]any) { m["call_timeout_seconds"] = 281 }, "call_timeout_seconds"},
		{"bad sha256", func(m map[string]any) { m["himalaya"].(map[string]any)["sha256"] = "ABC" }, "sha256"},
		{"no accounts", func(m map[string]any) { m["accounts"] = map[string]any{} }, "at least one account"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base()
			tt.edit(m)
			raw, _ := json.Marshal(m)
			_, err := Parse(raw)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestParseTrailingData(t *testing.T) {
	raw, _ := json.Marshal(base())
	if _, err := Parse(append(raw, []byte(` {}`)...)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func renameAccount(m map[string]any, name string) {
	accts := m["accounts"].(map[string]any)
	accts[name] = accts["proton"]
	delete(accts, "proton")
}

func setIMAP(m map[string]any, key string, v any) {
	account(m)["imap"].(map[string]any)[key] = v
}

func TestCheckSecretFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("secret\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok", 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"0600 file", ok, false},
		{"0400 file", write("ro", 0o400), false},
		{"0644 file", write("wide", 0o644), true},
		{"0640 file", write("group", 0o640), true},
		{"symlink to a good file", link, true},
		{"directory", dir, true},
		{"missing", filepath.Join(dir, "nope"), true},
	}
	for _, tt := range tests {
		if err := CheckSecretFile(tt.path); (err != nil) != tt.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

// os.OpenRoot follows symlinks, so a files_dir alias of the password
// directory would pass the lexical checks of Parse and expose the password
// file by name. Symlinks anywhere in these paths are refused instead.
func TestCheckDirsAndSecretPaths(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(dir, name) }
	for _, d := range []string{"state", "files", "secrets"} {
		if err := os.Mkdir(path(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path("secrets/p"), []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"secrets-alias": "secrets", "state-alias": "state"} {
		if err := os.Symlink(path(target), path(link)); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name string
		edit func(c *Config, a *Account)
		want string
	}{
		{"real paths", func(*Config, *Account) {}, ""},
		{"files_dir not created yet", func(_ *Config, a *Account) { a.FilesDir = path("files/new/proton") }, ""},
		{"files_dir to be created through a symlink", func(_ *Config, a *Account) { a.FilesDir = path("state-alias/new/proton") }, "accounts.proton.files_dir must not contain symlinks"},
		{"state_dir missing", func(c *Config, _ *Account) { c.StateDir = path("missing") }, "state_dir: "},
		{"files_dir aliases the secrets", func(_ *Config, a *Account) { a.FilesDir = path("secrets-alias") }, "accounts.proton.files_dir must not contain symlinks"},
		{"state_dir through a symlink", func(c *Config, _ *Account) { c.StateDir = path("state-alias") }, "state_dir must not contain symlinks"},
		{"password file through a symlink", func(_ *Config, a *Account) { a.IMAP.PasswordFile = path("secrets-alias/p") }, "accounts.proton.imap.password_file must not contain symlinks"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Account{Name: "proton", FilesDir: path("files"), IMAP: IMAP{PasswordFile: path("secrets/p")}}
			c := &Config{StateDir: path("state"), Accounts: map[string]*Account{"proton": a}}
			tt.edit(c, a)
			secrets, err := c.CheckSecrets(false)
			if err == nil {
				err = c.CheckDirs()
			}
			if tt.want == "" {
				fi, _ := os.Stat(path("secrets/p"))
				if err != nil || len(secrets) != 1 || !os.SameFile(secrets[0], fi) {
					t.Fatalf("secrets %v, err %v; want the password file and no error", secrets, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestCheckNoSymlinksSoFar(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(dir, name) }
	if err := os.MkdirAll(path("real/existing"), 0o700); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{"alias": "real", "dangling": "gone"} {
		if err := os.Symlink(path(target), path(link)); err != nil {
			t.Fatal(err)
		}
	}
	tests := map[string]bool{
		"real/existing":    true,
		"real/new/deeper":  true,
		"alias":            false,
		"alias/existing":   false, // an existing path below a symlink
		"alias/new/deeper": false, // a path to be created below a symlink
		"dangling/new":     false,
	}
	for name, ok := range tests {
		if err := checkNoSymlinksSoFar("f", path(name)); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok %v", name, err, ok)
		}
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string
		mode    os.FileMode
		want    string
	}{
		{"valid with newline", strings.Repeat("k", 32) + "\n", 0o600, strings.Repeat("k", 32)},
		{"31 bytes", strings.Repeat("k", 31), 0o600, ""},
		{"inner space", strings.Repeat("k", 20) + " " + strings.Repeat("k", 20), 0o600, ""},
		{"non-ASCII", strings.Repeat("ü", 20), 0o600, ""},
		{"world-readable", strings.Repeat("k", 40), 0o644, ""},
	}
	for i, tt := range tests {
		p := filepath.Join(dir, string(rune('a'+i)))
		if err := os.WriteFile(p, []byte(tt.content), tt.mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, tt.mode)
		got, err := ReadToken(p)
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Errorf("%s: got %q, err %v", tt.name, got, err)
		}
	}
}

func TestIsBareAddress(t *testing.T) {
	tests := map[string]bool{
		"bob@example.test":                   true,
		"first.last+tag@example.test":        true,
		"Bob <bob@example.test>":             false,
		"bob@example.test, x@y.test":         false,
		"--send":                             false,
		"-bob@example.test":                  false,
		`"a,b"@example.test`:                 false,
		"bob@example.test\r\nBcc: x@y":       false,
		"bob":                                false,
		"":                                   false,
		strings.Repeat("a", 250) + "@x.test": false,
	}
	for in, want := range tests {
		if got := IsBareAddress(in); got != want {
			t.Errorf("IsBareAddress(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCheckMailboxName(t *testing.T) {
	tests := map[string]bool{
		"INBOX":                  true,
		"Résumé/Ünïcødé 📬":       true,
		"Labels/Work":            true,
		"":                       false,
		"-c/etc/passwd":          false,
		"a\r\nb":                 false,
		"a\x7fb":                 false,
		"a\u0085b":               false,
		"Folders/Review\u200b":   false,
		"a\u202eb":               false,
		"\ufeffINBOX":            false,
		"Labels/Work\U000E0041":  false,
		strings.Repeat("x", 256): false,
		strings.Repeat("日", 255): true,
	}
	for in, want := range tests {
		if got := CheckMailboxName(in) == nil; got != want {
			t.Errorf("CheckMailboxName(%q) ok = %v, want %v", in, got, want)
		}
	}
}
