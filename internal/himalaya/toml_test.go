package himalaya

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
)

func testAccount(security, cert string) *config.Account {
	return &config.Account{
		Name:  "proton",
		Email: "you@proton.me",
		IMAP: config.IMAP{Host: "127.0.0.1", Port: 1143, Security: security, TLSCertFile: cert,
			PasswordFile: "/etc/hmcp/secrets/proton.password"},
	}
}

func TestAccountTOML(t *testing.T) {
	tests := []struct {
		name string
		got  []byte
		want string
	}{
		{"starttls with pinned cert", AccountTOML(testAccount("starttls", "/etc/hmcp/bridge-cert.pem")), `[accounts.proton]
default = true
email = "you@proton.me"
imap.server = "imap://127.0.0.1:1143"
imap.starttls = true
imap.tls.cert = "/etc/hmcp/bridge-cert.pem"
imap.sasl.plain.username = "you@proton.me"
imap.sasl.plain.password.command = ["/bin/cat", "/etc/hmcp/secrets/proton.password"]
`},
		{"implicit tls without cert", AccountTOML(testAccount("tls", "")), `[accounts.proton]
default = true
email = "you@proton.me"
imap.server = "imaps://127.0.0.1:1143"
imap.sasl.plain.username = "you@proton.me"
imap.sasl.plain.password.command = ["/bin/cat", "/etc/hmcp/secrets/proton.password"]
`},
		{"per-call label config", LabelTOML(testAccount("tls", "/etc/ca.pem"), `Labels/Wörk "q" \ $HOME`), `[accounts.proton]
default = true
email = "you@proton.me"
imap.server = "imaps://127.0.0.1:1143"
imap.tls.cert = "/etc/ca.pem"
imap.sasl.plain.username = "you@proton.me"
imap.sasl.plain.password.command = ["/bin/cat", "/etc/hmcp/secrets/proton.password"]
mailbox.alias.trash = "Labels/Wörk \"q\" \\ $HOME"
`},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("%s:\n got: %s\nwant: %s", tt.name, tt.got, tt.want)
		}
	}
}

func TestPrepareState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	cfg := &config.Config{StateDir: state, Accounts: map[string]*config.Account{"proton": testAccount("tls", "")}}
	leftover := filepath.Join(state, "tmp", "dl-old")
	if err := os.MkdirAll(leftover, 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlink planted where the config goes must be replaced, not followed.
	outside := filepath.Join(t.TempDir(), "outside")
	os.MkdirAll(filepath.Join(state, "himalaya"), 0o700)
	if err := os.Symlink(outside, ConfigPath(state, "proton")); err != nil {
		t.Fatal(err)
	}
	if err := PrepareState(cfg, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Errorf("tmp was not emptied: %v", err)
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Errorf("symlink target was written")
	}
	fi, err := os.Lstat(ConfigPath(state, "proton"))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", fi.Mode(), err)
	}
	for _, d := range []string{"himalaya", "home", "tmp"} {
		if fi, err := os.Stat(filepath.Join(state, d)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi.Mode(), err)
		}
	}
}
