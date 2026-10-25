//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerConfig mirrors the server's JSON config (DESIGN.md section 5 and
// internal/config.Config). It is a copy so this package builds without the
// server packages; zero optional fields are omitted and take the defaults.
type ServerConfig struct {
	Himalaya              HimalayaConfig            `json:"himalaya"`
	AllowSendCapableBuild bool                      `json:"allow_send_capable_build,omitempty"`
	StateDir              string                    `json:"state_dir"`
	CallTimeoutSeconds    int                       `json:"call_timeout_seconds,omitempty"`
	Limits                LimitsConfig              `json:"limits,omitzero"`
	HTTP                  HTTPConfig                `json:"http,omitzero"`
	Accounts              map[string]*AccountConfig `json:"accounts"`
}

// HimalayaConfig pins the binary the server runs.
type HimalayaConfig struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// LimitsConfig lowers the size limits; zero keeps the 25 MiB defaults.
type LimitsConfig struct {
	MaxAttachmentBytes int64 `json:"max_attachment_bytes,omitempty"`
	MaxMessageBytes    int64 `json:"max_message_bytes,omitempty"`
}

// HTTPConfig configures the http transport.
type HTTPConfig struct {
	Listen       string   `json:"listen,omitempty"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	TokenFile    string   `json:"token_file,omitempty"`
	TLSCertFile  string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile   string   `json:"tls_key_file,omitempty"`
}

// AccountConfig is one mail account.
type AccountConfig struct {
	Email              string          `json:"email"`
	IMAP               IMAPConfig      `json:"imap"`
	Mailboxes          MailboxesConfig `json:"mailboxes,omitzero"`
	ProtectedMailboxes []string        `json:"protected_mailboxes,omitempty"`
	LabelPrefix        string          `json:"label_prefix,omitempty"`
	FilesDir           string          `json:"files_dir"`
}

// IMAPConfig is how Himalaya reaches the account's server.
type IMAPConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Security     string `json:"security"` // "tls" or "starttls"
	TLSCertFile  string `json:"tls_cert_file,omitempty"`
	PasswordFile string `json:"password_file"`
}

// MailboxesConfig maps roles to mailbox names; empty fields take the Bridge defaults.
type MailboxesConfig struct {
	Inbox   string `json:"inbox,omitempty"`
	Drafts  string `json:"drafts,omitempty"`
	Sent    string `json:"sent,omitempty"`
	Trash   string `json:"trash,omitempty"`
	Archive string `json:"archive,omitempty"`
	Junk    string `json:"junk,omitempty"`
}

// ServerOptions configures WriteServerConfig.
type ServerOptions struct {
	Fixture *Fixture            // required: the accounts point at it
	Shim    *Shim               // required: himalaya.path and himalaya.sha256
	Edit    func(*ServerConfig) // optional, applied last, before writing
}

// ServerFiles is a written server config and the files it points at, all in
// one private Root.
type ServerFiles struct {
	Root          string
	ConfigPath    string
	StateDir      string
	TokenFile     string
	Token         string            // HTTP bearer token
	PasswordFiles map[string]string // account name -> password file (0600)
	FilesDirs     map[string]string // account name -> files_dir (0700)
	ServerLog     string            // stderr of every server started from this config
	Config        ServerConfig      // as written

	mu   sync.Mutex
	live int // servers started from these files that have not exited
}

// serverStarts counts the servers StartStdio and StartHTTP started, for TestMain's argv audit.
var serverStarts atomic.Int64

// started counts a running server; the returned func marks it exited and,
// once no server from these files runs, requires that no process still
// references Root (a leaked Himalaya or secret command).
func (files *ServerFiles) started() func(testing.TB) {
	serverStarts.Add(1)
	files.mu.Lock()
	files.live++
	files.mu.Unlock()
	return func(t testing.TB) {
		t.Helper()
		files.mu.Lock()
		files.live--
		last := files.live == 0
		files.mu.Unlock()
		if last {
			AssertNoProcs(t, files.Root)
		}
	}
}

// WriteServerConfig writes a server config for accounts alice (implicit TLS)
// and bob (STARTTLS) on opts.Fixture, both trusting its CA, with the fixture's
// role names and label_prefix "Labels/". HTTP listens on 127.0.0.1:0.
// allow_send_capable_build is set when the shim's target is not the
// IMAP-only build.
func WriteServerConfig(t testing.TB, opts ServerOptions) *ServerFiles {
	t.Helper()
	if opts.Fixture == nil || opts.Shim == nil {
		t.Fatal("WriteServerConfig needs a Fixture and a Shim")
	}
	root := TempDir(t)
	files := &ServerFiles{
		Root:          root,
		ConfigPath:    filepath.Join(root, "config.json"),
		StateDir:      filepath.Join(root, "state"),
		TokenFile:     filepath.Join(root, "secrets", "http-token"),
		Token:         randomHex(t, 24),
		PasswordFiles: map[string]string{},
		FilesDirs:     map[string]string{},
		ServerLog:     filepath.Join(root, "server.log"),
	}
	for _, dir := range []string{files.StateDir, filepath.Join(root, "secrets"), filepath.Join(root, "files")} {
		mkdirPrivate(t, dir)
	}
	writeFile(t, files.TokenFile, []byte(files.Token+"\n"), 0o600)

	f := opts.Fixture
	cfg := ServerConfig{
		Himalaya:              HimalayaConfig{Path: opts.Shim.Path, SHA256: opts.Shim.SHA256},
		AllowSendCapableBuild: sendCapable(t, opts.Shim.Target),
		StateDir:              files.StateDir,
		HTTP:                  HTTPConfig{Listen: "127.0.0.1:0", TokenFile: files.TokenFile},
		Accounts:              map[string]*AccountConfig{},
	}
	for _, a := range []struct {
		user     User
		security string
		port     int
	}{{Alice, "tls", f.TLSPort}, {Bob, "starttls", f.STARTTLSPort}} {
		pw := filepath.Join(root, "secrets", a.user.Name+".password")
		writeFile(t, pw, []byte(a.user.Password+"\n"), 0o600)
		dir := filepath.Join(root, "files", a.user.Name)
		mkdirPrivate(t, dir)
		files.PasswordFiles[a.user.Name] = pw
		files.FilesDirs[a.user.Name] = dir
		cfg.Accounts[a.user.Name] = &AccountConfig{
			Email: a.user.Login,
			IMAP: IMAPConfig{
				Host: f.Host, Port: a.port, Security: a.security,
				TLSCertFile: f.PKI.CA.CertFile, PasswordFile: pw,
			},
			Mailboxes: MailboxesConfig{
				Inbox: "INBOX", Drafts: "Drafts", Sent: "Sent",
				Trash: "Trash", Archive: "Archive", Junk: "Junk",
			},
			LabelPrefix: "Labels/",
			FilesDir:    dir,
		}
	}
	if opts.Edit != nil {
		opts.Edit(&cfg)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, files.ConfigPath, data, 0o600)
	files.Config = cfg
	return files
}

func mkdirPrivate(t testing.TB, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

var serverBinary = sync.OnceValues(func() (string, error) {
	dir, err := buildDir()
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "himalaya-mail-mcp")
	cmd := exec.Command("go", "build", "-race", "-o", bin, "./cmd/himalaya-mail-mcp")
	cmd.Dir = moduleRoot()
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, out)
	}
	return bin, nil
})

// BuildServer builds ./cmd/himalaya-mail-mcp with -race, once per process,
// and returns the binary. A build failure fails the test, so a broken server
// can never pass the suite as skips.
func BuildServer(t testing.TB) string {
	t.Helper()
	bin, err := serverBinary()
	if err != nil {
		t.Fatalf("go build -race ./cmd/himalaya-mail-mcp failed: %v", err)
	}
	return bin
}

// StartStdio starts `bin -config <config> stdio` and returns a connected
// client session. extraEnv is added to the test's environment. At cleanup
// the session is closed and the server must exit cleanly; once the last
// server started from files has exited, no process may reference files.Root.
func StartStdio(t testing.TB, bin string, files *ServerFiles, extraEnv ...string) *mcp.ClientSession {
	t.Helper()
	logf := openServerLog(t, files)
	cmd := exec.Command(bin, "-config", files.ConfigPath, "stdio")
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stderr = logf
	cs, err := newClient().Connect(t.Context(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect stdio: %v%s", err, serverLogTail(files))
	}
	exited := files.started()
	t.Cleanup(func() {
		if err := cs.Close(); err != nil {
			t.Errorf("stdio server exit: %v", err)
		}
		exited(t)
		if t.Failed() {
			t.Logf("server log:%s", serverLogTail(files))
		}
	})
	return cs
}

var listeningLine = regexp.MustCompile(`\blistening addr=(\S+)`)

// StartHTTP starts `bin -config <config> http`, waits for its
// "listening addr=<host:port>" stderr line and returns the base URL (no
// path) and a session connected to <base>/mcp with the bearer token. At
// cleanup the server gets SIGTERM and must exit cleanly within 15 s; process
// leaks are checked as for StartStdio.
func StartHTTP(t testing.TB, bin string, files *ServerFiles, extraEnv ...string) (string, *mcp.ClientSession) {
	t.Helper()
	logf := openServerLog(t, files)
	cmd := exec.Command(bin, "-config", files.ConfigPath, "http")
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Stdout = logf
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := files.started()
	addrc := make(chan string, 1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			fmt.Fprintln(logf, sc.Text())
			if m := listeningLine.FindStringSubmatch(sc.Text()); m != nil {
				select {
				case addrc <- m[1]:
				default:
				}
			}
		}
		io.Copy(logf, stderr) // after an over-long line; keeps the pipe drained
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-drained:
		case <-time.After(15 * time.Second):
			t.Errorf("http server still running 15 s after SIGTERM; killing it")
			_ = cmd.Process.Kill()
			<-drained
		}
		if err := cmd.Wait(); err != nil {
			t.Errorf("http server exit: %v", err)
		}
		exited(t)
		if t.Failed() {
			t.Logf("server log:%s", serverLogTail(files))
		}
	})
	var base string
	select {
	case addr := <-addrc:
		base = "http://" + addr
	case <-drained:
		t.Fatalf("http server exited before listening%s", serverLogTail(files))
	case <-time.After(30 * time.Second):
		t.Fatalf("no %q line from the http server within 30 s%s", "listening addr=", serverLogTail(files))
	}
	cs, err := ConnectHTTP(t, base, files.Token, "")
	if err != nil {
		t.Fatalf("connect http: %v%s", err, serverLogTail(files))
	}
	return base, cs
}

// ConnectHTTP connects a client session to <baseURL>/mcp, sending the bearer
// token on every request (none when token is empty). protocolVersion ""
// selects the SDK's latest. A connected session is closed at cleanup.
func ConnectHTTP(t testing.TB, baseURL, token, protocolVersion string) (*mcp.ClientSession, error) {
	t.Helper()
	tr := &mcp.StreamableClientTransport{
		Endpoint:   baseURL + "/mcp",
		HTTPClient: &http.Client{Transport: bearerTransport{token: token, base: http.DefaultTransport}},
		MaxRetries: -1,
	}
	var opts *mcp.ClientSessionOptions
	if protocolVersion != "" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: protocolVersion}
	}
	cs, err := newClient().Connect(t.Context(), tr, opts)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { cs.Close() })
	return cs, nil
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if b.token == "" {
		return b.base.RoundTrip(r)
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func newClient() *mcp.Client {
	return mcp.NewClient(&mcp.Implementation{Name: "hmcp-e2e", Version: "0"}, nil)
}

// resultText joins the text content of a tool result. A server tool error
// reads "<code>: <sentence>".
func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func openServerLog(t testing.TB, files *ServerFiles) *os.File {
	t.Helper()
	f, err := os.OpenFile(files.ServerLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// serverLogTail returns the last 60 lines of the server log, newline-prefixed.
func serverLogTail(files *ServerFiles) string {
	data, err := os.ReadFile(files.ServerLog)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		return "\n(server log: " + err.Error() + ")"
	}
	lines := strings.Split(string(bytes.TrimRight(data, "\n")), "\n")
	return "\n" + strings.Join(lines[max(0, len(lines)-60):], "\n")
}
