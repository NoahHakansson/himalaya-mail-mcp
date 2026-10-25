// Package config loads and validates the wrapper's JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Defaults applied by Load when a field is absent or zero.
const (
	DefaultCallTimeoutSeconds = 25
	MaxCallTimeoutSeconds     = 280
	DefaultMaxAttachmentBytes = 25 << 20
	DefaultMaxMessageBytes    = 25 << 20
	DefaultListen             = "127.0.0.1:8765"
)

// DefaultMailboxes are the Proton Bridge role names.
var DefaultMailboxes = Mailboxes{
	Inbox: "INBOX", Drafts: "Drafts", Sent: "Sent",
	Trash: "Trash", Archive: "Archive", Junk: "Spam",
}

// DefaultProtectedMailboxes are the Bridge mailboxes that are never a move or label source or target.
var DefaultProtectedMailboxes = []string{"All Mail", "Starred", "Scheduled", "Recovered Messages"}

// Config is the whole wrapper configuration.
type Config struct {
	Himalaya              Himalaya            `json:"himalaya"`
	AllowSendCapableBuild bool                `json:"allow_send_capable_build"`
	StateDir              string              `json:"state_dir"`
	CallTimeoutSeconds    int                 `json:"call_timeout_seconds"`
	Limits                Limits              `json:"limits"`
	HTTP                  HTTP                `json:"http"`
	Accounts              map[string]*Account `json:"accounts"`
}

// Himalaya pins the binary the wrapper runs.
type Himalaya struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Limits bounds message and attachment sizes.
type Limits struct {
	MaxAttachmentBytes int64 `json:"max_attachment_bytes"`
	MaxMessageBytes    int64 `json:"max_message_bytes"`
}

// HTTP configures the Streamable HTTP transport.
type HTTP struct {
	Listen       string   `json:"listen"`
	AllowedHosts []string `json:"allowed_hosts"`
	TokenFile    string   `json:"token_file"`
	TLSCertFile  string   `json:"tls_cert_file"`
	TLSKeyFile   string   `json:"tls_key_file"`
}

// Account is one mail account. Name is filled in from the map key.
type Account struct {
	Name               string    `json:"-"`
	Email              string    `json:"email"`
	IMAP               IMAP      `json:"imap"`
	Mailboxes          Mailboxes `json:"mailboxes"`
	ProtectedMailboxes []string  `json:"protected_mailboxes"`
	LabelPrefix        string    `json:"label_prefix"`
	FilesDir           string    `json:"files_dir"`
}

// IMAP describes how Himalaya reaches the account's server.
type IMAP struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Security     string `json:"security"`
	TLSCertFile  string `json:"tls_cert_file"`
	PasswordFile string `json:"password_file"`
}

// Mailboxes maps roles to mailbox names.
type Mailboxes struct {
	Inbox   string `json:"inbox"`
	Drafts  string `json:"drafts"`
	Sent    string `json:"sent"`
	Trash   string `json:"trash"`
	Archive string `json:"archive"`
	Junk    string `json:"junk"`
}

// Security modes. There is no cleartext mode.
const (
	SecurityTLS      = "tls"
	SecurityStartTLS = "starttls"
)

var (
	accountNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	hostRe        = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	sha256Re      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Load reads, defaults and validates the config file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse decodes a config document, rejecting unknown fields, then applies defaults and validates it.
func Parse(raw []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: trailing data after the JSON object")
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.CallTimeoutSeconds == 0 {
		c.CallTimeoutSeconds = DefaultCallTimeoutSeconds
	}
	if c.Limits.MaxAttachmentBytes == 0 {
		c.Limits.MaxAttachmentBytes = DefaultMaxAttachmentBytes
	}
	if c.Limits.MaxMessageBytes == 0 {
		c.Limits.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = DefaultListen
	}
	for name, a := range c.Accounts {
		if a == nil {
			continue
		}
		a.Name = name
		m, d := &a.Mailboxes, DefaultMailboxes
		for _, f := range []struct {
			v   *string
			def string
		}{
			{&m.Inbox, d.Inbox}, {&m.Drafts, d.Drafts}, {&m.Sent, d.Sent},
			{&m.Trash, d.Trash}, {&m.Archive, d.Archive}, {&m.Junk, d.Junk},
		} {
			if *f.v == "" {
				*f.v = f.def
			}
		}
		m.Inbox = NormalizeMailbox(m.Inbox)
		if a.ProtectedMailboxes == nil {
			a.ProtectedMailboxes = slices.Clone(DefaultProtectedMailboxes)
		}
	}
}

func (c *Config) validate() error {
	if err := checkPath("himalaya.path", c.Himalaya.Path); err != nil {
		return err
	}
	if !sha256Re.MatchString(c.Himalaya.SHA256) {
		return errors.New("himalaya.sha256 must be 64 lowercase hex digits")
	}
	if err := checkPath("state_dir", c.StateDir); err != nil {
		return err
	}
	if c.CallTimeoutSeconds < 1 || c.CallTimeoutSeconds > MaxCallTimeoutSeconds {
		return fmt.Errorf("call_timeout_seconds must be 1..%d", MaxCallTimeoutSeconds)
	}
	if c.Limits.MaxAttachmentBytes < 1 || c.Limits.MaxMessageBytes < 1 {
		return errors.New("limits must be positive")
	}
	if err := c.validateHTTP(); err != nil {
		return err
	}
	if len(c.Accounts) == 0 {
		return errors.New("at least one account is required")
	}
	for _, name := range c.AccountNames() {
		if err := c.validateAccount(c.Accounts[name]); err != nil {
			return fmt.Errorf("accounts.%s: %w", name, err)
		}
	}
	return c.validateDirs()
}

func (c *Config) validateHTTP() error {
	h := c.HTTP
	host, port, err := net.SplitHostPort(h.Listen)
	if err != nil {
		return fmt.Errorf("http.listen: %w", err)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		return errors.New("http.listen: invalid port")
	}
	for _, f := range []struct{ name, path string }{
		{"http.token_file", h.TokenFile}, {"http.tls_cert_file", h.TLSCertFile}, {"http.tls_key_file", h.TLSKeyFile},
	} {
		if f.path == "" {
			continue
		}
		if err := checkPath(f.name, f.path); err != nil {
			return err
		}
	}
	if (h.TLSCertFile == "") != (h.TLSKeyFile == "") {
		return errors.New("http.tls_cert_file and http.tls_key_file must be set together")
	}
	for _, ah := range h.AllowedHosts {
		if ah == "" || strings.ContainsFunc(ah, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
			return fmt.Errorf("http.allowed_hosts: invalid entry %q", ah)
		}
	}
	if !isLoopbackHost(host) && (len(h.AllowedHosts) == 0 || h.TLSCertFile == "") {
		return errors.New("http.listen is not loopback, so http.allowed_hosts and TLS are required")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) validateAccount(a *Account) error {
	if a == nil {
		return errors.New("account is null")
	}
	if !accountNameRe.MatchString(a.Name) || a.Name == "default" {
		return errors.New(`name must match ^[a-z][a-z0-9-]{0,31}$ and must not be "default"`)
	}
	if err := checkEmail(a.Email); err != nil {
		return err
	}
	im := a.IMAP
	if !hostRe.MatchString(im.Host) {
		return errors.New("imap.host must match ^[A-Za-z0-9.-]{1,253}$")
	}
	if im.Port < 1 || im.Port > 65535 {
		return errors.New("imap.port must be 1..65535")
	}
	if im.Security != SecurityTLS && im.Security != SecurityStartTLS {
		return errors.New(`imap.security must be "tls" or "starttls"`)
	}
	if im.TLSCertFile != "" {
		if err := checkPath("imap.tls_cert_file", im.TLSCertFile); err != nil {
			return err
		}
	}
	if err := checkPath("imap.password_file", im.PasswordFile); err != nil {
		return err
	}
	if err := checkPath("files_dir", a.FilesDir); err != nil {
		return err
	}

	if a.LabelPrefix != "" {
		if err := CheckMailboxName(a.LabelPrefix); err != nil {
			return fmt.Errorf("label_prefix: %w", err)
		}
		if !strings.HasSuffix(a.LabelPrefix, "/") {
			return errors.New(`label_prefix must end with "/"`)
		}
	}
	for _, p := range a.ProtectedMailboxes {
		if err := CheckMailboxName(p); err != nil {
			return fmt.Errorf("protected_mailboxes: %w", err)
		}
	}
	roles := a.Mailboxes.Roles()
	for i, r := range roles {
		if err := CheckMailboxName(r.Name); err != nil {
			return fmt.Errorf("mailboxes.%s: %w", r.Role, err)
		}
		if a.IsProtected(r.Name) {
			return fmt.Errorf("mailboxes.%s must not be a protected mailbox", r.Role)
		}
		if a.LabelPrefix != "" && hasFoldPrefix(r.Name, a.LabelPrefix) {
			return fmt.Errorf("mailboxes.%s must not be under label_prefix", r.Role)
		}
		for _, o := range roles[:i] {
			if strings.EqualFold(o.Name, r.Name) {
				return fmt.Errorf("mailboxes.%s and mailboxes.%s must differ", o.Role, r.Role)
			}
		}
	}
	return nil
}

// validateDirs keeps files_dir trees apart from each other, from the state
// directories Himalaya uses, and from every secret file. The comparison is
// lexical; CheckSecrets and CheckDirs make it exact by refusing symlinks.
func (c *Config) validateDirs() error {
	state := c.StateDir
	reserved := []string{
		filepath.Join(state, "himalaya"), filepath.Join(state, "home"), filepath.Join(state, "tmp"),
	}
	// The certificate counts too: it may be a combined file holding the key.
	secrets := []string{c.HTTP.TokenFile, c.HTTP.TLSKeyFile, c.HTTP.TLSCertFile}
	for _, a := range c.Accounts {
		secrets = append(secrets, a.IMAP.PasswordFile)
	}
	names := c.AccountNames()
	for i, n := range names {
		dir := c.Accounts[n].FilesDir
		if within(dir, state) {
			return fmt.Errorf("accounts.%s.files_dir must not contain state_dir", n)
		}
		for _, r := range reserved {
			if within(r, dir) {
				return fmt.Errorf("accounts.%s.files_dir must not be inside %s", n, r)
			}
		}
		for _, o := range names[:i] {
			od := c.Accounts[o].FilesDir
			if within(dir, od) || within(od, dir) {
				return fmt.Errorf("accounts.%s.files_dir and accounts.%s.files_dir overlap", o, n)
			}
		}
		for _, s := range secrets {
			if s != "" && within(dir, s) {
				return fmt.Errorf("secret file %s is inside accounts.%s.files_dir", s, n)
			}
		}
	}
	for _, s := range secrets {
		if s != "" && within(state, s) {
			return fmt.Errorf("secret file %s is inside state_dir", s)
		}
	}
	return nil
}

// within reports whether path equals dir or lies below it. Both are clean absolute paths.
func within(dir, path string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// AccountNames returns the configured account names in sorted order.
func (c *Config) AccountNames() []string {
	names := make([]string, 0, len(c.Accounts))
	for n := range c.Accounts {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// RoleMailbox pairs a role with its mailbox name.
type RoleMailbox struct{ Role, Name string }

// Roles lists the six roles in a fixed order.
func (m Mailboxes) Roles() []RoleMailbox {
	return []RoleMailbox{
		{"inbox", m.Inbox}, {"drafts", m.Drafts}, {"sent", m.Sent},
		{"trash", m.Trash}, {"archive", m.Archive}, {"junk", m.Junk},
	}
}

// IsProtected reports whether name is one of the account's protected mailboxes (case-insensitive).
func (a *Account) IsProtected(name string) bool {
	return slices.ContainsFunc(a.ProtectedMailboxes, func(p string) bool { return strings.EqualFold(p, name) })
}

func hasFoldPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// checkPath enforces the path rule: absolute, clean, and free of the
// characters Himalaya expands or splits on ($ ~ :) and of control characters.
func checkPath(field, p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%s is required", field)
	case !filepath.IsAbs(p) || filepath.Clean(p) != p:
		return fmt.Errorf("%s must be an absolute, clean path", field)
	case strings.ContainsAny(p, "$~:\"\\"):
		return fmt.Errorf("%s must not contain $ ~ : \" or \\", field)
	case hasControl(p) || !utf8.ValidString(p) || len(p) > 4096:
		return fmt.Errorf("%s contains invalid characters", field)
	}
	return nil
}

func checkEmail(s string) error {
	if strings.ContainsAny(s, "$~:") {
		return errors.New("email must not contain $ ~ or :")
	}
	if !IsBareAddress(s) {
		return errors.New("email must be a bare address such as user@example.com")
	}
	return nil
}

// IsBareAddress reports whether s is a plain addr-spec of at most 254 bytes
// that net/mail parses back to itself with no display name.
func IsBareAddress(s string) bool {
	if s == "" || len(s) > 254 || s[0] == '-' || strings.ContainsAny(s, " \t\r\n\",;<>()[]\\") || hasControl(s) {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s
}

// CheckMailboxName applies the mailbox rule: 1..255 code points, at most 1000
// bytes, valid UTF-8, no IsUnsafeRune character, and no leading '-'.
func CheckMailboxName(s string) error {
	switch {
	case s == "":
		return errors.New("mailbox name is empty")
	case !utf8.ValidString(s):
		return errors.New("mailbox name is not valid UTF-8")
	case len(s) > 1000 || utf8.RuneCountInString(s) > 255:
		return errors.New("mailbox name is too long")
	case s[0] == '-':
		return errors.New("mailbox name must not start with '-'")
	case strings.ContainsFunc(s, IsUnsafeRune):
		return errors.New("mailbox name contains control or invisible characters")
	}
	return nil
}

// IsUnsafeRune reports characters that are invisible or change how the text
// around them reads: C0, DEL, C1, bidi controls, zero-width characters and
// tag characters. Mailbox names must not hold them, and mail text shown to
// the agent loses them (except newline and tab), so a mailbox name that
// passes CheckMailboxName is shown exactly as the server has it.
func IsUnsafeRune(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f,
		r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069,
		r >= 0x200b && r <= 0x200f, r >= 0x2060 && r <= 0x2064,
		r == 0xfeff, r >= 0xe0000 && r <= 0xe007f:
		return true
	}
	return false
}

// NormalizeMailbox turns any spelling of inbox into INBOX.
func NormalizeMailbox(s string) string {
	if strings.EqualFold(s, "INBOX") {
		return "INBOX"
	}
	return s
}

// hasControl reports C0, DEL and C1 characters.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}
