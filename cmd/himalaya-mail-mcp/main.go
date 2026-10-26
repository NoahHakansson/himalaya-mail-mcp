// Command himalaya-mail-mcp is an MCP server with typed mail tools that runs
// a pinned Himalaya v2.2.1 binary with fixed argv. It cannot send mail.
//
// Usage: himalaya-mail-mcp -config <abs path> stdio|http|check
//
// Logs go to stderr as slog text. In http mode the first line after startup
// reads "msg=listening addr=<host:port>" with the bound address.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/NoahHakansson/himalaya-mail-mcp/internal/config"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/himalaya"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/httpapi"
	"github.com/NoahHakansson/himalaya-mail-mcp/internal/mailmcp"
)

const version = "0.2.0"

func main() { os.Exit(run()) }

func run() int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fs := flag.NewFlagSet("himalaya-mail-mcp", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "absolute path of the JSON config file")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	mode := fs.Arg(0)
	if fs.NArg() != 1 || !slices.Contains([]string{"stdio", "http", "check"}, mode) || !filepath.IsAbs(*cfgPath) {
		fmt.Fprintln(os.Stderr, "usage: himalaya-mail-mcp -config <abs path> stdio|http|check")
		return 2
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("startup failed", "error", err.Error())
		return 1
	}
	app, err := start(ctx, cfg, mode, log)
	if err != nil {
		log.Error("startup failed", "error", err.Error())
		return 1
	}
	defer app.close()

	switch mode {
	case "check":
		return app.check(ctx)
	case "stdio":
		err = app.server.MCP(version).Run(ctx, &mcp.StdioTransport{MaxLineLength: 4 << 20})
	case "http":
		err = app.serveHTTP(ctx, log)
	}
	app.stopCalls()
	app.runner.Wait()
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("transport stopped", "error", err.Error())
		return 1
	}
	return 0
}

// app is a started wrapper: checked binary, prepared state, open file roots.
type app struct {
	cfg       *config.Config
	runner    *himalaya.Runner
	server    *mailmcp.Server
	roots     map[string]*os.Root
	stopCalls context.CancelFunc
	token     string
}

// start runs the startup sequence of DESIGN section 5: binary checks
// (regular file, not group- or world-writable, sha256), secret files, the
// symlink checks of state_dir and every files_dir, state directories and
// generated configs, the files_dir roots, then --version and account list
// per account. No directory is changed before the symlink checks pass, and
// every path check comes before the first Himalaya run.
func start(ctx context.Context, cfg *config.Config, mode string, log *slog.Logger) (_ *app, err error) {
	bin := cfg.Himalaya.Path
	if err := config.CheckNotWritableByOthers(bin); err != nil {
		return nil, fmt.Errorf("himalaya.path: %w", err)
	}
	sum, err := himalaya.FileSHA256(bin)
	if err != nil {
		return nil, fmt.Errorf("himalaya.path: %w", err)
	}
	if sum != cfg.Himalaya.SHA256 {
		return nil, errors.New("himalaya.path does not match himalaya.sha256")
	}
	// check also covers the HTTP secrets when they are configured.
	withHTTP := mode == "http" || (mode == "check" && cfg.HTTP.TokenFile != "")
	secrets, err := cfg.CheckSecrets(withHTTP)
	if err != nil {
		return nil, err
	}
	a := &app{cfg: cfg, roots: map[string]*os.Root{}}
	defer func() {
		if err != nil {
			a.close()
		}
	}()
	if withHTTP {
		if a.token, err = config.ReadToken(cfg.HTTP.TokenFile); err != nil {
			return nil, fmt.Errorf("http.token_file: %w", err)
		}
	}
	// Before anything on disk changes, and again for the created files_dirs.
	if err := cfg.CheckDirs(); err != nil {
		return nil, err
	}
	if err := himalaya.PrepareState(cfg, mode != "check"); err != nil {
		return nil, fmt.Errorf("state_dir: %w", err)
	}
	for _, n := range cfg.AccountNames() {
		if err := os.MkdirAll(cfg.Accounts[n].FilesDir, 0o700); err != nil {
			return nil, fmt.Errorf("accounts.%s.files_dir: %w", n, err)
		}
	}
	if err := cfg.CheckDirs(); err != nil {
		return nil, err
	}
	for _, n := range cfg.AccountNames() {
		root, err := os.OpenRoot(cfg.Accounts[n].FilesDir)
		if err != nil {
			return nil, fmt.Errorf("accounts.%s.files_dir: %w", n, err)
		}
		a.roots[n] = root
	}
	a.runner = himalaya.NewRunner(bin, cfg.StateDir, cfg.AccountNames(), log)

	cctx, cancel := context.WithTimeout(himalaya.WithTool(ctx, "startup"), time.Duration(cfg.CallTimeoutSeconds)*time.Second)
	defer cancel()
	out, err := a.runner.Version(cctx)
	if err != nil {
		return nil, fmt.Errorf("himalaya --version: %w", err)
	}
	if err := himalaya.CheckVersion(out, cfg.AllowSendCapableBuild); err != nil {
		return nil, err
	}
	for _, n := range cfg.AccountNames() {
		if err := checkAccountList(cctx, a.runner, cfg, n); err != nil {
			return nil, fmt.Errorf("accounts.%s: %w", n, err)
		}
	}
	life, stopCalls := context.WithCancel(context.Background())
	a.stopCalls = stopCalls
	a.server = mailmcp.New(life, cfg, a.runner, a.roots, secrets, log)
	return a, nil
}

// checkAccountList requires the generated config to hold exactly this
// account with backends == ["imap"]. account list makes no connection.
func checkAccountList(ctx context.Context, r *himalaya.Runner, cfg *config.Config, name string) error {
	hx := himalaya.Account{Name: name, Config: himalaya.ConfigPath(cfg.StateDir, name)}
	out, err := r.Run(ctx, hx.AccountList())
	if err != nil {
		return fmt.Errorf("account list: %w", err)
	}
	entries, err := himalaya.ParseAccountList(out)
	if err != nil || len(entries) != 1 || entries[0].Name != name || !slices.Equal(entries[0].Backends, []string{"imap"}) {
		return errors.New("account list must report exactly this account with backends [imap]")
	}
	return nil
}

func (a *app) close() {
	for _, r := range a.roots {
		r.Close()
	}
}

// check logs in to every account and probes MOVE and UIDPLUS, printing one line per account.
func (a *app) check(ctx context.Context) int {
	code := 0
	for _, r := range a.server.Probe(ctx) {
		if r.Err != nil {
			fmt.Printf("%s: FAIL %v\n", r.Account, r.Err)
			code = 1
			continue
		}
		fmt.Printf("%s: ok\n", r.Account)
	}
	a.stopCalls()
	return code
}

func (a *app) serveHTTP(ctx context.Context, log *slog.Logger) error {
	h := a.cfg.HTTP
	var tlsCfg *tls.Config
	if h.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(h.TLSCertFile, h.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("http TLS: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	ln, err := net.Listen("tcp", h.Listen)
	if err != nil {
		return err
	}
	addr := ln.Addr().String()
	hosts := h.AllowedHosts
	if len(hosts) == 0 {
		hosts = []string{addr}
	}
	srv := httpapi.NewServer(httpapi.Handler(a.server.MCP(version), hosts, a.token),
		httpapi.Options{CallTimeout: time.Duration(a.cfg.CallTimeoutSeconds) * time.Second, TLS: tlsCfg, Log: log})
	log.Info("listening", "addr", addr, "tls", tlsCfg != nil)
	return httpapi.Serve(ctx, srv, ln)
}
