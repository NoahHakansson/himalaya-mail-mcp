// Package httpapi serves the MCP server over Streamable HTTP with an exact
// Host allowlist, cross-origin protection and a static bearer token.
package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Path is the only path served.
const Path = "/mcp"

// MaxBodyBytes bounds every request body.
const MaxBodyBytes = 4 << 20

// Handler serves srv at /mcp only (404 elsewhere). Middleware, outermost
// first: the exact Host allowlist (403), http.CrossOriginProtection (403 for
// cross-site browser requests), and the bearer token (401). The SDK handler
// is stateless and answers GET and DELETE with 405.
func Handler(srv *mcp.Server, allowedHosts []string, token string) http.Handler {
	var h http.Handler = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{
			Stateless:                    true,
			JSONResponse:                 true,
			PropagateRequestCancellation: true,
			MaxRequestBodyBytes:          MaxBodyBytes,
		})
	h = auth.RequireBearerToken(verifier(token), &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(h)
	h = http.NewCrossOriginProtection().Handler(h)
	h = requireHost(allowedHosts, h)
	mux := http.NewServeMux()
	mux.Handle(Path, h)
	return mux
}

// verifier compares sha256 digests in constant time, so the comparison
// does not depend on the presented token's length or content.
func verifier(token string) auth.TokenVerifier {
	want := sha256.Sum256([]byte(token))
	return func(_ context.Context, got string, _ *http.Request) (*auth.TokenInfo, error) {
		sum := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: "service"}, nil
	}
}

// requireHost rejects requests whose Host is not exactly one of allowed
// (host names compared case-insensitively). Unlike the SDK's loopback check,
// it also refuses localhost:<port> when only 127.0.0.1:<port> is allowed.
func requireHost(allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.ContainsFunc(allowed, func(h string) bool { return strings.EqualFold(h, r.Host) }) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Options configures NewServer.
type Options struct {
	CallTimeout time.Duration
	TLS         *tls.Config // nil serves plain HTTP
	Log         *slog.Logger
}

// NewServer returns the http.Server with the timeouts from DESIGN section 8.
func NewServer(h http.Handler, o Options) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      o.CallTimeout + 10*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig:         o.TLS,
		ErrorLog:          slog.NewLogLogger(o.Log.Handler(), slog.LevelWarn),
	}
}

// Serve runs srv on ln until ctx ends, then shuts down, waiting at most 10 s
// for requests in flight. The caller then cancels any tool calls still
// running, which kills their Himalaya processes.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := srv.Shutdown(sctx)
	if serr := <-errc; !errors.Is(serr, http.ErrServerClosed) && err == nil {
		err = serr
	}
	return err
}
