package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	token    = "0123456789abcdef0123456789abcdef-token"
	host     = "127.0.0.1:8765"
	initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
)

// readSpy records whether the handler read the request body.
type readSpy struct {
	r    io.Reader
	read bool
}

func (s *readSpy) Read(p []byte) (int, error) { s.read = true; return s.r.Read(p) }

func TestHandler(t *testing.T) {
	h := Handler(mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil), []string{host}, token)
	tests := []struct {
		name    string
		method  string
		path    string
		host    string
		headers map[string]string
		want    int
	}{
		{"initialize", "POST", "/mcp", host, map[string]string{"Authorization": "Bearer " + token}, 200},
		{"lowercase scheme", "POST", "/mcp", host, map[string]string{"Authorization": "bearer " + token}, 200},
		{"no token", "POST", "/mcp", host, nil, 401},
		{"wrong token, same length", "POST", "/mcp", host, map[string]string{"Authorization": "Bearer " + strings.Repeat("x", len(token))}, 401},
		{"short token", "POST", "/mcp", host, map[string]string{"Authorization": "Bearer 0123"}, 401},
		{"token prefix", "POST", "/mcp", host, map[string]string{"Authorization": "Bearer " + token[:len(token)-1]}, 401},
		{"basic", "POST", "/mcp", host, map[string]string{"Authorization": "Basic dTpw"}, 401},
		{"bad host", "POST", "/mcp", "evil.example", map[string]string{"Authorization": "Bearer " + token}, 403},
		{"localhost alias", "POST", "/mcp", "localhost:8765", map[string]string{"Authorization": "Bearer " + token}, 403},
		{"cross-site origin", "POST", "/mcp", host, map[string]string{"Authorization": "Bearer " + token, "Origin": "https://evil.example"}, 403},
		{"cross-site fetch", "POST", "/mcp", host, map[string]string{"Authorization": "Bearer " + token, "Sec-Fetch-Site": "cross-site"}, 403},
		{"GET", "GET", "/mcp", host, map[string]string{"Authorization": "Bearer " + token}, 405},
		{"DELETE", "DELETE", "/mcp", host, map[string]string{"Authorization": "Bearer " + token}, 405},
		{"other path", "POST", "/other", host, map[string]string{"Authorization": "Bearer " + token}, 404},
		{"sub path", "POST", "/mcp/x", host, map[string]string{"Authorization": "Bearer " + token}, 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &readSpy{r: strings.NewReader(initBody)}
			req := httptest.NewRequest(tt.method, tt.path, body)
			req.Host = tt.host
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
			if tt.want != 200 && body.read {
				t.Error("body was read before the request was rejected")
			}
		})
	}
}

func TestOversizedBody(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	// allowed_hosts defaults to the bound address, as at startup.
	srv.Config.Handler = Handler(mcp.NewServer(&mcp.Implementation{Name: "t", Version: "0"}, nil),
		[]string{srv.Listener.Addr().String()}, token)
	srv.Start()
	defer srv.Close()
	big := strings.Repeat(" ", MaxBodyBytes+1)
	for _, tt := range []struct {
		auth string
		want int
	}{{"Bearer " + token, 413}, {"", 401}} {
		req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(initBody[:len(initBody)-1]+big+"}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tt.auth != "" {
			req.Header.Set("Authorization", tt.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tt.want {
			t.Errorf("auth %q: status %d, want %d", tt.auth, resp.StatusCode, tt.want)
		}
	}
}
