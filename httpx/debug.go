package httpx

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// DebugEnabled reports whether full HTTP request/response logging is on. It is
// enabled when Terraform's log level is DEBUG or TRACE (via TF_LOG or the
// provider-scoped TF_LOG_PROVIDER), or when MSADMIN_HTTP_DEBUG is set to any
// non-empty value (a standalone toggle for non-Terraform callers/tests).
func DebugEnabled() bool {
	if os.Getenv("MSADMIN_HTTP_DEBUG") != "" {
		return true
	}
	return isVerbose(os.Getenv("TF_LOG_PROVIDER")) || isVerbose(os.Getenv("TF_LOG"))
}

func isVerbose(level string) bool {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG", "TRACE":
		return true
	}
	return false
}

// DebugTransport is an http.RoundTripper that logs the full request and response —
// method, URL, headers (with credentials redacted), and body — when DebugEnabled
// reports true; otherwise it is a transparent pass-through. Response bodies are
// decompressed for display (br/gzip/deflate), and the response handed downstream is
// left byte-for-byte unchanged.
//
// Wrap it as the base of retry.NewTransport so every attempt (and the service
// discovery handshake) is logged:
//
//	client := &http.Client{Transport: retry.NewTransport(httpx.NewDebugTransport(nil), cfg)}
type DebugTransport struct {
	Base http.RoundTripper // nil -> http.DefaultTransport
	Out  io.Writer         // nil -> os.Stderr
	// Enabled overrides the env-based check; nil -> DebugEnabled. For tests.
	Enabled func() bool
}

// NewDebugTransport wraps base (nil -> http.DefaultTransport) with debug logging.
func NewDebugTransport(base http.RoundTripper) *DebugTransport {
	return &DebugTransport{Base: base}
}

func (t *DebugTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *DebugTransport) out() io.Writer {
	if t.Out != nil {
		return t.Out
	}
	return os.Stderr
}

func (t *DebugTransport) enabled() bool {
	if t.Enabled != nil {
		return t.Enabled()
	}
	return DebugEnabled()
}

var debugSeq atomic.Uint64

// RoundTrip implements http.RoundTripper.
func (t *DebugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.enabled() {
		return t.base().RoundTrip(req)
	}
	out := t.out()
	id := fmt.Sprintf("%04d", debugSeq.Add(1)%10000) // pair request/response lines

	fmt.Fprintf(out, "[http %s] >>> %s %s\n", id, req.Method, req.URL.String())
	writeHeaders(out, id, ">>>", req.Header)
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body)) // restore for the real send
		if len(body) > 0 {
			fmt.Fprintf(out, "[http %s] >>> body: %s\n", id, body)
		}
	}

	start := time.Now()
	resp, err := t.base().RoundTrip(req)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(out, "[http %s] <<< transport error after %s: %v\n", id, elapsed, err)
		return resp, err
	}

	fmt.Fprintf(out, "[http %s] <<< %s (%s)\n", id, resp.Status, elapsed)
	writeHeaders(out, id, "<<<", resp.Header)
	if resp.Body != nil {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(raw)) // hand downstream the untouched bytes
		if len(raw) > 0 {
			fmt.Fprintf(out, "[http %s] <<< body: %s\n", id, decode(resp.Header.Get("Content-Encoding"), raw))
		}
	}
	return resp, err
}

// writeHeaders prints headers in sorted order, redacting credential-bearing ones.
func writeHeaders(out io.Writer, id, dir string, h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.Join(h[k], ", ")
		if sensitiveHeader(k) {
			v = "[REDACTED]"
		}
		fmt.Fprintf(out, "[http %s] %s %s: %s\n", id, dir, k, v)
	}
}

// sensitiveHeader reports whether a header carries a credential and must be redacted
// so full request logging never leaks bearer tokens, cookies or secrets.
func sensitiveHeader(k string) bool {
	switch http.CanonicalHeaderKey(k) {
	case "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Ms-Aad-Token":
		return true
	}
	lk := strings.ToLower(k)
	return strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "password")
}
