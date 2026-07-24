package httpx

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rtFunc adapts a function to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDebugTransport_LogsAndRedactsAndPreservesBodies(t *testing.T) {
	var got string // the request body the base transport actually receives
	base := rtFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		got = string(b)
		return &http.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	})

	var log bytes.Buffer
	tr := &DebugTransport{Base: base, Out: &log, Enabled: func() bool { return true }}

	req, _ := http.NewRequest("POST", "https://example.test/x", strings.NewReader(`{"in":1}`))
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("X-Ms-Cmdletname", "Set-Thing")

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	// Base still receives the request body (debug read did not consume it).
	if got != `{"in":1}` {
		t.Errorf("base got request body %q, want %q", got, `{"in":1}`)
	}
	// Downstream can still read the response body unchanged.
	rb, _ := io.ReadAll(resp.Body)
	if string(rb) != `{"ok":true}` {
		t.Errorf("downstream response body %q, want %q", rb, `{"ok":true}`)
	}

	out := log.String()
	if strings.Contains(out, "super-secret-token") {
		t.Errorf("bearer token leaked into debug log:\n%s", out)
	}
	for _, want := range []string{
		"POST https://example.test/x",
		"Authorization: [REDACTED]",
		"X-Ms-Cmdletname: Set-Thing",
		`>>> body: {"in":1}`,
		"<<< 200 OK",
		`<<< body: {"ok":true}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("debug log missing %q\n---\n%s", want, out)
		}
	}
}

func TestDebugTransport_DisabledIsPassThrough(t *testing.T) {
	called := false
	base := rtFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: 204, Status: "204", Body: http.NoBody}, nil
	})
	var log bytes.Buffer
	tr := &DebugTransport{Base: base, Out: &log, Enabled: func() bool { return false }}
	req, _ := http.NewRequest("GET", "https://example.test", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("base transport not called")
	}
	if log.Len() != 0 {
		t.Errorf("disabled transport wrote to log: %q", log.String())
	}
}

func TestIsVerbose(t *testing.T) {
	for _, s := range []string{"DEBUG", "debug", "TRACE", " trace "} {
		if !isVerbose(s) {
			t.Errorf("isVerbose(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "INFO", "WARN", "ERROR"} {
		if isVerbose(s) {
			t.Errorf("isVerbose(%q) = true, want false", s)
		}
	}
}
