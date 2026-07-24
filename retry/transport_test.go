package retry

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mkResp(code int, hdr map[string]string) *http.Response {
	h := http.Header{}
	for k, v := range hdr {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader("x"))}
}

func TestTransportRetries429ThenSucceeds(t *testing.T) {
	calls := 0
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return mkResp(429, map[string]string{"Retry-After": "0"}), nil
		}
		return mkResp(200, nil), nil
	})
	tr := &Transport{Base: base, Config: Config{MaxAttempts: 3, BaseDelay: time.Millisecond, Jitter: 0}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://x", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 || calls != 2 {
		t.Fatalf("code=%v err=%v calls=%d", resp.StatusCode, err, calls)
	}
}

func TestTransportGivesUpAfterMax(t *testing.T) {
	calls := 0
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return mkResp(503, nil), nil
	})
	tr := &Transport{Base: base, Config: Config{MaxAttempts: 3, BaseDelay: time.Millisecond, Jitter: 0}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://x", nil)
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 503 || calls != 3 {
		t.Fatalf("code=%v err=%v calls=%d", resp.StatusCode, err, calls)
	}
}

func TestTransportNoRetryOn400(t *testing.T) {
	calls := 0
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return mkResp(400, nil), nil
	})
	tr := &Transport{Base: base, Config: Config{MaxAttempts: 3, BaseDelay: time.Millisecond}}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://x", nil)
	_, err := tr.RoundTrip(req)
	if err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d (want 1)", err, calls)
	}
}
