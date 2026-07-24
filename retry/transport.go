package retry

import (
	"io"
	"net/http"
	"time"
)

// Transport is an http.RoundTripper that transparently retries transient
// responses (429 and retryable 5xx) and transient transport errors, honouring a
// server Retry-After header when present and otherwise backing off per Config.
//
// It replays the request body via Request.GetBody, which net/http populates
// automatically for requests created from a []byte/string/bytes.Buffer body, so
// the standard InvokeCommand POST and page GETs retry safely.
type Transport struct {
	Base   http.RoundTripper // nil -> http.DefaultTransport
	Config Config
	// now returns the current time; nil -> time.Now. Overridable in tests.
	now func() time.Time
}

// NewTransport wraps base with retry behaviour using cfg.
func NewTransport(base http.RoundTripper, cfg Config) *Transport {
	return &Transport{Base: base, Config: cfg}
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) clock() time.Time {
	if t.now != nil {
		return t.now()
	}
	return time.Now()
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	cfg := t.Config.withDefaults()
	ctx := req.Context()

	var resp *http.Response
	var err error
	for attempt := 1; ; attempt++ {
		// Replay the body on every attempt after the first.
		if attempt > 1 && req.Body != nil {
			if req.GetBody == nil {
				return resp, err // cannot safely replay: return the last result
			}
			body, gerr := req.GetBody()
			if gerr != nil {
				return resp, err
			}
			req.Body = body
		}

		resp, err = t.base().RoundTrip(req)

		var wait time.Duration
		retryable := false
		switch {
		case err != nil:
			retryable = IsTransientErr(err)
		case IsTransientStatus(resp.StatusCode):
			retryable = true
			wait = ParseRetryAfter(resp.Header.Get("Retry-After"), t.clock())
		}
		if !retryable || attempt >= cfg.MaxAttempts {
			return resp, err
		}

		// Drain and close the body so the connection can be reused.
		if resp != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			_ = resp.Body.Close()
		}
		if wait <= 0 {
			wait = cfg.backoff(attempt)
		}
		if wait > cfg.MaxDelay {
			wait = cfg.MaxDelay
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}
