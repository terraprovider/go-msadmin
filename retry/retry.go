// Package retry provides transient-error and rate-limit aware retries for the
// Microsoft admin APIs (Exchange Online / Purview, Teams, Graph, ARM).
//
// Every one of these services throttles with HTTP 429 (often carrying a
// Retry-After header) and returns transient 5xx / network errors under load,
// so every client on top of them — the Exchange/SCC cmdlet transport, the Teams
// REST client, ad-hoc tooling — needs the same behaviour: honour Retry-After
// when present, otherwise back off exponentially with jitter, and give up after
// a bounded number of attempts. Centralising it here keeps that policy uniform
// and TF-free (importable by pure API clients without pulling heavier deps).
package retry

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Defaults for a Config left zero-valued.
const (
	DefaultMaxAttempts = 5
	DefaultBaseDelay   = 1 * time.Second
	DefaultMaxDelay    = 30 * time.Second
	DefaultJitter      = 0.2
)

// Config bounds a Do loop. The zero value is valid and uses the defaults above.
type Config struct {
	MaxAttempts int           // total attempts including the first (<=0 -> DefaultMaxAttempts)
	BaseDelay   time.Duration // base of the exponential backoff (<=0 -> DefaultBaseDelay)
	MaxDelay    time.Duration // per-wait cap (<=0 -> DefaultMaxDelay)
	Jitter      float64       // fraction of the delay to randomise, [0,1) (<0 -> DefaultJitter)
}

func (c Config) withDefaults() Config {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.BaseDelay <= 0 {
		c.BaseDelay = DefaultBaseDelay
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = DefaultMaxDelay
	}
	if c.Jitter < 0 {
		c.Jitter = DefaultJitter
	}
	return c
}

// Decision tells Do how to treat the error returned by an operation.
type Decision struct {
	Retry bool
	// After, when > 0, overrides the computed backoff for the next wait — used
	// to honour a server-supplied Retry-After.
	After time.Duration
}

// Stop ends the loop and returns the operation's error to the caller.
func Stop() Decision { return Decision{} }

// Backoff retries after the loop's computed exponential backoff.
func Backoff() Decision { return Decision{Retry: true} }

// After retries after an explicit delay (e.g. a parsed Retry-After).
func After(d time.Duration) Decision { return Decision{Retry: true, After: d} }

// Do runs op until it returns nil, classify returns Stop, or the attempt budget
// is exhausted — in which case the last error is returned. classify inspects
// each error to decide retriability and may request an explicit delay. A
// cancelled context aborts immediately with the context error.
func Do(ctx context.Context, cfg Config, op func(context.Context) error, classify func(error) Decision) error {
	cfg = cfg.withDefaults()
	var err error
	for attempt := 1; ; attempt++ {
		if err = op(ctx); err == nil {
			return nil
		}
		d := classify(err)
		if !d.Retry || attempt >= cfg.MaxAttempts {
			return err
		}
		wait := d.After
		if wait <= 0 {
			wait = cfg.backoff(attempt)
		}
		if wait > cfg.MaxDelay {
			wait = cfg.MaxDelay
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// backoff returns BaseDelay * 2^(attempt-1), capped at MaxDelay, with +/- Jitter.
func (c Config) backoff(attempt int) time.Duration {
	d := float64(c.BaseDelay)
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= float64(c.MaxDelay) {
			d = float64(c.MaxDelay)
			break
		}
	}
	if c.Jitter > 0 {
		// symmetric jitter in [-Jitter, +Jitter]
		d += d * c.Jitter * (rand.Float64()*2 - 1)
	}
	if d < 0 {
		d = 0
	}
	return time.Duration(d)
}

// IsTransientStatus reports whether an HTTP status code warrants a retry:
// 408 (request timeout), 429 (throttled) and the retryable 5xx codes.
func IsTransientStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	default:
		return false
	}
}

// IsTransientErr reports whether a transport-level error is worth retrying
// (timeouts and other temporary network failures).
func IsTransientErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	// context cancellation/deadline is the caller's concern, not transient.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var oe *net.OpError
	return errors.As(err, &oe)
}

// ParseRetryAfter parses an HTTP Retry-After header value, which may be either
// a number of seconds or an HTTP-date. It returns 0 when the value is absent or
// unparseable, or when the date is in the past. now is passed explicitly for
// testability.
func ParseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
