// Package consistency provides bounded retry helpers for the eventually
// consistent Microsoft admin APIs (Exchange Online / Purview, Graph, ARM).
//
// These APIs are read-your-writes consistent only within a single backend
// session. A create or update performed in one session is frequently not yet
// visible to a read issued from a different session (a later CLI invocation,
// another worker, a Terraform refresh in a separate process). The object
// materialises after a short, unbounded-in-principle but usually small window.
//
// The rule of thumb for any client on top of these APIs is therefore: after a
// write, retry reads until the resource becomes visible (and, for updates,
// until the read reflects the value that was written) before concluding that
// the object is absent or that the server disagrees with the desired state.
//
// RetryUntil implements exactly that loop and is deliberately free of any
// dependency on the admin API client so it can be reused by every consumer
// (both Terraform providers, ad-hoc tooling).
package consistency

import (
	"context"
	"time"
)

// DefaultAttempts and DefaultDelay bound a retry loop when Config leaves them
// unset: ~40s of polling, which comfortably covers observed propagation windows
// while still failing fast enough to be usable interactively.
const (
	DefaultAttempts = 10
	DefaultDelay    = 4 * time.Second
)

// Config bounds a RetryUntil loop. The zero value is valid and uses the
// package defaults.
type Config struct {
	Attempts int           // maximum number of get attempts (<=0 uses DefaultAttempts)
	Delay    time.Duration // delay between attempts (<=0 uses DefaultDelay)
}

func (c Config) withDefaults() Config {
	if c.Attempts <= 0 {
		c.Attempts = DefaultAttempts
	}
	if c.Delay <= 0 {
		c.Delay = DefaultDelay
	}
	return c
}

// Getter fetches the current value of a resource.
//
//   - present == false signals "not visible yet" and is retryable (e.g. a 404
//     shortly after create, or an empty result set).
//   - a non-nil err is treated as fatal and aborts the loop immediately; map
//     retryable not-found conditions to (zero, false, nil) inside the Getter.
type Getter[T any] func(context.Context) (value T, present bool, err error)

// RetryUntil polls get until it returns a present value satisfying pred, the
// attempt budget is exhausted, or the context is cancelled.
//
// A nil pred means "present is sufficient" (retry only until the resource
// becomes visible). It returns:
//
//   - (value, true, nil)  on success;
//   - (zero, false, nil)  if the resource never became present/matching within
//     the budget (caller decides whether that means "gone" or "give up");
//   - (zero, false, err)  on a fatal Getter error or context cancellation.
func RetryUntil[T any](ctx context.Context, cfg Config, get Getter[T], pred func(T) bool) (T, bool, error) {
	cfg = cfg.withDefaults()
	var zero T
	for attempt := 0; ; attempt++ {
		v, present, err := get(ctx)
		if err != nil {
			return zero, false, err
		}
		if present && (pred == nil || pred(v)) {
			return v, true, nil
		}
		if attempt >= cfg.Attempts-1 {
			return zero, false, nil
		}
		select {
		case <-ctx.Done():
			return zero, false, ctx.Err()
		case <-time.After(cfg.Delay):
		}
	}
}
