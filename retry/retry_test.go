package retry

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestDoSucceedsAfterTransient(t *testing.T) {
	ctx := context.Background()
	calls := 0
	transient := errors.New("throttled")
	op := func(context.Context) error {
		calls++
		if calls < 3 {
			return transient
		}
		return nil
	}
	err := Do(ctx, Config{MaxAttempts: 5, BaseDelay: time.Millisecond, Jitter: 0}, op,
		func(error) Decision { return Backoff() })
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDoStopsOnFatal(t *testing.T) {
	ctx := context.Background()
	calls := 0
	fatal := errors.New("bad request")
	op := func(context.Context) error { calls++; return fatal }
	err := Do(ctx, Config{MaxAttempts: 5, BaseDelay: time.Millisecond}, op,
		func(error) Decision { return Stop() })
	if !errors.Is(err, fatal) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDoExhaustsAttempts(t *testing.T) {
	ctx := context.Background()
	calls := 0
	boom := errors.New("boom")
	op := func(context.Context) error { calls++; return boom }
	err := Do(ctx, Config{MaxAttempts: 3, BaseDelay: time.Millisecond, Jitter: 0}, op,
		func(error) Decision { return Backoff() })
	if !errors.Is(err, boom) || calls != 3 {
		t.Fatalf("err=%v calls=%d (want 3)", err, calls)
	}
}

func TestDoHonorsExplicitAfter(t *testing.T) {
	ctx := context.Background()
	calls := 0
	op := func(context.Context) error {
		calls++
		if calls < 2 {
			return errors.New("429")
		}
		return nil
	}
	start := time.Now()
	err := Do(ctx, Config{MaxAttempts: 3, BaseDelay: time.Hour}, op,
		func(error) Decision { return After(20 * time.Millisecond) })
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("explicit After ignored, waited %v", elapsed)
	}
}

func TestDoContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	op := func(context.Context) error { return errors.New("x") }
	err := Do(ctx, Config{MaxAttempts: 5, BaseDelay: time.Hour}, op,
		func(error) Decision { return Backoff() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestIsTransientStatus(t *testing.T) {
	for _, c := range []int{408, 429, 500, 502, 503, 504} {
		if !IsTransientStatus(c) {
			t.Errorf("%d should be transient", c)
		}
	}
	for _, c := range []int{200, 400, 401, 403, 404, 409} {
		if IsTransientStatus(c) {
			t.Errorf("%d should not be transient", c)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if d := ParseRetryAfter("30", now); d != 30*time.Second {
		t.Errorf("seconds: got %v", d)
	}
	if d := ParseRetryAfter("", now); d != 0 {
		t.Errorf("empty: got %v", d)
	}
	if d := ParseRetryAfter("garbage", now); d != 0 {
		t.Errorf("garbage: got %v", d)
	}
	future := now.Add(45 * time.Second).UTC().Format(http.TimeFormat)
	if d := ParseRetryAfter(future, now); d < 44*time.Second || d > 45*time.Second {
		t.Errorf("http-date: got %v", d)
	}
	past := now.Add(-time.Hour).UTC().Format(http.TimeFormat)
	if d := ParseRetryAfter(past, now); d != 0 {
		t.Errorf("past date should be 0, got %v", d)
	}
}
