package consistency

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryUntilBecomesVisible(t *testing.T) {
	ctx := context.Background()
	calls := 0
	get := func(context.Context) (string, bool, error) {
		calls++
		if calls < 3 {
			return "", false, nil // not visible yet
		}
		return "obj", true, nil
	}
	v, ok, err := RetryUntil(ctx, Config{Attempts: 5, Delay: time.Millisecond}, get, nil)
	if err != nil || !ok || v != "obj" {
		t.Fatalf("got %q ok=%v err=%v", v, ok, err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

func TestRetryUntilPredicate(t *testing.T) {
	ctx := context.Background()
	vals := []string{"old", "old", "new"}
	i := 0
	get := func(context.Context) (string, bool, error) {
		v := vals[i]
		i++
		return v, true, nil
	}
	v, ok, err := RetryUntil(ctx, Config{Attempts: 5, Delay: time.Millisecond}, get,
		func(s string) bool { return s == "new" })
	if err != nil || !ok || v != "new" {
		t.Fatalf("got %q ok=%v err=%v", v, ok, err)
	}
}

func TestRetryUntilExhausted(t *testing.T) {
	ctx := context.Background()
	get := func(context.Context) (string, bool, error) { return "", false, nil }
	_, ok, err := RetryUntil(ctx, Config{Attempts: 3, Delay: time.Millisecond}, get, nil)
	if err != nil || ok {
		t.Fatalf("expected (false,nil), got ok=%v err=%v", ok, err)
	}
}

func TestRetryUntilFatalError(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	get := func(context.Context) (string, bool, error) { return "", false, boom }
	_, ok, err := RetryUntil(ctx, Config{Attempts: 3, Delay: time.Millisecond}, get, nil)
	if ok || !errors.Is(err, boom) {
		t.Fatalf("expected fatal error, got ok=%v err=%v", ok, err)
	}
}

func TestRetryUntilContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	get := func(context.Context) (string, bool, error) { return "", false, nil }
	_, ok, err := RetryUntil(ctx, Config{Attempts: 5, Delay: time.Hour}, get, nil)
	if ok || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got ok=%v err=%v", ok, err)
	}
}
