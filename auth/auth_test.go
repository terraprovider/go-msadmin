package auth

import (
	"context"
	"testing"
)

func TestStaticToken(t *testing.T) {
	var tp TokenProvider = StaticToken("abc")
	got, err := tp.Token(context.Background(), "any-resource")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != "abc" {
		t.Errorf("Token = %q, want abc", got)
	}
	if _, err := StaticToken("").Token(context.Background(), ""); err == nil {
		t.Error("empty StaticToken should error")
	}
}
