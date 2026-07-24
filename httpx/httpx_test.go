package httpx

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"testing"

	"github.com/andybalholm/brotli"
)

func TestNewCorrelationID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewCorrelationID()
		if !re.MatchString(id) {
			t.Fatalf("not a v4 GUID: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id: %q", id)
		}
		seen[id] = true
	}
}

func TestIsNotFound(t *testing.T) {
	if !IsNotFound(&APIError{Status: 404}) {
		t.Error("404 APIError should be not-found")
	}
	if IsNotFound(&APIError{Status: 403}) {
		t.Error("403 is not not-found")
	}
	if IsNotFound(fmt.Errorf("plain error")) {
		t.Error("plain error is not not-found")
	}
	// wrapped
	if !IsNotFound(fmt.Errorf("wrapped: %w", &APIError{Status: 404})) {
		t.Error("wrapped 404 should be not-found")
	}
}

func TestDecodeBody(t *testing.T) {
	const payload = `[{"Identity":"Global"}]`
	cases := map[string]func() ([]byte, string){
		"plain": func() ([]byte, string) { return []byte(payload), "" },
		"gzip": func() ([]byte, string) {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			zw.Write([]byte(payload))
			zw.Close()
			return buf.Bytes(), "gzip"
		},
		"br": func() ([]byte, string) {
			var buf bytes.Buffer
			bw := brotli.NewWriter(&buf)
			bw.Write([]byte(payload))
			bw.Close()
			return buf.Bytes(), "br"
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			raw, enc := mk()
			resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(raw))}
			if enc != "" {
				resp.Header.Set("Content-Encoding", enc)
			}
			out, err := DecodeBody(resp)
			if err != nil {
				t.Fatalf("DecodeBody: %v", err)
			}
			if string(out) != payload {
				t.Errorf("got %q, want %q", out, payload)
			}
		})
	}
}
