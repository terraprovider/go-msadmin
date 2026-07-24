// Package httpx holds small HTTP helpers shared by the Microsoft admin REST
// clients: request correlation IDs, a uniform API error with a not-found check,
// and response-body decompression.
//
// These clients set Accept-Encoding themselves for wire fidelity (so net/http
// does not auto-decompress) and the services negotiate brotli, gzip and deflate —
// so decoding is centralised here. This is the one place go-msadmin takes a
// dependency (a pure-Go brotli decoder); everything else stays dependency-free.
package httpx

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// NewCorrelationID returns a random RFC-4122 v4 GUID (lowercase), suitable for the
// per-request correlation headers these APIs expect (client-request-id,
// X-MS-Correlation-Id, …).
func NewCorrelationID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// APIError is a non-2xx response from a Microsoft admin API. Clients parse their
// own error envelope into it; consumers use IsNotFound (and errors.As) uniformly.
type APIError struct {
	Status  int    // HTTP status code
	Code    string // service error code, if any
	Message string // human-readable message
	Body    string // raw response body (truncated by the client), for debugging
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s (%s, http %d)", e.Message, e.Code, e.Status)
	}
	return fmt.Sprintf("%s (http %d)", e.Message, e.Status)
}

// IsNotFound reports whether err (or anything it wraps) is an APIError with HTTP
// 404 — i.e. a missing object. Terraform providers wire their isNotFound to this.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// DecodeBody reads resp.Body (closing it) and returns the decompressed bytes,
// honouring Content-Encoding: br | gzip | deflate. It is defensive — some error
// responses advertise gzip yet aren't — so on any decode failure it falls back to
// the raw bytes rather than erroring.
func DecodeBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return decode(resp.Header.Get("Content-Encoding"), raw), nil
}

// decode decompresses raw per Content-Encoding (br | gzip | deflate). It is
// defensive — some error responses advertise gzip yet aren't — so on any decode
// failure it returns the raw bytes unchanged. Shared by DecodeBody and the debug
// transport's response-body logging.
func decode(encoding string, raw []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "br":
		if out, e := io.ReadAll(brotli.NewReader(bytes.NewReader(raw))); e == nil && len(out) > 0 {
			return out
		}
	case "gzip":
		if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
			if zr, e := gzip.NewReader(bytes.NewReader(raw)); e == nil {
				defer zr.Close()
				if out, e := io.ReadAll(zr); e == nil {
					return out
				}
			}
		}
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		if out, e := io.ReadAll(fr); e == nil {
			return out
		}
	}
	return raw
}
