# go-msadmin

[![CI](https://github.com/terraprovider/go-msadmin/actions/workflows/ci.yml/badge.svg)](https://github.com/terraprovider/go-msadmin/actions/workflows/ci.yml)

Small, near-zero-dependency Go building blocks for talking to the **eventually
consistent, throttled Microsoft admin APIs** (Exchange Online / Purview, Teams,
Graph, ARM). Shared by [`go-exoscc`](https://github.com/terraprovider/go-exoscc), the
Terraform providers built on [`tf-msadmin`](https://github.com/terraprovider/tf-msadmin),
and any other client that needs the same behaviour.

The only compiled dependency is a pure-Go brotli decoder (used by `httpx`, since
these services negotiate brotli); everything else is standard library.

```bash
go get github.com/terraprovider/go-msadmin
```

## Packages

### `auth` — one token abstraction

`TokenProvider` is `Token(ctx, resource) (string, error)` — the single thing every
client needs from a credential. The MSAL-backed providers and the transports agree
on this type, so a credential built for one client composes with any of them.
`StaticToken` serves a fixed JWT for tests/scripts.

### `httpx` — correlation IDs, uniform errors, body decode

Shared HTTP glue: `NewCorrelationID()` (v4 GUID for the per-request correlation
headers), `APIError` + `IsNotFound(err)` (uniform not-found across clients, wired to
Terraform providers' `isNotFound`), and `DecodeBody(resp)` (decompresses
`br`/`gzip`/`deflate` — the clients set `Accept-Encoding` themselves for wire
fidelity, so net/http does not auto-decode).

### `consistency` — retry until visible

These APIs are read-your-writes consistent only within a single backend session:
a create/update in one session is frequently not yet visible to a read from
another. `RetryUntil` polls a getter until the resource is present (and,
optionally, until it reflects a written value) before concluding it is absent.

```go
obj, ok, err := consistency.RetryUntil(ctx, consistency.Config{}, get, nil)
```

### `retry` — transient & rate-limit aware retries

Every service throttles with HTTP 429 (often with `Retry-After`) and returns
transient 5xx/network errors under load. `retry` centralises the policy: honour
`Retry-After`, otherwise exponential backoff with jitter, bounded attempts.

- `retry.Do` — retry an arbitrary operation with a caller-supplied classifier.
- `retry.Transport` — a drop-in `http.RoundTripper` that retries transient
  responses transparently (replays the body via `Request.GetBody`).

```go
hc := &http.Client{Transport: retry.NewTransport(nil, retry.Config{})}
```

## License

MIT — see [LICENSE](LICENSE). Not affiliated with or endorsed by Microsoft.
