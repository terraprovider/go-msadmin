// Package auth defines the minimal token abstraction shared by the Microsoft
// admin API clients (Exchange Online / Purview, Teams, Graph, ARM).
//
// Every one of these clients needs the same thing from a credential: a bearer
// access token for a given resource/audience, cached and refreshed. Factoring the
// interface out here lets the transports (the Exchange/SCC cmdlet client, the
// Teams REST client, …) and the MSAL-backed providers agree on one type, so a
// provider built for one composes with any of them without adapter shims.
package auth

import (
	"context"
	"errors"
)

// TokenProvider returns a bearer access token whose audience matches resource
// (e.g. "https://outlook.office365.com" for Exchange, or the Teams admin API's
// resource GUID). Implementations should cache and refresh; callers may invoke
// Token on every request.
type TokenProvider interface {
	Token(ctx context.Context, resource string) (string, error)
}

// StaticToken serves a fixed, pre-acquired JWT (handy for tests and short-lived
// scripts). It ignores the resource argument.
type StaticToken string

// Token returns the static token, or an error if it is empty.
func (s StaticToken) Token(context.Context, string) (string, error) {
	if s == "" {
		return "", errors.New("auth: empty static token")
	}
	return string(s), nil
}
