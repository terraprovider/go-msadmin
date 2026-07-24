// Package msalauth provides auth.TokenProvider implementations backed by
// MSAL (github.com/AzureAD/microsoft-authentication-library-for-go).
//
//   - Confidential: app-only via certificate (recommended; the PowerShell module
//     only ever uses a certificate) or client secret. Uses the client-credentials
//     grant; scope is {resource}/.default.
//   - Delegated: interactive (browser) user sign-in with silent refresh.
//
// MSAL caches tokens in memory, so Token can be called per request cheaply.
package msalauth

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// DefaultAuthorityHost is the commercial-cloud login host. For national clouds
// pass an override (e.g. https://login.microsoftonline.us).
const DefaultAuthorityHost = "https://login.microsoftonline.com"

// EXOFirstPartyClientID is the Exchange Online PowerShell public client, usable
// for delegated flows without registering your own app.
const EXOFirstPartyClientID = "fb78d390-0c51-40cd-8e17-fdbfab77341b"

func authority(host, tenantID string) string {
	if host == "" {
		host = DefaultAuthorityHost
	}
	return host + "/" + tenantID
}

func dotDefault(resource string) []string { return []string{resource + "/.default"} }

// Confidential is an app-only (client-credentials) TokenProvider.
type Confidential struct{ app confidential.Client }

// NewConfidentialCertPEM builds an app-only provider from a PEM bundle containing
// the certificate and its (unencrypted or password-protected) private key.
// CNG keys are not supported by the backend — use a CSP/exportable key.
func NewConfidentialCertPEM(tenantID, clientID string, pem []byte, password, authorityHost string) (*Confidential, error) {
	certs, key, err := confidential.CertFromPEM(pem, password)
	if err != nil {
		return nil, fmt.Errorf("msalauth: parse PEM cert: %w", err)
	}
	return newConfidentialCert(tenantID, clientID, certs, key, authorityHost)
}

// NewConfidentialCert builds an app-only provider from parsed cert chain + key.
func NewConfidentialCert(tenantID, clientID string, certs []*x509.Certificate, key crypto.PrivateKey, authorityHost string) (*Confidential, error) {
	return newConfidentialCert(tenantID, clientID, certs, key, authorityHost)
}

func newConfidentialCert(tenantID, clientID string, certs []*x509.Certificate, key crypto.PrivateKey, authorityHost string) (*Confidential, error) {
	cred, err := confidential.NewCredFromCert(certs, key)
	if err != nil {
		return nil, fmt.Errorf("msalauth: cred from cert: %w", err)
	}
	app, err := confidential.New(authority(authorityHost, tenantID), clientID, cred)
	if err != nil {
		return nil, err
	}
	return &Confidential{app: app}, nil
}

// NewConfidentialSecret builds an app-only provider from a client secret. Note:
// the EXO/SCC backend may reject secret-based tokens even though Entra issues them
// (the module only uses certificates) — validate before relying on this.
func NewConfidentialSecret(tenantID, clientID, secret, authorityHost string) (*Confidential, error) {
	cred, err := confidential.NewCredFromSecret(secret)
	if err != nil {
		return nil, err
	}
	app, err := confidential.New(authority(authorityHost, tenantID), clientID, cred)
	if err != nil {
		return nil, err
	}
	return &Confidential{app: app}, nil
}

// NewConfidentialAssertion builds an app-only provider that authenticates with a
// federated client assertion returned by getAssertion — e.g. a GitHub Actions
// OIDC token exchanged via an Entra federated identity credential (workload
// identity, no stored secret). Pair with GitHubOIDCAssertion in CI.
func NewConfidentialAssertion(tenantID, clientID string, getAssertion func(context.Context) (string, error), authorityHost string) (*Confidential, error) {
	cred := confidential.NewCredFromAssertionCallback(
		func(ctx context.Context, _ confidential.AssertionRequestOptions) (string, error) {
			return getAssertion(ctx)
		})
	app, err := confidential.New(authority(authorityHost, tenantID), clientID, cred)
	if err != nil {
		return nil, err
	}
	return &Confidential{app: app}, nil
}

// Token implements auth.TokenProvider.
func (c *Confidential) Token(ctx context.Context, resource string) (string, error) {
	res, err := c.app.AcquireTokenByCredential(ctx, dotDefault(resource))
	if err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

// Delegated is an interactive (browser) user TokenProvider with silent refresh.
type Delegated struct {
	app     public.Client
	mu      sync.Mutex
	account public.Account
	haveAcc bool
}

// NewDelegated builds a delegated provider. Pass clientID="" to use the EXO
// first-party app.
func NewDelegated(tenantID, clientID, authorityHost string) (*Delegated, error) {
	if clientID == "" {
		clientID = EXOFirstPartyClientID
	}
	app, err := public.New(clientID, public.WithAuthority(authority(authorityHost, tenantID)))
	if err != nil {
		return nil, err
	}
	return &Delegated{app: app}, nil
}

// Token implements auth.TokenProvider: silent from cache if possible, else
// an interactive browser sign-in (which caches the account for next time).
func (d *Delegated) Token(ctx context.Context, resource string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	scopes := dotDefault(resource)
	if d.haveAcc {
		if res, err := d.app.AcquireTokenSilent(ctx, scopes, public.WithSilentAccount(d.account)); err == nil {
			return res.AccessToken, nil
		}
	}
	res, err := d.app.AcquireTokenInteractive(ctx, scopes)
	if err != nil {
		return "", err
	}
	d.account = res.Account
	d.haveAcc = true
	return res.AccessToken, nil
}
