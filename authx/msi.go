package authx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/terraprovider/go-msadmin/auth"
)

// msiProvider gets tokens from a managed identity — the App Service/Functions
// IDENTITY_ENDPOINT when present, otherwise the IMDS endpoint.
type msiProvider struct {
	endpoint string
	clientID string
}

func newMSIProvider(endpoint, clientID string) auth.TokenProvider {
	return msiProvider{endpoint: endpoint, clientID: clientID}
}

func (p msiProvider) Token(ctx context.Context, resource string) (string, error) {
	identityEndpoint := os.Getenv("IDENTITY_ENDPOINT")
	identityHeader := os.Getenv("IDENTITY_HEADER")
	appService := identityEndpoint != "" && identityHeader != ""

	base := p.endpoint
	if base == "" {
		if appService {
			base = identityEndpoint
		} else {
			base = "http://169.254.169.254/metadata/identity/oauth2/token"
		}
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("resource", resource)
	if appService {
		q.Set("api-version", "2019-08-01")
	} else {
		q.Set("api-version", "2018-02-01")
	}
	if p.clientID != "" {
		q.Set("client_id", p.clientID)
	}
	u.RawQuery = q.Encode()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if appService {
		req.Header.Set("X-IDENTITY-HEADER", identityHeader)
	} else {
		req.Header.Set("Metadata", "true")
	}
	body, err := doJSON(req)
	if err != nil {
		return "", fmt.Errorf("authx: managed identity: %w", err)
	}
	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &res); err != nil || res.AccessToken == "" {
		return "", fmt.Errorf("authx: managed identity returned no token")
	}
	return res.AccessToken, nil
}

var _ auth.TokenProvider = msiProvider{}
