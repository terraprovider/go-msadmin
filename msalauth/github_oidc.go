package msalauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

// DefaultOIDCAudience is the audience Entra federated identity credentials expect
// for a GitHub Actions OIDC token used as a client assertion.
const DefaultOIDCAudience = "api://AzureADTokenExchange"

// GitHubOIDCAssertion returns an assertion callback (for NewConfidentialAssertion)
// that fetches a GitHub Actions OIDC token for the given audience. It requires the
// workflow job to have `permissions: id-token: write`, which sets
// ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN.
//
// Pass audience="" for the default (api://AzureADTokenExchange).
func GitHubOIDCAssertion(audience string) func(context.Context) (string, error) {
	if audience == "" {
		audience = DefaultOIDCAudience
	}
	return func(ctx context.Context) (string, error) {
		reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		if reqURL == "" || reqTok == "" {
			return "", fmt.Errorf("msalauth: GitHub OIDC env not set (need permissions: id-token: write)")
		}
		u, err := url.Parse(reqURL)
		if err != nil {
			return "", err
		}
		q := u.Query()
		q.Set("audience", audience)
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "Bearer "+reqTok)
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("msalauth: GitHub OIDC token request failed: %d %s", resp.StatusCode, body)
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", err
		}
		if out.Value == "" {
			return "", fmt.Errorf("msalauth: empty GitHub OIDC token")
		}
		return out.Value, nil
	}
}
