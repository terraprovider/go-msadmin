package authx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// githubAssertion fetches a GitHub Actions OIDC token (the request URL + bearer
// token are exposed to jobs with `permissions: id-token: write`).
func githubAssertion(ctx context.Context, requestURL, requestToken, audience string) (string, error) {
	if audience == "" {
		audience = "api://AzureADTokenExchange"
	}
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json")
	body, err := doJSON(req)
	if err != nil {
		return "", fmt.Errorf("authx: github oidc: %w", err)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return "", fmt.Errorf("authx: github oidc: empty token")
	}
	return out.Value, nil
}

// azureDevOpsAssertion exchanges the pipeline System.AccessToken for a federated
// OIDC token via the service connection (Workload Identity Federation).
func azureDevOpsAssertion(ctx context.Context, requestURI, accessToken, serviceConnectionID string) (string, error) {
	u, err := url.Parse(requestURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if q.Get("api-version") == "" {
		q.Set("api-version", "7.1")
	}
	q.Set("serviceConnectionId", serviceConnectionID)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	body, err := doJSON(req)
	if err != nil {
		return "", fmt.Errorf("authx: azure devops oidc: %w", err)
	}
	var out struct {
		OIDCToken string `json:"oidcToken"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.OIDCToken == "" {
		return "", fmt.Errorf("authx: azure devops oidc: empty token")
	}
	return out.OIDCToken, nil
}

func doJSON(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
