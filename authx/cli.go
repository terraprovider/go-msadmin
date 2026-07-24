package authx

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/terraprovider/go-msadmin/auth"
)

// cliProvider gets tokens via the Azure CLI (`az account get-access-token`).
type cliProvider struct{ tenant string }

func newCLIProvider(tenant string) auth.TokenProvider { return cliProvider{tenant: tenant} }

func (p cliProvider) Token(ctx context.Context, resource string) (string, error) {
	args := []string{"account", "get-access-token", "--resource", strings.TrimSuffix(resource, "/"), "--output", "json"}
	if p.tenant != "" {
		args = append(args, "--tenant", p.tenant)
	}
	out, err := exec.CommandContext(ctx, "az", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("authx: az cli: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("authx: az cli: %w (is the Azure CLI installed & logged in?)", err)
	}
	var res struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return "", fmt.Errorf("authx: az cli: decode: %w", err)
	}
	if res.AccessToken == "" {
		return "", fmt.Errorf("authx: az cli returned an empty token")
	}
	return res.AccessToken, nil
}
