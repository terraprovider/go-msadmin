// Package authx resolves credentials into an auth.TokenProvider using the
// same configuration surface as the hashicorp/azuread and azurerm Terraform
// providers (identical field and ARM_*/AZURE_* env-var names), but implemented
// lightly on MSAL-Go — no go-azure-sdk dependency.
//
// Supported methods (selection order when not forced): client secret, client
// certificate, OIDC/workload-identity (GitHub Actions, Azure DevOps, generic
// token or token file), Azure CLI, managed identity.
package authx

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/terraprovider/go-msadmin/auth"
	"github.com/terraprovider/go-msadmin/msalauth"
)

// Config mirrors the azuread/azurerm provider auth block. Empty fields fall back
// to environment variables via FromEnv.
type Config struct {
	Environment string // public | usgovernment | dod | china  (default public)
	TenantID    string
	ClientID    string

	ClientSecret string

	ClientCertificate         string // base64-encoded PKCS#12/PEM bundle
	ClientCertificatePath     string
	ClientCertificatePassword string

	UseOIDC                bool
	OIDCToken              string // a pre-fetched assertion JWT (generic / Azure DevOps task-provided)
	OIDCTokenFilePath      string // file containing the assertion (K8s projected token, etc.)
	OIDCRequestToken       string // GitHub: ACTIONS_ID_TOKEN_REQUEST_TOKEN
	OIDCRequestURL         string // GitHub: ACTIONS_ID_TOKEN_REQUEST_URL
	ADOServiceConnectionID string // Azure DevOps workload-identity service connection id

	UseCLI         bool
	UseMSI         bool
	MSIEndpoint    string
	ClientIDForMSI string // user-assigned identity client id (optional)

	// Audience for the OIDC/federated exchange (default api://AzureADTokenExchange).
	OIDCAudience string
}

func env(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

func envBool(keys ...string) bool {
	return strings.EqualFold(env(keys...), "true")
}

// FromEnv returns a Config populated from ARM_*/AZURE_* (and pipeline) env vars,
// matching azuread/azurerm precedence (ARM_ first, then AZURE_).
func FromEnv() Config {
	return Config{
		Environment:               firstNonEmpty(env("ARM_ENVIRONMENT", "AZURE_ENVIRONMENT"), "public"),
		TenantID:                  env("ARM_TENANT_ID", "AZURE_TENANT_ID"),
		ClientID:                  env("ARM_CLIENT_ID", "AZURE_CLIENT_ID"),
		ClientSecret:              env("ARM_CLIENT_SECRET", "AZURE_CLIENT_SECRET"),
		ClientCertificate:         env("ARM_CLIENT_CERTIFICATE", "AZURE_CLIENT_CERTIFICATE"),
		ClientCertificatePath:     env("ARM_CLIENT_CERTIFICATE_PATH", "AZURE_CLIENT_CERTIFICATE_PATH"),
		ClientCertificatePassword: env("ARM_CLIENT_CERTIFICATE_PASSWORD", "AZURE_CLIENT_CERTIFICATE_PASSWORD"),
		UseOIDC:                   envBool("ARM_USE_OIDC", "AZURE_USE_OIDC"),
		OIDCToken:                 env("ARM_OIDC_TOKEN", "AZURE_OIDC_TOKEN"),
		OIDCTokenFilePath:         env("ARM_OIDC_TOKEN_FILE_PATH", "AZURE_FEDERATED_TOKEN_FILE"),
		OIDCRequestToken:          env("ARM_OIDC_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "SYSTEM_ACCESSTOKEN"),
		OIDCRequestURL:            env("ARM_OIDC_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_URL", "SYSTEM_OIDCREQUESTURI"),
		ADOServiceConnectionID:    env("ARM_OIDC_AZURE_SERVICE_CONNECTION_ID", "ARM_ADO_PIPELINE_SERVICE_CONNECTION_ID"),
		UseCLI:                    envBool("ARM_USE_CLI", "AZURE_USE_CLI"),
		UseMSI:                    envBool("ARM_USE_MSI", "AZURE_USE_MSI"),
		MSIEndpoint:               env("ARM_MSI_ENDPOINT", "MSI_ENDPOINT", "IDENTITY_ENDPOINT"),
		ClientIDForMSI:            env("ARM_CLIENT_ID", "AZURE_CLIENT_ID"),
		OIDCAudience:              env("ARM_OIDC_AUDIENCE"),
	}
}

// Merge overlays non-empty fields of o onto c (explicit config wins over env).
func (c Config) Merge(o Config) Config {
	if o.Environment != "" {
		c.Environment = o.Environment
	}
	c.TenantID = firstNonEmpty(o.TenantID, c.TenantID)
	c.ClientID = firstNonEmpty(o.ClientID, c.ClientID)
	c.ClientSecret = firstNonEmpty(o.ClientSecret, c.ClientSecret)
	c.ClientCertificate = firstNonEmpty(o.ClientCertificate, c.ClientCertificate)
	c.ClientCertificatePath = firstNonEmpty(o.ClientCertificatePath, c.ClientCertificatePath)
	c.ClientCertificatePassword = firstNonEmpty(o.ClientCertificatePassword, c.ClientCertificatePassword)
	c.UseOIDC = c.UseOIDC || o.UseOIDC
	c.OIDCToken = firstNonEmpty(o.OIDCToken, c.OIDCToken)
	c.OIDCTokenFilePath = firstNonEmpty(o.OIDCTokenFilePath, c.OIDCTokenFilePath)
	c.OIDCRequestToken = firstNonEmpty(o.OIDCRequestToken, c.OIDCRequestToken)
	c.OIDCRequestURL = firstNonEmpty(o.OIDCRequestURL, c.OIDCRequestURL)
	c.ADOServiceConnectionID = firstNonEmpty(o.ADOServiceConnectionID, c.ADOServiceConnectionID)
	c.UseCLI = c.UseCLI || o.UseCLI
	c.UseMSI = c.UseMSI || o.UseMSI
	c.MSIEndpoint = firstNonEmpty(o.MSIEndpoint, c.MSIEndpoint)
	c.OIDCAudience = firstNonEmpty(o.OIDCAudience, c.OIDCAudience)
	return c
}

// AuthorityHost returns the AAD login host for the environment.
func (c Config) AuthorityHost() string {
	switch strings.ToLower(c.Environment) {
	case "usgovernment", "usgov", "dod":
		return "https://login.microsoftonline.us"
	case "china", "chinacloud":
		return "https://login.chinacloudapi.cn"
	default:
		return "https://login.microsoftonline.com"
	}
}

// Method reports the selected auth method, honouring explicit Use* flags then
// falling back to whichever credential material is present.
//
// OIDC is chosen when it is requested (use_oidc, oidc_token,
// oidc_token_file_path or oidc_request_url) and a token source is actually
// available (see hasOIDCSource). When it is requested but no source is
// available (e.g. ARM_USE_OIDC=true on a workstation with no pipeline token),
// a configured client secret or certificate is used instead, like the azurerm
// provider's fall-through. Without one, OIDC is still selected so the token
// request reports the missing source.
func (c Config) Method() string {
	wantsOIDC := c.UseOIDC || c.OIDCToken != "" || c.OIDCTokenFilePath != "" || c.OIDCRequestURL != ""
	switch {
	case c.UseCLI:
		return "cli"
	case c.UseMSI:
		return "msi"
	case wantsOIDC && c.hasOIDCSource():
		return "oidc"
	case c.ClientSecret != "":
		return "secret"
	case c.ClientCertificate != "" || c.ClientCertificatePath != "":
		return "certificate"
	case wantsOIDC:
		return "oidc"
	default:
		return ""
	}
}

// hasOIDCSource reports whether oidcAssertion has a token source to read from.
func (c Config) hasOIDCSource() bool {
	return c.OIDCToken != "" || c.OIDCTokenFilePath != "" ||
		(c.OIDCRequestURL != "" && c.OIDCRequestToken != "")
}

// Build resolves the config into an auth.TokenProvider.
func (c Config) Build() (auth.TokenProvider, error) {
	if c.TenantID == "" {
		return nil, fmt.Errorf("authx: tenant_id (ARM_TENANT_ID) is required")
	}
	method := c.Method()
	if method != "cli" && c.ClientID == "" {
		return nil, fmt.Errorf("authx: client_id (ARM_CLIENT_ID) is required for %q auth", method)
	}
	host := c.AuthorityHost()
	switch method {
	case "secret":
		return msalauth.NewConfidentialSecret(c.TenantID, c.ClientID, c.ClientSecret, host)
	case "certificate":
		pemBytes, pw, err := c.certPEM()
		if err != nil {
			return nil, err
		}
		return msalauth.NewConfidentialCertPEM(c.TenantID, c.ClientID, pemBytes, pw, host)
	case "oidc":
		return msalauth.NewConfidentialAssertion(c.TenantID, c.ClientID, c.oidcAssertion(), host)
	case "cli":
		return newCLIProvider(c.TenantID), nil
	case "msi":
		return newMSIProvider(c.MSIEndpoint, c.ClientIDForMSI), nil
	default:
		return nil, fmt.Errorf("authx: no credentials configured (set a client secret, certificate, use_oidc, use_cli, or use_msi)")
	}
}

// oidcAssertion returns a callback that sources the federated assertion JWT from
// whichever pipeline is configured, in precedence order.
func (c Config) oidcAssertion() func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		switch {
		case c.OIDCToken != "":
			return c.OIDCToken, nil
		case c.OIDCTokenFilePath != "":
			b, err := os.ReadFile(c.OIDCTokenFilePath)
			if err != nil {
				return "", fmt.Errorf("authx: read oidc_token_file_path: %w", err)
			}
			return strings.TrimSpace(string(b)), nil
		case c.ADOServiceConnectionID != "" && c.OIDCRequestURL != "" && c.OIDCRequestToken != "":
			return azureDevOpsAssertion(ctx, c.OIDCRequestURL, c.OIDCRequestToken, c.ADOServiceConnectionID)
		case c.OIDCRequestURL != "" && c.OIDCRequestToken != "":
			// GitHub Actions
			aud := c.OIDCAudience
			return githubAssertion(ctx, c.OIDCRequestURL, c.OIDCRequestToken, aud)
		default:
			return "", fmt.Errorf("authx: use_oidc set but no token source (oidc_token / oidc_token_file_path / request url+token)")
		}
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
