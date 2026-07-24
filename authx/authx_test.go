package authx

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMethodSelection(t *testing.T) {
	cases := []struct {
		c    Config
		want string
	}{
		{Config{ClientSecret: "s"}, "secret"},
		{Config{ClientCertificatePath: "/x.pem"}, "certificate"},
		{Config{ClientCertificate: "base64"}, "certificate"},
		{Config{UseOIDC: true}, "oidc"},
		{Config{OIDCToken: "jwt"}, "oidc"},
		{Config{OIDCRequestURL: "https://x"}, "oidc"},
		{Config{UseCLI: true}, "cli"},
		{Config{UseMSI: true}, "msi"},
		{Config{}, ""},
		// explicit flags win over material present
		{Config{UseCLI: true, ClientSecret: "s"}, "cli"},
	}
	for _, c := range cases {
		if got := c.c.Method(); got != c.want {
			t.Errorf("Method(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}

func TestAuthorityHost(t *testing.T) {
	cases := map[string]string{
		"":             "https://login.microsoftonline.com",
		"public":       "https://login.microsoftonline.com",
		"usgovernment": "https://login.microsoftonline.us",
		"dod":          "https://login.microsoftonline.us",
		"china":        "https://login.chinacloudapi.cn",
	}
	for env, want := range cases {
		if got := (Config{Environment: env}).AuthorityHost(); got != want {
			t.Errorf("AuthorityHost(%q) = %q, want %q", env, got, want)
		}
	}
}

func TestMergePrecedence(t *testing.T) {
	base := Config{TenantID: "env-tenant", ClientID: "env-client", ClientSecret: "env-secret"}
	over := Config{ClientID: "explicit-client"} // explicit client wins; others fall through
	got := base.Merge(over)
	if got.ClientID != "explicit-client" || got.TenantID != "env-tenant" || got.ClientSecret != "env-secret" {
		t.Fatalf("merge precedence wrong: %+v", got)
	}
}

func TestFromEnvPrecedence(t *testing.T) {
	t.Setenv("ARM_TENANT_ID", "arm-t")
	t.Setenv("AZURE_TENANT_ID", "azure-t")
	t.Setenv("ARM_USE_OIDC", "true")
	c := FromEnv()
	if c.TenantID != "arm-t" { // ARM_ wins over AZURE_
		t.Errorf("tenant precedence: got %q", c.TenantID)
	}
	if !c.UseOIDC {
		t.Errorf("UseOIDC not parsed from env")
	}
	if c.Environment != "public" {
		t.Errorf("default environment: got %q", c.Environment)
	}
}

func TestOIDCAssertionSources(t *testing.T) {
	ctx := context.Background()
	// direct token
	if v, err := (Config{OIDCToken: "direct-jwt"}).oidcAssertion()(ctx); err != nil || v != "direct-jwt" {
		t.Fatalf("direct: %q %v", v, err)
	}
	// token file
	dir := t.TempDir()
	f := filepath.Join(dir, "tok")
	_ = os.WriteFile(f, []byte("  file-jwt\n"), 0o600)
	if v, err := (Config{OIDCTokenFilePath: f}).oidcAssertion()(ctx); err != nil || v != "file-jwt" {
		t.Fatalf("file: %q %v", v, err)
	}
	// nothing configured
	if _, err := (Config{UseOIDC: true}).oidcAssertion()(ctx); err == nil {
		t.Fatalf("expected error when no OIDC source")
	}
}

func TestBuildValidations(t *testing.T) {
	if _, err := (Config{ClientSecret: "s"}).Build(); err == nil {
		t.Error("expected error without tenant")
	}
	if _, err := (Config{TenantID: "t", ClientSecret: "s"}).Build(); err == nil {
		t.Error("expected error without client_id")
	}
	if _, err := (Config{TenantID: "t", ClientID: "c", ClientSecret: "s"}).Build(); err != nil {
		t.Errorf("secret build should succeed: %v", err)
	}
	if _, err := (Config{TenantID: "t", ClientID: "c"}).Build(); err == nil {
		t.Error("expected error with no credentials")
	}
}
