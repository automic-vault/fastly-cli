package config

import (
	"path/filepath"
	"testing"

	"github.com/fastly/cli/pkg/automicvault"
)

func TestAutomicVaultConfigFailsClosed(t *testing.T) {
	previous := automicvault.Enabled
	automicvault.Enabled = "true"
	t.Cleanup(func() { automicvault.Enabled = previous })

	valid := File{Auth: Auth{Tokens: AuthTokens{
		"production": {Type: AuthTokenTypeStatic, Token: automicvault.Marker},
	}}}
	if err := valid.Write(filepath.Join(t.TempDir(), "config.toml")); err != nil {
		t.Fatalf("valid managed config: %v", err)
	}

	sso := valid
	sso.Auth.Tokens = AuthTokens{
		"production": {Type: AuthTokenTypeSSO, Token: automicvault.Marker, RefreshToken: "secret"},
	}
	if err := sso.Write(filepath.Join(t.TempDir(), "config.toml")); err == nil {
		t.Fatal("accepted SSO credentials")
	}

	alternate := valid
	alternate.Fastly.APIEndpoint = "https://example.invalid"
	if err := alternate.Write(filepath.Join(t.TempDir(), "config.toml")); err == nil {
		t.Fatal("accepted alternate API endpoint")
	}
}
