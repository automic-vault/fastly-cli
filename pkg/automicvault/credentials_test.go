package automicvault

import (
	"context"
	"os/exec"
	"testing"
)

func TestCredentialInputsFailClosed(t *testing.T) {
	for _, name := range []string{"", " leading", "trailing ", "line\nbreak", "☃"} {
		if validateName(name) == nil {
			t.Fatalf("accepted invalid token name %q", name)
		}
	}
	for _, token := range []string{"", "line\nbreak", "nul\x00byte"} {
		if validateToken(token) == nil {
			t.Fatalf("accepted invalid token %q", token)
		}
	}
	if validateName("production") != nil || validateToken("fastly-token") != nil {
		t.Fatal("rejected valid credential input")
	}
}

func TestGetRejectsAlternateEndpointBeforeExecution(t *testing.T) {
	previous := Enabled
	Enabled = "true"
	t.Cleanup(func() { Enabled = previous })
	if _, err := Get("production", "https://example.invalid"); err == nil {
		t.Fatal("accepted an alternate API endpoint")
	}
}

func TestGetUsesFixedHelperRoute(t *testing.T) {
	previousEnabled, previousCommand := Enabled, command
	Enabled = "true"
	command = func(_ context.Context, name string, args ...string) *exec.Cmd {
		if name != "/usr/local/bin/av" || len(args) != 4 || args[0] != "fastly-credential" || args[1] != "get" || args[2] != "production" || args[3] != APIEndpoint {
			t.Fatalf("unexpected helper invocation: %s %v", name, args)
		}
		return exec.Command("/usr/bin/printf", "fastly-token")
	}
	t.Cleanup(func() {
		Enabled, command = previousEnabled, previousCommand
	})
	token, err := Get("production", APIEndpoint)
	if err != nil || token != "fastly-token" {
		t.Fatalf("Get() = %q, %v", token, err)
	}
}
