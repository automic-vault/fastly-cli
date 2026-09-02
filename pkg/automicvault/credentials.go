package automicvault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	APIEndpoint = "https://api.fastly.com"
	Marker      = "@av"
	maxTokenLen = 64 * 1024
)

// Enabled is set to "true" only by the reviewed Automic Vault Isotope build.
var Enabled = "false"

var command = exec.CommandContext

func Get(name, endpoint string) (string, error) {
	if Enabled != "true" {
		return Marker, nil
	}
	if endpoint != APIEndpoint {
		return "", fmt.Errorf("Automic Vault credentials require %s", APIEndpoint)
	}
	if err := validateName(name); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(ctx, "/usr/local/bin/av", "fastly-credential", "get", name, endpoint)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to read Fastly token from Automic Vault: %w", err)
	}
	token := strings.TrimSuffix(string(out), "\n")
	if err := validateToken(token); err != nil {
		return "", err
	}
	return token, nil
}

func Store(name, token string) error {
	if Enabled != "true" {
		return nil
	}
	if err := validateName(name); err != nil {
		return err
	}
	if err := validateToken(token); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(ctx, "/usr/local/bin/av", "fastly-credential", "store", name, APIEndpoint)
	cmd.Stdin = strings.NewReader(token)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to store Fastly token in Automic Vault: %w", err)
	}
	return nil
}

func Forget(name string) error {
	if Enabled != "true" {
		return nil
	}
	if err := validateName(name); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := command(ctx, "/usr/local/bin/av", "fastly-credential", "forget", name, APIEndpoint)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete Fastly token from Automic Vault: %w", err)
	}
	return nil
}

func validateName(name string) error {
	if name == "" || len(name) > 128 || strings.TrimSpace(name) != name || !isASCII(name) {
		return fmt.Errorf("invalid Fastly token name")
	}
	return nil
}

func validateToken(token string) error {
	if token == "" || len(token) > maxTokenLen || strings.ContainsAny(token, "\x00\r\n") {
		return fmt.Errorf("invalid Fastly API token")
	}
	return nil
}

func isASCII(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 || r > 0x7e }) == -1
}
