package scanner

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"secret-sniffer/internal/detectors"
)

func TestScannerFindsSecretInFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.txt")
	err := os.WriteFile(path, []byte("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
}

func TestScannerIncludeExcludeGlobs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.txt"), []byte("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.env"), []byte("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, Include: []string{"*.txt"}, Exclude: []string{"ignored.*"}}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected finding in included file")
	}
	for _, f := range findings {
		if filepath.Base(f.File) != "config.txt" {
			t.Fatalf("unexpected file scanned: %s", f.File)
		}
	}
}

func TestScannerFindsSecretInBase64Payload(t *testing.T) {
	dir := t.TempDir()
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	path := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(path, []byte("encoded_secret="+encoded), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("expected decoded openai finding, got %#v", findings)
	}
}

func TestScannerFindsSecretInBase64URLPayload(t *testing.T) {
	dir := t.TempDir()
	secret := "github_token=ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	encoded := base64.RawURLEncoding.EncodeToString([]byte(secret))
	path := filepath.Join(dir, "config.txt")
	if err := os.WriteFile(path, []byte("encoded_secret="+encoded), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "github-token", "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("expected decoded github finding, got %#v", findings)
	}
}

func hasFinding(findings []detectors.Finding, detectorID, secret string) bool {
	for _, f := range findings {
		if f.DetectorID == detectorID && f.Secret == secret {
			return true
		}
	}
	return false
}

func TestGitHubCloneURLInjectsToken(t *testing.T) {
	got := githubCloneURL("https://github.com/acme/repo", "token123")
	want := "https://x-access-token:token123@github.com/acme/repo"
	if got != want {
		t.Fatalf("unexpected clone URL: %s", got)
	}
}
