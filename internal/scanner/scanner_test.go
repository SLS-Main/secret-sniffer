package scanner

import (
	"context"
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

func TestGitHubCloneURLInjectsToken(t *testing.T) {
	got := githubCloneURL("https://github.com/acme/repo", "token123")
	want := "https://x-access-token:token123@github.com/acme/repo"
	if got != want {
		t.Fatalf("unexpected clone URL: %s", got)
	}
}
