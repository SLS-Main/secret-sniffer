package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestScannerFindsSecretInZipArchive(t *testing.T) {
	dir := t.TempDir()
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	archive := filepath.Join(dir, "secrets.zip")
	if err := os.WriteFile(archive, zipBytes(t, map[string]string{"config/.env": secret}), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, ScanArchives: true}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("expected zip archive finding, got %#v", findings)
	}
	if !hasFileSuffix(findings, "secrets.zip!/config/.env") {
		t.Fatalf("expected virtual zip path, got %#v", findings)
	}
}

func TestScannerFindsSecretInTarGzArchive(t *testing.T) {
	dir := t.TempDir()
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	archive := filepath.Join(dir, "backup.tar.gz")
	if err := os.WriteFile(archive, tarGzBytes(t, map[string]string{"app/config.env": secret}), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, ScanArchives: true}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("expected tar.gz archive finding, got %#v", findings)
	}
}

func TestScannerFindsSecretInNestedArchive(t *testing.T) {
	dir := t.TempDir()
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	inner := zipBytes(t, map[string]string{"nested.env": secret})
	archive := filepath.Join(dir, "outer.zip")
	if err := os.WriteFile(archive, zipRawBytes(t, map[string][]byte{"inner.zip": inner}), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, ScanArchives: true, MaxArchiveDepth: 2}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("expected nested archive finding, got %#v", findings)
	}
	if !hasFileSuffix(findings, "outer.zip!/inner.zip!/nested.env") {
		t.Fatalf("expected nested virtual archive path, got %#v", findings)
	}
}

func TestScannerSkipsUnsafeArchivePath(t *testing.T) {
	dir := t.TempDir()
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	archive := filepath.Join(dir, "unsafe.zip")
	if err := os.WriteFile(archive, zipBytes(t, map[string]string{"../config.env": secret}), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, ScanArchives: true}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("did not expect finding from unsafe archive path, got %#v", findings)
	}
}

func TestScannerSkipsOversizedArchiveEntry(t *testing.T) {
	dir := t.TempDir()
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	archive := filepath.Join(dir, "large.zip")
	if err := os.WriteFile(archive, zipBytes(t, map[string]string{"large.env": strings.Repeat("A", 128) + secret}), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, ScanArchives: true, MaxExpandedFileBytes: 64}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("did not expect finding from oversized archive entry, got %#v", findings)
	}
}

func TestScannerFindsSecretInGitHistoryArchive(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	secret := "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
	archive := filepath.Join(dir, "historical.zip")
	if err := os.WriteFile(archive, zipBytes(t, map[string]string{"old.env": secret}), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "historical.zip")
	runGit(t, dir, "commit", "-m", "add archive")
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "historical.zip")
	runGit(t, dir, "commit", "-m", "remove archive")

	s := New(Config{Target: dir, Workers: 2, MaxFileBytes: 1024 * 1024, GitHistory: true, ScanArchives: true}, detectors.DefaultRegistry())
	findings, err := s.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "openai-key", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef") {
		t.Fatalf("expected git history archive finding, got %#v", findings)
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

func hasFileSuffix(findings []detectors.Finding, suffix string) bool {
	for _, f := range findings {
		if strings.HasSuffix(filepath.ToSlash(f.File), suffix) {
			return true
		}
	}
	return false
}

func zipBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	raw := make(map[string][]byte, len(files))
	for name, content := range files {
		raw[name] = []byte(content)
	}
	return zipRawBytes(t, raw)
}

func zipRawBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func tarGzBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		h := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v: %s", args, err, string(out))
	}
}

func TestGitHubCloneURLInjectsToken(t *testing.T) {
	got := githubCloneURL("https://github.com/acme/repo", "token123")
	want := "https://x-access-token:token123@github.com/acme/repo"
	if got != want {
		t.Fatalf("unexpected clone URL: %s", got)
	}
}

func TestRetryableGitCloneError(t *testing.T) {
	if !retryableGitCloneError("fatal: unable to access 'https://github.com/acme/repo.git/': Failed to connect to github.com port 443 via 127.0.0.1 after 0 ms: Could not connect to server") {
		t.Fatal("expected connection failure to be retryable")
	}
	if retryableGitCloneError("remote: Repository not found. fatal: Authentication failed") {
		t.Fatal("expected auth failure to be non-retryable")
	}
}
