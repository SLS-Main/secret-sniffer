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
	"sync/atomic"
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

func TestDetectorPlanSkipsMissingKeywords(t *testing.T) {
	var calls int32
	var prefilteredCalls int32
	d := countingDetector{id: "counting", keywords: []string{"needle"}, calls: &calls, prefilteredCalls: &prefilteredCalls}
	s := New(Config{Workers: 1, MaxFileBytes: 1024}, []detectors.Detector{d})
	if got := s.scanBytes(context.Background(), "config.txt", "", []byte("ordinary content")); len(got) != 0 {
		t.Fatalf("unexpected findings without keyword: %#v", got)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("detector called without keyword: %d", got)
	}
	s.scanBytes(context.Background(), "config.txt", "", []byte("needle content"))
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("regular detector calls=%d, want 0", got)
	}
	if got := atomic.LoadInt32(&prefilteredCalls); got != 1 {
		t.Fatalf("prefiltered detector calls=%d, want 1", got)
	}
}

func TestVerificationCacheDeduplicatesAndUsesScanContext(t *testing.T) {
	cache := newVerificationCache()
	var calls int32
	candidate := detectors.Candidate{DetectorID: "test", Secret: "same-secret", Verifier: func(context.Context, string) bool {
		atomic.AddInt32(&calls, 1)
		return true
	}}
	if !cache.verify(context.Background(), candidate) || !cache.verify(context.Background(), candidate) {
		t.Fatal("expected cached verification result")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("verifier calls=%d, want 1", got)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	candidate.Secret = "canceled-secret"
	var canceledCalls int32
	candidate.Verifier = func(ctx context.Context, _ string) bool {
		atomic.AddInt32(&canceledCalls, 1)
		return ctx.Err() == nil
	}
	if cache.verify(canceled, candidate) {
		t.Fatal("expected canceled verification to fail")
	}
	if !cache.verify(context.Background(), candidate) {
		t.Fatal("expected failed canceled result to be retried")
	}
	if got := atomic.LoadInt32(&canceledCalls); got != 2 {
		t.Fatalf("canceled verifier calls=%d, want 2", got)
	}
}

func TestScannerAllowedRelPathAppliesGitHistoryFilters(t *testing.T) {
	s := New(Config{Include: []string{"*.txt"}, Exclude: []string{"ignored.*"}}, nil)
	if !s.allowedRelPath("config.txt") {
		t.Fatal("expected included txt path")
	}
	if s.allowedRelPath("ignored.txt") {
		t.Fatal("expected excluded path to be rejected")
	}
	if s.allowedRelPath("image.png") {
		t.Fatal("expected default excluded binary path to be rejected")
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

func TestGitHistoryLogOnlyIncludesFilesChangedInCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(dir, "unchanged.txt"), []byte("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "unchanged.txt")
	runGit(t, dir, "commit", "-m", "add unchanged file")
	if err := os.WriteFile(filepath.Join(dir, "changed.txt"), []byte("ordinary content"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "changed.txt")
	runGit(t, dir, "commit", "-m", "change another file")
	commit := strings.TrimSpace(string(runGitOutput(t, dir, "rev-parse", "HEAD")))

	out := runGitOutput(t, dir, "log", commit+"^!", "--root", "-z", "--format=commit:%H", "--name-only", "--diff-filter=AMR")
	currentCommit := ""
	var paths []string
	for _, record := range bytes.Split(out, []byte{0}) {
		parsedCommit, file, ok := parseGitHistoryRecord(string(record), currentCommit)
		if parsedCommit != "" {
			currentCommit = parsedCommit
		}
		if ok {
			paths = append(paths, file)
		}
	}
	if len(paths) != 1 || paths[0] != "changed.txt" {
		t.Fatalf("expected only changed.txt for latest commit, got %#v", paths)
	}
}

func TestHistoryBlobCacheReusesAnalysisAndPreservesIdentity(t *testing.T) {
	cache := newHistoryBlobCache()
	var scans int
	scan := func() []detectors.Finding {
		scans++
		return []detectors.Finding{{DetectorID: "test", Secret: "secret-value", File: "old.env", Commit: "commit-one", Fingerprint: "old"}}
	}
	first := cache.findings(context.Background(), "blob-id", "old.env", "commit-one", scan)
	second := cache.findings(context.Background(), "blob-id", "new.env", "commit-two", scan)
	if scans != 1 {
		t.Fatalf("analysis ran %d times, want 1", scans)
	}
	if len(first) != 1 || first[0].File != "old.env" || first[0].Commit != "commit-one" {
		t.Fatalf("unexpected first findings: %#v", first)
	}
	if len(second) != 1 || second[0].File != "new.env" || second[0].Commit != "commit-two" {
		t.Fatalf("unexpected reidentified findings: %#v", second)
	}
	if second[0].Fingerprint == "old" {
		t.Fatal("expected fingerprint to be recomputed")
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

func runGitOutput(t *testing.T, dir string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v: %s", args, err, string(out))
	}
	return out
}

type countingDetector struct {
	id               string
	keywords         []string
	calls            *int32
	prefilteredCalls *int32
}

func (d countingDetector) Detect([]byte) []detectors.Candidate {
	atomic.AddInt32(d.calls, 1)
	return nil
}

func (d countingDetector) DetectPrefiltered([]byte) []detectors.Candidate {
	atomic.AddInt32(d.prefilteredCalls, 1)
	return nil
}

func (d countingDetector) Info() detectors.Info {
	return detectors.Info{ID: d.id, Keywords: d.keywords}
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
