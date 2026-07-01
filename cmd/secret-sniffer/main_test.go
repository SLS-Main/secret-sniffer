package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShouldRefreshToken(t *testing.T) {
	now := time.Unix(1000, 0)
	if !shouldRefreshToken(time.Time{}, now) {
		t.Fatal("zero expiry should refresh")
	}
	if !shouldRefreshToken(now.Add(9*time.Minute), now) {
		t.Fatal("token inside refresh window should refresh")
	}
	if shouldRefreshToken(now.Add(11*time.Minute), now) {
		t.Fatal("token outside refresh window should not refresh")
	}
}

func TestDefaultOutputPath(t *testing.T) {
	cases := map[string]string{
		"json":  "secret-sniffer-findings.json",
		"jsonl": "secret-sniffer-findings.jsonl",
		"sarif": "secret-sniffer-findings.sarif",
		"human": "",
	}
	for format, want := range cases {
		if got := defaultOutputPath(format); got != want {
			t.Fatalf("defaultOutputPath(%q)=%q, want %q", format, got, want)
		}
	}
}

func TestIsGitHubDiscovery(t *testing.T) {
	if !isGitHubDiscovery("org", "", false) {
		t.Fatal("org should count as github discovery")
	}
	if !isGitHubDiscovery("", "enterprise", false) {
		t.Fatal("enterprise should count as github discovery")
	}
	if !isGitHubDiscovery("", "", true) {
		t.Fatal("accessible should count as github discovery")
	}
	if isGitHubDiscovery("", "", false) {
		t.Fatal("empty discovery inputs should not count as github discovery")
	}
}

func TestDiscoverySummaryAddInstallation(t *testing.T) {
	var summary discoverySummary
	client := githubClient{installationID: 42, account: "acme", accountType: "Organization"}
	summary.addInstallation(client, 3)
	summary.addInstallation(client, 2)
	if len(summary.Installations) != 1 {
		t.Fatalf("expected one installation, got %d", len(summary.Installations))
	}
	if summary.Installations[0].Repositories != 5 {
		t.Fatalf("expected five repos, got %d", summary.Installations[0].Repositories)
	}
}

func TestIsGitHubCloneTarget(t *testing.T) {
	if !isGitHubCloneTarget("https://github.com/acme/repo.git") {
		t.Fatal("expected github URL to be clone target")
	}
	if !isGitHubCloneTarget("https://www.github.com/acme/repo.git") {
		t.Fatal("expected www github URL to be clone target")
	}
	if isGitHubCloneTarget("https://gitlab.com/acme/repo.git") {
		t.Fatal("did not expect non-github URL to be clone target")
	}
	if isGitHubCloneTarget("/tmp/repo") {
		t.Fatal("did not expect local path to be clone target")
	}
}

func TestDiscoverySummaryAddScanFailure(t *testing.T) {
	var summary discoverySummary
	summary.addScanFailure("https://github.com/acme/repo", errors.New("temporary clone failure"))
	if summary.FailedScans != 1 {
		t.Fatalf("expected one failed scan, got %d", summary.FailedScans)
	}
	if len(summary.ScanFailures) != 1 || summary.ScanFailures[0].Target != "https://github.com/acme/repo" {
		t.Fatalf("unexpected scan failures: %#v", summary.ScanFailures)
	}
}

func TestTargetOwner(t *testing.T) {
	if got := targetOwner("https://github.com/acme/repo.git"); got != "acme" {
		t.Fatalf("targetOwner github=%q, want acme", got)
	}
	if got := targetOwner("https://www.github.com/acme/repo.git"); got != "acme" {
		t.Fatalf("targetOwner www github=%q, want acme", got)
	}
	if got := targetOwner("https://gitlab.com/acme/repo.git"); got != "" {
		t.Fatalf("targetOwner gitlab=%q, want empty", got)
	}
}

func TestScanJobStatePath(t *testing.T) {
	if got := scanJobStatePath("nightly", ""); got != filepath.Join(".secret-sniffer-jobs", "nightly.json") {
		t.Fatalf("unexpected default path: %q", got)
	}
	if got := scanJobStatePath("nightly", "/tmp/job.json"); got != "/tmp/job.json" {
		t.Fatalf("explicit path not honored: %q", got)
	}
}

func TestScanJobStateTransitions(t *testing.T) {
	now := time.Unix(1000, 0)
	state := scanJobState{JobID: "nightly", Targets: map[string]scanJobTarget{}}
	state.addTargets([]string{"https://github.com/acme/one", "https://github.com/acme/two"})
	state.markRunning("https://github.com/acme/one", now)
	state.markCompleted("https://github.com/acme/one", 3, now.Add(time.Second))
	state.markRunning("https://github.com/acme/two", now)
	state.markFailed("https://github.com/acme/two", errors.New("proxy failed"), now.Add(time.Second))

	completed := state.Targets["https://github.com/acme/one"]
	if completed.Status != scanJobCompleted || completed.Findings != 3 || completed.Attempts != 1 || completed.Error != "" {
		t.Fatalf("unexpected completed state: %#v", completed)
	}
	failed := state.Targets["https://github.com/acme/two"]
	if failed.Status != scanJobFailed || failed.Error != "proxy failed" || failed.Attempts != 1 {
		t.Fatalf("unexpected failed state: %#v", failed)
	}
	state.markRunning("https://github.com/acme/two", now.Add(2*time.Second))
	retried := state.Targets["https://github.com/acme/two"]
	if got := retried.Attempts; got != 2 {
		t.Fatalf("expected retry attempt count 2, got %d", got)
	}
	if retried.Findings != 0 || retried.Error != "" {
		t.Fatalf("retry should clear stale result fields: %#v", retried)
	}
}

func TestFilterScanJobTargets(t *testing.T) {
	targets := []string{"completed", "failed", "running", "pending"}
	state := &scanJobState{Targets: map[string]scanJobTarget{
		"completed": {Status: scanJobCompleted},
		"failed":    {Status: scanJobFailed},
		"running":   {Status: scanJobRunning},
		"pending":   {Status: scanJobPending},
	}}

	resume := filterScanJobTargets(targets, state, true, false)
	if want := []string{"failed", "running", "pending"}; !equalStrings(resume, want) {
		t.Fatalf("resume targets=%v, want %v", resume, want)
	}
	retry := filterScanJobTargets(targets, state, false, true)
	if want := []string{"failed"}; !equalStrings(retry, want) {
		t.Fatalf("retry targets=%v, want %v", retry, want)
	}
}

func TestWriteAndLoadScanJobState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jobs", "nightly.json")
	now := time.Unix(1000, 0)
	state := &scanJobState{JobID: "nightly", CreatedAt: now, UpdatedAt: now, Targets: map[string]scanJobTarget{"repo": {Status: scanJobCompleted, Findings: 2}}}
	if err := writeScanJobState(path, state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode=%o, want 600", info.Mode().Perm())
	}
	loaded, err := loadOrCreateScanJobState(path, "nightly", now)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Targets["repo"].Status != scanJobCompleted || loaded.Targets["repo"].Findings != 2 {
		t.Fatalf("unexpected loaded state: %#v", loaded.Targets["repo"])
	}

	b, err := json.Marshal(scanJobState{JobID: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateScanJobState(path, "nightly", now); err == nil {
		t.Fatal("expected job ID mismatch error")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
