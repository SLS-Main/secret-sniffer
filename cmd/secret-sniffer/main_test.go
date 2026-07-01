package main

import (
	"errors"
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
