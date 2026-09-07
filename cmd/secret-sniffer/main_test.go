package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/progress"
	"secret-sniffer/internal/scanner"
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

func TestScanExitCode(t *testing.T) {
	cases := []struct {
		name         string
		scanErrors   bool
		failFindings bool
		findings     int
		want         int
	}{
		{name: "success", want: 0},
		{name: "ignored scan error", scanErrors: false, want: 0},
		{name: "scan error", scanErrors: true, want: 1},
		{name: "findings", failFindings: true, findings: 1, want: 2},
		{name: "findings take precedence", scanErrors: true, failFindings: true, findings: 1, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanExitCode(tc.scanErrors, tc.failFindings, tc.findings); got != tc.want {
				t.Fatalf("scanExitCode()=%d, want %d", got, tc.want)
			}
		})
	}
}

func TestExtensionExcludePatterns(t *testing.T) {
	patterns, err := extensionExcludePatterns("png, .JPG,png")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"*.png", "*.jpg"}; !equalStrings(patterns, want) {
		t.Fatalf("patterns=%v, want %v", patterns, want)
	}
	if _, err := extensionExcludePatterns("*.png"); err == nil {
		t.Fatal("expected glob to be rejected as an extension")
	}
}

func TestRepairFindingJournalTruncatesIncompleteRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	valid := `{"detector_id":"one","fingerprint":"first"}` + "\n"
	if err := os.WriteFile(path, []byte(valid+`{"detector_id":"two"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := repairFindingJournal(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != valid {
		t.Fatalf("journal=%q, want %q", b, valid)
	}
}

func TestCountFindingJournalDeduplicatesReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	contents := `{"detector_id":"one","fingerprint":"same"}` + "\n" + `{"detector_id":"one","fingerprint":"same"}` + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := countFindingJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count=%d, want 1", count)
	}
}

func TestParseResumeOutputAction(t *testing.T) {
	cases := map[string]resumeOutputAction{
		"":          resumeOutputAppend,
		"a":         resumeOutputAppend,
		"append":    resumeOutputAppend,
		"o":         resumeOutputOverwrite,
		"overwrite": resumeOutputOverwrite,
		"n":         resumeOutputNew,
		"new":       resumeOutputNew,
	}
	for input, want := range cases {
		got, ok := parseResumeOutputAction(input)
		if !ok || got != want {
			t.Fatalf("parseResumeOutputAction(%q)=(%q,%v), want (%q,true)", input, got, ok, want)
		}
	}
	if _, ok := parseResumeOutputAction("invalid"); ok {
		t.Fatal("expected invalid action to be rejected")
	}
}

func TestNewResumeOutputPath(t *testing.T) {
	now := time.Date(2026, 7, 1, 14, 30, 45, 0, time.UTC)
	if got := newResumeOutputPath("findings.jsonl", now); got != "findings.resume-20260701-143045.jsonl" {
		t.Fatalf("unexpected resume output path: %q", got)
	}
	if got := newResumeOutputPath("findings", now); got != "findings.resume-20260701-143045" {
		t.Fatalf("unexpected extensionless resume output path: %q", got)
	}
}

func TestResumeOutputOpenOptionsDefaultsToAppendNonInteractive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	if err := os.WriteFile(path, []byte("existing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nonTerminal, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer nonTerminal.Close()
	gotPath, flags, err := resumeOutputOpenOptions(path, time.Unix(0, 0), nonTerminal, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path {
		t.Fatalf("path=%q, want %q", gotPath, path)
	}
	if flags&os.O_APPEND == 0 || flags&os.O_TRUNC != 0 {
		t.Fatalf("expected append flags, got %#x", flags)
	}
}

func TestAsyncJSONLWriterWritesAndRedacts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := newAsyncJSONLWriter(file, false, 1)
	writer.Write(detectors.Finding{DetectorID: "test", Secret: "supersecret", Redacted: "supe***cret"})
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "supersecret") || !strings.Contains(string(b), "supe***cret") {
		t.Fatalf("unexpected JSONL output: %s", b)
	}
}

func TestAsyncJSONLWriterReportsWriteFailureAtFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := newAsyncJSONLWriter(file, true, 25)
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	writer.Write(detectors.Finding{DetectorID: "test", Secret: "supersecret"})
	if err := writer.Flush(); err == nil {
		t.Fatal("expected closed output file error")
	}
	if err := writer.Close(); err == nil {
		t.Fatal("expected close to retain output error")
	}
}

func TestAsyncJSONLWriterAcknowledgesThresholdSyncFailure(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "findings.jsonl"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("forced fsync failure")
	writer := newAsyncJSONLWriterWithSync(file, true, 1, func() error { return syncErr })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.WriteFinding(ctx, detectors.Finding{DetectorID: "test", Secret: "secret-value"}); !errors.Is(err, syncErr) {
		t.Fatalf("WriteFinding error=%v, want %v", err, syncErr)
	}
	if err := writer.Close(); !errors.Is(err, syncErr) {
		t.Fatalf("Close error=%v, want %v", err, syncErr)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestThresholdSyncFailureStopsScanAndFailsProgress(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.env"), []byte("secret=abcdefghijklmnop"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputFile, err := os.OpenFile(filepath.Join(t.TempDir(), "findings.jsonl"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	syncErr := errors.New("forced fsync failure")
	writer := newAsyncJSONLWriterWithSync(outputFile, true, 1, func() error { return syncErr })
	progressPath := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := progress.New(progressPath, time.Millisecond, "filesystem", dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner := scanner.New(scanner.Config{Target: dir, Workers: 2, MaxFileBytes: 1024, Progress: reporter}, []detectors.Detector{
		detectors.NewRegex("test", "Test", "high", nil, `secret=([a-z]{16})`, 1, nil),
	})
	done := make(chan error, 1)
	go func() {
		_, scanErr := runner.ScanWithOptions(context.Background(), scanner.ScanOptions{
			FindingSink: scanner.FindingSinkFunc(func(ctx context.Context, finding detectors.Finding) error {
				return writer.WriteFinding(ctx, finding)
			}),
			RetainFindings: false,
		})
		done <- scanErr
	}()
	select {
	case scanErr := <-done:
		if !errors.Is(scanErr, syncErr) {
			t.Fatalf("scan error=%v, want %v", scanErr, syncErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan remained blocked waiting for writer acknowledgement")
	}
	if err := writer.Close(); !errors.Is(err, syncErr) {
		t.Fatalf("writer close error=%v, want %v", err, syncErr)
	}
	if err := outputFile.Close(); err != nil {
		t.Fatal(err)
	}
	if code := scanExitCode(true, false, 0); code != 1 {
		t.Fatalf("scan failure exit code=%d, want 1", code)
	}
	reporter.Close(progress.Final{Phase: progress.PhaseFailed, Error: syncErr.Error()})
	b, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatal(err)
	}
	var state progress.State
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != progress.PhaseFailed || state.Counters.ItemsFailed == 0 || state.Counters.Findings != 0 {
		t.Fatalf("unexpected failed progress state: %#v", state)
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

func TestProgressSourceType(t *testing.T) {
	if got := progressSourceType("bucket", false, "", "", false, "", false, "."); got != "s3" {
		t.Fatalf("S3 source type=%q", got)
	}
	if got := progressSourceType("", false, "", "", false, "", true, "/tmp/repo"); got != "git" {
		t.Fatalf("local history source type=%q", got)
	}
	if got := progressSourceType("", false, "acme", "", false, "", false, "."); got != "github" {
		t.Fatalf("GitHub source type=%q", got)
	}
	if got := progressSourceType("", false, "", "", false, "", false, "/tmp/files"); got != "filesystem" {
		t.Fatalf("filesystem source type=%q", got)
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

func TestReadRepoList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repos.txt")
	contents := strings.Join([]string{
		"# production repositories",
		"",
		"https://github.com/acme/one",
		"  https://github.com/acme/two.git  ",
		"https://github.com/acme/one",
	}, "\n")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := readRepoList(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://github.com/acme/one", "https://github.com/acme/two.git"}; !equalStrings(targets, want) {
		t.Fatalf("targets=%v, want %v", targets, want)
	}
}

func TestReadPatternFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "patterns.txt")
	if err := os.WriteFile(path, []byte("# comment\nsrc/**\n\n*.env\nsrc/**\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	patterns, err := readPatternFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"src/**", "*.env"}; !equalStrings(patterns, want) {
		t.Fatalf("patterns=%v, want %v", patterns, want)
	}
}

func TestScanTargetsRepoList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repos.txt")
	if err := os.WriteFile(path, []byte("https://github.com/acme/one\nhttps://github.com/acme/two\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, tokens, _, installations, summary, err := scanTargets(context.Background(), ".", path, "", "", false, []githubClient{{token: "token", installationID: 42}}, newConsole(true, true))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://github.com/acme/one", "https://github.com/acme/two"}; !equalStrings(targets, want) {
		t.Fatalf("targets=%v, want %v", targets, want)
	}
	if tokens[targets[0]] != "token" || installations[targets[1]] != 42 {
		t.Fatalf("repo-list targets did not receive client metadata: tokens=%v installations=%v", tokens, installations)
	}
	if summary.TotalRepositories != 2 {
		t.Fatalf("summary.TotalRepositories=%d, want 2", summary.TotalRepositories)
	}
}

func TestScanTargetsRepoListRejectsDiscoveryFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repos.txt")
	if err := os.WriteFile(path, []byte("https://github.com/acme/one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := scanTargets(context.Background(), ".", path, "acme", "", false, nil, newConsole(true, true)); err == nil {
		t.Fatal("expected --repo-list with discovery flags to fail")
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

func TestDiscoverySummaryAddScanResultCountsSuccess(t *testing.T) {
	var summary discoverySummary
	summary.addScanResult("https://github.com/acme/repo", 3)
	if summary.SuccessfulScans != 1 {
		t.Fatalf("successful scans=%d, want 1", summary.SuccessfulScans)
	}
	if summary.FindingsBeforeBaseline != 3 {
		t.Fatalf("findings before baseline=%d, want 3", summary.FindingsBeforeBaseline)
	}
	if len(summary.Orgs) != 1 || summary.Orgs[0].Name != "acme" || summary.Orgs[0].Findings != 3 {
		t.Fatalf("unexpected org summary: %#v", summary.Orgs)
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

func TestScanJobPrefix(t *testing.T) {
	cases := []struct {
		name         string
		target       string
		repoListPath string
		orgs         string
		enterprise   string
		accessible   bool
		want         string
	}{
		{name: "enterprise", enterprise: "Prod Enterprise", want: "enterprise-prod-enterprise"},
		{name: "org", orgs: "Acme, Example Org", want: "org-acme-example-org"},
		{name: "accessible", accessible: true, want: "accessible"},
		{name: "repo list", target: ".", repoListPath: "/tmp/repos.txt", want: "repo-list-repos"},
		{name: "github target", target: "https://github.com/Acme/Repo.git", want: "repo-acme-repo"},
		{name: "local target", target: "/tmp/My Repo", want: "target-my-repo"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scanJobPrefix(tc.target, tc.repoListPath, tc.orgs, tc.enterprise, tc.accessible); got != tc.want {
				t.Fatalf("scanJobPrefix()=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultScanJobID(t *testing.T) {
	jobID, err := defaultScanJobID("org-acme")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(jobID, "org-acme-") {
		t.Fatalf("job ID %q missing prefix", jobID)
	}
	digits := strings.TrimPrefix(jobID, "org-acme-")
	if len(digits) != 8 {
		t.Fatalf("job ID random suffix %q length=%d, want 8", digits, len(digits))
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			t.Fatalf("job ID random suffix contains non-digit: %q", digits)
		}
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

func TestScanJobCounts(t *testing.T) {
	targets := []string{"completed", "failed", "running", "pending", "missing"}
	state := &scanJobState{Targets: map[string]scanJobTarget{
		"completed": {Status: scanJobCompleted},
		"failed":    {Status: scanJobFailed},
		"running":   {Status: scanJobRunning},
		"pending":   {Status: scanJobPending},
	}}

	counts := scanJobCounts(targets, state)
	if counts.Discovered != 5 || counts.Completed != 1 || counts.Failed != 1 || counts.Running != 1 || counts.Pending != 2 {
		t.Fatalf("unexpected counts: %#v", counts)
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
