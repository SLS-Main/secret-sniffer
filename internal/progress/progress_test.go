package progress

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReporterPublishesTransitionsAndFinalState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, 5*time.Millisecond, "s3", "bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.SetPhase(PhaseDownloading)
	reporter.DiscoverItems(1)
	reporter.QueueItems(1)
	reporter.StartItem("s3-object-01", Item{Stage: StageDownloading, Bucket: "bucket", Path: "config.env", BytesTotal: 12, CountBytes: true})
	reporter.UpdateItem("s3-object-01", ItemUpdate{Stage: StageScanning, BytesRead: 12})
	reporter.CompleteItem("s3-object-01", ItemResult{Stage: StageCompleted, BytesRead: 12, Findings: 1})
	reporter.Close(Final{Phase: PhaseCompleted})

	state := readState(t, path)
	if state.Phase != PhaseCompleted || state.Sequence < 2 {
		t.Fatalf("unexpected final state: %#v", state)
	}
	if state.Counters.ItemsDiscovered != 1 || state.Counters.ItemsQueued != 0 || state.Counters.ItemsActive != 0 || state.Counters.ItemsCompleted != 1 || state.Counters.BytesDownloaded != 12 || state.Counters.Findings != 1 {
		t.Fatalf("unexpected counters: %#v", state.Counters)
	}
	if state.LastCompleted == nil || state.LastCompleted.Path != "config.env" || state.LastCompleted.Findings != 1 {
		t.Fatalf("unexpected last completed item: %#v", state.LastCompleted)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("progress mode=%o, want 600", info.Mode().Perm())
	}
}

func TestReporterCancellationAndSanitization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "s3", "bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.DiscoverItems(1)
	reporter.StartItem("slot", Item{Stage: StageDownloading, Path: "https://user:path-token@example.com/safe.env?X-Amz-Signature=path-secret"})
	reporter.CompleteItem("slot", ItemResult{Stage: StageFailed, Error: `Authorization: Bearer ghp_super_secret, "token":"raw-json-token" https://example.com/file?X-Amz-Signature=credential`})
	reporter.Close(Final{Phase: PhaseCancelled, Error: "token=raw-credential"})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "ghp_super_secret") || strings.Contains(text, "raw-json-token") || strings.Contains(text, "raw-credential") || strings.Contains(text, "path-token") || strings.Contains(text, "path-secret") || strings.Contains(text, "X-Amz-Signature=credential") {
		t.Fatalf("progress state leaked sensitive data: %s", text)
	}
	if state := readState(t, path); state.Phase != PhaseCancelled {
		t.Fatalf("phase=%q, want cancelled", state.Phase)
	}
}

func TestReporterSanitizesCredentialBearingTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "github", "https://user:github-token@github.com/acme/repo?signature=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.Close(Final{Phase: PhaseCompleted})
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "github-token") || strings.Contains(string(b), "signature=secret") {
		t.Fatalf("target credentials leaked: %s", b)
	}
}

func TestReporterPreservesLegitimatePathMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "filesystem", "configs/token=prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.StartItem("file-01", Item{Stage: StageScanning, Path: "configs/token=prod/app.env"})
	reporter.CompleteItem("file-01", ItemResult{Stage: StageCompleted})
	reporter.Close(Final{Phase: PhaseCompleted})
	state := readState(t, path)
	if state.Target != "configs/token=prod" || state.LastCompleted == nil || state.LastCompleted.Path != "configs/token=prod/app.env" {
		t.Fatalf("legitimate path metadata was changed: %#v", state)
	}
}

func TestExtractingPhaseTracksAllActiveSlots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "filesystem", ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.SetPhase(PhaseScanningWorktree)
	reporter.StartItem("file-01", Item{Stage: StageScanning, Path: "one.zip"})
	reporter.StartItem("file-02", Item{Stage: StageScanning, Path: "two.zip"})
	reporter.UpdateItem("file-01", ItemUpdate{Stage: StageExtracting})
	reporter.UpdateItem("file-02", ItemUpdate{Stage: StageExtracting})
	reporter.UpdateItem("file-01", ItemUpdate{Stage: StageScanning})
	reporter.mu.Lock()
	phaseWhileExtracting := reporter.state.Phase
	reporter.mu.Unlock()
	if phaseWhileExtracting != PhaseExtracting {
		t.Fatalf("phase=%q while a slot is extracting", phaseWhileExtracting)
	}
	reporter.UpdateItem("file-02", ItemUpdate{Stage: StageScanning})
	reporter.mu.Lock()
	restoredPhase := reporter.state.Phase
	reporter.mu.Unlock()
	if restoredPhase != PhaseScanningWorktree {
		t.Fatalf("restored phase=%q, want scanning_worktree", restoredPhase)
	}
	reporter.Close(Final{Phase: PhaseCompleted})
}

func TestReporterUpdatesDoNotBlockSlowWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "filesystem", ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	reporter.writeFile = func(string, State) error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}
	reporter.StartItem("file-01", Item{Stage: StageScanning, Path: "config.env"})
	reporter.Snapshot()
	start := time.Now()
	for i := 0; i < 1000; i++ {
		reporter.UpdateItem("file-01", ItemUpdate{BytesRead: int64(i)})
		reporter.Snapshot()
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("progress updates blocked for %s", elapsed)
	}
	reporter.Close(Final{Phase: PhaseCompleted})
}

func TestLaterWriteFailureWarnsWithoutBlockingUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	warnings := make(chan error, 10)
	reporter, err := New(path, time.Hour, "filesystem", ".", func(err error) { warnings <- err })
	if err != nil {
		t.Fatal(err)
	}
	reporter.writeFile = func(string, State) error { return errors.New("disk unavailable") }
	reporter.SetPhase(PhaseScanning)
	select {
	case warning := <-warnings:
		if !strings.Contains(warning.Error(), "disk unavailable") {
			t.Fatalf("unexpected warning: %v", warning)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for progress warning")
	}
	reporter.DiscoverItems(1)
	reporter.Close(Final{Phase: PhaseCompleted})
}

func TestTerminalSnapshotRetriesTransientWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "filesystem", ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	var attempts int
	reporter.writeFile = func(path string, state State) error {
		attempts++
		if attempts == 1 {
			return errors.New("transient failure")
		}
		return writeState(path, state)
	}
	reporter.Close(Final{Phase: PhaseCompleted})
	if state := readState(t, path); state.Phase != PhaseCompleted {
		t.Fatalf("phase=%q, want completed", state.Phase)
	}
	if attempts != 2 {
		t.Fatalf("terminal write attempts=%d, want 2", attempts)
	}
}

func TestTerminalPublicationRejectsLateWorkerUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Hour, "filesystem", ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	reporter.writeFile = func(path string, state State) error {
		close(writeStarted)
		<-releaseWrite
		return writeState(path, state)
	}
	closed := make(chan struct{})
	go func() {
		reporter.Close(Final{Phase: PhaseFailed, Error: "scan failed"})
		close(closed)
	}()
	<-writeStarted
	reporter.SetPhase(PhaseScanning)
	reporter.DiscoverItems(1)
	reporter.StartItem("late-worker", Item{Stage: StageScanning, Path: "late.env"})
	close(releaseWrite)
	<-closed
	state := readState(t, path)
	if state.Phase != PhaseFailed || state.Counters.ItemsDiscovered != 0 || len(state.ActiveItems) != 0 {
		t.Fatalf("late worker overwrote terminal state: %#v", state)
	}
}

func TestConcurrentSnapshotsAlwaysRemainValidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := New(path, time.Millisecond, "filesystem", ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			slot := "file-" + string(rune('a'+worker))
			for i := 0; i < 100; i++ {
				reporter.StartItem(slot, Item{Stage: StageScanning, Path: slot})
				reporter.UpdateItem(slot, ItemUpdate{BytesRead: int64(i + 1)})
				reporter.CompleteItem(slot, ItemResult{Stage: StageCompleted})
			}
		}(worker)
	}
	for i := 0; i < 100; i++ {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var state State
		if err := json.Unmarshal(b, &state); err != nil {
			t.Fatalf("invalid concurrent snapshot: %v", err)
		}
	}
	wg.Wait()
	reporter.Close(Final{Phase: PhaseCompleted})
}

func TestReporterFailsStartupWhenPathCannotBeCreated(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(parent, "progress.json"), time.Second, "filesystem", ".", nil); err == nil {
		t.Fatal("expected startup progress write to fail")
	}
}

func readState(t *testing.T, path string) State {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	return state
}
