package s3scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/progress"
)

type fakeS3 struct {
	mu            sync.Mutex
	objects       map[string][]types.Object
	bodies        map[string]string
	getCalls      []string
	getIfMatch    map[string]string
	listTokens    []string
	truncated     bool
	nextToken     string
	activeBuckets int
	maxActive     int
	listDelay     time.Duration
	bodyFactory   func(string) io.ReadCloser
	listBarrier   chan struct{}
	barrierOnce   sync.Once
	listFailures  int
	getFailures   map[string]int
	versions      map[string][]types.ObjectVersion
	deleteMarkers map[string][]types.DeleteMarkerEntry
	getVersionIDs []string
}

func (f *fakeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{}, nil
}

func (f *fakeS3) ListObjectVersions(_ context.Context, in *s3.ListObjectVersionsInput, _ ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bucket := aws.ToString(in.Bucket)
	return &s3.ListObjectVersionsOutput{Versions: f.versions[bucket], DeleteMarkers: f.deleteMarkers[bucket], IsTruncated: aws.Bool(false)}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	if f.listFailures > 0 {
		f.listFailures--
		f.mu.Unlock()
		return nil, &smithy.GenericAPIError{Code: "SlowDown", Message: "retry"}
	}
	f.activeBuckets++
	if f.activeBuckets > f.maxActive {
		f.maxActive = f.activeBuckets
	}
	f.listTokens = append(f.listTokens, aws.ToString(in.ContinuationToken))
	if f.listBarrier != nil && f.activeBuckets >= 2 {
		f.barrierOnce.Do(func() { close(f.listBarrier) })
	}
	f.mu.Unlock()
	if f.listBarrier != nil {
		<-f.listBarrier
	}
	time.Sleep(f.listDelay)
	f.mu.Lock()
	f.activeBuckets--
	objects := f.objects[aws.ToString(in.Bucket)]
	f.mu.Unlock()
	return &s3.ListObjectsV2Output{Contents: objects, IsTruncated: aws.Bool(f.truncated), NextContinuationToken: aws.String(f.nextToken)}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := aws.ToString(in.Key)
	f.mu.Lock()
	f.getCalls = append(f.getCalls, key)
	f.getVersionIDs = append(f.getVersionIDs, aws.ToString(in.VersionId))
	if f.getFailures[key] > 0 {
		f.getFailures[key]--
		f.mu.Unlock()
		return nil, &smithy.GenericAPIError{Code: "ServiceUnavailable", Message: "retry"}
	}
	if f.getIfMatch == nil {
		f.getIfMatch = map[string]string{}
	}
	f.getIfMatch[key] = aws.ToString(in.IfMatch)
	body := f.bodies[key+"@"+aws.ToString(in.VersionId)]
	if body == "" {
		body = f.bodies[key]
	}
	factory := f.bodyFactory
	f.mu.Unlock()
	if factory != nil {
		return &s3.GetObjectOutput{Body: factory(key)}, nil
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewBufferString(body))}, nil
}

func TestS3VersionScanningUsesVersionIDsAndDistinctFingerprints(t *testing.T) {
	client := &fakeS3{
		versions: map[string][]types.ObjectVersion{"bucket": {
			{Key: aws.String("config.env"), VersionId: aws.String("v1"), ETag: aws.String(`"one"`), Size: aws.Int64(6), IsLatest: aws.Bool(false)},
			{Key: aws.String("config.env"), VersionId: aws.String("v2"), ETag: aws.String(`"two"`), Size: aws.Int64(6), IsLatest: aws.Bool(true)},
		}},
		bodies: map[string]string{"config.env@v1": "secret", "config.env@v2": "secret"},
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"bucket"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var committed []detectors.Finding
	runner, err := New(client, Config{
		Buckets: []string{"bucket"}, VersionPolicy: "all", Store: store,
		ScanObject: func(_ context.Context, file string, _ []byte) []detectors.Finding {
			return []detectors.Finding{{DetectorID: "test", File: file, Secret: "same"}}
		},
		CommitFindings: func(findings []detectors.Finding) error { committed = append(committed, findings...); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Scan(context.Background())
	if result.ObjectsScanned != 2 || len(committed) != 2 || len(client.getVersionIDs) != 2 {
		t.Fatalf("unexpected version result=%#v findings=%#v versions=%v", result, committed, client.getVersionIDs)
	}
	if committed[0].Fingerprint == committed[1].Fingerprint || committed[0].Provenance.S3VersionID == committed[1].Provenance.S3VersionID {
		t.Fatalf("version provenance/fingerprints are not distinct: %#v", committed)
	}
}

func TestTransientS3FailuresRetryWithoutDuplicateCommit(t *testing.T) {
	client := &fakeS3{
		objects: map[string][]types.Object{"bucket": {{Key: aws.String("config.env"), Size: aws.Int64(6)}}},
		bodies:  map[string]string{"config.env": "secret"}, listFailures: 1, getFailures: map[string]int{"config.env": 1},
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"bucket"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	commits := 0
	runner, err := New(client, Config{
		Buckets: []string{"bucket"}, Store: store, RetryAttempts: 3, RetryBaseDelay: time.Millisecond,
		ScanObject: func(context.Context, string, []byte) []detectors.Finding {
			return []detectors.Finding{{DetectorID: "test"}}
		},
		CommitFindings: func(findings []detectors.Finding) error {
			commits += len(findings)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Scan(context.Background())
	if result.BucketsFailed != 0 || result.Findings != 1 || commits != 1 {
		t.Fatalf("unexpected retried result=%#v commits=%d", result, commits)
	}
	if len(client.getCalls) != 2 {
		t.Fatalf("GetObject calls=%d, want 2", len(client.getCalls))
	}
}

func TestS3ProgressShowsConcurrentDownloadAndScanning(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := progress.New(statePath, 2*time.Millisecond, "s3", "bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	downloadStarted := make(chan struct{}, 2)
	downloadRelease := make(chan struct{})
	scanStarted := make(chan struct{}, 2)
	scanRelease := make(chan struct{})
	client := &fakeS3{
		objects: map[string][]types.Object{"bucket": {
			{Key: aws.String("one.env"), Size: aws.Int64(7)},
			{Key: aws.String("two.env"), Size: aws.Int64(7)},
		}},
		bodies: map[string]string{},
		bodyFactory: func(string) io.ReadCloser {
			return &blockingReadCloser{reader: bytes.NewBufferString("content"), started: downloadStarted, release: downloadRelease}
		},
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"bucket"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(client, Config{
		Buckets: []string{"bucket"}, ObjectConcurrency: 2, Store: store, Progress: reporter,
		ScanObject: func(context.Context, string, []byte) []detectors.Finding {
			scanStarted <- struct{}{}
			<-scanRelease
			return nil
		},
		CommitFindings: func([]detectors.Finding) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan Result, 1)
	go func() { done <- runner.Scan(context.Background()) }()
	<-downloadStarted
	<-downloadStarted
	downloading := waitS3Progress(t, statePath, func(state progress.State) bool {
		return countItemStage(state.ActiveItems, progress.StageDownloading) == 2
	})
	if downloading.Counters.ItemsActive != 2 || downloading.Counters.ItemsQueued != 0 {
		t.Fatalf("unexpected downloading counters: %#v", downloading.Counters)
	}
	close(downloadRelease)
	<-scanStarted
	<-scanStarted
	waitS3Progress(t, statePath, func(state progress.State) bool {
		return countItemStage(state.ActiveItems, progress.StageScanning) == 2
	})
	close(scanRelease)
	result := <-done
	if result.BucketsFailed != 0 {
		t.Fatalf("unexpected scan result: %#v", result)
	}
	reporter.Close(progress.Final{Phase: progress.PhaseCompleted})
	final := waitS3Progress(t, statePath, func(state progress.State) bool { return state.Phase == progress.PhaseCompleted })
	if final.Counters.ItemsCompleted != 2 || final.Counters.ItemsActive != 0 || final.Counters.BytesDownloaded != 14 {
		t.Fatalf("unexpected final counters: %#v", final.Counters)
	}
}

func TestS3ProgressRecordsPreDownloadExtensionSkip(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "progress.json")
	reporter, err := progress.New(statePath, time.Hour, "s3", "bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeS3{
		objects: map[string][]types.Object{"bucket": {{Key: aws.String("photo.PNG"), Size: aws.Int64(100)}}},
		bodies:  map[string]string{},
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"bucket"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(client, Config{
		Buckets: []string{"bucket"}, Store: store, Progress: reporter,
		SkipObjectReason: func(string) string { return "extension_excluded" },
		ScanObject:       func(context.Context, string, []byte) []detectors.Finding { return nil },
		CommitFindings:   func([]detectors.Finding) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := runner.Scan(context.Background())
	if result.ObjectsSkipped != 1 || len(client.getCalls) != 0 {
		t.Fatalf("excluded object was not skipped before download: result=%#v gets=%v", result, client.getCalls)
	}
	reporter.Close(progress.Final{Phase: progress.PhaseCompleted})
	state := waitS3Progress(t, statePath, func(state progress.State) bool { return state.Phase == progress.PhaseCompleted })
	if state.Counters.ItemsSkipped != 1 || state.LastCompleted == nil || state.LastCompleted.Reason != "extension_excluded" {
		t.Fatalf("unexpected skipped progress state: %#v", state)
	}
}

type blockingReadCloser struct {
	reader  io.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingReadCloser) Read(p []byte) (int, error) {
	r.once.Do(func() {
		r.started <- struct{}{}
		<-r.release
	})
	return r.reader.Read(p)
}

func (r *blockingReadCloser) Close() error { return nil }

func waitS3Progress(t *testing.T, path string, predicate func(progress.State) bool) progress.State {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			var state progress.State
			if json.Unmarshal(b, &state) == nil && predicate(state) {
				return state
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for S3 progress state")
	return progress.State{}
}

func countItemStage(items []progress.Item, stage string) int {
	count := 0
	for _, item := range items {
		if item.Stage == stage {
			count++
		}
	}
	return count
}

func TestScannerScansBucketsConcurrentlyAndSkipsBeforeDownload(t *testing.T) {
	client := &fakeS3{
		objects: map[string][]types.Object{
			"one": {{Key: aws.String("secret.txt"), Size: aws.Int64(6), ETag: aws.String(`"etag-one"`)}, {Key: aws.String("photo.PNG"), Size: aws.Int64(6)}},
			"two": {{Key: aws.String("config.env"), Size: aws.Int64(6)}},
		},
		bodies: map[string]string{"secret.txt": "secret", "config.env": "secret"}, listBarrier: make(chan struct{}),
	}
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"one", "two"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := New(client, Config{
		Buckets: []string{"one", "two"}, BucketConcurrency: 2, ObjectConcurrency: 2, MaxObjectBytes: 1024, Store: store,
		AllowObject: func(key string) bool { return filepath.Ext(key) != ".PNG" },
		ScanObject: func(_ context.Context, name string, _ []byte) []detectors.Finding {
			return []detectors.Finding{{File: name}}
		},
		CommitFindings: func([]detectors.Finding) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := scanner.Scan(context.Background())
	if result.BucketsCompleted != 2 || result.ObjectsScanned != 2 || result.ObjectsSkipped != 1 || result.Findings != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if client.maxActive != 2 {
		t.Fatalf("max concurrent buckets=%d, want 2", client.maxActive)
	}
	for _, key := range client.getCalls {
		if key == "photo.PNG" {
			t.Fatal("excluded object was downloaded")
		}
	}
	if client.getIfMatch["secret.txt"] != `"etag-one"` {
		t.Fatalf("GetObject If-Match=%q, want listed ETag", client.getIfMatch["secret.txt"])
	}
	if store.Bucket("one").Status != StatusCompleted || store.Bucket("two").Status != StatusCompleted {
		t.Fatalf("buckets not completed: %#v", store.Snapshot().Buckets)
	}
}

func TestCommitFailureDoesNotAdvanceCheckpoint(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"bucket"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeS3{
		objects: map[string][]types.Object{"bucket": {{Key: aws.String("config.env"), Size: aws.Int64(6)}}},
		bodies:  map[string]string{"config.env": "secret"}, truncated: true, nextToken: "next-page",
	}
	scanner, err := New(client, Config{
		Buckets: []string{"bucket"}, Store: store,
		ScanObject: func(context.Context, string, []byte) []detectors.Finding {
			return []detectors.Finding{{DetectorID: "test"}}
		},
		CommitFindings: func([]detectors.Finding) error { return errors.New("disk full") },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := scanner.Scan(context.Background())
	if result.BucketsFailed != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	state := store.Bucket("bucket")
	if state.Status != StatusFailed || state.ContinuationToken != "" || state.ObjectsScanned != 0 {
		t.Fatalf("checkpoint advanced after output failure: %#v", state)
	}
}

func TestScannerResumesFromCommittedContinuationToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := OpenStore(path, "job", "scope", []string{"bucket"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Start("bucket", false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.Checkpoint("bucket", "page-two", 10, 2, 3, time.Now()); err != nil {
		t.Fatal(err)
	}
	client := &fakeS3{objects: map[string][]types.Object{"bucket": {}}, bodies: map[string]string{}}
	scanner, err := New(client, Config{
		Buckets: []string{"bucket"}, Resume: true, Store: store,
		ScanObject:     func(context.Context, string, []byte) []detectors.Finding { return nil },
		CommitFindings: func([]detectors.Finding) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	scanner.Scan(context.Background())
	if len(client.listTokens) != 1 || client.listTokens[0] != "page-two" {
		t.Fatalf("list tokens=%v, want page-two", client.listTokens)
	}
	state := store.Bucket("bucket")
	if state.Status != StatusCompleted || state.ObjectsScanned != 10 || state.ObjectsSkipped != 2 || state.Findings != 3 {
		t.Fatalf("unexpected resumed state: %#v", state)
	}
}

func TestOpenStoreRejectsDifferentScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if _, err := OpenStore(path, "job", "first", []string{"bucket"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(path, "job", "different", []string{"bucket"}, time.Now()); err == nil {
		t.Fatal("expected scope mismatch")
	}
}

func TestCancelledScanMarksUndispatchedBucketsFailed(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "state.json"), "job", "scope", []string{"one", "two"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeS3{objects: map[string][]types.Object{}, bodies: map[string]string{}}
	scanner, err := New(client, Config{
		Buckets: []string{"one", "two"}, BucketConcurrency: 1, Store: store,
		ScanObject:     func(context.Context, string, []byte) []detectors.Finding { return nil },
		CommitFindings: func([]detectors.Finding) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := scanner.Scan(ctx)
	if result.BucketsFailed != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if store.Bucket("one").Status != StatusFailed || store.Bucket("two").Status != StatusFailed {
		t.Fatalf("cancelled buckets were not marked failed: %#v", store.Snapshot().Buckets)
	}
}

func TestStoreLockPreventsConcurrentJob(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	first, err := LockStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockStore(path); err == nil {
		t.Fatal("expected concurrent lock attempt to fail")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := LockStore(path)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
