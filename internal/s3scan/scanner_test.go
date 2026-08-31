package s3scan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"secret-sniffer/internal/detectors"
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
}

func (f *fakeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	f.activeBuckets++
	if f.activeBuckets > f.maxActive {
		f.maxActive = f.activeBuckets
	}
	f.listTokens = append(f.listTokens, aws.ToString(in.ContinuationToken))
	f.mu.Unlock()
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
	if f.getIfMatch == nil {
		f.getIfMatch = map[string]string{}
	}
	f.getIfMatch[key] = aws.ToString(in.IfMatch)
	body := f.bodies[key]
	f.mu.Unlock()
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewBufferString(body))}, nil
}

func TestScannerScansBucketsConcurrentlyAndSkipsBeforeDownload(t *testing.T) {
	client := &fakeS3{
		objects: map[string][]types.Object{
			"one": {{Key: aws.String("secret.txt"), Size: aws.Int64(6), ETag: aws.String(`"etag-one"`)}, {Key: aws.String("photo.PNG"), Size: aws.Int64(6)}},
			"two": {{Key: aws.String("config.env"), Size: aws.Int64(6)}},
		},
		bodies: map[string]string{"secret.txt": "secret", "config.env": "secret"}, listDelay: 25 * time.Millisecond,
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
