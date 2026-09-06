package s3scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/progress"
)

type S3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	ListObjectVersions(context.Context, *s3.ListObjectVersionsInput, ...func(*s3.Options)) (*s3.ListObjectVersionsOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type Config struct {
	Buckets            []string
	Prefix             string
	AllBuckets         bool
	Resume             bool
	BucketConcurrency  int
	ObjectConcurrency  int
	MaxObjectBytes     int64
	Store              *Store
	ScanObject         func(context.Context, string, []byte) []detectors.Finding
	AllowObject        func(string) bool
	SkipObjectReason   func(string) string
	CommitFindings     func([]detectors.Finding) error
	Progress           progress.ProgressReporter
	ExactKeys          map[string]struct{}
	RetryAttempts      int
	RetryBaseDelay     time.Duration
	BucketRegions      map[string]string
	VersionPolicy      string
	DeleteMarkerPolicy string
	StorageClassPolicy string
}

type Result struct {
	BucketsCompleted int
	BucketsFailed    int
	ObjectsScanned   int64
	ObjectsSkipped   int64
	Findings         int64
	Failures         map[string]string
}

type Scanner struct {
	client     S3API
	cfg        Config
	nextSlotID atomic.Uint64
}

func New(client S3API, cfg Config) (*Scanner, error) {
	if client == nil || cfg.Store == nil || cfg.ScanObject == nil || cfg.CommitFindings == nil {
		return nil, errors.New("S3 scanner requires client, state store, object scanner, and finding committer")
	}
	if cfg.BucketConcurrency < 1 {
		cfg.BucketConcurrency = 1
	}
	if cfg.ObjectConcurrency < 1 {
		cfg.ObjectConcurrency = 1
	}
	if cfg.RetryAttempts < 1 {
		cfg.RetryAttempts = 1
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 200 * time.Millisecond
	}
	if cfg.VersionPolicy == "" {
		cfg.VersionPolicy = "current"
	}
	if cfg.DeleteMarkerPolicy == "" {
		cfg.DeleteMarkerPolicy = "ignore"
	}
	if cfg.StorageClassPolicy == "" {
		cfg.StorageClassPolicy = "skip"
	}
	if !slices.Contains([]string{"current", "all", "noncurrent"}, cfg.VersionPolicy) {
		return nil, fmt.Errorf("invalid S3 version policy %q", cfg.VersionPolicy)
	}
	if !slices.Contains([]string{"ignore", "skip", "error"}, cfg.DeleteMarkerPolicy) {
		return nil, fmt.Errorf("invalid S3 delete-marker policy %q", cfg.DeleteMarkerPolicy)
	}
	if !slices.Contains([]string{"skip", "error", "attempt"}, cfg.StorageClassPolicy) {
		return nil, fmt.Errorf("invalid S3 storage-class policy %q", cfg.StorageClassPolicy)
	}
	if cfg.VersionPolicy == "current" && cfg.DeleteMarkerPolicy != "ignore" {
		return nil, errors.New("S3 delete-marker policy requires --s3-version-policy=all or noncurrent")
	}
	return &Scanner{client: client, cfg: cfg}, nil
}

func DiscoverBuckets(ctx context.Context, client S3API) ([]string, error) {
	paginator := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{MaxBuckets: aws.Int32(10000)})
	var buckets []string
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list S3 buckets: %w", err)
		}
		for _, bucket := range out.Buckets {
			if name := aws.ToString(bucket.Name); name != "" {
				buckets = append(buckets, name)
			}
		}
	}
	slices.Sort(buckets)
	return slices.Compact(buckets), nil
}

func (s *Scanner) Scan(ctx context.Context) Result {
	result := Result{Failures: map[string]string{}}
	selected := make([]string, 0, len(s.cfg.Buckets))
	for _, bucket := range s.cfg.Buckets {
		if !s.cfg.Resume || s.cfg.Store.Bucket(bucket).Status != StatusCompleted {
			selected = append(selected, bucket)
		}
	}
	buckets := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range s.cfg.BucketConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bucket := range buckets {
				stats, err := s.scanBucket(ctx, bucket)
				mu.Lock()
				result.ObjectsScanned += stats.scanned
				result.ObjectsSkipped += stats.skipped
				result.Findings += stats.findings
				if err != nil {
					result.BucketsFailed++
					result.Failures[bucket] = err.Error()
				} else {
					result.BucketsCompleted++
				}
				mu.Unlock()
			}
		}()
	}
	for i, bucket := range selected {
		select {
		case <-ctx.Done():
			close(buckets)
			wg.Wait()
			for _, pending := range selected[i:] {
				err := ctx.Err()
				if stateErr := s.cfg.Store.Fail(pending, err, time.Now()); stateErr != nil {
					err = errors.Join(err, stateErr)
				}
				result.BucketsFailed++
				result.Failures[pending] = err.Error()
			}
			return result
		case buckets <- bucket:
		}
	}
	close(buckets)
	wg.Wait()
	return result
}

type bucketStats struct{ scanned, skipped, findings int64 }

func (s *Scanner) scanBucket(ctx context.Context, bucket string) (bucketStats, error) {
	if err := s.cfg.Store.Start(bucket, s.cfg.Resume, time.Now()); err != nil {
		return bucketStats{}, err
	}
	if s.cfg.VersionPolicy != "current" {
		return s.scanVersionBucket(ctx, bucket)
	}
	continuation := s.cfg.Store.Bucket(bucket).ContinuationToken
	var total bucketStats
	for {
		if s.cfg.Progress != nil {
			s.cfg.Progress.SetPhase(progress.PhaseListing)
		}
		input := &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(s.cfg.Prefix)}
		if continuation != "" {
			input.ContinuationToken = aws.String(continuation)
		}
		page, err := retryValue(ctx, s.cfg, func() (*s3.ListObjectsV2Output, error) {
			return s.client.ListObjectsV2(ctx, input)
		})
		if err != nil {
			return total, s.fail(bucket, fmt.Errorf("list s3://%s: %w", bucket, err))
		}
		if s.cfg.Progress != nil {
			s.cfg.Progress.DiscoverItems(int64(len(page.Contents)))
			s.cfg.Progress.SetPhase(progress.PhaseDownloading)
		}
		objects := make([]objectRef, 0, len(page.Contents))
		for _, object := range page.Contents {
			objects = append(objects, objectRef{object: object})
		}
		pageStats, findings, err := s.scanPage(ctx, bucket, objects)
		if err != nil {
			return total, s.fail(bucket, err)
		}
		if err := s.cfg.CommitFindings(findings); err != nil {
			return total, s.fail(bucket, fmt.Errorf("commit findings for s3://%s: %w", bucket, err))
		}
		next := aws.ToString(page.NextContinuationToken)
		if aws.ToBool(page.IsTruncated) && (next == "" || next == continuation) {
			return total, s.fail(bucket, fmt.Errorf("S3 returned an invalid or repeated continuation token for s3://%s", bucket))
		}
		if err := s.cfg.Store.Checkpoint(bucket, next, pageStats.scanned, pageStats.skipped, pageStats.findings, time.Now()); err != nil {
			return total, s.fail(bucket, fmt.Errorf("persist checkpoint for s3://%s: %w", bucket, err))
		}
		total.scanned += pageStats.scanned
		total.skipped += pageStats.skipped
		total.findings += pageStats.findings
		if !aws.ToBool(page.IsTruncated) || next == "" {
			if err := s.cfg.Store.Complete(bucket, time.Now()); err != nil {
				return total, s.fail(bucket, fmt.Errorf("persist completion for s3://%s: %w", bucket, err))
			}
			return total, nil
		}
		continuation = next
	}
}

func (s *Scanner) scanVersionBucket(ctx context.Context, bucket string) (bucketStats, error) {
	state := s.cfg.Store.Bucket(bucket)
	keyMarker, versionMarker := state.KeyMarker, state.VersionIDMarker
	var total bucketStats
	for {
		if s.cfg.Progress != nil {
			s.cfg.Progress.SetPhase(progress.PhaseListing)
		}
		input := &s3.ListObjectVersionsInput{Bucket: aws.String(bucket), Prefix: aws.String(s.cfg.Prefix)}
		if keyMarker != "" {
			input.KeyMarker = aws.String(keyMarker)
		}
		if versionMarker != "" {
			input.VersionIdMarker = aws.String(versionMarker)
		}
		page, err := retryValue(ctx, s.cfg, func() (*s3.ListObjectVersionsOutput, error) {
			return s.client.ListObjectVersions(ctx, input)
		})
		if err != nil {
			return total, s.fail(bucket, fmt.Errorf("list versions s3://%s: %w", bucket, err))
		}
		objects := make([]objectRef, 0, len(page.Versions))
		for _, version := range page.Versions {
			if s.cfg.VersionPolicy == "noncurrent" && aws.ToBool(version.IsLatest) {
				continue
			}
			objects = append(objects, objectRef{object: types.Object{
				Key: version.Key, ETag: version.ETag, Size: version.Size, LastModified: version.LastModified,
				StorageClass: types.ObjectStorageClass(version.StorageClass),
			}, versionID: aws.ToString(version.VersionId)})
		}
		markerSkips := int64(0)
		if len(page.DeleteMarkers) > 0 {
			switch s.cfg.DeleteMarkerPolicy {
			case "error":
				return total, s.fail(bucket, fmt.Errorf("encountered %d delete marker(s) in s3://%s", len(page.DeleteMarkers), bucket))
			case "skip":
				markerSkips = int64(len(page.DeleteMarkers))
			}
		}
		if s.cfg.Progress != nil {
			discovered := len(objects)
			if s.cfg.DeleteMarkerPolicy == "skip" {
				discovered += len(page.DeleteMarkers)
			}
			s.cfg.Progress.DiscoverItems(int64(discovered))
			if markerSkips > 0 {
				s.cfg.Progress.SkipItems(markerSkips)
			}
			s.cfg.Progress.SetPhase(progress.PhaseDownloading)
		}
		pageStats, findings, err := s.scanPage(ctx, bucket, objects)
		pageStats.skipped += markerSkips
		if err != nil {
			return total, s.fail(bucket, err)
		}
		if err := s.cfg.CommitFindings(findings); err != nil {
			return total, s.fail(bucket, fmt.Errorf("commit findings for s3://%s: %w", bucket, err))
		}
		nextKey, nextVersion := aws.ToString(page.NextKeyMarker), aws.ToString(page.NextVersionIdMarker)
		if aws.ToBool(page.IsTruncated) && (nextKey == "" || nextKey == keyMarker && nextVersion == versionMarker) {
			return total, s.fail(bucket, fmt.Errorf("S3 returned an invalid or repeated version cursor for s3://%s", bucket))
		}
		if err := s.cfg.Store.CheckpointVersions(bucket, nextKey, nextVersion, pageStats.scanned, pageStats.skipped, pageStats.findings, time.Now()); err != nil {
			return total, s.fail(bucket, fmt.Errorf("persist version checkpoint for s3://%s: %w", bucket, err))
		}
		total.scanned += pageStats.scanned
		total.skipped += pageStats.skipped
		total.findings += pageStats.findings
		if !aws.ToBool(page.IsTruncated) {
			if err := s.cfg.Store.Complete(bucket, time.Now()); err != nil {
				return total, s.fail(bucket, fmt.Errorf("persist completion for s3://%s: %w", bucket, err))
			}
			return total, nil
		}
		keyMarker, versionMarker = nextKey, nextVersion
	}
}

type objectResult struct {
	findings []detectors.Finding
	skipped  bool
	err      error
}

type objectRef struct {
	object    types.Object
	versionID string
}

func (s *Scanner) scanPage(ctx context.Context, bucket string, objects []objectRef) (bucketStats, []detectors.Finding, error) {
	jobs := make(chan objectRef, s.cfg.ObjectConcurrency)
	results := make(chan objectResult)
	var wg sync.WaitGroup
	for range s.cfg.ObjectConcurrency {
		slot := fmt.Sprintf("s3-object-%02d", s.nextSlotID.Add(1))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for object := range jobs {
				results <- s.scanObjectVersion(ctx, slot, bucket, object.object, object.versionID)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, object := range objects {
			if s.cfg.Progress != nil {
				s.cfg.Progress.QueueItems(1)
			}
			select {
			case <-ctx.Done():
				if s.cfg.Progress != nil {
					s.cfg.Progress.QueueItems(-1)
				}
				return
			case jobs <- object:
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var stats bucketStats
	var findings []detectors.Finding
	var pageErr error
	for result := range results {
		if result.err != nil {
			pageErr = errors.Join(pageErr, result.err)
			continue
		}
		if result.skipped {
			stats.skipped++
			continue
		}
		stats.scanned++
		stats.findings += int64(len(result.findings))
		findings = append(findings, result.findings...)
	}
	if ctx.Err() != nil {
		pageErr = errors.Join(pageErr, ctx.Err())
	}
	return stats, findings, pageErr
}

func (s *Scanner) scanObject(ctx context.Context, slot, bucket string, object types.Object) objectResult {
	return s.scanObjectVersion(ctx, slot, bucket, object, "")
}

func (s *Scanner) scanObjectVersion(ctx context.Context, slot, bucket string, object types.Object, versionID string) objectResult {
	key := aws.ToString(object.Key)
	virtualPath := "s3://" + bucket + "/" + key
	item := progress.Item{Stage: progress.StageDownloading, Bucket: bucket, Path: key, CountBytes: true}
	if object.Size != nil {
		item.BytesTotal = *object.Size
	}
	skipReason := ""
	if len(s.cfg.ExactKeys) > 0 {
		if _, selected := s.cfg.ExactKeys[key]; !selected {
			skipReason = "path_excluded"
		}
	}
	switch {
	case skipReason != "":
	case key == "":
		skipReason = "path_excluded"
	case s.cfg.MaxObjectBytes > 0 && object.Size != nil && *object.Size > s.cfg.MaxObjectBytes:
		skipReason = "object_too_large"
	case object.StorageClass == types.ObjectStorageClassGlacier || object.StorageClass == types.ObjectStorageClassDeepArchive:
		if s.cfg.StorageClassPolicy == "skip" {
			skipReason = "unsupported_storage_class"
		} else if s.cfg.StorageClassPolicy == "error" {
			if s.cfg.Progress != nil {
				item.Stage = progress.StageFailed
				s.cfg.Progress.StartItem(slot, item)
				s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageFailed, Reason: "unsupported_storage_class"})
			}
			return objectResult{err: fmt.Errorf("unsupported storage class for %s", virtualPath)}
		}
	case s.cfg.SkipObjectReason != nil:
		skipReason = s.cfg.SkipObjectReason(key)
	case s.cfg.AllowObject != nil && !s.cfg.AllowObject(key):
		skipReason = "path_excluded"
	}
	if skipReason != "" {
		if s.cfg.Progress != nil {
			item.Stage = progress.StageSkipped
			s.cfg.Progress.StartItem(slot, item)
			s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageSkipped, Reason: skipReason})
		}
		return objectResult{skipped: true}
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.StartItem(slot, item)
	}
	input := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if versionID != "" {
		input.VersionId = aws.String(versionID)
	}
	if object.ETag != nil {
		input.IfMatch = object.ETag
	}
	var b []byte
	var totalRead int64
	err := retryAction(ctx, s.cfg, func() error {
		out, err := s.client.GetObject(ctx, input)
		if err != nil {
			return err
		}
		counter := &progressReader{reader: out.Body, reporter: s.cfg.Progress, slot: slot, read: totalRead}
		reader := io.Reader(counter)
		if s.cfg.MaxObjectBytes > 0 {
			reader = io.LimitReader(counter, s.cfg.MaxObjectBytes+1)
		}
		content, readErr := io.ReadAll(reader)
		closeErr := out.Body.Close()
		totalRead = counter.read
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		b = content
		return nil
	})
	if err != nil {
		if s.cfg.Progress != nil {
			s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageFailed, Reason: "read_error", Error: err.Error(), BytesRead: totalRead})
		}
		return objectResult{err: fmt.Errorf("read %s: %w", virtualPath, err)}
	}
	if s.cfg.MaxObjectBytes > 0 && int64(len(b)) > s.cfg.MaxObjectBytes {
		if s.cfg.Progress != nil {
			s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageSkipped, Reason: "object_too_large", BytesRead: int64(len(b))})
		}
		return objectResult{skipped: true}
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageDownloaded, ClearArchive: true, BytesRead: totalRead, BytesTotal: int64(len(b))})
		s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageScanning, ClearArchive: true, BytesRead: totalRead, BytesTotal: int64(len(b))})
		s.cfg.Progress.SetPhase(progress.PhaseScanning)
	}
	findings := s.cfg.ScanObject(progress.WithSlot(ctx, slot), virtualPath, b)
	for i := range findings {
		findings[i] = detectors.SetS3Provenance(findings[i], bucket, key, versionID, aws.ToString(object.ETag), s.cfg.BucketRegions[bucket])
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageCompleted, BytesRead: totalRead})
	}
	return objectResult{findings: findings}
}

func retryValue[T any](ctx context.Context, cfg Config, operation func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := 1; attempt <= cfg.RetryAttempts; attempt++ {
		value, err := operation()
		if err == nil {
			return value, nil
		}
		lastErr = err
		if attempt == cfg.RetryAttempts || !retryableS3Error(err) {
			break
		}
		if err := sleepRetry(ctx, retryDelay(cfg.RetryBaseDelay, attempt)); err != nil {
			return zero, err
		}
	}
	return zero, lastErr
}

func retryAction(ctx context.Context, cfg Config, operation func() error) error {
	_, err := retryValue(ctx, cfg, func() (struct{}, error) { return struct{}{}, operation() })
	return err
}

func retryableS3Error(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(apiErr.ErrorCode())
		switch code {
		case "accessdenied", "invalidaccesskeyid", "signaturedoesnotmatch", "nosuchbucket", "nosuchkey", "notfound", "invalidobjectstate", "preconditionfailed":
			return false
		case "slowdown", "throttling", "throttlingexception", "requesttimeout", "internalerror", "serviceunavailable":
			return true
		}
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "connection reset") || strings.Contains(message, "connection refused") || strings.Contains(message, "unexpected eof") || strings.Contains(message, "temporary")
}

func retryDelay(base time.Duration, attempt int) time.Duration {
	delay := base
	for i := 1; i < attempt && delay < 30*time.Second; i++ {
		delay *= 2
	}
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return delay + time.Duration(rand.Int64N(max(1, int64(delay/2))))
}

func sleepRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type progressReader struct {
	reader   io.Reader
	reporter progress.ProgressReporter
	slot     string
	read     int64
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)
	if n > 0 && r.reporter != nil {
		r.reporter.UpdateItem(r.slot, progress.ItemUpdate{BytesRead: r.read})
	}
	return n, err
}

func (s *Scanner) fail(bucket string, err error) error {
	if stateErr := s.cfg.Store.Fail(bucket, err, time.Now()); stateErr != nil {
		return errors.Join(err, stateErr)
	}
	return err
}
