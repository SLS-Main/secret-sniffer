package s3scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"secret-sniffer/internal/detectors"
)

type S3API interface {
	ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

type Config struct {
	Buckets           []string
	Prefix            string
	AllBuckets        bool
	Resume            bool
	BucketConcurrency int
	ObjectConcurrency int
	MaxObjectBytes    int64
	Store             *Store
	ScanObject        func(context.Context, string, []byte) []detectors.Finding
	AllowObject       func(string) bool
	CommitFindings    func([]detectors.Finding) error
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
	client S3API
	cfg    Config
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
	continuation := s.cfg.Store.Bucket(bucket).ContinuationToken
	var total bucketStats
	for {
		input := &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(s.cfg.Prefix)}
		if continuation != "" {
			input.ContinuationToken = aws.String(continuation)
		}
		page, err := s.client.ListObjectsV2(ctx, input)
		if err != nil {
			return total, s.fail(bucket, fmt.Errorf("list s3://%s: %w", bucket, err))
		}
		pageStats, findings, err := s.scanPage(ctx, bucket, page.Contents)
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

type objectResult struct {
	findings []detectors.Finding
	skipped  bool
	err      error
}

func (s *Scanner) scanPage(ctx context.Context, bucket string, objects []types.Object) (bucketStats, []detectors.Finding, error) {
	jobs := make(chan types.Object)
	results := make(chan objectResult)
	var wg sync.WaitGroup
	for range s.cfg.ObjectConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for object := range jobs {
				results <- s.scanObject(ctx, bucket, object)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, object := range objects {
			select {
			case <-ctx.Done():
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

func (s *Scanner) scanObject(ctx context.Context, bucket string, object types.Object) objectResult {
	key := aws.ToString(object.Key)
	virtualPath := "s3://" + bucket + "/" + key
	if key == "" || s.cfg.MaxObjectBytes > 0 && object.Size != nil && *object.Size > s.cfg.MaxObjectBytes || s.cfg.AllowObject != nil && !s.cfg.AllowObject(key) {
		return objectResult{skipped: true}
	}
	input := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if object.ETag != nil {
		input.IfMatch = object.ETag
	}
	out, err := s.client.GetObject(ctx, input)
	if err != nil {
		return objectResult{err: fmt.Errorf("get %s: %w", virtualPath, err)}
	}
	defer out.Body.Close()
	reader := io.Reader(out.Body)
	if s.cfg.MaxObjectBytes > 0 {
		reader = io.LimitReader(out.Body, s.cfg.MaxObjectBytes+1)
	}
	b, err := io.ReadAll(reader)
	if err != nil {
		return objectResult{err: fmt.Errorf("read %s: %w", virtualPath, err)}
	}
	if s.cfg.MaxObjectBytes > 0 && int64(len(b)) > s.cfg.MaxObjectBytes {
		return objectResult{skipped: true}
	}
	return objectResult{findings: s.cfg.ScanObject(ctx, virtualPath, b)}
}

func (s *Scanner) fail(bucket string, err error) error {
	if stateErr := s.cfg.Store.Fail(bucket, err, time.Now()); stateErr != nil {
		return errors.Join(err, stateErr)
	}
	return err
}
