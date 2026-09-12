package azurescan

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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/progress"
)

type Client interface {
	ListContainers(context.Context) ([]string, error)
	ListBlobs(context.Context, string, string, func([]Blob) error) error
	DownloadBlob(context.Context, string, string) (io.ReadCloser, error)
}

type Blob struct {
	Name string
	Size *int64
	ETag string
}

type Config struct {
	Account              string
	Containers           []string
	Prefix               string
	AllContainers        bool
	ContainerConcurrency int
	BlobConcurrency      int
	MaxObjectBytes       int64
	ScanObject           func(context.Context, string, []byte) []detectors.Finding
	AllowObject          func(string) bool
	SkipObjectReason     func(string) string
	CommitFindings       func([]detectors.Finding) error
	Progress             progress.ProgressReporter
	ExactBlobs           map[string]struct{}
	RetryAttempts        int
	RetryBaseDelay       time.Duration
}

type Result struct {
	ContainersCompleted int
	ContainersFailed    int
	ObjectsScanned      int64
	ObjectsSkipped      int64
	Findings            int64
	Failures            map[string]string
}

type Scanner struct {
	client     Client
	cfg        Config
	nextSlotID atomic.Uint64
}

func New(client Client, cfg Config) (*Scanner, error) {
	if client == nil || cfg.ScanObject == nil || cfg.CommitFindings == nil {
		return nil, errors.New("Azure Blob scanner requires client, object scanner, and finding committer")
	}
	if cfg.ContainerConcurrency < 1 {
		cfg.ContainerConcurrency = 1
	}
	if cfg.BlobConcurrency < 1 {
		cfg.BlobConcurrency = 1
	}
	if cfg.RetryAttempts < 1 {
		cfg.RetryAttempts = 1
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = 200 * time.Millisecond
	}
	return &Scanner{client: client, cfg: cfg}, nil
}

func DiscoverContainers(ctx context.Context, client Client) ([]string, error) {
	containers, err := client.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Azure Blob containers: %w", err)
	}
	slices.Sort(containers)
	return slices.Compact(containers), nil
}

func (s *Scanner) Scan(ctx context.Context) Result {
	result := Result{Failures: map[string]string{}}
	containers := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range s.cfg.ContainerConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for container := range containers {
				stats, err := s.scanContainer(ctx, container)
				mu.Lock()
				result.ObjectsScanned += stats.scanned
				result.ObjectsSkipped += stats.skipped
				result.Findings += stats.findings
				if err != nil {
					result.ContainersFailed++
					result.Failures[container] = err.Error()
				} else {
					result.ContainersCompleted++
				}
				mu.Unlock()
			}
		}()
	}
	for i, container := range s.cfg.Containers {
		select {
		case <-ctx.Done():
			close(containers)
			wg.Wait()
			for _, pending := range s.cfg.Containers[i:] {
				result.ContainersFailed++
				result.Failures[pending] = ctx.Err().Error()
			}
			return result
		case containers <- container:
		}
	}
	close(containers)
	wg.Wait()
	return result
}

type containerStats struct{ scanned, skipped, findings int64 }

func (s *Scanner) scanContainer(ctx context.Context, container string) (containerStats, error) {
	var total containerStats
	err := retryAction(ctx, s.cfg, func() error {
		var attemptTotal containerStats
		if s.cfg.Progress != nil {
			s.cfg.Progress.SetPhase(progress.PhaseListing)
		}
		err := s.client.ListBlobs(ctx, container, s.cfg.Prefix, func(blobs []Blob) error {
			if s.cfg.Progress != nil {
				s.cfg.Progress.DiscoverItems(int64(len(blobs)))
				s.cfg.Progress.SetPhase(progress.PhaseDownloading)
			}
			stats, findings, err := s.scanBlobs(ctx, container, blobs)
			if err != nil {
				return err
			}
			if err := s.cfg.CommitFindings(findings); err != nil {
				return fmt.Errorf("commit findings for azureblob://%s/%s: %w", s.cfg.Account, container, err)
			}
			attemptTotal.scanned += stats.scanned
			attemptTotal.skipped += stats.skipped
			attemptTotal.findings += stats.findings
			return nil
		})
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		total = attemptTotal
		return nil
	})
	if err != nil {
		return total, fmt.Errorf("list azureblob://%s/%s: %w", s.cfg.Account, container, err)
	}
	return total, nil
}

type blobResult struct {
	findings []detectors.Finding
	skipped  bool
	err      error
}

func (s *Scanner) scanBlobs(ctx context.Context, container string, blobs []Blob) (containerStats, []detectors.Finding, error) {
	jobs := make(chan Blob, s.cfg.BlobConcurrency)
	results := make(chan blobResult)
	var wg sync.WaitGroup
	for range s.cfg.BlobConcurrency {
		slot := fmt.Sprintf("azure-blob-%02d", s.nextSlotID.Add(1))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for blob := range jobs {
				results <- s.scanBlob(ctx, slot, container, blob)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, blob := range blobs {
			if s.cfg.Progress != nil {
				s.cfg.Progress.QueueItems(1)
			}
			select {
			case <-ctx.Done():
				if s.cfg.Progress != nil {
					s.cfg.Progress.QueueItems(-1)
				}
				return
			case jobs <- blob:
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var stats containerStats
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

func (s *Scanner) scanBlob(ctx context.Context, slot, container string, blob Blob) blobResult {
	virtualPath := "azureblob://" + s.cfg.Account + "/" + container + "/" + blob.Name
	item := progress.Item{Stage: progress.StageDownloading, Bucket: s.cfg.Account + "/" + container, Path: blob.Name, CountBytes: true}
	if blob.Size != nil {
		item.BytesTotal = *blob.Size
	}
	skipReason := ""
	if len(s.cfg.ExactBlobs) > 0 {
		if _, selected := s.cfg.ExactBlobs[blob.Name]; !selected {
			skipReason = "path_excluded"
		}
	}
	switch {
	case skipReason != "":
	case blob.Name == "":
		skipReason = "path_excluded"
	case s.cfg.MaxObjectBytes > 0 && blob.Size != nil && *blob.Size > s.cfg.MaxObjectBytes:
		skipReason = "object_too_large"
	case s.cfg.SkipObjectReason != nil:
		skipReason = s.cfg.SkipObjectReason(blob.Name)
	case s.cfg.AllowObject != nil && !s.cfg.AllowObject(blob.Name):
		skipReason = "path_excluded"
	}
	if skipReason != "" {
		if s.cfg.Progress != nil {
			item.Stage = progress.StageSkipped
			s.cfg.Progress.StartItem(slot, item)
			s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageSkipped, Reason: skipReason})
		}
		return blobResult{skipped: true}
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.StartItem(slot, item)
	}
	var b []byte
	var totalRead int64
	err := retryAction(ctx, s.cfg, func() error {
		body, err := s.client.DownloadBlob(ctx, container, blob.Name)
		if err != nil {
			return err
		}
		counter := &progressReader{reader: body, reporter: s.cfg.Progress, slot: slot, read: totalRead}
		reader := io.Reader(counter)
		if s.cfg.MaxObjectBytes > 0 {
			reader = io.LimitReader(counter, s.cfg.MaxObjectBytes+1)
		}
		content, readErr := io.ReadAll(reader)
		closeErr := body.Close()
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
		return blobResult{err: fmt.Errorf("read %s: %w", virtualPath, err)}
	}
	if s.cfg.MaxObjectBytes > 0 && int64(len(b)) > s.cfg.MaxObjectBytes {
		if s.cfg.Progress != nil {
			s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageSkipped, Reason: "object_too_large", BytesRead: int64(len(b))})
		}
		return blobResult{skipped: true}
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageDownloaded, ClearArchive: true, BytesRead: totalRead, BytesTotal: int64(len(b))})
		s.cfg.Progress.UpdateItem(slot, progress.ItemUpdate{Stage: progress.StageScanning, ClearArchive: true, BytesRead: totalRead, BytesTotal: int64(len(b))})
		s.cfg.Progress.SetPhase(progress.PhaseScanning)
	}
	findings := s.cfg.ScanObject(progress.WithSlot(ctx, slot), virtualPath, b)
	for i := range findings {
		findings[i] = detectors.SetAzureBlobProvenance(findings[i], s.cfg.Account, container, blob.Name, "", blob.ETag)
	}
	if s.cfg.Progress != nil {
		s.cfg.Progress.CompleteItem(slot, progress.ItemResult{Stage: progress.StageCompleted, BytesRead: totalRead})
	}
	return blobResult{findings: findings}
}

type progressReader struct {
	reader   io.Reader
	reporter progress.ProgressReporter
	slot     string
	read     int64
}

func (r *progressReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.read += int64(n)
		if r.reporter != nil {
			r.reporter.UpdateItem(r.slot, progress.ItemUpdate{BytesRead: r.read})
		}
	}
	return n, err
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
		if attempt == cfg.RetryAttempts || !retryableAzureError(err) {
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

func retryableAzureError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.StatusCode {
		case 408, 429, 500, 502, 503, 504:
			return true
		case 401, 403, 404, 409, 412:
			return false
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
	for range max(0, attempt-1) {
		delay *= 2
	}
	jitter := time.Duration(rand.Int64N(int64(delay / 2)))
	return delay + jitter
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
