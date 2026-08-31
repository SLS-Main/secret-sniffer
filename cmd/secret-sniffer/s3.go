package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"secret-sniffer/internal/awsauth"
	"secret-sniffer/internal/baseline"
	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/output"
	"secret-sniffer/internal/s3scan"
	"secret-sniffer/internal/scanner"
)

type s3RunOptions struct {
	ScannerConfig       scanner.Config
	Registry            []detectors.Detector
	Buckets             []string
	AllBuckets          bool
	Prefix              string
	BucketConcurrency   int
	ObjectConcurrency   int
	JobID               string
	StatePath           string
	Resume              bool
	AWSProfile          string
	AWSRegion           string
	AWSAccessKeyID      string
	AWSSecretAccessKey  string
	AWSSessionToken     string
	SSODeviceAuth       bool
	Format              string
	OutputPath          string
	OutputFlushFindings int
	IncludeSecrets      bool
	BaselinePath        string
	WriteBaselinePath   string
	CustomDetectorsPath string
	Console             console
	StartedAt           time.Time
}

func runS3Scan(ctx context.Context, opts s3RunOptions) (int, error) {
	if len(opts.Buckets) > 0 && opts.AllBuckets {
		return 0, errors.New("--s3-buckets and --s3-all-buckets cannot be used together")
	}
	awsCfg, err := awsauth.Load(ctx, awsauth.Options{
		Profile: opts.AWSProfile, Region: opts.AWSRegion, AccessKeyID: opts.AWSAccessKeyID,
		SecretAccessKey: opts.AWSSecretAccessKey, SessionToken: opts.AWSSessionToken, SSODeviceAuth: opts.SSODeviceAuth,
		DevicePrompt: func(uri, code string) {
			opts.Console.info("AWS device authentication: open %s and enter code %s", uri, code)
		},
	})
	if err != nil {
		return 0, err
	}
	client := s3.NewFromConfig(awsCfg)
	if opts.AllBuckets {
		opts.Console.info("Discovering S3 buckets owned by the authenticated account")
		opts.Buckets, err = s3scan.DiscoverBuckets(ctx, client)
		if err != nil {
			return 0, err
		}
	}
	opts.Buckets = dedupeStrings(opts.Buckets)
	if len(opts.Buckets) == 0 {
		return 0, errors.New("no S3 buckets selected")
	}
	regionalClient := resolveS3BucketClients(ctx, awsCfg, client, opts.Buckets, opts.BucketConcurrency, opts.Console)
	format := strings.ToLower(opts.Format)
	switch format {
	case "human", "json", "jsonl", "sarif":
	default:
		return 0, fmt.Errorf("unknown output format %q", opts.Format)
	}
	if opts.OutputPath == "" {
		opts.OutputPath = defaultOutputPath(format)
	}
	if opts.JobID == "" {
		opts.JobID, err = defaultScanJobID("s3")
		if err != nil {
			return 0, err
		}
	}
	if opts.StatePath == "" {
		opts.StatePath = filepath.Join(".secret-sniffer-jobs", opts.JobID+"-s3.json")
	}
	journalPath := opts.OutputPath
	if format != "jsonl" {
		journalPath = opts.StatePath + ".findings.jsonl"
	}
	scopeHash, err := s3ScopeHash(opts)
	if err != nil {
		return 0, err
	}
	jobLock, err := s3scan.LockStore(opts.StatePath)
	if err != nil {
		return 0, err
	}
	defer jobLock.Close()
	store, err := s3scan.OpenStore(opts.StatePath, opts.JobID, scopeHash, opts.Buckets, opts.StartedAt)
	if err != nil {
		return 0, err
	}
	resumeProgress := opts.Resume && stateHasProgress(store.Snapshot())
	if resumeProgress {
		if _, err := os.Stat(journalPath); err != nil {
			if os.IsNotExist(err) {
				return 0, fmt.Errorf("cannot resume S3 job: finding journal %s is missing", journalPath)
			}
			return 0, err
		}
		if err := repairFindingJournal(journalPath); err != nil {
			return 0, err
		}
	}
	opts.Console.info("S3 scan job %s state=%s buckets=%d bucket_concurrency=%d object_concurrency=%d", opts.JobID, opts.StatePath, len(opts.Buckets), opts.BucketConcurrency, opts.ObjectConcurrency)

	var outputFile *os.File
	var streamWriter *asyncJSONLWriter
	if opts.OutputPath != "" {
		flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if resumeProgress && format == "jsonl" {
			// Checkpointed pages already exist only in this journal, so resume must append.
			flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		outputFile, err = os.OpenFile(opts.OutputPath, flags, 0o600)
		if err != nil {
			return 0, err
		}
		if err := syncParentDirectory(opts.OutputPath); err != nil {
			return 0, err
		}
		defer outputFile.Close()
		if format == "jsonl" {
			streamWriter = newAsyncJSONLWriter(outputFile, opts.IncludeSecrets, opts.OutputFlushFindings)
			opts.Console.info("Streaming S3 findings to %s", opts.OutputPath)
		}
	}
	journalFile := outputFile
	if format != "jsonl" {
		flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if resumeProgress {
			flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		journalFile, err = os.OpenFile(journalPath, flags, 0o600)
		if err != nil {
			return 0, err
		}
		defer journalFile.Close()
		if err := syncParentDirectory(journalPath); err != nil {
			return 0, err
		}
		streamWriter = newAsyncJSONLWriter(journalFile, true, opts.OutputFlushFindings)
	}
	var knownBaseline map[string]struct{}
	if opts.BaselinePath != "" {
		knownBaseline, err = baseline.Load(opts.BaselinePath)
		if err != nil {
			return 0, err
		}
	}

	runner := scanner.New(opts.ScannerConfig, opts.Registry)
	var committedFindings atomic.Int64
	commit := func(page []detectors.Finding) error {
		if knownBaseline != nil {
			page = baseline.Filter(page, knownBaseline)
		}
		for _, finding := range page {
			opts.Console.finding(finding)
			streamWriter.Write(finding)
		}
		if err := streamWriter.Flush(); err != nil {
			return err
		}
		committedFindings.Add(int64(len(page)))
		return nil
	}
	s3Scanner, err := s3scan.New(regionalClient, s3scan.Config{
		Buckets: opts.Buckets, Prefix: opts.Prefix, Resume: opts.Resume, BucketConcurrency: opts.BucketConcurrency,
		ObjectConcurrency: opts.ObjectConcurrency, MaxObjectBytes: opts.ScannerConfig.MaxFileBytes, Store: store,
		AllowObject: runner.AllowsRemotePath, ScanObject: runner.ScanContent, CommitFindings: commit,
	})
	if err != nil {
		return 0, err
	}
	result := s3Scanner.Scan(ctx)
	if streamWriter != nil {
		if err := streamWriter.Close(); err != nil {
			return 0, err
		}
	}
	var findings []detectors.Finding
	if format != "jsonl" || opts.WriteBaselinePath != "" {
		findings, err = readFindingJournal(journalPath)
		if err != nil {
			return 0, err
		}
		findings = dedupeFindings(findings)
	}
	if opts.WriteBaselinePath != "" {
		if err := baseline.Write(opts.WriteBaselinePath, findings); err != nil {
			return 0, err
		}
	}
	findingCount := int(committedFindings.Load())
	if format != "jsonl" {
		findingCount = len(findings)
	} else if opts.WriteBaselinePath != "" {
		findingCount = len(findings)
	} else {
		findingCount, err = countFindingJournal(journalPath)
		if err != nil {
			return 0, err
		}
	}
	meta := output.Meta{Target: strings.Join(opts.Buckets, ","), StartedAt: opts.StartedAt, Duration: time.Since(opts.StartedAt), Findings: findingCount}
	if outputFile == nil {
		if err := output.Write(os.Stdout, format, findings, meta, opts.IncludeSecrets); err != nil {
			return 0, err
		}
	} else if format != "jsonl" {
		if err := output.Write(outputFile, format, findings, meta, opts.IncludeSecrets); err != nil {
			return 0, err
		}
		if err := outputFile.Sync(); err != nil {
			return 0, err
		}
	}
	fmt.Fprintf(os.Stdout, "S3 scan complete: buckets_completed=%d buckets_failed=%d objects_scanned=%d objects_skipped=%d findings=%d duration=%s", result.BucketsCompleted, result.BucketsFailed, result.ObjectsScanned, result.ObjectsSkipped, findingCount, time.Since(opts.StartedAt).Round(time.Millisecond))
	if opts.OutputPath != "" {
		fmt.Fprintf(os.Stdout, " output=%s", opts.OutputPath)
	}
	fmt.Fprintln(os.Stdout)
	if result.BucketsFailed > 0 {
		failureErr := errors.New("one or more S3 buckets failed")
		for bucket, message := range result.Failures {
			failureErr = errors.Join(failureErr, fmt.Errorf("s3://%s: %s", bucket, message))
		}
		return findingCount, failureErr
	}
	return findingCount, nil
}

func stateHasProgress(state s3scan.State) bool {
	for _, bucket := range state.Buckets {
		if bucket.Status == s3scan.StatusCompleted || bucket.Status == s3scan.StatusRunning || bucket.Status == s3scan.StatusFailed || bucket.ContinuationToken != "" || bucket.ObjectsScanned > 0 || bucket.ObjectsSkipped > 0 {
			return true
		}
	}
	return false
}

func repairFindingJournal(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var validBytes int64
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			var finding detectors.Finding
			if line[len(line)-1] != '\n' || json.Unmarshal(line, &finding) != nil {
				if err := file.Truncate(validBytes); err != nil {
					return err
				}
				if err := file.Sync(); err != nil {
					return err
				}
				return syncParentDirectory(path)
			}
			validBytes += int64(len(line))
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}

func syncParentDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

func countFindingJournal(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	seen := map[string]struct{}{}
	decoder := json.NewDecoder(file)
	for {
		var finding detectors.Finding
		if err := decoder.Decode(&finding); err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("read S3 finding journal %s: %w", path, err)
		}
		key := finding.Fingerprint
		if key == "" {
			key = finding.DetectorID + "\x00" + finding.File + "\x00" + finding.Secret
		}
		seen[key] = struct{}{}
	}
	return len(seen), nil
}

type regionalS3Client struct {
	defaultClient *s3.Client
	byBucket      map[string]*s3.Client
}

func (c *regionalS3Client) ListBuckets(ctx context.Context, input *s3.ListBucketsInput, options ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return c.defaultClient.ListBuckets(ctx, input, options...)
}

func (c *regionalS3Client) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input, options ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	return c.client(aws.ToString(input.Bucket)).ListObjectsV2(ctx, input, options...)
}

func (c *regionalS3Client) GetObject(ctx context.Context, input *s3.GetObjectInput, options ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return c.client(aws.ToString(input.Bucket)).GetObject(ctx, input, options...)
}

func (c *regionalS3Client) client(bucket string) *s3.Client {
	if client := c.byBucket[bucket]; client != nil {
		return client
	}
	return c.defaultClient
}

func resolveS3BucketClients(ctx context.Context, cfg aws.Config, bootstrap *s3.Client, buckets []string, concurrency int, console console) *regionalS3Client {
	if concurrency < 1 {
		concurrency = 1
	}
	clients := &regionalS3Client{defaultClient: bootstrap, byBucket: map[string]*s3.Client{}}
	jobs := make(chan string)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range min(concurrency, len(buckets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bucket := range jobs {
				region, err := manager.GetBucketRegion(ctx, bootstrap, bucket)
				if err != nil {
					console.info("Could not resolve region for s3://%s; trying configured region %s: %v", bucket, cfg.Region, err)
					continue
				}
				bucketCfg := cfg.Copy()
				bucketCfg.Region = region
				mu.Lock()
				clients.byBucket[bucket] = s3.NewFromConfig(bucketCfg)
				mu.Unlock()
			}
		}()
	}
	for _, bucket := range buckets {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return clients
		case jobs <- bucket:
		}
	}
	close(jobs)
	wg.Wait()
	return clients
}

func readFindingJournal(path string) ([]detectors.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var findings []detectors.Finding
	decoder := json.NewDecoder(file)
	for {
		var finding detectors.Finding
		if err := decoder.Decode(&finding); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read S3 finding journal %s: %w", path, err)
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func dedupeFindings(findings []detectors.Finding) []detectors.Finding {
	seen := map[string]struct{}{}
	out := make([]detectors.Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Fingerprint
		if key == "" {
			key = finding.DetectorID + "\x00" + finding.File + "\x00" + finding.Secret
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

func extensionExcludePatterns(raw string) ([]string, error) {
	var patterns []string
	for _, extension := range splitCSV(raw) {
		extension = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(extension), "."))
		if extension == "" || strings.ContainsAny(extension, `/\\*?[]`) {
			return nil, fmt.Errorf("invalid excluded extension %q", extension)
		}
		patterns = append(patterns, "*."+extension)
	}
	return dedupeStrings(patterns), nil
}

func s3ScopeHash(opts s3RunOptions) (string, error) {
	detectorIDs := make([]string, 0, len(opts.Registry))
	for _, detector := range opts.Registry {
		detectorIDs = append(detectorIDs, detector.Info().ID)
	}
	payload := struct {
		Prefix               string   `json:"prefix"`
		MaxObjectBytes       int64    `json:"max_object_bytes"`
		Include              []string `json:"include"`
		Exclude              []string `json:"exclude"`
		ExcludeExtensions    []string `json:"exclude_extensions"`
		ScanArchives         bool     `json:"scan_archives"`
		MaxArchiveDepth      int      `json:"max_archive_depth"`
		MaxArchiveEntries    int      `json:"max_archive_entries"`
		MaxArchiveBytes      int64    `json:"max_archive_bytes"`
		MaxExpandedFileBytes int64    `json:"max_expanded_file_bytes"`
		Verify               bool     `json:"verify"`
		IncludeSecrets       bool     `json:"include_secrets"`
		Format               string   `json:"format"`
		JournalPath          string   `json:"journal_path"`
		Buckets              []string `json:"buckets"`
		AllBuckets           bool     `json:"all_buckets"`
		BaselineHash         string   `json:"baseline_hash"`
		CustomDetectorsHash  string   `json:"custom_detectors_hash"`
		DetectorIDs          []string `json:"detector_ids"`
	}{
		Prefix: opts.Prefix, MaxObjectBytes: opts.ScannerConfig.MaxFileBytes, Include: opts.ScannerConfig.Include,
		Exclude: opts.ScannerConfig.Exclude, ExcludeExtensions: opts.ScannerConfig.ExcludeExtensions,
		ScanArchives: opts.ScannerConfig.ScanArchives, MaxArchiveDepth: opts.ScannerConfig.MaxArchiveDepth,
		MaxArchiveEntries: opts.ScannerConfig.MaxArchiveEntries, MaxArchiveBytes: opts.ScannerConfig.MaxArchiveBytes,
		MaxExpandedFileBytes: opts.ScannerConfig.MaxExpandedFileBytes, Verify: opts.ScannerConfig.Verify,
		IncludeSecrets: opts.IncludeSecrets, Format: strings.ToLower(opts.Format), AllBuckets: opts.AllBuckets, DetectorIDs: detectorIDs,
	}
	payload.Buckets = append([]string(nil), opts.Buckets...)
	slices.Sort(payload.Buckets)
	journalPath := opts.OutputPath
	if payload.Format != "jsonl" {
		journalPath = opts.StatePath + ".findings.jsonl"
	}
	absoluteJournalPath, err := filepath.Abs(journalPath)
	if err != nil {
		return "", err
	}
	payload.JournalPath = absoluteJournalPath
	payload.BaselineHash, err = fileContentHash(opts.BaselinePath)
	if err != nil {
		return "", err
	}
	payload.CustomDetectorsHash, err = fileContentHash(opts.CustomDetectorsPath)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}

func fileContentHash(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:]), nil
}
