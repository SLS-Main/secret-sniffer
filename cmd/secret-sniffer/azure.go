package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"

	"secret-sniffer/internal/azurescan"
	"secret-sniffer/internal/baseline"
	"secret-sniffer/internal/detectors"
	"secret-sniffer/internal/output"
	"secret-sniffer/internal/progress"
	"secret-sniffer/internal/scanner"
)

type azureRunOptions struct {
	ScannerConfig        scanner.Config
	Registry             []detectors.Detector
	Account              string
	ServiceURL           string
	Containers           []string
	AllContainers        bool
	Prefix               string
	ContainerConcurrency int
	BlobConcurrency      int
	Auth                 string
	SharedKey            string
	ConnectionString     string
	SASURL               string
	Anonymous            bool
	TenantID             string
	ClientID             string
	ClientSecret         string
	ClientCertificate    string
	ClientCertPassword   string
	FederatedTokenFile   string
	ManagedIdentityID    string
	Format               string
	OutputPath           string
	OutputFlushFindings  int
	IncludeSecrets       bool
	BaselinePath         string
	WriteBaselinePath    string
	CustomDetectorsPath  string
	VerificationStatuses map[detectors.VerificationStatus]struct{}
	MaxObjectBytes       int64
	ExactBlobs           []string
	ExcludeContainers    []string
	RetryAttempts        int
	RetryBaseDelay       time.Duration
	Console              console
	StartedAt            time.Time
}

type azureScanFailuresError struct {
	Failures map[string]string
}

func (e *azureScanFailuresError) Error() string {
	return fmt.Sprintf("%d Azure Blob container(s) failed", len(e.Failures))
}

func runAzureBlobScan(ctx context.Context, opts azureRunOptions) (int, error) {
	if len(opts.Containers) > 0 && opts.AllContainers {
		return 0, errors.New("--azure-blob-containers and --azure-blob-all-containers cannot be used together")
	}
	normalizeAzureSASOptions(&opts)
	client, account, err := newAzureBlobClient(opts)
	if err != nil {
		return 0, err
	}
	if opts.Account == "" {
		opts.Account = account
	}
	if opts.AllContainers {
		if opts.ScannerConfig.Progress != nil {
			opts.ScannerConfig.Progress.SetPhase(progress.PhaseDiscovering)
		}
		opts.Console.info("Discovering Azure Blob containers for account %s", opts.Account)
		opts.Containers, err = azurescan.DiscoverContainers(ctx, client)
		if err != nil {
			return 0, err
		}
	}
	opts.Containers = dedupeStrings(opts.Containers)
	excluded := stringSet(opts.ExcludeContainers)
	opts.Containers = slices.DeleteFunc(opts.Containers, func(container string) bool {
		_, ok := excluded[container]
		return ok
	})
	if len(opts.Containers) == 0 {
		return 0, errors.New("no Azure Blob containers selected")
	}
	format := strings.ToLower(opts.Format)
	switch format {
	case "human", "json", "jsonl", "sarif":
	default:
		return 0, fmt.Errorf("unknown output format %q", opts.Format)
	}
	if opts.OutputPath == "" {
		opts.OutputPath = defaultOutputPath(format)
	}
	jobID, err := defaultScanJobID("azure-blob")
	if err != nil {
		return 0, err
	}
	journalPath := opts.OutputPath
	if format != "jsonl" {
		journalPath = filepath.Join(".secret-sniffer-jobs", jobID+"-azure-blob.findings.jsonl")
	}
	var outputFile *os.File
	var streamWriter *asyncJSONLWriter
	if opts.OutputPath != "" {
		outputFile, err = os.OpenFile(opts.OutputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return 0, err
		}
		defer outputFile.Close()
		if err := syncParentDirectory(opts.OutputPath); err != nil {
			return 0, err
		}
		if format == "jsonl" {
			streamWriter = newAsyncJSONLWriter(outputFile, opts.IncludeSecrets, opts.OutputFlushFindings)
			opts.Console.info("Streaming Azure Blob findings to %s", opts.OutputPath)
		}
	}
	journalFile := outputFile
	if format != "jsonl" {
		journalFile, err = os.OpenFile(journalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
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
	committedFingerprints := map[string]struct{}{}
	var committedFindings atomic.Int64
	var commitMu sync.Mutex
	commit := func(page []detectors.Finding) error {
		page = detectors.FilterVerification(page, opts.VerificationStatuses)
		if knownBaseline != nil {
			page = baseline.Filter(page, knownBaseline)
		}
		commitMu.Lock()
		defer commitMu.Unlock()
		unique := page[:0]
		for _, finding := range page {
			if _, exists := committedFingerprints[finding.Fingerprint]; !exists {
				unique = append(unique, finding)
			}
		}
		page = unique
		for _, finding := range page {
			opts.Console.finding(finding)
			streamWriter.Write(finding)
		}
		if err := streamWriter.Flush(); err != nil {
			return err
		}
		if opts.ScannerConfig.Progress != nil {
			opts.ScannerConfig.Progress.AddFindings(int64(len(page)))
		}
		for _, finding := range page {
			committedFingerprints[finding.Fingerprint] = struct{}{}
		}
		committedFindings.Add(int64(len(page)))
		return nil
	}
	azScanner, err := azurescan.New(client, azurescan.Config{
		Account: opts.Account, Containers: opts.Containers, Prefix: opts.Prefix,
		ContainerConcurrency: opts.ContainerConcurrency, BlobConcurrency: opts.BlobConcurrency,
		MaxObjectBytes: opts.MaxObjectBytes, ScanObject: runner.ScanContent,
		AllowObject: runner.AllowsRemotePath, SkipObjectReason: runner.RemotePathSkipReason,
		CommitFindings: commit, Progress: opts.ScannerConfig.Progress, ExactBlobs: stringSet(opts.ExactBlobs),
		RetryAttempts: opts.RetryAttempts, RetryBaseDelay: opts.RetryBaseDelay,
	})
	if err != nil {
		return 0, err
	}
	opts.Console.info("Azure Blob scan account=%s containers=%d container_concurrency=%d blob_concurrency=%d auth=%s", opts.Account, len(opts.Containers), opts.ContainerConcurrency, opts.BlobConcurrency, azureAuthMode(opts))
	result := azScanner.Scan(ctx)
	if opts.ScannerConfig.Progress != nil {
		opts.ScannerConfig.Progress.SetPhase(progress.PhaseFinalizing)
	}
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
	if format != "jsonl" || opts.WriteBaselinePath != "" {
		findingCount = len(findings)
	} else {
		findingCount, err = countFindingJournal(journalPath)
		if err != nil {
			return 0, err
		}
	}
	meta := output.Meta{Target: strings.Join(opts.Containers, ","), StartedAt: opts.StartedAt, Duration: time.Since(opts.StartedAt), Findings: findingCount}
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
	fmt.Fprintf(os.Stdout, "Azure Blob scan complete: containers_completed=%d containers_failed=%d objects_scanned=%d objects_skipped=%d findings=%d duration=%s", result.ContainersCompleted, result.ContainersFailed, result.ObjectsScanned, result.ObjectsSkipped, findingCount, time.Since(opts.StartedAt).Round(time.Millisecond))
	if opts.OutputPath != "" {
		fmt.Fprintf(os.Stdout, " output=%s", opts.OutputPath)
	}
	fmt.Fprintln(os.Stdout)
	if result.ContainersFailed > 0 {
		return findingCount, &azureScanFailuresError{Failures: result.Failures}
	}
	return findingCount, nil
}

type azureBlobClient struct {
	client *azblob.Client
}

func (c *azureBlobClient) ListContainers(ctx context.Context) ([]string, error) {
	pager := c.client.NewListContainersPager(nil)
	var containers []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range page.ContainerItems {
			if item != nil && item.Name != nil && *item.Name != "" {
				containers = append(containers, *item.Name)
			}
		}
	}
	return containers, nil
}

func (c *azureBlobClient) ListBlobs(ctx context.Context, containerName, prefix string, yield func([]azurescan.Blob) error) error {
	options := &azblob.ListBlobsFlatOptions{}
	if prefix != "" {
		options.Prefix = &prefix
	}
	pager := c.client.NewListBlobsFlatPager(containerName, options)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		if page.Segment == nil {
			continue
		}
		blobs := make([]azurescan.Blob, 0, len(page.Segment.BlobItems))
		for _, item := range page.Segment.BlobItems {
			if item == nil || item.Name == nil || *item.Name == "" || item.Properties == nil {
				continue
			}
			blob := azurescan.Blob{Name: *item.Name}
			blob.Size = item.Properties.ContentLength
			if item.Properties.ETag != nil {
				blob.ETag = string(*item.Properties.ETag)
			}
			blobs = append(blobs, blob)
		}
		if len(blobs) > 0 {
			if err := yield(blobs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *azureBlobClient) DownloadBlob(ctx context.Context, containerName, blobName string) (io.ReadCloser, error) {
	out, err := c.client.DownloadStream(ctx, containerName, blobName, nil)
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func newAzureBlobClient(opts azureRunOptions) (*azureBlobClient, string, error) {
	mode := azureAuthMode(opts)
	if err := validateAzureAuthMode(mode); err != nil {
		return nil, "", err
	}
	serviceURL := opts.ServiceURL
	if serviceURL == "" && opts.Account != "" {
		serviceURL = "https://" + opts.Account + ".blob.core.windows.net/"
	}
	if serviceURL == "" && opts.SASURL != "" {
		serviceURL = opts.SASURL
	}
	if opts.ConnectionString == "" && serviceURL == "" {
		return nil, "", errors.New("--azure-storage-account, --azure-blob-service-url, --azure-storage-connection-string, or --azure-storage-sas-url is required")
	}
	var client *azblob.Client
	var err error
	switch mode {
	case "connection-string":
		client, err = azblob.NewClientFromConnectionString(opts.ConnectionString, nil)
	case "shared-key":
		if opts.Account == "" || opts.SharedKey == "" {
			return nil, "", errors.New("--azure-storage-account and --azure-storage-key are required for shared-key auth")
		}
		cred, credErr := azblob.NewSharedKeyCredential(opts.Account, opts.SharedKey)
		if credErr != nil {
			return nil, "", credErr
		}
		client, err = azblob.NewClientWithSharedKeyCredential(serviceURL, cred, nil)
	case "sas", "anonymous":
		client, err = azblob.NewClientWithNoCredential(serviceURL, nil)
	case "default":
		cred, credErr := azureTokenCredential(mode, opts)
		if credErr != nil {
			return nil, "", credErr
		}
		client, err = azblob.NewClient(serviceURL, cred, nil)
	case "client-secret", "client-certificate", "managed-identity", "workload-identity", "azure-cli", "azure-dev-cli":
		cred, credErr := azureTokenCredential(mode, opts)
		if credErr != nil {
			return nil, "", credErr
		}
		client, err = azblob.NewClient(serviceURL, cred, nil)
	default:
		return nil, "", fmt.Errorf("unknown Azure Blob auth mode %q", opts.Auth)
	}
	if err != nil {
		return nil, "", err
	}
	account := opts.Account
	if account == "" {
		account = accountFromAzureURL(client.URL())
	}
	return &azureBlobClient{client: client}, account, nil
}

func azureTokenCredential(mode string, opts azureRunOptions) (azcore.TokenCredential, error) {
	switch mode {
	case "default":
		return azidentity.NewDefaultAzureCredential(nil)
	case "client-secret":
		if opts.TenantID == "" || opts.ClientID == "" || opts.ClientSecret == "" {
			return nil, errors.New("--azure-tenant-id, --azure-client-id, and --azure-client-secret are required for client-secret auth")
		}
		return azidentity.NewClientSecretCredential(opts.TenantID, opts.ClientID, opts.ClientSecret, nil)
	case "client-certificate":
		if opts.TenantID == "" || opts.ClientID == "" || opts.ClientCertificate == "" {
			return nil, errors.New("--azure-tenant-id, --azure-client-id, and --azure-client-certificate are required for client-certificate auth")
		}
		certData, err := os.ReadFile(opts.ClientCertificate)
		if err != nil {
			return nil, fmt.Errorf("read Azure client certificate %s: %w", opts.ClientCertificate, err)
		}
		var password []byte
		if opts.ClientCertPassword != "" {
			password = []byte(opts.ClientCertPassword)
		}
		certs, key, err := azidentity.ParseCertificates(certData, password)
		if err != nil {
			return nil, err
		}
		return azidentity.NewClientCertificateCredential(opts.TenantID, opts.ClientID, certs, key, nil)
	case "managed-identity":
		options := &azidentity.ManagedIdentityCredentialOptions{}
		if opts.ManagedIdentityID != "" {
			options.ID = azidentity.ClientID(opts.ManagedIdentityID)
		} else if opts.ClientID != "" {
			options.ID = azidentity.ClientID(opts.ClientID)
		}
		return azidentity.NewManagedIdentityCredential(options)
	case "workload-identity":
		options := &azidentity.WorkloadIdentityCredentialOptions{TenantID: opts.TenantID, ClientID: opts.ClientID, TokenFilePath: opts.FederatedTokenFile}
		return azidentity.NewWorkloadIdentityCredential(options)
	case "azure-cli":
		return azidentity.NewAzureCLICredential(nil)
	case "azure-dev-cli":
		return azidentity.NewAzureDeveloperCLICredential(nil)
	default:
		return nil, fmt.Errorf("unknown Azure Blob auth mode %q", mode)
	}
}

func azureAuthMode(opts azureRunOptions) string {
	if opts.Auth != "" {
		return strings.ToLower(strings.TrimSpace(opts.Auth))
	}
	switch {
	case opts.ConnectionString != "":
		return "connection-string"
	case opts.SharedKey != "":
		return "shared-key"
	case opts.SASURL != "":
		return "sas"
	case opts.Anonymous:
		return "anonymous"
	default:
		return "default"
	}
}

func validateAzureAuthMode(mode string) error {
	switch mode {
	case "default", "client-secret", "client-certificate", "managed-identity", "workload-identity", "azure-cli", "azure-dev-cli", "connection-string", "shared-key", "sas", "anonymous":
		return nil
	default:
		return fmt.Errorf("unknown Azure Blob auth mode %q", mode)
	}
}

func accountFromAzureURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	account, _, _ := strings.Cut(host, ".")
	return account
}

func normalizeAzureSASOptions(opts *azureRunOptions) {
	if opts == nil || opts.SASURL == "" {
		return
	}
	u, err := url.Parse(opts.SASURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) > 0 && parts[0] != "" && len(opts.Containers) == 0 && !opts.AllContainers {
		containerName, err := url.PathUnescape(parts[0])
		if err == nil && containerName != "" {
			opts.Containers = []string{containerName}
		}
	}
	if len(parts) > 1 && len(opts.ExactBlobs) == 0 {
		blobName, err := url.PathUnescape(strings.Join(parts[1:], "/"))
		if err == nil && blobName != "" {
			opts.ExactBlobs = []string{blobName}
		}
	}
	u.Path = "/"
	u.RawPath = ""
	opts.SASURL = u.String()
	if opts.ServiceURL == "" {
		opts.ServiceURL = opts.SASURL
	}
	if opts.Account == "" {
		opts.Account = accountFromAzureURL(opts.SASURL)
	}
}
