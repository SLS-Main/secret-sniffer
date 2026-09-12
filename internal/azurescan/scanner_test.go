package azurescan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"secret-sniffer/internal/detectors"
)

type fakeAzureClient struct {
	containers []string
	blobs      map[string][]Blob
	bodies     map[string]string
	listErrs   int
	getErrs    int
}

func (f *fakeAzureClient) ListContainers(context.Context) ([]string, error) {
	return append([]string(nil), f.containers...), nil
}

func (f *fakeAzureClient) ListBlobs(_ context.Context, container, prefix string, yield func([]Blob) error) error {
	if f.listErrs > 0 {
		f.listErrs--
		return temporaryError{}
	}
	blobs := f.blobs[container]
	out := make([]Blob, 0, len(blobs))
	for _, blob := range blobs {
		if prefix == "" || stringsHasPrefix(blob.Name, prefix) {
			out = append(out, blob)
		}
	}
	return yield(out)
}

func (f *fakeAzureClient) DownloadBlob(_ context.Context, container, name string) (io.ReadCloser, error) {
	if f.getErrs > 0 {
		f.getErrs--
		return nil, temporaryError{}
	}
	body, ok := f.bodies[container+"/"+name]
	if !ok {
		return nil, errors.New("missing blob")
	}
	return io.NopCloser(bytes.NewBufferString(body)), nil
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary network error" }
func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

func TestScanBlobsSetsAzureProvenanceAndCommitsAfterDownload(t *testing.T) {
	size := int64(11)
	client := &fakeAzureClient{
		blobs:  map[string][]Blob{"configs": {{Name: "app.env", Size: &size, ETag: "etag-one"}}},
		bodies: map[string]string{"configs/app.env": "secret=abc"},
	}
	var committed []detectors.Finding
	s, err := New(client, Config{
		Account: "acct", Containers: []string{"configs"}, BlobConcurrency: 1,
		ScanObject: func(_ context.Context, path string, b []byte) []detectors.Finding {
			if path != "azureblob://acct/configs/app.env" {
				t.Fatalf("path=%q", path)
			}
			if string(b) != "secret=abc" {
				t.Fatalf("body=%q", string(b))
			}
			return []detectors.Finding{{DetectorID: "test", Name: "Test", Severity: "high", File: path, Secret: "abc", Fingerprint: "legacy"}}
		},
		CommitFindings: func(findings []detectors.Finding) error {
			committed = append(committed, findings...)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := s.Scan(context.Background())
	if result.ContainersFailed != 0 || result.ObjectsScanned != 1 || result.Findings != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(committed) != 1 {
		t.Fatalf("committed=%d", len(committed))
	}
	prov := committed[0].Provenance
	if prov == nil || prov.Provider != "azure_blob" || prov.AzureAccount != "acct" || prov.AzureContainer != "configs" || prov.AzureBlob != "app.env" || prov.AzureETag != "etag-one" {
		t.Fatalf("unexpected provenance: %#v", prov)
	}
	if committed[0].Fingerprint == "legacy" || committed[0].LegacyFingerprint != "legacy" {
		t.Fatalf("fingerprint was not updated: %#v", committed[0])
	}
}

func TestScanBlobsRetriesTransientListAndDownloadErrors(t *testing.T) {
	size := int64(4)
	client := &fakeAzureClient{
		blobs:    map[string][]Blob{"configs": {{Name: "app.env", Size: &size}}},
		bodies:   map[string]string{"configs/app.env": "data"},
		listErrs: 1,
		getErrs:  1,
	}
	s, err := New(client, Config{
		Account: "acct", Containers: []string{"configs"}, BlobConcurrency: 1, RetryAttempts: 3,
		ScanObject:     func(context.Context, string, []byte) []detectors.Finding { return nil },
		CommitFindings: func([]detectors.Finding) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	result := s.Scan(context.Background())
	if result.ContainersFailed != 0 || result.ObjectsScanned != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
