package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"secret-sniffer/internal/detectors"
)

func TestWriteLoadAndFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	findings := []detectors.Finding{{Fingerprint: "b"}, {Fingerprint: "a"}}
	if err := Write(path, findings); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	known, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	filtered := Filter([]detectors.Finding{{Fingerprint: "a"}, {Fingerprint: "c"}}, known)
	if len(filtered) != 1 || filtered[0].Fingerprint != "c" {
		t.Fatalf("unexpected filtered findings: %#v", filtered)
	}
}
