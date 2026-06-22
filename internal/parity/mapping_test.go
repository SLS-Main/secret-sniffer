package parity

import (
	"testing"

	"secret-sniffer/internal/detectors"
)

func TestCurrentReportCountsMappings(t *testing.T) {
	r := CurrentReport()
	if r.TotalTracked == 0 {
		t.Fatal("expected tracked mappings")
	}
	if r.TotalTracked != r.Implemented+r.Partial+r.Planned {
		t.Fatalf("counts do not add up: %#v", r)
	}
	if r.CatalogSize != len(TruffleHogCatalog) || r.CatalogSize == 0 {
		t.Fatalf("unexpected catalog size: %d", r.CatalogSize)
	}
	if r.Untracked != len(r.UntrackedTruffleHogs) {
		t.Fatalf("untracked count mismatch: %#v", r)
	}
	if r.CatalogTracked+r.Untracked != r.CatalogSize {
		t.Fatalf("catalog accounting mismatch: %#v", r)
	}
	if r.CatalogTracked+r.SubDetectorTracked != r.TotalTracked {
		t.Fatalf("tracked accounting mismatch: %#v", r)
	}
}

func TestCatalogSnapshotMatchesExpectedSize(t *testing.T) {
	if GeneratedSnapshotCommit != "9b6b5326bfe25dbd856eccc8a8275eb5dea7bd52" {
		t.Fatalf("unexpected snapshot commit: %s", GeneratedSnapshotCommit)
	}
	if len(TruffleHogCatalog) != 870 {
		t.Fatalf("unexpected catalog size: %d", len(TruffleHogCatalog))
	}
}

func TestMappedDetectorIDsExist(t *testing.T) {
	known := map[string]struct{}{}
	for _, info := range detectors.RegistryInfo(detectors.DefaultRegistry()) {
		known[info.ID] = struct{}{}
	}
	for _, m := range CurrentMappings() {
		if m.SecretSnifferID == nil {
			continue
		}
		if _, ok := known[*m.SecretSnifferID]; !ok {
			t.Fatalf("mapping references missing detector id %q for %s", *m.SecretSnifferID, m.TruffleHogID)
		}
	}
}
