package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRegistryFindsGitHubToken(t *testing.T) {
	input := []byte("token := \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"")
	var found bool
	for _, d := range DefaultRegistry() {
		for _, c := range d.Detect(input) {
			if c.DetectorID == "github-token" {
				found = true
				if c.Secret != "ghp_abcdefghijklmnopqrstuvwxyz0123456789" {
					t.Fatalf("unexpected secret: %q", c.Secret)
				}
			}
		}
	}
	if !found {
		t.Fatal("expected github-token finding")
	}
}

func TestRedact(t *testing.T) {
	got := Redact("abcdefghijklmnop")
	if got != "abcd********mnop" {
		t.Fatalf("unexpected redaction: %q", got)
	}
}

func TestPlausibleSecretRejectsRegexFragments(t *testing.T) {
	if plausibleSecret(`[^\s*\"]+`) {
		t.Fatal("expected regex fragment to be rejected")
	}
}

func TestLoadCustomFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detectors.json")
	err := os.WriteFile(path, []byte(`{
		"detectors": [{
			"id": "internal",
			"name": "Internal",
			"keywords": ["internal_key"],
			"regex": "internal_key=([a-z0-9]{16})",
			"secret_group": 1
		}]
	}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	ds, err := LoadCustomFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 {
		t.Fatalf("expected one detector, got %d", len(ds))
	}
	candidates := ds[0].Detect([]byte("internal_key=abcdefghijklmnop"))
	if len(candidates) != 1 || candidates[0].Secret != "abcdefghijklmnop" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestRegistryInfo(t *testing.T) {
	infos := RegistryInfo(DefaultRegistry())
	if len(infos) == 0 {
		t.Fatal("expected detector info")
	}
	if infos[0].ID == "" || infos[0].Name == "" || infos[0].Severity == "" {
		t.Fatalf("incomplete detector info: %#v", infos[0])
	}
}
