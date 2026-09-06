package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"secret-sniffer/internal/detectors"
)

func TestWriteJSONRedactsRawSecretByDefault(t *testing.T) {
	findings := []detectors.Finding{{DetectorID: "test", Name: "Test", Severity: "high", File: "x", Line: 1, Column: 1, Secret: "supersecretvalue", Redacted: "supe********alue"}}
	var b bytes.Buffer
	if err := Write(&b, "json", findings, Meta{Target: ".", StartedAt: time.Now(), Findings: 1}, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "supersecretvalue") {
		t.Fatalf("raw secret leaked in output: %s", b.String())
	}
	if !strings.Contains(b.String(), "supe********alue") {
		t.Fatalf("redacted secret missing from output: %s", b.String())
	}
}

func TestSARIFIsDeterministicAndIncludesVerificationProvenance(t *testing.T) {
	findings := []detectors.Finding{
		{DetectorID: "z-rule", Name: "Z", Severity: "high", File: "/tmp/z.env", Line: 2, Column: 3, Redacted: "z***", Fingerprint: "z", Verification: detectors.VerificationResult{Status: detectors.VerificationUnknown, ErrorCategory: "timeout"}, Provenance: &detectors.Provenance{Provider: "git", CommitSHA: "abc"}},
		{DetectorID: "a-rule", Name: "A", Severity: "medium", File: "src/a.env", Line: 1, Column: 1, Redacted: "a***", Fingerprint: "a", Verification: detectors.VerificationResult{Status: detectors.VerificationVerified}},
	}
	var first, second bytes.Buffer
	if err := Write(&first, "sarif", findings, Meta{}, false); err != nil {
		t.Fatal(err)
	}
	if err := Write(&second, "sarif", findings, Meta{}, false); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("SARIF output is not deterministic")
	}
	var document struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				Properties          map[string]any    `json:"properties"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(first.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Version != "2.1.0" || len(document.Runs) != 1 || document.Runs[0].Tool.Driver.Rules[0].ID != "a-rule" {
		t.Fatalf("invalid or unsorted SARIF: %#v", document)
	}
	if document.Runs[0].Results[1].Properties["verification_status"] != "unknown" || document.Runs[0].Results[1].PartialFingerprints["secretSnifferFingerprint"] != "z" {
		t.Fatalf("SARIF result metadata missing: %#v", document.Runs[0].Results)
	}
}

func TestWriteJSONCanIncludeRawSecret(t *testing.T) {
	findings := []detectors.Finding{{DetectorID: "test", Name: "Test", Severity: "high", File: "x", Line: 1, Column: 1, Secret: "supersecretvalue", Redacted: "supe********alue"}}
	var b bytes.Buffer
	if err := Write(&b, "json", findings, Meta{Target: ".", StartedAt: time.Now(), Findings: 1}, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "supersecretvalue") {
		t.Fatalf("raw secret missing from output: %s", b.String())
	}
}
