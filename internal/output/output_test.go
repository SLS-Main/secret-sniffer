package output

import (
	"bytes"
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
