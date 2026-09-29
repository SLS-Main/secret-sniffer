package output

import (
	"errors"
	"testing"

	"secret-sniffer/internal/detectors"
)

type failedWriter struct{ err error }

func (w failedWriter) Write([]byte) (int, error) { return 0, w.err }

func TestHumanWriteFailures(t *testing.T) {
	failure := errors.New("output unavailable")
	for _, findings := range [][]detectors.Finding{nil, {{Name: "fixture"}}} {
		if err := Write(failedWriter{failure}, "human", findings, Meta{}, false); !errors.Is(err, failure) {
			t.Fatalf("error=%v", err)
		}
	}
}
