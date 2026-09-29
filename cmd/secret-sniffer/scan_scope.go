package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// Default to including new flags so future coverage options cannot silently
// reuse completed targets. Operational controls may change on a resumed run.
func scanJobScope(flags *flag.FlagSet, registry any, files ...string) (string, error) {
	values := map[string]string{}
	flags.VisitAll(func(f *flag.Flag) {
		switch f.Name {
		case "scan-resume", "scan-retry-failed", "scan-job-id", "scan-job-path", "quiet", "progress-state", "progress-interval", "workers", "repo-concurrency", "verification-workers", "output-flush-findings", "fail-on-findings", "fail-on-scan-errors":
			return
		}
		values[f.Name] = f.Value.String()
	})
	var contents [][]byte
	for _, path := range files {
		if path == "" {
			contents = append(contents, nil)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("scan scope: %w", err)
		}
		contents = append(contents, data)
	}
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(struct {
		Schema    int
		Version   string
		Directory string
		Flags     map[string]string
		Registry  any
		Files     [][]byte
	}{1, version, directory, values, registry, contents})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func (s *scanJobState) validateScope(scope string, resume bool) error {
	if resume && s.ScopeHash != scope {
		return fmt.Errorf("scan job configuration differs or predates scope validation; start a new job")
	}
	if !resume && s.ScopeHash != scope {
		s.Targets = map[string]scanJobTarget{}
	}
	s.ScopeHash = scope
	return nil
}
