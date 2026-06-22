package baseline

import (
	"encoding/json"
	"os"
	"sort"

	"secret-sniffer/internal/detectors"
)

type File struct {
	Fingerprints []string `json:"fingerprints"`
}

func Load(path string) (map[string]struct{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	out := make(map[string]struct{}, len(f.Fingerprints))
	for _, fp := range f.Fingerprints {
		if fp != "" {
			out[fp] = struct{}{}
		}
	}
	return out, nil
}

func Filter(findings []detectors.Finding, known map[string]struct{}) []detectors.Finding {
	if len(known) == 0 {
		return findings
	}
	out := make([]detectors.Finding, 0, len(findings))
	for _, f := range findings {
		if _, ok := known[f.Fingerprint]; ok {
			continue
		}
		out = append(out, f)
	}
	return out
}

func Write(path string, findings []detectors.Finding) error {
	seen := map[string]struct{}{}
	for _, f := range findings {
		if f.Fingerprint != "" {
			seen[f.Fingerprint] = struct{}{}
		}
	}
	fps := make([]string, 0, len(seen))
	for fp := range seen {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	b, err := json.MarshalIndent(File{Fingerprints: fps}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600)
}
