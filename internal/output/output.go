package output

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"secret-sniffer/internal/detectors"
)

type Meta struct {
	Target    string        `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Findings  int           `json:"findings"`
}

type JSONLWriter struct {
	encoder        *json.Encoder
	includeSecrets bool
}

func NewJSONLWriter(w io.Writer, includeSecrets bool) *JSONLWriter {
	return &JSONLWriter{encoder: json.NewEncoder(w), includeSecrets: includeSecrets}
}

func (w *JSONLWriter) Write(finding detectors.Finding) error {
	if !w.includeSecrets {
		finding.Secret = ""
	}
	return w.encoder.Encode(finding)
}

func Write(w io.Writer, format string, findings []detectors.Finding, meta Meta, includeSecrets bool) error {
	findings = prepareFindings(findings, includeSecrets)
	switch format {
	case "json":
		return json.NewEncoder(w).Encode(struct {
			Meta     Meta                `json:"meta"`
			Findings []detectors.Finding `json:"findings"`
		}{meta, findings})
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, f := range findings {
			if err := enc.Encode(f); err != nil {
				return err
			}
		}
		return nil
	case "sarif":
		return writeSARIF(w, findings)
	case "human", "":
		for _, f := range findings {
			fmt.Fprintf(w, "%s:%d:%d %s %s %s verification=%s\n", f.File, f.Line, f.Column, f.Severity, f.Name, f.Redacted, f.Verification.Status)
		}
		fmt.Fprintf(w, "scan complete: %d findings in %s\n", len(findings), meta.Duration.Round(time.Millisecond))
		return nil
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func WriteDetectorInfo(w io.Writer, infos []detectors.Info) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(infos)
}

func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func WriteFindingJSONL(w io.Writer, finding detectors.Finding, includeSecrets bool) error {
	return NewJSONLWriter(w, includeSecrets).Write(finding)
}

func WriteFindingHuman(w io.Writer, finding detectors.Finding) error {
	_, err := fmt.Fprintf(w, "%s:%d:%d %s %s %s verification=%s\n", finding.File, finding.Line, finding.Column, finding.Severity, finding.Name, finding.Secret, finding.Verification.Status)
	return err
}

func prepareFindings(findings []detectors.Finding, includeSecrets bool) []detectors.Finding {
	if includeSecrets {
		return findings
	}
	out := make([]detectors.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		out[i].Secret = ""
	}
	return out
}

func writeSARIF(w io.Writer, findings []detectors.Finding) error {
	rules := map[string]map[string]any{}
	findings = append([]detectors.Finding(nil), findings...)
	slices.SortFunc(findings, func(a, b detectors.Finding) int {
		if value := strings.Compare(a.DetectorID, b.DetectorID); value != 0 {
			return value
		}
		if value := strings.Compare(a.File, b.File); value != 0 {
			return value
		}
		if a.Line != b.Line {
			return a.Line - b.Line
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	results := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		rules[f.DetectorID] = map[string]any{"id": f.DetectorID, "name": f.Name, "shortDescription": map[string]string{"text": f.Name}}
		results = append(results, map[string]any{
			"ruleId":              f.DetectorID,
			"level":               sarifLevel(f.Severity),
			"message":             map[string]string{"text": f.Name + " " + f.Redacted},
			"locations":           []map[string]any{{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": sarifURI(f.File)}, "region": map[string]int{"startLine": f.Line, "startColumn": f.Column}}}},
			"partialFingerprints": map[string]string{"secretSnifferFingerprint": f.Fingerprint},
			"properties":          map[string]any{"verification_status": f.Verification.Status, "verification_error_category": f.Verification.ErrorCategory, "commit": f.Commit, "provenance": f.Provenance},
		})
	}
	ruleIDs := make([]string, 0, len(rules))
	for id := range rules {
		ruleIDs = append(ruleIDs, id)
	}
	slices.Sort(ruleIDs)
	ruleList := make([]map[string]any, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		ruleList = append(ruleList, rules[id])
	}
	doc := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []map[string]any{{"tool": map[string]any{"driver": map[string]any{"name": "secret-sniffer", "rules": ruleList}}, "results": results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifURI(file string) string {
	outer, _, _ := strings.Cut(file, "!/")
	if strings.HasPrefix(outer, "s3://") || strings.Contains(outer, "://") {
		return outer
	}
	outer = filepath.ToSlash(outer)
	if filepath.IsAbs(outer) {
		return (&url.URL{Scheme: "file", Path: outer}).String()
	}
	return outer
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
