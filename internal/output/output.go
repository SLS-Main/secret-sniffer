package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"secret-sniffer/internal/detectors"
)

type Meta struct {
	Target    string        `json:"target"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	Findings  int           `json:"findings"`
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
			verified := ""
			if f.Verified {
				verified = " verified"
			}
			fmt.Fprintf(w, "%s:%d:%d %s %s %s%s\n", f.File, f.Line, f.Column, f.Severity, f.Name, f.Redacted, verified)
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
	findings := prepareFindings([]detectors.Finding{finding}, includeSecrets)
	return json.NewEncoder(w).Encode(findings[0])
}

func WriteFindingHuman(w io.Writer, finding detectors.Finding) error {
	verified := ""
	if finding.Verified {
		verified = " verified"
	}
	_, err := fmt.Fprintf(w, "%s:%d:%d %s %s %s%s\n", finding.File, finding.Line, finding.Column, finding.Severity, finding.Name, finding.Secret, verified)
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
	results := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		rules[f.DetectorID] = map[string]any{"id": f.DetectorID, "name": f.Name, "shortDescription": map[string]string{"text": f.Name}}
		results = append(results, map[string]any{
			"ruleId":    f.DetectorID,
			"level":     sarifLevel(f.Severity),
			"message":   map[string]string{"text": f.Name + " " + f.Redacted},
			"locations": []map[string]any{{"physicalLocation": map[string]any{"artifactLocation": map[string]string{"uri": f.File}, "region": map[string]int{"startLine": f.Line, "startColumn": f.Column}}}},
		})
	}
	ruleList := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	doc := map[string]any{"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": []map[string]any{{"tool": map[string]any{"driver": map[string]any{"name": "secret-sniffer", "rules": ruleList}}, "results": results}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
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
