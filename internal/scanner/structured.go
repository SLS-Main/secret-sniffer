package scanner

import (
	"bytes"
	"regexp"
	"strings"

	"secret-sniffer/internal/detectors"
)

var structuredFieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

type structuredSpan struct{ start, end int }

func withinStructuredReplacement(c detectors.Candidate, spans []structuredSpan) bool {
	for _, span := range spans {
		if c.Start >= span.start && c.End <= span.end {
			return true
		}
	}
	return false
}

// Scan each mapping as a separate decoded view. Context comes only from its
// ancestor keys and its own scalar fields, never adjacent objects/documents.
func (s *Scanner) detectStructuredCandidates(source []byte) ([]detectors.Candidate, []structuredSpan) {
	if !bytes.ContainsAny(source, ":\\|>") {
		return nil, nil
	}
	values, ok := detectors.StructuredValues(source)
	if !ok {
		return nil, nil
	}
	records := make(map[int][]detectors.StructuredValue)
	var order []int
	for _, value := range values {
		if _, exists := records[value.Record]; !exists {
			order = append(order, value.Record)
		}
		records[value.Record] = append(records[value.Record], value)
	}
	var out []detectors.Candidate
	var replaced []structuredSpan
	for _, record := range order {
		fields := records[record]
		changed := false
		for _, field := range fields {
			if string(source[field.Start:field.End]) != field.Value {
				changed = true
			}
		}
		if changed {
			for _, field := range fields {
				replaced = append(replaced, structuredSpan{field.Start, field.End})
			}
		}
		var view strings.Builder
		for _, name := range fields[0].Context {
			if structuredFieldName.MatchString(name) {
				view.WriteString(name)
				view.WriteByte('\n')
			}
		}
		// Explicit provider selectors belong to this mapping regardless of field
		// order. Only identifier values can contribute this local context.
		for _, field := range fields {
			if (strings.EqualFold(field.Key, "provider") || strings.EqualFold(field.Key, "service")) && structuredFieldName.MatchString(field.Value) {
				view.WriteString(field.Value)
				view.WriteByte('\n')
			}
		}
		type mapping struct {
			start, end int
			field      detectors.StructuredValue
		}
		var mappings []mapping
		for _, field := range fields {
			value := strings.TrimRight(field.Value, "\r\n")
			// Multiline/quoted values are scanned in isolation: inserting them
			// into a record could manufacture assignments or provider context.
			if strings.ContainsAny(value, "\r\n\"'\\") {
				out = append(out, s.detectStructuredScalar(source, field)...)
				continue
			}
			if field.Key != "" && !structuredFieldName.MatchString(field.Key) {
				out = append(out, s.detectStructuredScalar(source, field)...)
				continue
			}
			view.WriteString(field.Key)
			view.WriteString(" = \"")
			start := view.Len()
			view.WriteString(value)
			mappings = append(mappings, mapping{start, view.Len(), field})
			view.WriteString("\"\n")
		}
		content := []byte(view.String())
		for _, detector := range s.plan.selectDetectors(content) {
			if detector.id == "generic-assigned-secret" {
				continue
			}
			for _, candidate := range detectPlanned(detector, content) {
				for _, mapping := range mappings {
					if candidate.Start < mapping.start || candidate.End > mapping.end {
						continue
					}
					candidate.Start -= mapping.start
					candidate.End -= mapping.start
					out = append(out, remapStructuredCandidate(source, candidate, mapping.field))
					break
				}
			}
		}
	}
	return out, replaced
}

func (s *Scanner) detectStructuredScalar(source []byte, field detectors.StructuredValue) []detectors.Candidate {
	var out []detectors.Candidate
	value := []byte(field.Value)
	for _, detector := range s.plan.selectDetectors(value) {
		if detector.id == "generic-assigned-secret" {
			continue
		}
		for _, candidate := range detectPlanned(detector, value) {
			out = append(out, remapStructuredCandidate(source, candidate, field))
		}
	}
	return out
}

func remapStructuredCandidate(source []byte, candidate detectors.Candidate, field detectors.StructuredValue) detectors.Candidate {
	if string(source[field.Start:field.End]) == field.Value {
		candidate.Start += field.Start
		candidate.End += field.Start
	} else {
		candidate.Start, candidate.End = field.Start, field.End
	}
	candidate.DecoderChain = []string{field.Format}
	return candidate
}
