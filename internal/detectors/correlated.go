package detectors

import (
	"regexp"
	"strings"
)

type CorrelatedField struct {
	Name       string
	Regex      *regexp.Regexp
	ValueGroup int
	Required   bool
}

type CorrelatedDetector struct {
	ID                string
	Name              string
	Severity          string
	Keywords          []string
	Fields            []CorrelatedField
	PrimaryPart       string
	MaxDistance       int
	StopAtBlankLine   bool
	CompositeVerifier CompositeVerifier
}

type correlatedOccurrence struct {
	matchStart int
	matchEnd   int
	valueStart int
	valueEnd   int
	value      string
}

func (d CorrelatedDetector) Detect(b []byte) []Candidate {
	content := string(b)
	low := strings.ToLower(content)
	if len(d.Keywords) > 0 {
		matched := false
		for _, keyword := range d.Keywords {
			if strings.Contains(low, strings.ToLower(keyword)) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}
	return d.detectContent(content)
}

func (d CorrelatedDetector) DetectPrefiltered(b []byte) []Candidate {
	return d.detectContent(string(b))
}

func (d CorrelatedDetector) Info() Info {
	return Info{ID: d.ID, Name: d.Name, Severity: d.Severity, Keywords: d.Keywords, Verifiable: d.CompositeVerifier != nil}
}

func (d CorrelatedDetector) detectContent(content string) []Candidate {
	primaryIndex := -1
	occurrences := make([][]correlatedOccurrence, len(d.Fields))
	for fieldIndex, field := range d.Fields {
		if field.Name == d.PrimaryPart {
			primaryIndex = fieldIndex
		}
		for _, match := range field.Regex.FindAllStringSubmatchIndex(content, -1) {
			group := field.ValueGroup
			if group < 0 {
				group = 0
			}
			if group*2+1 >= len(match) || match[group*2] < 0 {
				continue
			}
			occurrences[fieldIndex] = append(occurrences[fieldIndex], correlatedOccurrence{
				matchStart: match[0],
				matchEnd:   match[1],
				valueStart: match[group*2],
				valueEnd:   match[group*2+1],
				value:      content[match[group*2]:match[group*2+1]],
			})
		}
		if field.Required && len(occurrences[fieldIndex]) == 0 {
			return nil
		}
	}
	if primaryIndex < 0 || !d.Fields[primaryIndex].Required {
		return nil
	}

	used := make([]map[int]bool, len(d.Fields))
	for i := range used {
		used[i] = map[int]bool{}
	}
	seen := map[[32]byte]struct{}{}
	out := make([]Candidate, 0, len(occurrences[primaryIndex]))
	for primaryOccurrenceIndex, primary := range occurrences[primaryIndex] {
		parts := map[string]string{d.PrimaryPart: primary.value}
		selected := map[int]int{primaryIndex: primaryOccurrenceIndex}
		clusterStart, clusterEnd := primary.matchStart, primary.matchEnd
		valid := true
		for fieldIndex, field := range d.Fields {
			if fieldIndex == primaryIndex || !field.Required {
				continue
			}
			occurrenceIndex := d.nearestOccurrence(content, occurrences[fieldIndex], used[fieldIndex], clusterStart, clusterEnd)
			if occurrenceIndex < 0 {
				valid = false
				break
			}
			occurrence := occurrences[fieldIndex][occurrenceIndex]
			selected[fieldIndex] = occurrenceIndex
			parts[field.Name] = occurrence.value
			clusterStart = min(clusterStart, occurrence.matchStart)
			clusterEnd = max(clusterEnd, occurrence.matchEnd)
		}
		if !valid {
			continue
		}
		for fieldIndex, field := range d.Fields {
			if field.Required {
				continue
			}
			occurrenceIndex := d.nearestOccurrence(content, occurrences[fieldIndex], used[fieldIndex], clusterStart, clusterEnd)
			if occurrenceIndex < 0 {
				continue
			}
			occurrence := occurrences[fieldIndex][occurrenceIndex]
			selected[fieldIndex] = occurrenceIndex
			parts[field.Name] = occurrence.value
			clusterStart = min(clusterStart, occurrence.matchStart)
			clusterEnd = max(clusterEnd, occurrence.matchEnd)
		}

		candidate := Candidate{
			DetectorID:        d.ID,
			Name:              d.Name,
			Severity:          d.Severity,
			Secret:            primary.value,
			SecretParts:       parts,
			Start:             primary.valueStart,
			End:               primary.valueEnd,
			CompositeVerifier: d.CompositeVerifier,
		}
		if !plausibleSecret(candidate.Secret) {
			continue
		}
		identity := candidate.VerificationCacheKey()
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		for fieldIndex, occurrenceIndex := range selected {
			used[fieldIndex][occurrenceIndex] = true
		}
		out = append(out, candidate)
	}
	return out
}

func (d CorrelatedDetector) nearestOccurrence(content string, occurrences []correlatedOccurrence, used map[int]bool, clusterStart, clusterEnd int) int {
	bestIndex, bestDistance := -1, 0
	for index, occurrence := range occurrences {
		if used[index] {
			continue
		}
		distance, between := 0, ""
		switch {
		case occurrence.matchEnd < clusterStart:
			distance = clusterStart - occurrence.matchEnd
			between = content[occurrence.matchEnd:clusterStart]
		case occurrence.matchStart > clusterEnd:
			distance = occurrence.matchStart - clusterEnd
			between = content[clusterEnd:occurrence.matchStart]
		}
		if d.MaxDistance > 0 && distance > d.MaxDistance {
			continue
		}
		if d.StopAtBlankLine && hasContextBoundary(between) {
			continue
		}
		if bestIndex < 0 || distance < bestDistance {
			bestIndex, bestDistance = index, distance
		}
	}
	return bestIndex
}
