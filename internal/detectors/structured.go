package detectors

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

func sensitiveField(name string) bool {
	switch strings.ToLower(name) {
	case "password", "passwd", "secret", "token", "api_key", "api-key", "apikey", "client_secret", "client-secret":
		return true
	}
	return false
}

// StructuredValue associates a decoded scalar with its original byte span and
// mapping scope. Record IDs are local to a single call to StructuredValues.
type StructuredValue struct {
	Key, Parent, Value string
	Start, End, Record int
	Context            []string
	Literal            bool
	Format             string
}

func (d AssignedSecretDetector) detectStructuredAssignments(b []byte) ([]Candidate, bool) {
	if !assignedKey.Match(b) && !bytes.Contains(b, []byte(`\u`)) && !bytes.Contains(b, []byte(`\U`)) && !bytes.Contains(b, []byte(`\x`)) {
		return nil, false
	}
	values, ok := StructuredValues(b)
	if !ok {
		return nil, false
	}
	var out []Candidate
	for _, value := range values {
		secret := value.Value
		if sensitiveField(value.Key) && len(secret) >= 16 && plausibleSecret(secret) && !looksLikeNamedResourceReference(secret) && !assignedNonSecret(secret) && !(resourceName.MatchString(secret) && referenceContainer(value.Parent)) && (value.Literal || !structuredExpression(secret)) {
			info := d.Info()
			out = append(out, Candidate{DetectorID: info.ID, Name: info.Name, Severity: info.Severity, Secret: secret, Start: value.Start, End: value.End})
		}
	}
	return out, true
}

// StructuredValues decodes scalar nodes without expanding container aliases.
// Separate mappings, array entries and documents never share a record ID.
func StructuredValues(b []byte) ([]StructuredValue, bool) {
	if json.Valid(b) {
		return jsonStructuredValues(b), true
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	var documents []*yaml.Node
	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		if len(doc.Content) == 0 {
			continue
		}
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode && root.Kind != yaml.SequenceNode {
			return nil, false
		}
		documents = append(documents, root)
	}
	if len(documents) == 0 {
		return nil, false
	}
	content := string(b)
	lineStarts := []int{0}
	if bytes.HasPrefix(b, []byte{0xef, 0xbb, 0xbf}) {
		lineStarts[0] = 3
	}
	for i, c := range b {
		if c == '\n' || (c == '\r' && (i+1 == len(b) || b[i+1] != '\n')) {
			lineStarts = append(lineStarts, i+1)
		}
	}
	var out []StructuredValue
	type entry struct {
		node    *yaml.Node
		parent  string
		context []string
	}
	var stack []entry
	for _, doc := range documents {
		stack = append(stack, entry{node: doc})
	}
	record := 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		node := current.node
		switch node.Kind {
		case yaml.MappingNode:
			record++
			for i := 0; i+1 < len(node.Content); i += 2 {
				key, value := node.Content[i], node.Content[i+1]
				if key.Kind != yaml.ScalarNode {
					continue
				}
				if value.Kind == yaml.AliasNode && value.Alias != nil && value.Alias.Kind == yaml.ScalarNode {
					value = value.Alias
				}
				if value.Kind == yaml.ScalarNode && (value.Tag == "!!str" || value.Tag == "!!int" || value.Tag == "!!float") {
					start, end := scalarSpan(content, lineStarts, value)
					secret := value.Value
					literal := value.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.LiteralStyle|yaml.FoldedStyle) != 0
					if start >= 0 {
						out = append(out, StructuredValue{Key: key.Value, Parent: current.parent, Value: secret, Start: start, End: end, Record: record, Context: current.context, Literal: literal, Format: "yaml"})
					}
				}
				if value.Kind == yaml.ScalarNode {
					continue
				}
				context := append(append([]string(nil), current.context...), key.Value)
				stack = append(stack, entry{node: value, parent: key.Value, context: context})
			}
		case yaml.SequenceNode:
			for _, child := range node.Content {
				stack = append(stack, entry{node: child, parent: current.parent, context: current.context})
			}
		case yaml.ScalarNode:
			if node.Tag != "!!str" && node.Tag != "!!int" && node.Tag != "!!float" {
				continue
			}
			start, end := scalarSpan(content, lineStarts, node)
			if start >= 0 {
				record++
				out = append(out, StructuredValue{Value: node.Value, Start: start, End: end, Record: record, Context: current.context, Literal: true, Format: "yaml"})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out, true
}

// JSON has its own decoder because surrogate-pair escapes are valid JSON but
// are not accepted by every YAML parser. Token offsets retain the original span.
func jsonStructuredValues(b []byte) []StructuredValue {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	type frame struct {
		object      bool
		key, parent string
		wantKey     bool
		record      int
		context     []string
	}
	var stack []frame
	var out []StructuredValue
	record := 0
	for {
		before := int(decoder.InputOffset())
		token, err := decoder.Token()
		if err != nil {
			break
		}
		end := int(decoder.InputOffset())
		key, parent := "", ""
		var context []string
		currentRecord := 0
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			context, currentRecord = top.context, top.record
			if top.object {
				if text, ok := token.(string); ok && top.wantKey {
					top.key, top.wantKey = text, false
					continue
				}
				key, parent = top.key, top.parent
				top.wantKey = true
			}
		}
		if delimiter, ok := token.(json.Delim); ok {
			if len(stack) > 0 && !stack[len(stack)-1].object {
				key = stack[len(stack)-1].parent
			}
			switch delimiter {
			case '{':
				record++
				if key != "" {
					context = append(append([]string(nil), context...), key)
				}
				stack = append(stack, frame{object: true, parent: key, wantKey: true, record: record, context: context})
			case '[':
				stack = append(stack, frame{parent: key, context: context})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
			continue
		}
		secret, quoted := token.(string)
		if number, ok := token.(json.Number); ok {
			secret = number.String()
		}
		if secret == "" {
			continue
		}
		if len(stack) == 0 || !stack[len(stack)-1].object {
			record++
			currentRecord = record
		}
		start := before
		if quoted {
			for start < end && b[start] != '"' {
				start++
			}
			start++
			end--
		} else {
			start = end - len(secret)
		}
		out = append(out, StructuredValue{Key: key, Parent: parent, Value: secret, Start: start, End: end, Record: currentRecord, Context: context, Literal: quoted, Format: "json"})
	}
	return out
}

func referenceContainer(name string) bool {
	switch strings.ToLower(name) {
	case "secretref", "secretkeyref", "remoteref", "externalsecretref":
		return true
	}
	return false
}

func structuredExpression(value string) bool {
	value = strings.TrimSpace(strings.TrimSuffix(value, ";"))
	if looksLikeVariableReference(value) {
		return true
	}
	if match := memberReferencePattern.FindString(value); match == value {
		return true
	}
	if index := strings.IndexByte(value, '('); index >= 0 && variableNamePattern.MatchString(strings.TrimSpace(value[:index])) {
		return true
	}
	return false
}

// yaml.Node columns count Unicode code points; scanner offsets count bytes.
// For quoted scalars the span excludes quotes. Block spans start at their style
// indicator and include the indented source, while Secret is the decoded value.
func scalarSpan(content string, lines []int, node *yaml.Node) (int, int) {
	if node.Line < 1 || node.Line > len(lines) {
		return -1, -1
	}
	start := lines[node.Line-1]
	for col := 1; col < node.Column && start < len(content); col++ {
		_, width := utf8.DecodeRuneInString(content[start:])
		start += width
	}
	if start >= len(content) {
		return -1, -1
	}
	// Node positions can include an anchor or explicit string tag before the
	// scalar. These are syntax, not part of the credential's source span.
	for start < len(content) && (content[start] == '&' || content[start] == '!') {
		for start < len(content) && !strings.ContainsRune(" \t\r\n", rune(content[start])) {
			start++
		}
		for start < len(content) && (content[start] == ' ' || content[start] == '\t') {
			start++
		}
	}
	if start >= len(content) {
		return -1, -1
	}
	if node.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 {
		quote := content[start]
		start++
		for end := start; end < len(content); end++ {
			if quote == '"' && content[end] == '\\' {
				end++
				continue
			}
			if content[end] != quote {
				continue
			}
			if quote == '\'' && end+1 < len(content) && content[end+1] == '\'' {
				end++
				continue
			}
			return start, end
		}
		return -1, -1
	}
	end := start
	for end < len(content) && content[end] != '\n' && content[end] != '\r' {
		end++
	}
	if node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		line := content[lines[node.Line-1]:start]
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if strings.HasPrefix(strings.TrimLeft(line, " "), "- ") {
			indent += 2
		}
		blockIndent := 0
		for _, c := range content[start+1 : end] {
			if c >= '1' && c <= '9' {
				blockIndent = indent + int(c-'0')
				break
			}
			if c == '#' {
				break
			}
		}
		for next := node.Line; next < len(lines); next++ {
			lineEnd := len(content)
			if next+1 < len(lines) {
				lineEnd = lines[next+1]
			}
			line := content[lines[next]:lineEnd]
			if strings.TrimSpace(line) != "" {
				lineIndent := len(line) - len(strings.TrimLeft(line, " "))
				if lineIndent <= indent {
					break
				}
				if blockIndent == 0 {
					blockIndent = lineIndent
				}
				if lineIndent < blockIndent {
					break
				}
			}
			end = lineEnd
		}
		return start, end
	}
	// Plain, single-line values retain their exact token span. A decoded plain
	// multiline scalar may contain folding; its start still locates the source.
	if strings.HasPrefix(content[start:], node.Value) {
		return start, start + len(node.Value)
	}
	return start, end
}
