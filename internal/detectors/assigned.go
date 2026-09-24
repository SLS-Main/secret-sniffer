package detectors

import (
	"regexp"
	"strings"
)

// AssignedSecretDetector extracts complete scalar values rather than matching a
// prefix from a restricted token alphabet. Offsets refer to the original bytes.
type AssignedSecretDetector struct{}

func (AssignedSecretDetector) Info() Info {
	return Info{ID: "generic-assigned-secret", Name: "Assigned Secret", Severity: "medium", Keywords: []string{"password", "passwd", "secret", "token", "api_key", "api-key", "apikey"}}
}

func (d AssignedSecretDetector) Detect(b []byte) []Candidate { return d.DetectPrefiltered(b) }

var assignedKey = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9_.-])["']?(password|passwd|secret|token|api[_-]?key|client[_-]?secret)["']?[ \t]*[:=][ \t]*`)

func (d AssignedSecretDetector) DetectPrefiltered(b []byte) []Candidate {
	content := string(b)
	var out []Candidate
	consumed := 0
	for _, match := range assignedKey.FindAllStringSubmatchIndex(content, -1) {
		if match[2] < consumed {
			continue
		}
		start := match[1]
		if start >= len(content) {
			continue
		}
		end := start
		quoted := content[start] == '"' || content[start] == '\''
		if quoted {
			quote := content[start]
			start++
			end = start
			for end < len(content) && content[end] != '\n' && content[end] != '\r' {
				if content[end] == '\\' && end+1 < len(content) {
					end += 2
					continue
				}
				if content[end] == quote {
					break
				}
				end++
			}
			if end >= len(content) || content[end] != quote {
				continue
			}
		} else {
			for end < len(content) && !strings.ContainsRune(" \t\r\n;,}])(#", rune(content[end])) {
				end++
			}
			// Calls, mappings, tags and expression operators are not literal values.
			if end < len(content) && content[end] == '(' {
				continue
			}
			rest := strings.TrimLeft(content[end:], " \t")
			if strings.HasPrefix(rest, "(") {
				continue
			}
			if strings.ContainsAny(content[start:end], "{[") || strings.HasSuffix(content[start:end], ":") || strings.HasPrefix(content[start:end], "!") {
				continue
			}
		}
		consumed = end
		secret := content[start:end]
		if len(secret) < 16 || !plausibleSecret(secret) || looksLikeAssignedReference(content, start) || looksLikeNamedResourceReference(secret) || assignedNonSecret(secret) || assignedResourceContext(content, start, secret) {
			continue
		}
		info := d.Info()
		out = append(out, Candidate{DetectorID: info.ID, Name: info.Name, Severity: info.Severity, Secret: secret, Start: start, End: end})
	}
	return out
}

var resourceName = regexp.MustCompile(`^[a-z0-9]+(?:[-.][a-z0-9]+)+$`)

// A versioned slug alone could be a password. Suppress it only under an
// explicit YAML reference container, never under a Secret's data/stringData.
func assignedResourceContext(content string, start int, value string) bool {
	if !resourceName.MatchString(value) {
		return false
	}
	lineStart := strings.LastIndexByte(content[:start], '\n') + 1
	line := content[lineStart:start]
	indent := len(line) - len(strings.TrimLeft(line, " \t"))
	for lineStart > 0 {
		end := lineStart - 1
		lineStart = strings.LastIndexByte(content[:end], '\n') + 1
		line = content[lineStart:end]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if yamlDocumentMarker(trimmed, "---") || yamlDocumentMarker(trimmed, "...") {
			return false
		}
		parentIndent := len(line) - len(strings.TrimLeft(line, " \t"))
		if parentIndent >= indent {
			continue
		}
		key, rest, ok := strings.Cut(trimmed, ":")
		if !ok || (strings.TrimSpace(rest) != "" && !strings.HasPrefix(strings.TrimSpace(rest), "#")) {
			return false
		}
		switch strings.ToLower(strings.Trim(key, `"'`)) {
		case "secretref", "secretkeyref", "remoteref", "externalsecretref":
			return true
		default:
			return false
		}
	}
	return false
}

// Only explicit reference conventions and instructional placeholders belong
// here. Ordinary words, low entropy, and versioned slugs are not sufficient.
func assignedNonSecret(value string) bool {
	lower := strings.ToLower(value)
	for _, prefix := range []string{"/run/secrets/", "/var/run/secrets/", "/mnt/secrets-store/", "vault://", "ref+vault://", "op://", "arn:aws:secretsmanager:", "arn:aws-us-gov:secretsmanager:", "arn:aws-cn:secretsmanager:"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if strings.HasPrefix(lower, "projects/") && strings.Contains(lower, "/secrets/") && strings.Contains(lower, "/versions/") {
		return true
	}
	normalized := strings.NewReplacer("_", "-", " ", "-").Replace(lower)
	switch normalized {
	case "replace-with-your-secret-here", "replace-with-your-password-here", "replace-with-your-token-here", "replace-with-your-api-key-here",
		"insert-your-secret-here", "insert-your-password-here", "insert-your-token-here", "insert-your-api-key-here",
		"your-secret-goes-here", "your-password-goes-here", "your-token-goes-here", "your-api-key-goes-here":
		return true
	}
	return false
}
