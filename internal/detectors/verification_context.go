package detectors

import (
	"regexp"
	"strings"
)

// Context fields are optional for detection, but may be required by a verifier.
// Only explicit provider-qualified assignments are accepted. Context contributes
// to the verification cache key through SecretParts, just like credential parts.
func withVerificationContext(detector Detector, verifier CompositeVerifier, fields map[string]string, credentialPattern string, assignments ...string) Detector {
	d := detector.(RegexDetector)
	d.ContextFields = fields
	d.CompositeVerifier = verifier
	if d.VerificationSafety != VerificationSafetyAuthOnly {
		d.VerificationSafety = VerificationSafetyReadOnly
	}
	d.TrailingSecretChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-/+="
	// Keep legacy detection while recognizing the providers' environment variables.
	if len(assignments) > 0 {
		old := d.Regex.String()
		for _, name := range assignments {
			d.Keywords = append(d.Keywords, name)
		}
		d.Regex = regexp.MustCompile(old + `|(?i)\b(?:` + strings.Join(assignments, "|") + `)\b["']?\s*[:=]\s*["']?(` + credentialPattern + `)`)
		d.SecretGroups = []int{1, 2}
	}
	return d
}

func contextualRegistry(registry []Detector) []Detector {
	for i, detector := range registry {
		spec, ok := contextualProviders[detector.Info().ID]
		if !ok {
			continue
		}
		registry[i] = withVerificationContext(detector, verifyContextualProvider, spec.fields, spec.credentialPattern, spec.assignments...)
	}
	return registry
}

var verificationContextAssignment = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?["']?([A-Za-z_][A-Za-z0-9_-]*)["']?[ \t]*[:=][ \t]*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s#;,]*))`)
var verificationContextINISection = regexp.MustCompile(`^\[[A-Za-z0-9_. -]+\][ \t]*(?:\r?\n|$)`)

var contextCredentialAssignments = map[string]struct{ selector, kind string }{
	"beebole_api_key":         {"beebole_credential_type", "graphql"},
	"beebole_api_token":       {"beebole_credential_type", "legacy"},
	"apacta_access_token":     {"apacta_credential_type", "bearer"},
	"pandadoc_api_key":        {"pandadoc_credential_type", "api_key"},
	"pandadoc_access_token":   {"pandadoc_credential_type", "bearer"},
	"pandadoc_client_secret":  {"pandadoc_credential_type", "client_secret"},
	"flexport_api_key":        {"flexport_credential_type", "bearer"},
	"flexport_access_token":   {"flexport_credential_type", "bearer"},
	"flexport_client_secret":  {"flexport_credential_type", "client_secret"},
	"gyazo_access_token":      {"gyazo_credential_type", "bearer"},
	"gyazo_client_secret":     {"gyazo_credential_type", "client_secret"},
	"airbyte_access_token":    {"airbyte_credential_type", "bearer"},
	"access_token":            {"airbyte_credential_type", "bearer"},
	"airbyte_client_secret":   {"airbyte_credential_type", "client_secret"},
	"client_secret":           {"airbyte_credential_type", "client_secret"},
	"ngrok_api_key":           {"ngrok_credential_type", "api"},
	"ngrok_authtoken":         {"ngrok_credential_type", "agent"},
	"convertapi_master_token": {"convertapi_credential_type", "master"},
	"convertapi_api_token":    {"convertapi_credential_type", "api"},
}

func addVerificationContext(parts, fields map[string]string, name, value string, invalid bool) {
	name = strings.ToLower(name)
	if kind, exists := contextCredentialAssignments[name]; exists {
		if _, applies := fields[kind.selector]; applies {
			name, value = kind.selector, kind.kind
		}
	}
	if part, ok := fields[name]; ok {
		if previous, exists := parts[part]; invalid || (exists && previous != value) {
			parts["context_conflict"] = "true"
		}
		parts[part] = value
	}
}

// WithStructuredContext replaces context inferred from a synthetic detection
// view with the original mapping's fields. Structured scope has no env/INI
// distance limit, and invalid fields must not disappear during reconstruction.
func (d RegexDetector) WithStructuredContext(c Candidate, values []StructuredValue) Candidate {
	if len(d.ContextFields) == 0 {
		return c
	}
	parts := map[string]string{"credential": c.Secret}
	for _, value := range values {
		addVerificationContext(parts, d.ContextFields, value.Key, value.Value, value.Invalid)
	}
	c.SecretParts = nil
	if len(parts) > 1 {
		c.SecretParts = parts
	}
	return c
}

func attachVerificationContext(content string, candidates []Candidate, fields map[string]string) {
	if len(candidates) == 0 {
		return
	}
	values, structured := StructuredValues([]byte(content))
	for i := range candidates {
		c := &candidates[i]
		parts := map[string]string{"credential": c.Secret}
		add := func(name, value string) {
			addVerificationContext(parts, fields, name, value, false)
		}
		if structured {
			record := -1
			for _, value := range values {
				if !value.Invalid && c.Start >= value.Start && c.End <= value.End {
					record = value.Record
					break
				}
			}
			if record >= 0 {
				for _, value := range values {
					if value.Record == record {
						addVerificationContext(parts, fields, value.Key, value.Value, value.Invalid)
					}
				}
			}
		} else {
			// A malformed structured document must not become an unscoped cloud
			// credential merely because its endpoint assignment was not parsed.
			trimmed := strings.TrimSpace(content)
			if strings.HasPrefix(trimmed, "{") || (strings.HasPrefix(trimmed, "[") && !verificationContextINISection.MatchString(trimmed)) {
				parts["context_conflict"] = "true"
			}
			for j, other := range candidates {
				if j == i {
					continue
				}
				lo, hi := min(c.End, other.End), max(c.Start, other.Start)
				if hi >= lo && hi-lo <= 512 && !hasCorrelationBoundary(content[lo:hi]) {
					parts["context_conflict"] = "true"
				}
			}
			for _, match := range verificationContextAssignment.FindAllStringSubmatchIndex(content, -1) {
				start, end := match[0], match[1]
				lo, hi := min(end, c.Start), max(start, c.End)
				if hi-lo > 512 || hasCorrelationBoundary(content[lo:hi]) || strings.ContainsAny(content[lo:hi], "{}[]") {
					continue
				}
				// Never borrow context across another credential of this family.
				crossed := false
				for j, other := range candidates {
					if j != i && other.Start >= lo && other.End <= hi {
						crossed = true
						break
					}
				}
				if crossed {
					continue
				}
				// Context must be a complete literal assignment, not the prefix
				// of a concatenation or a URL truncated at a fragment delimiter.
				lineEnd := strings.IndexByte(content[end:], '\n')
				if lineEnd < 0 {
					lineEnd = len(content) - end
				}
				tail := strings.TrimSuffix(content[end:end+lineEnd], "\r")
				comment := strings.TrimSpace(tail)
				if comment != "" && !(len(tail) > 0 && (tail[0] == ' ' || tail[0] == '\t') && (strings.HasPrefix(comment, "#") || strings.HasPrefix(comment, ";"))) {
					if _, known := fields[strings.ToLower(content[match[2]:match[3]])]; known {
						parts["context_conflict"] = "true"
					}
					continue
				}
				for group := 2; group <= 4; group++ {
					if match[group*2] >= 0 {
						add(content[match[2]:match[3]], content[match[group*2]:match[group*2+1]])
						break
					}
				}
			}
		}
		// Preserve existing finding identities when no context was captured.
		if len(parts) > 1 {
			c.SecretParts = parts
		}
	}
}
