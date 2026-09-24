package detectors

import (
	"regexp"
	"strings"
)

var siblingObjectBoundary = regexp.MustCompile(`}[ \t\r\n]*,[ \t\r\n]*(?:"[^"\r\n]+"[ \t\r\n]*:[ \t\r\n]*)?\{`)
var iniSectionBoundary = regexp.MustCompile(`^\[[A-Za-z0-9_. /-]+\][ \t]*(?:[;#].*)?$`)

// Contextual provider names must not lend their identity to a different record.
func hasProviderContextBoundary(content string, start, end int) bool {
	s := content[start:end]
	if hasCorrelationBoundary(s) || siblingObjectBoundary.MatchString(s) {
		return true
	}
	lines := strings.Split(s, "\n")
	lineStart := strings.LastIndexByte(content[:start], '\n') + 1
	providerIndent := len(content[lineStart:start]) - len(strings.TrimLeft(content[lineStart:start], " \t"))
	yamlContainer := strings.HasSuffix(strings.TrimSpace(lines[0]), ":")
	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if iniSectionBoundary.MatchString(trimmed) {
			return true
		}
		if yamlContainer && trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			indent := len(line) - len(strings.TrimLeft(line, " \t"))
			if indent <= providerIndent {
				return true
			}
		}
	}
	return false
}
