package pathfilter

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

type Filter struct {
	include      []string
	exclude      []string
	includeRegex []*regexp.Regexp
	excludeRegex []*regexp.Regexp
}

func New(include, exclude, includeRegex, excludeRegex []string) (*Filter, error) {
	f := &Filter{include: normalize(include), exclude: normalize(exclude)}
	for _, pattern := range append(append([]string{}, f.include...), f.exclude...) {
		if !doublestar.ValidatePattern(pattern) {
			return nil, fmt.Errorf("invalid glob pattern %q", pattern)
		}
	}
	var err error
	if f.includeRegex, err = compileRegexps("include", includeRegex); err != nil {
		return nil, err
	}
	if f.excludeRegex, err = compileRegexps("exclude", excludeRegex); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *Filter) Allowed(name string) bool {
	name = strings.ReplaceAll(name, "\\", "/")
	base := path.Base(name)
	if (len(f.include) > 0 || len(f.includeRegex) > 0) && !f.matches(f.include, f.includeRegex, name, base) {
		return false
	}
	return !f.matches(f.exclude, f.excludeRegex, name, base)
}

func (f *Filter) matches(globs []string, regexps []*regexp.Regexp, name, base string) bool {
	for _, pattern := range globs {
		if matched, _ := doublestar.Match(pattern, name); matched {
			return true
		}
		if matched, _ := doublestar.Match(pattern, base); matched {
			return true
		}
	}
	for _, expression := range regexps {
		if expression.MatchString(name) || expression.MatchString(base) {
			return true
		}
	}
	return false
}

func compileRegexps(kind string, expressions []string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	seen := map[string]struct{}{}
	for _, expression := range expressions {
		expression = strings.TrimSpace(expression)
		if expression == "" {
			continue
		}
		if _, ok := seen[expression]; ok {
			continue
		}
		seen[expression] = struct{}{}
		compiled, err := regexp.Compile(expression)
		if err != nil {
			return nil, fmt.Errorf("invalid %s path regex %q: %w", kind, expression, err)
		}
		out = append(out, compiled)
	}
	return out, nil
}

func normalize(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
