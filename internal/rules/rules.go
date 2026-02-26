package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type File struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string          `yaml:"id"`
	Name        string          `yaml:"name"`
	Severity    string          `yaml:"severity"`
	Category    string          `yaml:"category"`
	Description string          `yaml:"description"`
	Detection   DetectionSpec   `yaml:"detection"`
	Validation  ValidationSpec  `yaml:"validation"`
	Remediation RemediationSpec `yaml:"remediation"`
	Tests       RuleTests       `yaml:"tests"`

	Regex        *regexp.Regexp   `yaml:"-"`
	MustMatch    []*regexp.Regexp `yaml:"-"`
	MustNotMatch []*regexp.Regexp `yaml:"-"`
}

type DetectionSpec struct {
	Regex        string         `yaml:"regex"`
	MustMatch    []RegexWrapper `yaml:"must_match"`
	MustNotMatch []RegexWrapper `yaml:"must_not_match"`
}

type RegexWrapper struct {
	Regex        string `yaml:"regex"`
	ContextRegex string `yaml:"context_regex"`
}

type ValidationSpec struct {
	Connector string `yaml:"connector"`
	Method    string `yaml:"method"`
}

type RemediationSpec struct {
	Connector string              `yaml:"connector"`
	Actions   []RemediationAction `yaml:"actions"`
}

type RemediationAction struct {
	Type        string `yaml:"type"`
	Description string `yaml:"description"`
	EnvVarName  string `yaml:"env_var_name"`
}

type RuleTests struct {
	Positive []RuleTestCase `yaml:"positive"`
	Negative []RuleTestCase `yaml:"negative"`
}

type RuleTestCase struct {
	Input       string `yaml:"input"`
	ShouldMatch bool   `yaml:"should_match"`
}

func Load(defaultRulesDir string, customPath string) ([]Rule, error) {
	all := map[string]Rule{}

	defaultRules, err := loadFromPath(defaultRulesDir)
	if err != nil {
		return nil, err
	}
	for _, r := range defaultRules {
		all[r.ID] = r
	}

	if customPath != "" {
		customRules, err := loadFromPath(customPath)
		if err != nil {
			return nil, err
		}
		for _, r := range customRules {
			all[r.ID] = r
		}
	}

	out := make([]Rule, 0, len(all))
	for _, r := range all {
		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})

	return out, nil
}

func loadFromPath(path string) ([]Rule, error) {
	if path == "" {
		return nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat rules path: %w", err)
	}

	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			if ext == ".yml" || ext == ".yaml" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		files = []string{path}
	}

	sort.Strings(files)
	loaded := make([]Rule, 0)

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read rules file %s: %w", f, err)
		}

		var rf File
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parse rules file %s: %w", f, err)
		}

		for _, r := range rf.Rules {
			if err := compileRule(&r); err != nil {
				return nil, fmt.Errorf("invalid rule %s: %w", r.ID, err)
			}
			loaded = append(loaded, r)
		}
	}

	return loaded, nil
}

func compileRule(r *Rule) error {
	if r.ID == "" {
		return fmt.Errorf("missing rule id")
	}
	if r.Name == "" {
		r.Name = r.ID
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	if r.Detection.Regex == "" {
		return fmt.Errorf("missing detection.regex")
	}

	re, err := regexp.Compile(r.Detection.Regex)
	if err != nil {
		return fmt.Errorf("compile detection regex: %w", err)
	}
	r.Regex = re

	for _, w := range r.Detection.MustMatch {
		pattern := choosePattern(w)
		if pattern == "" {
			continue
		}
		p, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("compile must_match regex: %w", err)
		}
		r.MustMatch = append(r.MustMatch, p)
	}

	for _, w := range r.Detection.MustNotMatch {
		pattern := choosePattern(w)
		if pattern == "" {
			continue
		}
		p, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("compile must_not_match regex: %w", err)
		}
		r.MustNotMatch = append(r.MustNotMatch, p)
	}

	return nil
}

func choosePattern(w RegexWrapper) string {
	if w.Regex != "" {
		return w.Regex
	}
	return w.ContextRegex
}

func MatchRule(r Rule, line string) bool {
	if !r.Regex.MatchString(line) {
		return false
	}
	if len(r.MustMatch) > 0 {
		matched := false
		for _, re := range r.MustMatch {
			if re.MatchString(line) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, re := range r.MustNotMatch {
		if re.MatchString(line) {
			return false
		}
	}
	return true
}

func TestRuleAgainstInput(r Rule, input string) bool {
	return MatchRule(r, normalizeTestInput(input))
}

func normalizeTestInput(input string) string {
	// Keep sample payloads non-sensitive in-repo while still testable.
	return strings.ReplaceAll(input, "__CUT__", "")
}
