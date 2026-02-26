package patch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/peter941221/secrethawk/internal/model"
	"github.com/peter941221/secrethawk/internal/scan"
)

type Options struct {
	Target       string
	PolicyPath   string
	RulesPath    string
	BaselinePath string
	ReplaceWith  string
	VarPrefix    string
	DryRun       bool
	Version      string
}

type Change struct {
	File        string
	RuleID      string
	VarName     string
	Replacement string
	Count       int
}

type Result struct {
	Changes []Change
}

func Apply(ctx context.Context, opts Options) (Result, error) {
	if opts.Target == "" {
		opts.Target = "."
	}
	if opts.PolicyPath == "" {
		opts.PolicyPath = ".secrethawk/policy.yaml"
	}
	if opts.BaselinePath == "" {
		opts.BaselinePath = ".secrethawk/baseline.json"
	}
	if opts.ReplaceWith == "" {
		opts.ReplaceWith = "env"
	}

	scanResult, err := scan.Run(ctx, scan.Options{
		Target:             opts.Target,
		PolicyPath:         opts.PolicyPath,
		RulesPath:          opts.RulesPath,
		BaselinePath:       opts.BaselinePath,
		Severity:           "low",
		MaxTargetMegabytes: 50,
		Version:            opts.Version,
		Now:                time.Now().UTC(),
	})
	if err != nil {
		return Result{}, err
	}

	grouped := map[string][]model.Finding{}
	for _, f := range scanResult.Report.Findings {
		if f.RawSecret == "" {
			continue
		}
		if f.Location.Commit != nil {
			continue
		}
		if f.RuleID == "generic-high-entropy" {
			continue
		}
		if !isPatchableCodeFile(f.Location.File) {
			continue
		}
		grouped[f.Location.File] = append(grouped[f.Location.File], f)
	}

	changes := []Change{}
	varsToAdd := map[string]struct{}{}

	for file, findings := range grouped {
		data, err := os.ReadFile(file)
		if err != nil {
			return Result{}, err
		}
		content := string(data)
		seen := map[string]struct{}{}
		fileChanged := false
		for _, f := range findings {
			key := file + "|" + f.RawSecret
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			varName := envVarName(f.RuleID, opts.VarPrefix)
			repl := replacementByFile(file, varName, opts.ReplaceWith)
			count := strings.Count(content, f.RawSecret)
			if count == 0 {
				continue
			}
			content = strings.ReplaceAll(content, f.RawSecret, repl)
			fileChanged = true
			changes = append(changes, Change{
				File:        file,
				RuleID:      f.RuleID,
				VarName:     varName,
				Replacement: repl,
				Count:       count,
			})
			if opts.ReplaceWith == "env" {
				varsToAdd[varName] = struct{}{}
			}
		}

		if fileChanged && !opts.DryRun {
			if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
				return Result{}, err
			}
		}
	}

	if opts.ReplaceWith == "env" && !opts.DryRun && len(varsToAdd) > 0 {
		if err := appendEnvExample(varsToAdd, opts.Target); err != nil {
			return Result{}, err
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].File == changes[j].File {
			return changes[i].RuleID < changes[j].RuleID
		}
		return changes[i].File < changes[j].File
	})

	return Result{Changes: changes}, nil
}

func envVarName(ruleID string, prefix string) string {
	base := strings.ToUpper(strings.ReplaceAll(ruleID, "-", "_"))
	if prefix == "" {
		return base
	}
	return strings.ToUpper(prefix) + base
}

func replacementByFile(file string, varName string, replaceWith string) string {
	ext := strings.ToLower(filepath.Ext(file))
	switch replaceWith {
	case "placeholder":
		return "<" + varName + ">"
	case "secretmanager":
		return "secrets[\"" + varName + "\"]"
	}

	switch ext {
	case ".py":
		return "os.environ[\"" + varName + "\"]"
	case ".js", ".jsx", ".ts", ".tsx":
		return "process.env." + varName
	case ".go":
		return "os.Getenv(\"" + varName + "\")"
	case ".sh", ".bash", ".zsh":
		return "$" + varName
	default:
		return "${" + varName + "}"
	}
}

func appendEnvExample(vars map[string]struct{}, target string) error {
	root := target
	if root == "" {
		root = "."
	}
	path := filepath.Join(root, ".env.example")
	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}

	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	if existing != "" {
		b.WriteString(existing)
		if !strings.HasSuffix(existing, "\n") {
			b.WriteString("\n")
		}
	}

	for _, k := range keys {
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(k) + `=`)
		if re.MatchString(existing) {
			continue
		}
		b.WriteString(fmt.Sprintf("%s=<your-key-here>\n", k))
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func isPatchableCodeFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".sh", ".bash", ".zsh", ".ps1":
		return true
	default:
		return false
	}
}
