package scan

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/peter941221/secrethawk/internal/baseline"
	"github.com/peter941221/secrethawk/internal/config"
	"github.com/peter941221/secrethawk/internal/connector"
	"github.com/peter941221/secrethawk/internal/model"
	"github.com/peter941221/secrethawk/internal/rules"
	"github.com/peter941221/secrethawk/internal/severity"
)

type Options struct {
	Target             string
	Staged             bool
	SinceRef           string
	AllHistory         bool
	RulesPath          string
	PolicyPath         string
	BaselinePath       string
	Severity           string
	Validate           bool
	FailOn             string
	FailOnActive       bool
	MaxTargetMegabytes int
	Threads            int
	Version            string
	Now                time.Time
}

type Result struct {
	Report      model.FindingReport
	ShouldFail  bool
	ScannedMode string
}

func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.Target == "" {
		opts.Target = "."
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Threads <= 0 {
		opts.Threads = runtime.NumCPU()
		if opts.Threads < 1 {
			opts.Threads = 1
		}
	}
	if opts.MaxTargetMegabytes <= 0 {
		opts.MaxTargetMegabytes = 50
	}

	threshold := "low"
	if opts.Severity != "" {
		v, err := severity.Normalize(opts.Severity)
		if err != nil {
			return Result{}, err
		}
		threshold = v
	}

	policy, err := config.LoadPolicy(opts.PolicyPath)
	if err != nil {
		return Result{}, err
	}

	defaultRulesDir, err := resolveRulesDir("rules")
	if err != nil {
		return Result{}, err
	}

	allRules, err := rules.Load(defaultRulesDir, opts.RulesPath)
	if err != nil {
		return Result{}, err
	}

	base, err := baseline.Load(opts.BaselinePath)
	if err != nil {
		return Result{}, err
	}

	start := time.Now()

	mode := "directory"
	var findings []model.Finding
	var filesScanned int
	if opts.AllHistory {
		mode = "all-history"
		findings, filesScanned, err = scanAllHistory(ctx, allRules, policy, threshold)
	} else {
		if opts.Staged {
			mode = "staged"
		} else if opts.SinceRef != "" {
			mode = "since"
		}
		findings, filesScanned, err = scanWorkingTree(ctx, opts, allRules, policy, threshold)
	}
	if err != nil {
		return Result{}, err
	}

	filtered := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if baseline.IsSuppressed(base, f) {
			continue
		}
		filtered = append(filtered, f)
	}

	if opts.Validate {
		for i := range filtered {
			now := time.Now().UTC()
			filtered[i].Validation.ValidatedAt = &now
			c := connector.FindByRuleID(filtered[i].RuleID)
			if c == nil {
				filtered[i].Validation.Status = "unknown"
				filtered[i].Validation.Method = "no-connector"
				continue
			}
			status, details := connector.ValidateWithConnector(ctx, c, filtered[i].RawSecret)
			filtered[i].Validation.Status = status
			filtered[i].Validation.Method = c.Name()
			filtered[i].Validation.Details = details
			filtered[i].Confidence = confidenceFromValidation(filtered[i].Confidence, status)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Location.File == filtered[j].Location.File {
			return filtered[i].Location.LineStart < filtered[j].Location.LineStart
		}
		return filtered[i].Location.File < filtered[j].Location.File
	})

	report := model.FindingReport{
		Schema:   "https://secrethawk.dev/schemas/finding-v1.json",
		Findings: filtered,
		Metadata: model.Metadata{
			Tool:             "secrethawk",
			Version:          opts.Version,
			ScannedAt:        opts.Now,
			ScanTarget:       opts.Target,
			ScanMode:         mode,
			FilesScanned:     filesScanned,
			DurationMS:       time.Since(start).Milliseconds(),
			RulesLoaded:      len(allRules),
			PolicyFile:       opts.PolicyPath,
			SeverityCounts:   countBySeverity(filtered),
			ValidationCounts: countByValidation(filtered),
			ConfidenceCounts: countByConfidence(filtered),
		},
	}

	shouldFail := false
	if opts.FailOn != "" {
		failOn, err := severity.Normalize(opts.FailOn)
		if err != nil {
			return Result{}, err
		}
		for _, f := range filtered {
			if opts.FailOnActive && f.Validation.Status != "active" {
				continue
			}
			if severity.MeetsOrAbove(f.Severity, failOn) {
				shouldFail = true
				break
			}
		}
	}

	return Result{Report: report, ShouldFail: shouldFail, ScannedMode: mode}, nil
}

func scanWorkingTree(ctx context.Context, opts Options, allRules []rules.Rule, policy config.Policy, threshold string) ([]model.Finding, int, error) {
	files, err := discoverFiles(ctx, opts)
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return []model.Finding{}, 0, nil
	}

	maxSizeBytes := int64(opts.MaxTargetMegabytes) * 1024 * 1024
	jobs := make(chan string)
	res := make(chan []model.Finding)
	errCh := make(chan error, 1)

	workerCount := opts.Threads
	if workerCount > len(files) {
		workerCount = len(files)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				fnds, err := scanFile(path, allRules, policy, threshold, maxSizeBytes)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				res <- fnds
			}
		}()
	}

	go func() {
		for _, f := range files {
			jobs <- f
		}
		close(jobs)
		wg.Wait()
		close(res)
	}()

	collected := make([]model.Finding, 0)
	for {
		select {
		case err := <-errCh:
			if err != nil {
				return nil, 0, err
			}
		case batch, ok := <-res:
			if !ok {
				return collected, len(files), nil
			}
			collected = append(collected, batch...)
		}
	}
}

func discoverFiles(ctx context.Context, opts Options) ([]string, error) {
	if opts.Staged {
		return gitNameOnly(ctx, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
	}
	if opts.SinceRef != "" {
		rangeRef := fmt.Sprintf("%s...HEAD", opts.SinceRef)
		return gitNameOnly(ctx, "diff", "--name-only", rangeRef, "--diff-filter=ACMR")
	}

	files := make([]string, 0)
	err := filepath.WalkDir(opts.Target, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func gitNameOnly(ctx context.Context, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("git %s failed: %s", strings.Join(args, " "), strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("git %s failed: %w", strings.Join(args, " "), err)
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	files := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		files = append(files, l)
	}
	return files, nil
}

func scanFile(path string, allRules []rules.Rule, policy config.Policy, threshold string, maxSizeBytes int64) ([]model.Finding, error) {
	norm := filepath.ToSlash(path)
	if shouldExcludePath(norm, policy) {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if info.Size() > maxSizeBytes {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isBinary(data) {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		lineFindings := scanLine(norm, line, lineNo, allRules, policy, threshold)
		findings = append(findings, lineFindings...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	generic := scanHighEntropy(norm, string(data), threshold, policy)
	findings = append(findings, generic...)
	return findings, nil
}

func scanLine(path string, line string, lineNo int, allRules []rules.Rule, policy config.Policy, threshold string) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, rule := range allRules {
		if !severity.MeetsOrAbove(rule.Severity, threshold) {
			continue
		}
		if !rules.MatchRule(rule, line) {
			continue
		}

		idx := rule.Regex.FindStringSubmatchIndex(line)
		if len(idx) == 0 {
			continue
		}
		secret := extractSecret(line, idx)
		if isAllowlisted(policy, path, rule.ID, secret, line, nil) {
			continue
		}
		findings = append(findings, makeFinding(path, lineNo, secret, line, rule.ID, rule.Name, rule.Severity, rule.Category, nil))
	}
	return findings
}

func scanHighEntropy(path string, text string, threshold string, policy config.Policy) []model.Finding {
	if !severity.MeetsOrAbove("medium", threshold) {
		return nil
	}
	tokenRE := regexp.MustCompile(`[A-Za-z0-9_\-+/=]{20,}`)
	findings := make([]model.Finding, 0)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		for _, token := range tokenRE.FindAllString(line, -1) {
			ent := entropy(token)
			if ent < 4.5 {
				continue
			}
			if isAllowlisted(policy, path, "generic-high-entropy", token, line, nil) {
				continue
			}
			f := makeFinding(path, i+1, token, line, "generic-high-entropy", "Generic High-Entropy String", "medium", "generic", nil)
			f.Match.Entropy = ent
			findings = append(findings, f)
		}
	}
	return findings
}

func makeFinding(path string, lineNo int, secret string, line string, ruleID string, ruleName string, sev string, category string, commit *string) model.Finding {
	colStart := strings.Index(line, secret)
	if colStart < 0 {
		colStart = 0
	}
	colStart++
	colEnd := colStart + len(secret) - 1
	if colEnd < colStart {
		colEnd = colStart
	}
	lineHash := baseline.ComputeLineHash(line)
	idBase := ruleID + "|" + path + "|" + fmt.Sprintf("%d", lineNo) + "|" + lineHash
	sum := sha1.Sum([]byte(idBase))
	id := "f-" + hex.EncodeToString(sum[:8])

	return model.Finding{
		ID:         id,
		RuleID:     ruleID,
		RuleName:   ruleName,
		Severity:   sev,
		Confidence: baseConfidence(ruleID),
		Category:   category,
		Location: model.Location{
			File:        path,
			LineStart:   lineNo,
			LineEnd:     lineNo,
			ColumnStart: colStart,
			ColumnEnd:   colEnd,
			Commit:      commit,
		},
		Match: model.Match{
			RawRedacted: redact(secret),
			Entropy:     entropy(secret),
			Length:      len(secret),
		},
		Validation: model.Validation{
			Status:  "unknown",
			Method:  "",
			Details: map[string]any{},
		},
		Remediation: model.Remediation{
			Status:       "pending",
			ActionsTaken: []string{},
		},
		LineHash:  lineHash,
		RawSecret: secret,
	}
}

func baseConfidence(ruleID string) string {
	if ruleID == "generic-high-entropy" {
		return "medium"
	}
	return "high"
}

func confidenceFromValidation(current string, validationStatus string) string {
	switch validationStatus {
	case "active", "inactive":
		return "high"
	case "unknown":
		if current == "" {
			return "medium"
		}
		return current
	case "error":
		return "low"
	default:
		if current == "" {
			return "medium"
		}
		return current
	}
}

func redact(secret string) string {
	if len(secret) <= 8 {
		return "****"
	}
	return secret[:4] + "..." + secret[len(secret)-4:]
}

func entropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	length := float64(len(s))
	for _, c := range freq {
		p := c / length
		ent -= p * math.Log2(p)
	}
	return ent
}

func shouldExcludePath(path string, policy config.Policy) bool {
	for _, pattern := range policy.Scan.ExcludePaths {
		m, err := doublestar.PathMatch(pattern, path)
		if err == nil && m {
			return true
		}
	}
	return false
}

func isAllowlisted(policy config.Policy, path string, ruleID string, secret string, line string, commit *string) bool {
	for _, p := range policy.Allowlist.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		if re.MatchString(secret) || re.MatchString(line) {
			return true
		}
	}
	for _, p := range policy.Allowlist.Paths {
		if len(p.Rules) > 0 {
			matchedRule := false
			for _, rid := range p.Rules {
				if rid == ruleID {
					matchedRule = true
					break
				}
			}
			if !matchedRule {
				continue
			}
		}
		m, err := doublestar.PathMatch(p.Pattern, path)
		if err == nil && m {
			return true
		}
	}
	if commit != nil {
		for _, c := range policy.Allowlist.Commits {
			if c.SHA == *commit {
				return true
			}
		}
	}
	return false
}

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	limit := len(data)
	if limit > 8192 {
		limit = 8192
	}
	for i := 0; i < limit; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func extractSecret(line string, submatchIdx []int) string {
	if len(submatchIdx) >= 4 && submatchIdx[2] >= 0 && submatchIdx[3] >= 0 {
		return line[submatchIdx[2]:submatchIdx[3]]
	}
	return strings.TrimSpace(line[submatchIdx[0]:submatchIdx[1]])
}

func scanAllHistory(ctx context.Context, allRules []rules.Rule, policy config.Policy, threshold string) ([]model.Finding, int, error) {
	revs, err := gitNameOnly(ctx, "rev-list", "--all")
	if err != nil {
		return nil, 0, err
	}
	if len(revs) == 0 {
		return []model.Finding{}, 0, nil
	}

	findings := make([]model.Finding, 0)
	fileSet := map[string]struct{}{}
	for _, rule := range allRules {
		if !severity.MeetsOrAbove(rule.Severity, threshold) {
			continue
		}

		args := []string{"grep", "-nI", "-E", "-e", rule.Detection.Regex}
		args = append(args, revs...)
		cmd := exec.CommandContext(ctx, "git", args...)
		out, err := cmd.Output()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ee.ExitCode() == 1 {
					continue
				}
				return nil, 0, fmt.Errorf("git grep history failed: %s", strings.TrimSpace(string(ee.Stderr)))
			}
			return nil, 0, err
		}
		lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
		for _, l := range lines {
			if strings.TrimSpace(l) == "" {
				continue
			}
			parts := strings.SplitN(l, ":", 4)
			if len(parts) < 4 {
				continue
			}
			commit := parts[0]
			path := parts[1]
			lineNo := parseInt(parts[2])
			content := parts[3]
			if lineNo < 1 {
				lineNo = 1
			}
			if !rules.MatchRule(rule, content) {
				continue
			}
			idx := rule.Regex.FindStringSubmatchIndex(content)
			if len(idx) == 0 {
				continue
			}
			secret := extractSecret(content, idx)
			if isAllowlisted(policy, path, rule.ID, secret, content, &commit) {
				continue
			}
			fileSet[path] = struct{}{}
			findings = append(findings, makeFinding(path, lineNo, secret, content, rule.ID, rule.Name, rule.Severity, rule.Category, &commit))
		}
	}

	return findings, len(fileSet), nil
}

func parseInt(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return n
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func countBySeverity(findings []model.Finding) map[string]int {
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, f := range findings {
		if _, ok := out[f.Severity]; ok {
			out[f.Severity]++
			continue
		}
		out[f.Severity]++
	}
	return out
}

func countByValidation(findings []model.Finding) map[string]int {
	out := map[string]int{"active": 0, "inactive": 0, "unknown": 0, "error": 0}
	for _, f := range findings {
		status := strings.TrimSpace(f.Validation.Status)
		if status == "" {
			status = "unknown"
		}
		out[status]++
	}
	return out
}

func countByConfidence(findings []model.Finding) map[string]int {
	out := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, f := range findings {
		level := strings.TrimSpace(f.Confidence)
		if level == "" {
			level = "medium"
		}
		out[level]++
	}
	return out
}
