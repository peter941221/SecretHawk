package growth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	allowedChannels = []string{"x", "linkedin", "reddit", "hackernews", "producthunt", "email"}
	slugInvalidRe   = regexp.MustCompile(`[^a-z0-9]+`)
)

const (
	StatusDraft    = "draft"
	StatusApproved = "approved"
	StatusExported = "exported"
)

type Brief struct {
	Name         string   `yaml:"name" json:"name"`
	Product      string   `yaml:"product" json:"product"`
	OneLiner     string   `yaml:"one_liner" json:"one_liner"`
	CTAURL       string   `yaml:"cta_url" json:"cta_url"`
	Audience     string   `yaml:"audience" json:"audience"`
	KeyPoints    []string `yaml:"key_points" json:"key_points"`
	Channels     []string `yaml:"channels" json:"channels"`
	PublishStart string   `yaml:"publish_start" json:"publish_start"`
	Timezone     string   `yaml:"timezone" json:"timezone"`
}

type Queue struct {
	GeneratedAt time.Time `json:"generated_at"`
	BriefName   string    `json:"brief_name"`
	Items       []Item    `json:"items"`
}

type Item struct {
	ID               string     `json:"id"`
	Channel          string     `json:"channel"`
	Status           string     `json:"status"`
	Title            string     `json:"title"`
	Body             string     `json:"body"`
	UTMURL           string     `json:"utm_url"`
	ScheduledAt      time.Time  `json:"scheduled_at"`
	ApprovalRequired bool       `json:"approval_required"`
	ApprovedBy       string     `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time `json:"approved_at,omitempty"`
	ExportedAt       *time.Time `json:"exported_at,omitempty"`
}

func InitTemplate(path string) error {
	if path == "" {
		return errors.New("template path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	template := `name: "secrethawk-beta-wave1"
product: "SecretHawk"
one_liner: "开源 Secret 检测 + 验证 + 自动修复 CLI"
cta_url: "https://github.com/peter941221/SecretHawk"
audience: "DevSecOps / Indie Hackers / Solo Founders"
channels:
  - x
  - linkedin
  - reddit
  - hackernews
  - producthunt
key_points:
  - "默认只阻断 verified active，降低误报打断"
  - "一键链路：validate -> rotate/revoke -> patch -> report"
  - "CLI 可直接集成 CI，适合小团队先落地"
publish_start: "2026-03-02T09:00:00"
timezone: "America/Los_Angeles"
`
	return os.WriteFile(path, []byte(template), 0o644)
}

func LoadBrief(path string) (Brief, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Brief{}, err
	}
	var brief Brief
	if err := yaml.Unmarshal(data, &brief); err != nil {
		return Brief{}, fmt.Errorf("parse brief yaml: %w", err)
	}
	if err := ValidateBrief(brief); err != nil {
		return Brief{}, err
	}
	return brief, nil
}

func ValidateBrief(brief Brief) error {
	if strings.TrimSpace(brief.Name) == "" {
		return errors.New("brief.name is required")
	}
	if strings.TrimSpace(brief.Product) == "" {
		return errors.New("brief.product is required")
	}
	if strings.TrimSpace(brief.OneLiner) == "" {
		return errors.New("brief.one_liner is required")
	}
	if strings.TrimSpace(brief.CTAURL) == "" {
		return errors.New("brief.cta_url is required")
	}
	if len(brief.Channels) == 0 {
		return errors.New("brief.channels must contain at least one channel")
	}
	for _, ch := range brief.Channels {
		if !slices.Contains(allowedChannels, strings.ToLower(strings.TrimSpace(ch))) {
			return fmt.Errorf("unsupported channel: %s", ch)
		}
	}
	if len(brief.KeyPoints) == 0 {
		return errors.New("brief.key_points must contain at least one value")
	}
	if _, err := parsePublishTime(brief.PublishStart, brief.Timezone); err != nil {
		return err
	}
	return nil
}

func GenerateQueue(brief Brief, now time.Time) (Queue, error) {
	start, err := parsePublishTime(brief.PublishStart, brief.Timezone)
	if err != nil {
		return Queue{}, err
	}
	if start.Before(now) {
		start = now.Add(2 * time.Hour)
	}
	items := make([]Item, 0, len(brief.Channels)*len(brief.KeyPoints))
	sequence := 0
	for _, rawCh := range brief.Channels {
		channel := strings.ToLower(strings.TrimSpace(rawCh))
		for _, point := range brief.KeyPoints {
			sequence++
			id := fmt.Sprintf("%s-%02d", sanitizeSlug(channel), sequence)
			scheduled := start.Add(time.Duration(sequence-1) * 6 * time.Hour).UTC()
			items = append(items, Item{
				ID:               id,
				Channel:          channel,
				Status:           StatusDraft,
				Title:            makeTitle(brief.Product, point),
				Body:             makeBody(channel, brief, point),
				UTMURL:           addUTM(brief.CTAURL, channel, brief.Name, sequence),
				ScheduledAt:      scheduled,
				ApprovalRequired: true,
			})
		}
	}
	return Queue{
		GeneratedAt: now.UTC(),
		BriefName:   brief.Name,
		Items:       items,
	}, nil
}

func SaveQueue(path string, queue Queue) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(queue, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func LoadQueue(path string) (Queue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Queue{}, err
	}
	var q Queue
	if err := json.Unmarshal(data, &q); err != nil {
		return Queue{}, fmt.Errorf("parse queue json: %w", err)
	}
	return q, nil
}

func Approve(queue *Queue, id string, approver string, now time.Time) error {
	if queue == nil {
		return errors.New("queue is nil")
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("item id is required")
	}
	if strings.TrimSpace(approver) == "" {
		return errors.New("approver is required")
	}
	for i := range queue.Items {
		if queue.Items[i].ID != id {
			continue
		}
		queue.Items[i].Status = StatusApproved
		queue.Items[i].ApprovedBy = approver
		at := now.UTC()
		queue.Items[i].ApprovedAt = &at
		return nil
	}
	return fmt.Errorf("queue item not found: %s", id)
}

func ExportApproved(queue *Queue, outDir string, now time.Time) ([]string, error) {
	if queue == nil {
		return nil, errors.New("queue is nil")
	}
	if strings.TrimSpace(outDir) == "" {
		return nil, errors.New("output directory is required")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	files := make([]string, 0)
	for i := range queue.Items {
		item := &queue.Items[i]
		if item.Status != StatusApproved {
			continue
		}
		filename := fmt.Sprintf("%s-%s.md", item.ID, sanitizeSlug(item.Channel))
		fullPath := filepath.Join(outDir, filename)
		body := renderPublishCard(queue.BriefName, *item)
		if err := os.WriteFile(fullPath, []byte(body), 0o644); err != nil {
			return nil, err
		}
		at := now.UTC()
		item.Status = StatusExported
		item.ExportedAt = &at
		files = append(files, fullPath)
	}
	return files, nil
}

func parsePublishTime(raw string, timezone string) (time.Time, error) {
	tz := strings.TrimSpace(timezone)
	if tz == "" {
		tz = "UTC"
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone: %s", timezone)
	}
	s := strings.TrimSpace(raw)
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid publish_start: %s", raw)
}

func sanitizeSlug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = slugInvalidRe.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "item"
	}
	return s
}

func addUTM(baseURL string, channel string, campaign string, index int) string {
	joiner := "?"
	if strings.Contains(baseURL, "?") {
		joiner = "&"
	}
	return fmt.Sprintf("%s%sutm_source=%s&utm_medium=social&utm_campaign=%s&utm_content=post-%02d",
		baseURL,
		joiner,
		sanitizeSlug(channel),
		sanitizeSlug(campaign),
		index,
	)
}

func makeTitle(product string, keyPoint string) string {
	return fmt.Sprintf("%s: %s", strings.TrimSpace(product), strings.TrimSpace(keyPoint))
}

func makeBody(channel string, brief Brief, keyPoint string) string {
	base := fmt.Sprintf("%s\n\n%s\n\nCTA: %s", brief.OneLiner, strings.TrimSpace(keyPoint), brief.CTAURL)
	switch channel {
	case "x":
		return fmt.Sprintf("%s\n\n如果你也在做 DevSecOps 工程化，欢迎试用反馈。", base)
	case "linkedin":
		return fmt.Sprintf("%s\n\n更适合团队分享：我会在评论区放上实测流程。", base)
	case "reddit":
		return fmt.Sprintf("Context: %s\n\nWhat we built: %s\n\nQuestion: 你会如何改进这个流程？", brief.Audience, base)
	case "hackernews":
		return fmt.Sprintf("Show HN: %s\n\n%s", brief.Product, base)
	case "producthunt":
		return fmt.Sprintf("Maker Note\n\n%s\n\n欢迎提问，我会逐条回复。", base)
	case "email":
		return fmt.Sprintf("Hi,\n\n%s\n\n%s", brief.OneLiner, base)
	default:
		return base
	}
}

func renderPublishCard(briefName string, item Item) string {
	var b strings.Builder
	b.WriteString("# Growth Publish Card\n\n")
	b.WriteString(fmt.Sprintf("- Brief: `%s`\n", briefName))
	b.WriteString(fmt.Sprintf("- Item ID: `%s`\n", item.ID))
	b.WriteString(fmt.Sprintf("- Channel: `%s`\n", item.Channel))
	b.WriteString(fmt.Sprintf("- Scheduled(UTC): `%s`\n", item.ScheduledAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- UTM URL: `%s`\n\n", item.UTMURL))
	b.WriteString("## Copy\n\n")
	b.WriteString(fmt.Sprintf("### %s\n\n", item.Title))
	b.WriteString(item.Body)
	b.WriteString("\n\n## Manual Checklist\n\n")
	b.WriteString("- [ ] Verify account/session is correct\n")
	b.WriteString("- [ ] Verify post follows platform rules\n")
	b.WriteString("- [ ] Publish manually and paste live URL into your tracker\n")
	return b.String()
}
