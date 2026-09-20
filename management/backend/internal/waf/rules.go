package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type RuleInfo struct {
	ID       string `json:"id"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Enabled  bool   `json:"enabled"`
	CVE      string `json:"cve,omitempty"`
	Expire   string `json:"expire,omitempty"`
	Priority int    `json:"priority"`
}

var (
	metaLineRe = regexp.MustCompile(`(?i)^\s*#\s*META:\s*(.+)$`)
	secRuleRe  = regexp.MustCompile(`(?i)^\s*#?\s*(SecRule|SecAction)\b`)
	idInRuleRe = regexp.MustCompile(`(?i)\bid:(\d+)\b`)
)

func (m *Manager) CustomDir() string {
	return filepath.Join(filepath.Dir(m.ModSecConf), "custom")
}

func (m *Manager) ruleDirs() []string {
	dirs := []string{}
	if m.RulesActive != "" {
		dirs = append(dirs, m.RulesActive)
	}
	custom := m.CustomDir()
	if custom != "" && custom != m.RulesActive {
		dirs = append(dirs, custom)
	}
	return dirs
}

func parseMetaBody(body string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(body, ";") {
		part = strings.TrimSpace(part)
		if part == "" || !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		out[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return out
}

func formatMeta(meta map[string]string) string {
	keys := []string{"enabled", "priority", "cve", "expire"}
	var parts []string
	seen := map[string]bool{}
	for _, k := range keys {
		if v, ok := meta[k]; ok && v != "" {
			parts = append(parts, k+"="+v)
			seen[k] = true
		}
	}
	for k, v := range meta {
		if seen[k] || v == "" {
			continue
		}
		parts = append(parts, k+"="+v)
	}
	return "# META: " + strings.Join(parts, "; ")
}

func scanRulesInFile(path string) ([]RuleInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	var rules []RuleInfo
	meta := map[string]string{}
	base := filepath.Base(path)

	for i, line := range lines {
		if m := metaLineRe.FindStringSubmatch(line); m != nil {
			meta = parseMetaBody(m[1])
			continue
		}
		if !secRuleRe.MatchString(line) {
			continue
		}
		window := line
		end := i + 1
		for end < len(lines) && end < i+12 {
			window += "\n" + lines[end]
			if !strings.HasSuffix(strings.TrimRight(lines[end-1], "\r"), "\\") && end > i+1 {
				break
			}
			end++
		}
		id := "unknown"
		if m := idInRuleRe.FindStringSubmatch(window); m != nil {
			id = m[1]
		}
		enabled := true
		if v, ok := meta["enabled"]; ok && strings.EqualFold(v, "false") {
			enabled = false
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			enabled = false
		}
		pri := 100
		if v, ok := meta["priority"]; ok {
			if n, err := strconv.Atoi(v); err == nil {
				pri = n
			}
		}
		rules = append(rules, RuleInfo{
			ID: id, File: base, Line: i + 1, Enabled: enabled,
			CVE: meta["cve"], Expire: meta["expire"], Priority: pri,
		})
		meta = map[string]string{}
	}
	return rules, nil
}

func (m *Manager) ListRulesDetailed() ([]RuleInfo, error) {
	seen := map[string]RuleInfo{}
	for _, dir := range m.ruleDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			rules, err := scanRulesInFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			for _, r := range rules {
				key := r.ID + "@" + r.File
				if r.ID == "unknown" {
					key = fmt.Sprintf("%s:%d", r.File, r.Line)
				}
				seen[key] = r
			}
		}
	}
	out := make([]RuleInfo, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// SetRuleEnabled 按规则 ID 启用/禁用：更新 META.enabled，并注释/取消注释 SecRule 块。
func (m *Manager) SetRuleEnabled(ruleID string, enabled bool) error {
	if ruleID == "" || ruleID == "unknown" {
		return fmt.Errorf("invalid rule id")
	}
	if _, err := m.Backup(); err != nil {
		return err
	}
	found := false
	for _, dir := range m.ruleDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			changed, err := toggleRuleInFile(path, ruleID, enabled, nil)
			if err != nil {
				return err
			}
			if changed {
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("rule id %s not found", ruleID)
	}
	return m.Reload()
}

// SetRulePriority 更新 META.priority（不改规则体）。
func (m *Manager) SetRulePriority(ruleID string, priority int) error {
	if ruleID == "" || ruleID == "unknown" {
		return fmt.Errorf("invalid rule id")
	}
	if priority < 0 || priority > 9999 {
		return fmt.Errorf("priority out of range")
	}
	if _, err := m.Backup(); err != nil {
		return err
	}
	pri := strconv.Itoa(priority)
	found := false
	for _, dir := range m.ruleDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			changed, err := toggleRuleInFile(path, ruleID, true, &pri)
			if err != nil {
				return err
			}
			if changed {
				found = true
			}
		}
	}
	if !found {
		return fmt.Errorf("rule id %s not found", ruleID)
	}
	return nil
}

// toggleRuleInFile: enabled 控制注释；priority 非 nil 时只改 META（仍保持当前启用态除非同时改 enabled）。
// 当 priority != nil 且仅改优先级时，enabled 参数表示“保持/设置 enabled META”，不强制改注释态。
func toggleRuleInFile(path, ruleID string, enabled bool, priority *string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(b), "\n")
	changed := false
	metaIdx := -1
	meta := map[string]string{}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if m := metaLineRe.FindStringSubmatch(line); m != nil {
			metaIdx = i
			meta = parseMetaBody(m[1])
			continue
		}
		if !secRuleRe.MatchString(line) {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				metaIdx = -1
				meta = map[string]string{}
			}
			continue
		}
		// collect multiline window for id
		end := i
		for end+1 < len(lines) && strings.HasSuffix(strings.TrimRight(lines[end], "\r"), "\\") {
			end++
		}
		window := strings.Join(lines[i:end+1], "\n")
		m := idInRuleRe.FindStringSubmatch(window)
		if m == nil || m[1] != ruleID {
			metaIdx = -1
			meta = map[string]string{}
			i = end
			continue
		}

		// update meta
		if meta == nil {
			meta = map[string]string{}
		}
		if priority != nil {
			meta["priority"] = *priority
			if _, ok := meta["enabled"]; !ok {
				meta["enabled"] = strconv.FormatBool(enabled)
			}
		} else {
			meta["enabled"] = strconv.FormatBool(enabled)
		}
		if _, ok := meta["priority"]; !ok {
			meta["priority"] = "100"
		}
		metaLine := formatMeta(meta)
		if metaIdx >= 0 {
			lines[metaIdx] = metaLine
		} else {
			// insert META before rule
			newLines := make([]string, 0, len(lines)+1)
			newLines = append(newLines, lines[:i]...)
			newLines = append(newLines, metaLine)
			newLines = append(newLines, lines[i:]...)
			lines = newLines
			end++
			i++
		}

		// comment/uncomment only when not priority-only
		if priority == nil {
			for j := i; j <= end; j++ {
				trimmed := strings.TrimLeft(lines[j], " \t")
				if enabled {
					if strings.HasPrefix(trimmed, "#") {
						// strip one leading # and optional space
						idx := strings.Index(lines[j], "#")
						rest := lines[j][idx+1:]
						if strings.HasPrefix(rest, " ") {
							rest = rest[1:]
						}
						lines[j] = lines[j][:idx] + rest
					}
				} else {
					if !strings.HasPrefix(trimmed, "#") {
						// preserve indent
						indent := lines[j][:len(lines[j])-len(trimmed)]
						lines[j] = indent + "# " + trimmed
					}
				}
			}
		}
		changed = true
		metaIdx = -1
		meta = map[string]string{}
		i = end
	}

	if !changed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o640)
}
