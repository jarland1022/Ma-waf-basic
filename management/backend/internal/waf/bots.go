package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var goodBotRe = regexp.MustCompile(`(?i)^[\w\.\*\+\?\|\(\)\-\^\\\[\]\$]+$`)

func (m *Manager) goodBotsPath() string {
	return filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), "..", "bot", "good_bots.map"))
}

func (m *Manager) goodBotsMapConf() string {
	return filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), "..", "bot", "00-good-bots.conf"))
}

// ReadGoodBots 读取善意 Bot UA 正则列表（每行一条，不含 ~* 前缀）。
func (m *Manager) ReadGoodBots() ([]string, error) {
	b, err := os.ReadFile(m.goodBotsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return defaultGoodBots(), nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func defaultGoodBots() []string {
	return []string{
		"Googlebot",
		"bingbot",
		"Baiduspider",
		"DuckDuckBot",
		"Applebot",
		"YandexBot",
	}
}

// WriteGoodBots 写入善意 Bot 列表并生成 nginx map 片段。
func (m *Manager) WriteGoodBots(patterns []string, doReload bool) error {
	var cleaned []string
	seen := map[string]bool{}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if !goodBotRe.MatchString(p) {
			return fmt.Errorf("非法 UA 模式: %s", p)
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	dir := filepath.Dir(m.goodBotsPath())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	var raw strings.Builder
	raw.WriteString("# managed by ma-waf-api — good bot UA patterns\n")
	for _, p := range cleaned {
		raw.WriteString(p)
		raw.WriteByte('\n')
	}
	if err := os.WriteFile(m.goodBotsPath(), []byte(raw.String()), 0o644); err != nil {
		return err
	}
	var mapBody strings.Builder
	mapBody.WriteString("# AUTO-GENERATED — do not edit; use API /bots/good\n")
	mapBody.WriteString("map $http_user_agent $is_good_bot {\n")
	mapBody.WriteString("    default 0;\n")
	for _, p := range cleaned {
		mapBody.WriteString(fmt.Sprintf("    ~*(?:%s) 1;\n", p))
	}
	mapBody.WriteString("}\n")
	if err := os.WriteFile(m.goodBotsMapConf(), []byte(mapBody.String()), 0o644); err != nil {
		return err
	}
	if doReload {
		return m.Reload()
	}
	return nil
}

// EnsureGoodBotsFile 首次启动时写入默认善意 Bot map。
func (m *Manager) EnsureGoodBotsFile() {
	if _, err := os.Stat(m.goodBotsMapConf()); err == nil {
		return
	}
	_ = m.WriteGoodBots(defaultGoodBots(), false)
}
