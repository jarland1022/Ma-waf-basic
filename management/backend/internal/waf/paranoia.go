package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

func (m *Manager) paranoiaPath() string {
	return filepath.Join(filepath.Dir(m.ModSecConf), "custom", "001-paranoia.conf")
}

// GetParanoiaLevel 读取 CRS 偏执级别（1–4），默认 2。
func (m *Manager) GetParanoiaLevel() int {
	b, err := os.ReadFile(m.paranoiaPath())
	if err != nil {
		return 2
	}
	re := regexp.MustCompile(`tx\.blocking_paranoia_level=(\d)`)
	if m := re.FindSubmatch(b); len(m) == 2 {
		n, _ := strconv.Atoi(string(m[1]))
		if n >= 1 && n <= 4 {
			return n
		}
	}
	return 2
}

// SetParanoiaLevel 写入 custom/001-paranoia.conf 覆盖 CRS 默认偏执级。
func (m *Manager) SetParanoiaLevel(level int, doReload bool) error {
	if level < 1 || level > 4 {
		return fmt.Errorf("paranoia 须为 1–4")
	}
	body := fmt.Sprintf(`# managed-by: ma-waf-api — CRS paranoia override
# META: enabled=true; priority=5
SecAction \
  "id:900010,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.blocking_paranoia_level=%d,\
   setvar:tx.detection_paranoia_level=%d"
`, level, level)
	if _, err := m.Backup(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.paranoiaPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(m.paranoiaPath(), []byte(body), 0o644); err != nil {
		return err
	}
	if doReload {
		return m.Reload()
	}
	return nil
}

func ParanoiaHint(n int) string {
	switch n {
	case 1:
		return "PL1 宽松，适合遗留/上线观察"
	case 2:
		return "PL2 均衡（CRS 推荐）"
	case 3:
		return "PL3 严格，误报可能上升"
	case 4:
		return "PL4 最严，仅高对抗场景"
	default:
		return ""
	}
}