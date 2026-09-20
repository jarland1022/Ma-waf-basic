package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ProtectionPack 自定义防护规则包（custom/*.conf）
type ProtectionPack struct {
	ID          string `json:"id"`
	File        string `json:"file"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

var packHints = map[string]string{
	"000-exceptions":  "误报例外策略",
	"110000-upload":   "文件上传检测",
	"110100-pii":      "敏感信息泄露",
	"110200-bot":      "Bot / 扫描器 UA",
	"110300-session":  "会话保护",
	"110400-protocol": "HTTP 协议合规",
	"120000-virtpatch": "虚拟补丁",
	"130000-openapi":  "OpenAPI API 安全基线",
}

func (m *Manager) ListProtectionPacks() ([]ProtectionPack, error) {
	dir := m.CustomDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []ProtectionPack{}, nil
		}
		return nil, err
	}
	var out []ProtectionPack
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		enabled := true
		base := name
		if strings.HasSuffix(name, ".conf.off") || strings.HasSuffix(name, ".conf.disabled") {
			enabled = false
			base = strings.TrimSuffix(strings.TrimSuffix(name, ".disabled"), ".off")
			if !strings.HasSuffix(base, ".conf") {
				base = strings.TrimSuffix(name, ".off")
				base = strings.TrimSuffix(base, ".disabled")
			}
		} else if !strings.HasSuffix(name, ".conf") {
			continue
		}
		id := strings.TrimSuffix(base, ".conf")
		desc := packHints[id]
		if desc == "" {
			desc = "自定义规则包"
		}
		out = append(out, ProtectionPack{ID: id, File: name, Enabled: enabled, Description: desc})
	}
	return out, nil
}

// SetProtectionPack 启用/禁用：通过重命名 .conf <-> .conf.off
func (m *Manager) SetProtectionPack(id string, enabled bool, doReload bool) error {
	id = filepath.Base(strings.TrimSpace(id))
	if id == "" || strings.Contains(id, "..") {
		return fmt.Errorf("非法包名")
	}
	dir := m.CustomDir()
	on := filepath.Join(dir, id+".conf")
	off := filepath.Join(dir, id+".conf.off")
	if _, err := m.Backup(); err != nil {
		return err
	}
	if enabled {
		if _, err := os.Stat(on); err == nil {
			// already on
		} else if _, err := os.Stat(off); err == nil {
			if err := os.Rename(off, on); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("找不到规则包: %s", id)
		}
	} else {
		if _, err := os.Stat(off); err == nil {
			// already off
		} else if _, err := os.Stat(on); err == nil {
			if err := os.Rename(on, off); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("找不到规则包: %s", id)
		}
	}
	if doReload {
		return m.Reload()
	}
	return nil
}

// ValidateRules 静态检查 custom 目录 + nginx -t
func (m *Manager) ValidateRules() (map[string]interface{}, error) {
	dir := m.CustomDir()
	issues := []string{}
	count := 0
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".conf") {
			return nil
		}
		count++
		b, err := os.ReadFile(path)
		if err != nil {
			issues = append(issues, path+": read error")
			return nil
		}
		text := string(b)
		// 忽略注释行后再做引号粗检，减少误报
		var code strings.Builder
		for _, line := range strings.Split(text, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "#") {
				continue
			}
			code.WriteString(line)
			code.WriteByte('\n')
		}
		if strings.Count(code.String(), `"`)%2 != 0 {
			issues = append(issues, filepath.Base(path)+": 引号可能未闭合")
		}
		if strings.Contains(text, "SecRule") && !strings.Contains(text, "id:") {
			issues = append(issues, filepath.Base(path)+": 存在无 id 的 SecRule 嫌疑")
		}
		return nil
	})
	nginxOK := true
	nginxMsg := "ok"
	if err := m.TestConfig(); err != nil {
		nginxOK = false
		nginxMsg = err.Error()
	}
	return map[string]interface{}{
		"custom_files": count,
		"issues":       issues,
		"nginx_ok":     nginxOK,
		"nginx_msg":    nginxMsg,
		"ok":           nginxOK && len(issues) == 0,
	}, nil
}

// DisableExpiredVirtPatches 禁用已过期虚拟补丁规则
func (m *Manager) DisableExpiredVirtPatches() (int, error) {
	list, err := m.ListVirtPatches()
	if err != nil {
		return 0, err
	}
	today := time.Now().Format("2006-01-02")
	n := 0
	for _, p := range list {
		if p.Expire == "" || p.Expire >= today || !p.Enabled {
			continue
		}
		if err := m.SetRuleEnabled(p.ID, false); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// MergeThreatIntel 将 IOC IP 合并进黑名单并记入带 TTL 的账本。
func (m *Manager) MergeThreatIntel(ips []string, doReload bool) (int, error) {
	n, err := m.AddIPs("blacklist", ips, doReload)
	if err != nil {
		return n, err
	}
	days := 30
	if ops, e := m.ReadOps(); e == nil && ops.IntelExpireDays > 0 {
		days = ops.IntelExpireDays
	}
	m.RecordIntel(ips, "merge", days)
	return n, nil
}
