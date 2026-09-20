package waf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Manager struct {
	NginxBin     string
	ModSecConf   string
	RulesActive  string
	RulesStaging string
	BackupDir    string
	// lastSiteUpsertWarning: 最近一次 UpsertSite 的能力降级提示（非错误）
	lastSiteUpsertWarning string
}

var engineRe = regexp.MustCompile(`(?m)^SecRuleEngine\s+\S+`)

func (m *Manager) nginxConfRoot() string {
	return filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), ".."))
}

func (m *Manager) GetEngineMode() (string, error) {
	b, err := os.ReadFile(m.ModSecConf)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SecRuleEngine") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				return f[1], nil
			}
		}
	}
	return "", fmt.Errorf("SecRuleEngine not found")
}

func (m *Manager) SetEngineMode(mode string) error {
	switch mode {
	case "On", "DetectionOnly", "Off":
	default:
		return fmt.Errorf("invalid mode")
	}
	if _, err := m.Backup(); err != nil {
		return err
	}
	b, err := os.ReadFile(m.ModSecConf)
	if err != nil {
		return err
	}
	nb := engineRe.ReplaceAllString(string(b), "SecRuleEngine "+mode)
	if err := os.WriteFile(m.ModSecConf, []byte(nb), 0o640); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) TestConfig() error {
	// 管理面 :8443 引用 admin.crt；缺失会导致任何站点变更时的 nginx -t 失败
	if err := m.EnsureAdminTLSPresent(); err != nil {
		return fmt.Errorf("管理面 TLS 缺失且自动生成失败: %w（可手动: openssl 生成 conf/tls/admin.crt）", err)
	}
	if n, err := m.SanitizeConfigsForNginxCaps(); err != nil {
		return fmt.Errorf("清理不兼容指令失败: %w", err)
	} else if n > 0 {
		// 已自动去掉 auth_request 等，继续 nginx -t
	}
	cmd := exec.Command(m.NginxBin, "-t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %s: %w", string(out), err)
	}
	return nil
}

// LastSiteUpsertWarning 返回最近一次站点写入的能力降级说明。
func (m *Manager) LastSiteUpsertWarning() string {
	return m.lastSiteUpsertWarning
}

// Reload 先 nginx -t 再 reload；配置检测或 reload 失败时自动回滚最近备份。
func (m *Manager) Reload() error {
	if err := m.TestConfig(); err != nil {
		_ = m.Rollback("")
		return fmt.Errorf("nginx -t failed (attempted rollback): %w", err)
	}
	return m.SignalReload()
}

// SignalReload 仅执行 nginx -s reload（调用方须已 nginx -t 通过）。
func (m *Manager) SignalReload() error {
	cmd := exec.Command(m.NginxBin, "-s", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = m.Rollback("")
		return fmt.Errorf("reload failed (attempted rollback): %s: %w", string(out), err)
	}
	return nil
}

// Backup 完整备份 nginx conf + 产品 rules，返回备份时间戳。
func (m *Manager) Backup() (string, error) {
	ts := time.Now().Format("20060102150405")
	dest := filepath.Join(m.BackupDir, "cfg-"+ts)
	if err := os.MkdirAll(dest, 0o750); err != nil {
		return "", err
	}
	confRoot := m.nginxConfRoot()
	if err := copyTree(confRoot, filepath.Join(dest, "nginx-conf")); err != nil {
		// 至少备份 ModSec 相关
		_ = os.MkdirAll(filepath.Join(dest, "nginx-conf", "modsecurity"), 0o750)
		_ = copyFile(m.ModSecConf, filepath.Join(dest, "nginx-conf", "modsecurity", "modsecurity.conf"))
		customSrc := filepath.Join(filepath.Dir(m.ModSecConf), "custom")
		_ = copyTree(customSrc, filepath.Join(dest, "nginx-conf", "modsecurity", "custom"))
		confD := filepath.Join(confRoot, "conf.d")
		_ = copyTree(confD, filepath.Join(dest, "nginx-conf", "conf.d"))
	}
	if m.RulesActive != "" {
		rulesRoot := filepath.Dir(m.RulesActive)
		_ = copyTree(rulesRoot, filepath.Join(dest, "rules"))
	}
	_ = os.WriteFile(filepath.Join(m.BackupDir, "LATEST"), []byte(ts+"\n"), 0o640)
	// 兼容旧仅复制 modsec 的调用方：额外写一份摘要
	_ = copyFile(m.ModSecConf, filepath.Join(dest, "modsecurity.conf"))
	return ts, nil
}

// Rollback 恢复指定或最近备份；stamp 空则读 LATEST。
func (m *Manager) Rollback(stamp string) error {
	if stamp == "" {
		b, err := os.ReadFile(filepath.Join(m.BackupDir, "LATEST"))
		if err != nil {
			return fmt.Errorf("无可用备份: %w", err)
		}
		stamp = strings.TrimSpace(string(b))
	}
	src := filepath.Join(m.BackupDir, "cfg-"+stamp)
	nginxSrc := filepath.Join(src, "nginx-conf")
	if st, err := os.Stat(nginxSrc); err != nil || !st.IsDir() {
		return fmt.Errorf("备份不存在: %s", src)
	}
	confRoot := m.nginxConfRoot()
	if err := copyTree(nginxSrc, confRoot); err != nil {
		return fmt.Errorf("恢复 nginx conf 失败: %w", err)
	}
	rulesSrc := filepath.Join(src, "rules")
	if st, err := os.Stat(rulesSrc); err == nil && st.IsDir() && m.RulesActive != "" {
		_ = copyTree(rulesSrc, filepath.Dir(m.RulesActive))
	}
	if err := m.TestConfig(); err != nil {
		return err
	}
	cmd := exec.Command(m.NginxBin, "-s", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rollback reload failed: %s: %w", string(out), err)
	}
	return nil
}

func (m *Manager) ListBackups() ([]string, error) {
	entries, err := os.ReadDir(m.BackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "cfg-") {
			out = append(out, strings.TrimPrefix(e.Name(), "cfg-"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyFile(src, dst)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func (m *Manager) ListRuleFiles() ([]string, error) {
	if m.RulesActive == "" {
		return []string{}, nil
	}
	_ = os.MkdirAll(m.RulesActive, 0o750)
	entries, err := os.ReadDir(m.RulesActive)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func (m *Manager) PromoteStaging() error {
	if _, err := m.Backup(); err != nil {
		return err
	}
	entries, err := os.ReadDir(m.RulesStaging)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(m.RulesStaging, e.Name())
		dst := filepath.Join(m.RulesActive, e.Name())
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(dst, b, 0o640); err != nil {
			return err
		}
		nginxCustom := filepath.Join(filepath.Dir(m.ModSecConf), "custom", e.Name())
		if err := os.WriteFile(nginxCustom, b, 0o640); err != nil {
			return err
		}
	}
	return m.Reload()
}

// TailAudit 返回审计日志最后 limit 条（JSON 行）
func TailAudit(path string, limit int) ([]map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*64)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > limit*2 {
			lines = lines[len(lines)-limit:]
		}
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	out := make([]map[string]interface{}, 0, len(lines))
	for _, ln := range lines {
		out = append(out, map[string]interface{}{"raw": ln})
	}
	return out, sc.Err()
}
