package waf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DiagCheck 单项故障排查结果。
type DiagCheck struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	OK       bool   `json:"ok"`
	Severity string `json:"severity"` // critical | warn | info
	Detail   string `json:"detail"`
	Hint     string `json:"hint,omitempty"`
	Action   string `json:"action,omitempty"` // ensure_tls | reload | none
}

// TroubleshootOpts 由 API 层补充的路径/状态。
type TroubleshootOpts struct {
	ConsoleDir string
	AuditLog   string
	LicenseOK  bool
	LicenseMsg string
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func nginxPrefixFromBuild(info string) string {
	for _, part := range strings.Fields(info) {
		if strings.HasPrefix(part, "--prefix=") {
			return strings.Trim(strings.TrimPrefix(part, "--prefix="), `"'`)
		}
	}
	return "/usr/local/nginx"
}

func tailTextFile(path string, maxLines int) string {
	if maxLines <= 0 {
		maxLines = 40
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func diskFreeGB(path string) (float64, error) {
	// Linux: df -Pk；避免依赖平台相关的 syscall.Statfs
	cmd := exec.Command("df", "-Pk", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("df 输出异常")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return 0, fmt.Errorf("df 字段不足")
	}
	availKB, err := strconv.ParseFloat(fields[3], 64)
	if err != nil {
		return 0, err
	}
	return availKB / (1024 * 1024), nil
}

func listenHint(ports ...string) string {
	args := []string{"-lntp"}
	cmd := exec.Command("ss", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmd = exec.Command("netstat", "-lntp")
		out, err = cmd.CombinedOutput()
		if err != nil {
			return "无法执行 ss/netstat（可跳过）"
		}
	}
	text := string(out)
	var found, missing []string
	for _, p := range ports {
		needle := ":" + p
		ok := false
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, needle) && (strings.Contains(line, "LISTEN") || strings.Contains(line, "LISTEN ")) {
				ok = true
				break
			}
		}
		if ok {
			found = append(found, p)
		} else {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return "监听中: " + strings.Join(found, ", ")
	}
	return fmt.Sprintf("已监听 %s；未检测到 %s", strings.Join(found, ","), strings.Join(missing, ","))
}

// Troubleshoot 汇总常见故障检查项（只读，不修改配置）。
func (m *Manager) Troubleshoot(opts TroubleshootOpts) map[string]interface{} {
	var checks []DiagCheck
	root := filepath.Clean(filepath.Join(m.BackupDir, ".."))
	if root == "." || root == "" {
		root = "/usr/local/Ma-waf"
	}

	// --- 二进制 / 进程相关 ---
	bin := m.NginxBin
	if bin == "" {
		bin = "nginx"
	}
	binOK := fileExists(bin) || fileExists("/usr/local/nginx/sbin/nginx")
	binPath := bin
	if !fileExists(bin) && fileExists("/usr/local/nginx/sbin/nginx") {
		binPath = "/usr/local/nginx/sbin/nginx"
		binOK = true
	}
	checks = append(checks, DiagCheck{
		ID: "nginx_bin", Category: "服务", Title: "Nginx 二进制",
		OK: binOK, Severity: "critical",
		Detail: binPath,
		Hint:   "确认 NginxBin 配置或 /usr/local/nginx/sbin/nginx 存在",
	})

	nginxTDetail := ""
	nginxTOK := false
	if binOK {
		cmd := exec.Command(binPath, "-t")
		out, err := cmd.CombinedOutput()
		nginxTDetail = strings.TrimSpace(string(out))
		nginxTOK = err == nil
		if nginxTDetail == "" && err != nil {
			nginxTDetail = err.Error()
		}
	} else {
		nginxTDetail = "跳过：nginx 二进制不可用"
	}
	checks = append(checks, DiagCheck{
		ID: "nginx_t", Category: "配置", Title: "Nginx 配置检测 (nginx -t)",
		OK: nginxTOK, Severity: "critical",
		Detail: truncateRunes(nginxTDetail, 800),
		Hint:   "失败时用系统→配置备份回滚，或修复 conf.d/site-*.conf 与 admin.crt",
		Action: "reload",
	})

	// --- TLS ---
	tlsDir := m.tlsDir()
	crt := filepath.Join(tlsDir, "admin.crt")
	key := filepath.Join(tlsDir, "admin.key")
	tlsOK := fileExists(crt) && fileExists(key)
	checks = append(checks, DiagCheck{
		ID: "admin_tls", Category: "证书", Title: "管理面 TLS (admin.crt/key)",
		OK: tlsOK, Severity: "critical",
		Detail: crt,
		Hint:   "缺失会导致 nginx -t 与 :8443 失败。可点「修复证书」或到 PKI 页生成",
		Action: "ensure_tls",
	})

	// --- ModSec / 引擎 ---
	modOK := fileExists(m.ModSecConf)
	checks = append(checks, DiagCheck{
		ID: "modsec_conf", Category: "配置", Title: "ModSecurity 主配置",
		OK: modOK, Severity: "critical",
		Detail: m.ModSecConf,
		Hint:   "检查 API 配置 ModSecConf 路径",
	})
	mode, modeErr := m.GetEngineMode()
	modeOK := modeErr == nil && (mode == "On" || mode == "DetectionOnly" || mode == "Off")
	sev := "info"
	if mode == "Off" {
		sev = "warn"
	}
	detail := mode
	if modeErr != nil {
		detail = modeErr.Error()
	}
	checks = append(checks, DiagCheck{
		ID: "engine_mode", Category: "防护", Title: "SecRuleEngine 模式",
		OK: modeOK && mode != "Off", Severity: sev,
		Detail: detail,
		Hint:   "Off 为旁路；上线拦截需 On；排障可临时 DetectionOnly",
	})

	// --- 控制台静态资源 ---
	consoleDir := opts.ConsoleDir
	if consoleDir == "" {
		consoleDir = filepath.Join(root, "share", "console")
	}
	idx := filepath.Join(consoleDir, "index.html")
	js := filepath.Join(consoleDir, "assets", "app.js")
	consoleOK := fileExists(idx) && fileExists(js)
	checks = append(checks, DiagCheck{
		ID: "console_files", Category: "服务", Title: "控制台静态文件",
		OK: consoleOK, Severity: "critical",
		Detail: consoleDir,
		Hint:   "执行 sync_console / 复制 management/console → share/console 后重启 API",
	})

	// --- Nginx 能力 ---
	authReq := m.HasAuthRequestModule()
	checks = append(checks, DiagCheck{
		ID: "auth_request", Category: "能力", Title: "http_auth_request_module",
		OK: true, Severity: "info", // 缺失会自动降级，不算失败
		Detail: map[bool]string{true: "已编译（HMAC 硬校验可用）", false: "未编译（自动降级为 JS 软挑战）"}[authReq],
		Hint:   "未编译时站点不会写 auth_request，避免 nginx -t 失败",
	})

	// --- 站点 ---
	sites, _ := m.ListSites()
	checks = append(checks, DiagCheck{
		ID: "sites", Category: "配置", Title: "受保护站点",
		OK: true, Severity: "info",
		Detail: fmt.Sprintf("%d 个 site-*.conf", len(sites)),
	})

	// --- 磁盘 ---
	if free, err := diskFreeGB(root); err == nil {
		ok := free >= 1.0
		sev := "info"
		if free < 1.0 {
			sev = "warn"
		}
		if free < 0.2 {
			sev = "critical"
			ok = false
		}
		checks = append(checks, DiagCheck{
			ID: "disk", Category: "主机", Title: "产品目录可用空间",
			OK: ok, Severity: sev,
			Detail: fmt.Sprintf("%.2f GB @ %s", free, root),
			Hint:   "空间不足会导致备份/升级失败",
		})
	}

	// --- 许可 ---
	licOK := opts.LicenseOK
	licMsg := opts.LicenseMsg
	if licMsg == "" {
		licMsg = "未提供"
	}
	checks = append(checks, DiagCheck{
		ID: "license", Category: "许可", Title: "许可证状态",
		OK: licOK, Severity: map[bool]string{true: "info", false: "warn"}[licOK],
		Detail: licMsg,
		Hint:   "宽限期结束后变更类 API 将被拒绝，请到许可证页导入",
	})

	// --- 端口（提示性） ---
	listenDetail := listenHint("8443", "9090", "80", "443")
	listenOK := strings.Contains(listenDetail, "8443") || strings.Contains(listenDetail, "9090")
	checks = append(checks, DiagCheck{
		ID: "listen", Category: "服务", Title: "关键端口监听",
		OK: listenOK, Severity: "warn",
		Detail: listenDetail,
		Hint:   "管理面通常为 :8443（Nginx）→ API :9090；数据面 :80/:443",
	})

	// --- HA ---
	ha := m.HAStatus()
	haOK := ha.HealthOK || ha.RoleGuess == "standalone"
	checks = append(checks, DiagCheck{
		ID: "ha", Category: "主机", Title: "HA / 健康探测",
		OK: haOK, Severity: map[bool]string{true: "info", false: "warn"}[haOK],
		Detail: fmt.Sprintf("%s — %s", ha.RoleGuess, ha.HealthDetail),
	})

	// 汇总
	fail, warn, okN := 0, 0, 0
	for _, c := range checks {
		if c.OK {
			okN++
			continue
		}
		if c.Severity == "critical" {
			fail++
		} else {
			warn++
		}
	}

	// 日志尾
	prefix := nginxPrefixFromBuild(m.NginxBuildInfo())
	errLog := filepath.Join(prefix, "logs", "error.log")
	if !fileExists(errLog) {
		alt := "/var/log/nginx/error.log"
		if fileExists(alt) {
			errLog = alt
		}
	}
	logs := map[string]string{
		"nginx_error": tailTextFile(errLog, 35),
	}
	if opts.AuditLog != "" {
		logs["modsec_audit_snip"] = truncateRunes(strings.Join(func() []string {
			lines, _ := TailAuditRawLines(opts.AuditLog, 5)
			return lines
		}(), "\n"), 1200)
	}

	tips := []map[string]string{
		{"title": "管理面 Failed to fetch / 404", "body": "同步 share/console，确认 ma-waf-api 运行，nginx -t 通过后 reload；浏览器 Ctrl+F5。"},
		{"title": "站点保存失败 / nginx -t 失败", "body": "检查 admin.crt、auth_request 模块降级、conf.d 语法；可点「修复证书」或回滚备份。"},
		{"title": "数据面 502", "body": "上游业务服务未启动或 upstream 地址错误；与 WAF 引擎无关时请先查 upstream。"},
		{"title": "误报冲高", "body": "临时 DetectionOnly 或紧急旁路；在规则例外中放行 URI/规则 ID；调低 CRS 偏执级。"},
		{"title": "CPU 飙高", "body": "检查 CC 限流、静态资源白名单、SecPcreMatchLimit；查看本页 Nginx error 尾部。"},
	}

	overall := "ok"
	if fail > 0 {
		overall = "fail"
	} else if warn > 0 {
		overall = "warn"
	}

	return map[string]interface{}{
		"overall":    overall,
		"summary":    map[string]int{"ok": okN, "warn": warn, "fail": fail, "total": len(checks)},
		"checks":     checks,
		"logs":       logs,
		"log_paths":  map[string]string{"nginx_error": errLog},
		"tips":       tips,
		"caps":       m.NginxCapabilities(),
		"time_utc":   time.Now().UTC().Format(time.RFC3339),
		"product_root": root,
	}
}
