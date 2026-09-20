package waf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var (
	nginxCapsOnce sync.Once
	nginxCapsOut  string
)

// NginxBuildInfo 返回 `nginx -V` 输出（含 configure arguments）。
func (m *Manager) NginxBuildInfo() string {
	nginxCapsOnce.Do(func() {
		bin := m.NginxBin
		if bin == "" {
			bin = "nginx"
		}
		cmd := exec.Command(bin, "-V")
		out, _ := cmd.CombinedOutput() // nginx -V 写在 stderr，CombinedOutput 一并捕获
		nginxCapsOut = string(out)
	})
	return nginxCapsOut
}

// InvalidateNginxCapsCache 在更换 nginx 二进制后可调用。
func InvalidateNginxCapsCache() {
	nginxCapsOnce = sync.Once{}
	nginxCapsOut = ""
}

// HasNginxModule 检测 nginx 是否编译了指定模块名（如 http_auth_request_module）。
func (m *Manager) HasNginxModule(mod string) bool {
	mod = strings.TrimSpace(mod)
	if mod == "" {
		return false
	}
	info := m.NginxBuildInfo()
	if info == "" {
		return false
	}
	// 常见形式：--with-http_auth_request_module 或已内置显示在 modules 列表
	if strings.Contains(info, mod) {
		return true
	}
	// 有的构建只写 with-http_auth_request_module 不带 http_ 前缀重复
	alt := strings.TrimPrefix(mod, "http_")
	return alt != mod && strings.Contains(info, alt)
}

func (m *Manager) HasAuthRequestModule() bool {
	return m.HasNginxModule("http_auth_request_module")
}

// NginxCapabilities 供控制台/状态接口展示。
func (m *Manager) NginxCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"auth_request": m.HasAuthRequestModule(),
		"build_snip":   truncateRunes(m.NginxBuildInfo(), 240),
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// SanitizeConfigsForNginxCaps 按已编译模块清理会令 nginx -t 失败的指令。
// 当前：无 auth_request 模块时，从 managed site-*.conf 去掉硬校验并尽量降级为软挑战。
func (m *Manager) SanitizeConfigsForNginxCaps() (fixed int, err error) {
	if m.HasAuthRequestModule() {
		return 0, nil
	}
	dir := m.confDDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "site-") || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		orig := string(b)
		if !strings.Contains(orig, "auth_request") {
			continue
		}
		next := stripAuthRequestDirectives(orig)
		if next == orig {
			continue
		}
		if err := os.WriteFile(path, []byte(next), 0o644); err != nil {
			return fixed, fmt.Errorf("sanitize %s: %w", e.Name(), err)
		}
		fixed++
	}
	return fixed, nil
}

func stripAuthRequestDirectives(text string) string {
	lines := strings.Split(text, "\n")
	var out []string
	removedAuth := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "auth_request ") || strings.HasPrefix(t, "auth_request\t") {
			removedAuth = true
			continue
		}
		// 仅去掉挑战相关的 401→挑战页（保留其它 error_page）
		if strings.Contains(t, "error_page 401") && strings.Contains(t, "waf-challenge") {
			removedAuth = true
			continue
		}
		out = append(out, line)
	}
	joined := strings.Join(out, "\n")
	if !removedAuth {
		return text
	}
	// 若去掉硬校验后没有软挑战，在 location / 内补一条，避免功能空窗
	if !strings.Contains(joined, "$need_js_challenge") {
		joined = injectSoftJSChallenge(joined)
	}
	// 更新头注释中的 enable_challenge_auth=true
	joined = strings.ReplaceAll(joined, "enable_challenge_auth=true", "enable_challenge_auth=false")
	return joined
}

func injectSoftJSChallenge(text string) string {
	needle := "if ($block_bad_bot) { return 403; }"
	inject := "if ($need_js_challenge) { return 302 /waf-challenge.html?r=$request_uri; }\n        " + needle
	if strings.Contains(text, needle) && !strings.Contains(text, "$need_js_challenge") {
		return strings.Replace(text, needle, inject, 1)
	}
	return text
}
