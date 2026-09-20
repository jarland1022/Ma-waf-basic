package waf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type SiteInfo struct {
	File                string   `json:"file"`
	Name                string   `json:"name,omitempty"` // site-<name>.conf 可管理名称
	Managed             bool     `json:"managed"`        // 是否由控制台创建
	ServerName          []string `json:"server_name"`
	Listens             []string `json:"listens"`
	ModSec              string   `json:"modsecurity"` // on|off|unknown
	Upstream            string   `json:"upstream,omitempty"`
	SSL                 bool     `json:"ssl"`
	EnableCSP           bool     `json:"enable_csp,omitempty"`
	EnableGeo           bool     `json:"enable_geo,omitempty"`
	EnableJSChallenge   bool     `json:"enable_js_challenge,omitempty"`
	EnableChallengeAuth bool     `json:"enable_challenge_auth,omitempty"`
	ProfileID           string   `json:"profile_id,omitempty"`
	ProfileName         string   `json:"profile_name,omitempty"`
}

var (
	reServerName = regexp.MustCompile(`(?i)^\s*server_name\s+([^;]+);`)
	reListen     = regexp.MustCompile(`(?i)^\s*listen\s+([^;]+);`)
	reModSec     = regexp.MustCompile(`(?i)^\s*modsecurity\s+(on|off)\s*;`)
	reProxyPass  = regexp.MustCompile(`(?i)^\s*proxy_pass\s+([^;]+);`)
	reSSL        = regexp.MustCompile(`(?i)\bssl\b`)
)

// ListSites 从 nginx conf.d 粗解析受保护站点（只读运维视图）。
func (m *Manager) ListSites() ([]SiteInfo, error) {
	confDir := filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), "..", "conf.d"))
	entries, err := os.ReadDir(confDir)
	if err != nil {
		return nil, err
	}
	var out []SiteInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		// 跳过示例
		if strings.Contains(e.Name(), ".example") {
			continue
		}
		path := filepath.Join(confDir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := string(b)
		// 文件头画像注释（整文件级，不在单个 server 块内）
		fileProfileID, fileProfileName := "", ""
		if m := regexp.MustCompile(`(?m)^#\s*profile_id=([^\s#]+)\s+profile_name=(.+)$`).FindStringSubmatch(text); m != nil {
			fileProfileID = strings.TrimSpace(m[1])
			fileProfileName = strings.TrimSpace(m[2])
		}
		// 按 server { 粗分块
		blocks := splitServerBlocks(text)
		if len(blocks) == 0 {
			blocks = []string{text}
		}
		managedName := ""
		if strings.HasPrefix(e.Name(), "site-") && strings.HasSuffix(e.Name(), ".conf") {
			managedName = strings.TrimSuffix(strings.TrimPrefix(e.Name(), "site-"), ".conf")
		}
		for _, blk := range blocks {
			info := SiteInfo{
				File:                e.Name(),
				Name:                managedName,
				Managed:             managedName != "",
				ModSec:              "unknown",
				EnableCSP:           strings.Contains(blk, "csp_headers.conf"),
				EnableGeo:           strings.Contains(blk, "$geo_block"),
				EnableJSChallenge:   strings.Contains(blk, "$need_js_challenge") || strings.Contains(blk, "auth_request /waf-challenge/verify"),
				EnableChallengeAuth: strings.Contains(blk, "auth_request /waf-challenge/verify"),
				ProfileID:           fileProfileID,
				ProfileName:         fileProfileName,
			}
			for _, line := range strings.Split(blk, "\n") {
				if m := reServerName.FindStringSubmatch(line); m != nil {
					info.ServerName = append(info.ServerName, strings.Fields(m[1])...)
				}
				if m := reListen.FindStringSubmatch(line); m != nil {
					l := strings.TrimSpace(m[1])
					info.Listens = append(info.Listens, l)
					if reSSL.MatchString(l) {
						info.SSL = true
					}
				}
				if m := reModSec.FindStringSubmatch(line); m != nil {
					info.ModSec = strings.ToLower(m[1])
				}
				if m := reProxyPass.FindStringSubmatch(line); m != nil && info.Upstream == "" {
					info.Upstream = strings.TrimSpace(m[1])
				}
			}
			if len(info.Listens) == 0 && len(info.ServerName) == 0 {
				continue
			}
			out = append(out, info)
		}
	}
	return out, nil
}

func splitServerBlocks(text string) []string {
	var blocks []string
	lines := strings.Split(text, "\n")
	var cur []string
	depth := 0
	inServer := false
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if !inServer && strings.HasPrefix(trim, "server") && strings.Contains(trim, "{") {
			inServer = true
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			cur = []string{line}
			if depth <= 0 {
				blocks = append(blocks, strings.Join(cur, "\n"))
				cur = nil
				inServer = false
			}
			continue
		}
		if !inServer {
			continue
		}
		cur = append(cur, line)
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			blocks = append(blocks, strings.Join(cur, "\n"))
			cur = nil
			inServer = false
			depth = 0
		}
	}
	return blocks
}
