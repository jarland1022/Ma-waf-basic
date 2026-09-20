package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var isoCountryRe = regexp.MustCompile(`(?i)^[A-Z]{2}$`)

func (m *Manager) geoBlockPath() string {
	return filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), "..", "geo", "geo_block.conf"))
}

// ReadGeoBlock 读取被封锁的 ISO 国家码列表。
func (m *Manager) ReadGeoBlock() ([]string, error) {
	b, err := os.ReadFile(m.geoBlockPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		cc := strings.ToUpper(fields[0])
		if !isoCountryRe.MatchString(cc) || seen[cc] {
			continue
		}
		seen[cc] = true
		out = append(out, cc)
	}
	return out, nil
}

// WriteGeoBlock 写入国家封锁清单（nginx map include 格式）。
func (m *Manager) WriteGeoBlock(codes []string, doReload bool) error {
	if _, err := m.Backup(); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# managed by ma-waf-api — Geo country block list\n")
	b.WriteString("# Format: ISO 1;\n")
	seen := map[string]bool{}
	for _, c := range codes {
		c = strings.ToUpper(strings.TrimSpace(c))
		if !isoCountryRe.MatchString(c) || seen[c] {
			continue
		}
		seen[c] = true
		b.WriteString(c)
		b.WriteString(" 1;\n")
	}
	path := m.geoBlockPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o640); err != nil {
		return err
	}
	if doReload {
		return m.Reload()
	}
	return nil
}

// VirtPatchInfo 虚拟补丁元数据（来自 custom 规则 META）。
type VirtPatchInfo struct {
	ID      string `json:"id"`
	CVE     string `json:"cve,omitempty"`
	Expire  string `json:"expire,omitempty"`
	Enabled bool   `json:"enabled"`
	File    string `json:"file,omitempty"`
	Expired bool   `json:"expired"`
	Msg     string `json:"msg,omitempty"`
}

func (m *Manager) ListVirtPatches() ([]VirtPatchInfo, error) {
	detail, err := m.ListRulesDetailed()
	if err != nil {
		return nil, err
	}
	today := time.Now().Format("2006-01-02")
	var out []VirtPatchInfo
	for _, r := range detail {
		isVP := strings.HasPrefix(r.ID, "12") && len(r.ID) == 6
		if r.CVE == "" && !isVP {
			continue
		}
		if r.CVE == "" && !strings.Contains(strings.ToLower(r.File), "virtpatch") {
			continue
		}
		expired := r.Expire != "" && r.Expire < today
		out = append(out, VirtPatchInfo{
			ID: r.ID, CVE: r.CVE, Expire: r.Expire, Enabled: r.Enabled,
			File: r.File, Expired: expired, Msg: fmt.Sprintf("priority=%d", r.Priority),
		})
	}
	return out, nil
}
