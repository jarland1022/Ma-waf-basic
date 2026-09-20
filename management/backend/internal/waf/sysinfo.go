package waf

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// SysInfo 系统与特征库概览（对齐企业 WAF 系统/特征库页）。
func (m *Manager) SysInfo() map[string]interface{} {
	root := filepath.Clean(filepath.Join(m.BackupDir, ".."))
	host, _ := os.Hostname()
	mode, _ := m.GetEngineMode()
	pl := m.GetParanoiaLevel()
	geo := m.GeoStatus()
	ha := m.HAStatus()
	intel := m.IntelStatus()

	crsVer := "unknown"
	crsPath := filepath.Join(filepath.Dir(m.ModSecConf), "crs-setup.conf")
	if b, err := os.ReadFile(crsPath); err == nil {
		s := string(b)
		if strings.Contains(s, "paranoia") {
			crsVer = "OWASP CRS (crs-setup present)"
		}
	}
	customDir := filepath.Join(filepath.Dir(m.ModSecConf), "custom")
	customN := 0
	_ = filepath.Walk(customDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			customN++
		}
		return nil
	})

	ops, _ := m.ReadOps()
	return map[string]interface{}{
		"hostname":         host,
		"product":          "Ma-WAF",
		"product_root":     root,
		"go_version":       runtime.Version(),
		"engine_mode":      mode,
		"paranoia_level":   pl,
		"paranoia_hint":    ParanoiaHint(pl),
		"crs":              crsVer,
		"custom_rules":     customN,
		"geo":              geo,
		"ha":               ha,
		"intel":            intel,
		"heavy_security":   ops.HeavySecurity,
		"rules_upgrade":    m.LastRulesUpgrade(),
		"time_utc":         time.Now().UTC().Format(time.RFC3339),
		"modsec_conf":      m.ModSecConf,
	}
}

// SetHeavySecurity 重保模式：PL4 + 引擎 On（可审计）。
func (m *Manager) SetHeavySecurity(on bool, reason string) error {
	ops, err := m.ReadOps()
	if err != nil {
		ops = DefaultOps()
	}
	ops.HeavySecurity = on
	if err := m.WriteOps(ops); err != nil {
		return err
	}
	if on {
		if err := m.SetParanoiaLevel(4, false); err != nil {
			return err
		}
		return m.EmergencyBypass("On", "heavy_security:"+reason, "system")
	}
	_ = m.SetParanoiaLevel(2, false)
	return m.Reload()
}
