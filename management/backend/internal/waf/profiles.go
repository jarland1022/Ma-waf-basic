package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PolicyProfile 命名防护画像（对齐 Imperva 策略模板思路：一键套用到站点/规则包）。
type PolicyProfile struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Description        string   `json:"description,omitempty"`
	EngineMode         string   `json:"engine_mode,omitempty"` // On|DetectionOnly|Off
	EnablePacks        []string `json:"enable_packs,omitempty"`
	DisablePacks       []string `json:"disable_packs,omitempty"`
	BurstPerIP         int      `json:"burst_per_ip,omitempty"`
	BurstPerServer     int      `json:"burst_per_server,omitempty"`
	ConnLimit          int      `json:"conn_limit,omitempty"`
	EnableJSChallenge  bool     `json:"enable_js_challenge"`
	EnableChallengeAuth bool    `json:"enable_challenge_auth"`
	EnableGeo          bool     `json:"enable_geo"`
	EnableAPIProtect   bool     `json:"enable_api_protect"`
	APIPrefix          string   `json:"api_prefix,omitempty"`
	ParanoiaLevel      int      `json:"paranoia_level,omitempty"`
}

func (m *Manager) profilesPath() string {
	root := filepath.Clean(filepath.Join(m.BackupDir, ".."))
	return filepath.Join(root, "var", "lib", "profiles.json")
}

func DefaultProfiles() []PolicyProfile {
	return []PolicyProfile{
		{
			ID: "policy_loose", Name: "宽松 (policy_loose)", Description: "仅高严重级别倾向；低误报，适合观察期后的宽松生产",
			EngineMode: "On", BurstPerIP: 80, BurstPerServer: 800, ConnLimit: 100,
			EnableJSChallenge: true, DisablePacks: []string{"130000-openapi"}, ParanoiaLevel: 1,
		},
		{
			ID: "policy_normal", Name: "标准 (policy_normal)", Description: "默认防护：高准确规则 + 软挑战",
			EngineMode: "On", BurstPerIP: 40, BurstPerServer: 400, ConnLimit: 50,
			EnableJSChallenge: true, EnablePacks: []string{"110000-upload", "110100-pii", "110200-bot", "110300-session"},
			ParanoiaLevel: 2,
		},
		{
			ID: "policy_strict", Name: "严格 (policy_strict)", Description: "启用多数规则包；最大防护，误报可能升高",
			EngineMode: "On", BurstPerIP: 20, BurstPerServer: 200, ConnLimit: 30,
			EnableAPIProtect: true, APIPrefix: "/api/", EnableChallengeAuth: true,
			EnablePacks: []string{"110000-upload", "110100-pii", "110200-bot", "110300-session", "130000-openapi"},
			ParanoiaLevel: 3,
		},
		{
			ID: "policy_debug", Name: "调试 (policy_debug)", Description: "DetectionOnly，便于排查误报",
			EngineMode: "DetectionOnly", BurstPerIP: 60, BurstPerServer: 600, ConnLimit: 80,
			EnableJSChallenge: false, ParanoiaLevel: 1,
		},
		{
			ID: "policy_emergency", Name: "紧急/重保 (policy_emergency)", Description: "最高偏执级别 + 全开引擎，重大活动期间使用",
			EngineMode: "On", BurstPerIP: 15, BurstPerServer: 150, ConnLimit: 20,
			EnableJSChallenge: true, EnableChallengeAuth: true, EnableGeo: true,
			EnablePacks: []string{"110000-upload", "110100-pii", "110200-bot", "110300-session", "130000-openapi"},
			ParanoiaLevel: 4,
		},
		// 兼容旧 ID
		{
			ID: "balanced", Name: "均衡防护（兼容）", Description: "同 policy_normal",
			EngineMode: "On", BurstPerIP: 40, BurstPerServer: 400, ConnLimit: 50,
			EnableJSChallenge: true, EnablePacks: []string{"110000-upload", "110100-pii", "110200-bot", "110300-session"},
			ParanoiaLevel: 2,
		},
		{
			ID: "api-strict", Name: "API 严格（兼容）", Description: "同 policy_strict 侧重 API",
			EngineMode: "On", BurstPerIP: 20, BurstPerServer: 200, ConnLimit: 30,
			EnableAPIProtect: true, APIPrefix: "/api/", EnableChallengeAuth: true,
			EnablePacks: []string{"130000-openapi", "110200-bot", "110300-session"},
			ParanoiaLevel: 3,
		},
		{
			ID: "detection-only", Name: "仅检测（兼容）", Description: "同 policy_debug",
			EngineMode: "DetectionOnly", BurstPerIP: 60, BurstPerServer: 600, ConnLimit: 80,
			EnableJSChallenge: false, ParanoiaLevel: 1,
		},
		{
			ID: "cms-legacy", Name: "CMS/遗留（兼容）", Description: "同 policy_loose",
			EngineMode: "On", BurstPerIP: 80, BurstPerServer: 800, ConnLimit: 100,
			EnableJSChallenge: true, DisablePacks: []string{"130000-openapi"}, ParanoiaLevel: 1,
		},
	}
}

func (m *Manager) ListProfiles() ([]PolicyProfile, error) {
	b, err := os.ReadFile(m.profilesPath())
	if err != nil {
		if os.IsNotExist(err) {
			defs := DefaultProfiles()
			_ = m.SaveProfiles(defs)
			return defs, nil
		}
		return nil, err
	}
	var list []PolicyProfile
	if err := json.Unmarshal(b, &list); err != nil {
		return DefaultProfiles(), nil
	}
	if len(list) == 0 {
		return DefaultProfiles(), nil
	}
	return list, nil
}

func (m *Manager) SaveProfiles(list []PolicyProfile) error {
	path := m.profilesPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o640)
}

func (m *Manager) GetProfile(id string) (*PolicyProfile, error) {
	list, err := m.ListProfiles()
	if err != nil {
		return nil, err
	}
	id = strings.TrimSpace(id)
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, fmt.Errorf("profile not found: %s", id)
}

// ApplyProfileToSite 将画像套用到可管理站点（合并站点字段 + 启停规则包 + 可选引擎模式）。
func (m *Manager) ApplyProfileToSite(siteName, profileID string, setEngine bool) error {
	p, err := m.GetProfile(profileID)
	if err != nil {
		return err
	}
	spec, err := m.GetManagedSite(siteName)
	if err != nil {
		return err
	}
	if p.BurstPerIP > 0 {
		spec.BurstPerIP = p.BurstPerIP
	}
	if p.BurstPerServer > 0 {
		spec.BurstPerServer = p.BurstPerServer
	}
	if p.ConnLimit > 0 {
		spec.ConnLimit = p.ConnLimit
	}
	spec.EnableJSChallenge = p.EnableJSChallenge
	spec.EnableChallengeAuth = p.EnableChallengeAuth
	spec.EnableGeo = p.EnableGeo
	spec.EnableAPIProtect = p.EnableAPIProtect
	spec.ProfileID = p.ID
	spec.ProfileName = p.Name
	if p.APIPrefix != "" {
		spec.APIPrefix = p.APIPrefix
	}
	if err := m.UpsertSite(*spec); err != nil {
		return err
	}
	for _, id := range p.EnablePacks {
		_ = m.SetProtectionPack(id, true, false)
	}
	for _, id := range p.DisablePacks {
		_ = m.SetProtectionPack(id, false, false)
	}
	if p.ParanoiaLevel >= 1 {
		if err := m.SetParanoiaLevel(p.ParanoiaLevel, false); err != nil {
			return err
		}
	}
	if setEngine && p.EngineMode != "" {
		if err := m.SetEngineMode(p.EngineMode); err != nil {
			return err
		}
		return nil
	}
	return m.Reload()
}
