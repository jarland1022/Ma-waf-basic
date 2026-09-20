package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// OpsSettings 运维告警与自动加黑配置（独立于 api.yaml，避免改写密钥文件）。
type OpsSettings struct {
	AlertWebhook       string `json:"alert_webhook"`
	AutoblockThreshold int    `json:"autoblock_threshold"`
	AutoblockTopN      int    `json:"autoblock_top_n"`
	AutoblockEnabled   bool   `json:"autoblock_enabled"`
	// CronToken: 本机定时任务调用 /api/v1/cron/* 时校验；空则拒绝
	CronToken string `json:"cron_token"`
	// AttackAlertMin: 审计近期事件数超过则告警（0=关闭）
	AttackAlertMin int `json:"attack_alert_min"`
	// IntelExpireDays: 威胁情报 IOC 默认存活天数
	IntelExpireDays int `json:"intel_expire_days"`
	// SIEMAddr: syslog host:port（空则关闭）
	SIEMAddr  string `json:"siem_addr"`
	SIEMProto string `json:"siem_proto"` // udp|tcp
	// HeavySecurity: 重保模式（PL4 + 引擎 On）
	HeavySecurity bool `json:"heavy_security"`
}

func (m *Manager) opsPath() string {
	root := filepath.Clean(filepath.Join(m.BackupDir, ".."))
	return filepath.Join(root, "var", "lib", "ops.json")
}

func DefaultOps() OpsSettings {
	return OpsSettings{
		AutoblockThreshold: 30,
		AutoblockTopN:      20,
		AttackAlertMin:     100,
		IntelExpireDays:    30,
		SIEMProto:          "udp",
	}
}

func (m *Manager) ReadOps() (OpsSettings, error) {
	cfg := DefaultOps()
	b, err := os.ReadFile(m.opsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return DefaultOps(), err
	}
	if cfg.AutoblockThreshold <= 0 {
		cfg.AutoblockThreshold = 30
	}
	if cfg.AutoblockTopN <= 0 {
		cfg.AutoblockTopN = 20
	}
	if cfg.IntelExpireDays <= 0 {
		cfg.IntelExpireDays = 30
	}
	if cfg.SIEMProto == "" {
		cfg.SIEMProto = "udp"
	}
	return cfg, nil
}

func (m *Manager) WriteOps(cfg OpsSettings) error {
	if cfg.AutoblockThreshold <= 0 {
		cfg.AutoblockThreshold = 30
	}
	if cfg.AutoblockTopN <= 0 {
		cfg.AutoblockTopN = 20
	}
	if cfg.IntelExpireDays <= 0 {
		cfg.IntelExpireDays = 30
	}
	if cfg.SIEMProto == "" {
		cfg.SIEMProto = "udp"
	}
	path := m.opsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o640)
}

// AutoBlockIPs 将命中次数 >= threshold 的源 IP 写入黑名单（按次数降序截断 topN）。
func (m *Manager) AutoBlockIPs(counts map[string]int, threshold, topN int, doReload bool) (added int, blocked []string, err error) {
	if threshold <= 0 {
		threshold = 30
	}
	if topN <= 0 {
		topN = 20
	}
	type kv struct {
		ip string
		n  int
	}
	var list []kv
	for ip, n := range counts {
		ip = strings.TrimSpace(ip)
		if ip == "" || n < threshold {
			continue
		}
		list = append(list, kv{ip: ip, n: n})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
	if len(list) > topN {
		list = list[:topN]
	}
	var candidates []string
	for _, x := range list {
		candidates = append(candidates, x.ip)
	}
	if len(candidates) == 0 {
		return 0, nil, nil
	}
	n, err := m.AddIPs("blacklist", candidates, doReload)
	if err != nil {
		return 0, nil, err
	}
	return n, candidates, nil
}

// OpenAPIStatus 返回 OpenAPI 规则包是否存在/启用。
func (m *Manager) OpenAPIStatus() (exists, enabled bool, path string) {
	custom := filepath.Join(filepath.Dir(m.ModSecConf), "custom")
	on := filepath.Join(custom, "130000-openapi.conf")
	off := on + ".off"
	if st, err := os.Stat(on); err == nil && !st.IsDir() {
		return true, true, on
	}
	if st, err := os.Stat(off); err == nil && !st.IsDir() {
		return true, false, off
	}
	return false, false, on
}

// PreviewOpenAPIPaths 仅解析 paths 数量，不写盘。
func PreviewOpenAPIPaths(content []byte) (int, error) {
	var spec map[string]interface{}
	if err := json.Unmarshal(content, &spec); err != nil {
		return 0, fmt.Errorf("仅支持 OpenAPI JSON: %w", err)
	}
	pathsObj, _ := spec["paths"].(map[string]interface{})
	if len(pathsObj) == 0 {
		return 0, fmt.Errorf("spec 无 paths")
	}
	return len(pathsObj), nil
}

func (m *Manager) findMMDB() string {
	root := filepath.Clean(filepath.Join(m.BackupDir, ".."))
	nginxRoot := filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), ".."))
	candidates := []string{
		filepath.Join(root, "conf", "geoip", "GeoLite2-Country.mmdb"),
		filepath.Join(nginxRoot, "geoip", "GeoLite2-Country.mmdb"),
		"/usr/share/GeoIP/GeoLite2-Country.mmdb",
		"/var/lib/GeoIP/GeoLite2-Country.mmdb",
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Size() > 0 {
			return p
		}
	}
	return ""
}

func (m *Manager) mmdbPath() string {
	return m.findMMDB()
}

// GeoStatus 探测 GeoIP 数据与封锁名单就绪情况。
func (m *Manager) GeoStatus() map[string]interface{} {
	mmdb := m.findMMDB()
	countries, _ := m.ReadGeoBlock()
	blockPath := m.geoBlockPath()
	mod := m.geoip2ModulePresent()
	enforced := m.geoEnforced()
	return map[string]interface{}{
		"mmdb_found":      mmdb != "",
		"mmdb_path":       mmdb,
		"blocklist_path":  blockPath,
		"blocklist_count": len(countries),
		"blocklist":       countries,
		"module_loaded":   mod,
		"enforced":        enforced,
		"hint":            "将 GeoLite2-Country.mmdb 放到 conf/geoip/ 即可驱动报表国家热力；国家封锁另需 ngx_http_geoip2_module + /geo/enforce",
		"ready":           mmdb != "" && len(countries) > 0 && mod,
		"report_ready":    mmdb != "",
	}
}
