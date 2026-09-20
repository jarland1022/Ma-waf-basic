package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (m *Manager) geoMapPath() string {
	return filepath.Join(filepath.Dir(m.ModSecConf), "..", "geo", "geo_block_map.conf")
}

func (m *Manager) geoip2ModulePresent() bool {
	root := m.nginxConfRoot()
	candidates := []string{
		filepath.Join(root, "modules-ma-waf.conf"),
		filepath.Join(root, "nginx.conf"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := string(b)
		if strings.Contains(s, "ngx_http_geoip2_module") && !strings.Contains(s, "# load_module modules/ngx_http_geoip2_module") {
			if strings.Contains(s, "load_module") && strings.Contains(s, "geoip2") {
				for _, line := range strings.Split(s, "\n") {
					t := strings.TrimSpace(line)
					if strings.HasPrefix(t, "#") {
						continue
					}
					if strings.Contains(t, "ngx_http_geoip2_module") {
						return true
					}
				}
			}
		}
	}
	so := []string{
		filepath.Join(root, "modules", "ngx_http_geoip2_module.so"),
		"/usr/local/nginx/modules/ngx_http_geoip2_module.so",
	}
	for _, p := range so {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func (m *Manager) geoEnforced() bool {
	b, err := os.ReadFile(m.geoMapPath())
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "$geoip2_country_code") || strings.Contains(string(b), "$geoip2_data_country_code")
}

// EnableGeoEnforcement 在已有 MMDB + geoip2 模块时，把 $geo_block 接到国家码。
func (m *Manager) EnableGeoEnforcement(doReload bool) error {
	mmdb := m.mmdbPath()
	if mmdb == "" {
		return fmt.Errorf("未找到 GeoLite2-Country.mmdb，请先运行 scripts/update_geoip.sh")
	}
	if !m.geoip2ModulePresent() {
		return fmt.Errorf("未检测到 ngx_http_geoip2_module（请编译模块并写入 modules-ma-waf.conf）")
	}
	body := fmt.Sprintf(`# managed-by: ma-waf-api — Geo enforcement
geoip2 %s {
    $geoip2_country_code country iso_code;
}
map $geoip2_country_code $geo_block {
    default 0;
    include geo/geo_block.conf;
}
`, mmdb)
	if _, err := m.Backup(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.geoMapPath()), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(m.geoMapPath(), []byte(body), 0o644); err != nil {
		return err
	}
	if doReload {
		return m.Reload()
	}
	return nil
}

func (m *Manager) DisableGeoEnforcement(doReload bool) error {
	body := `# managed-by: ma-waf-api — Geo placeholder (no country lookup)
map $host $geo_block {
    default 0;
}
`
	if _, err := m.Backup(); err != nil {
		return err
	}
	if err := os.WriteFile(m.geoMapPath(), []byte(body), 0o644); err != nil {
		return err
	}
	if doReload {
		return m.Reload()
	}
	return nil
}
