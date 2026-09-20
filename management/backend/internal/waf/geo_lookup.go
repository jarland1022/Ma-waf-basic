package waf

import (
	"net"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	geoDBOnce sync.Once
	geoDB     *geoip2.Reader
	geoDBPath string
)

func (m *Manager) openCountryDB() *geoip2.Reader {
	geoDBOnce.Do(func() {
		path := m.findMMDB()
		if path == "" {
			return
		}
		db, err := geoip2.Open(path)
		if err != nil {
			return
		}
		geoDB = db
		geoDBPath = path
	})
	return geoDB
}

// LookupCountryISO 用 GeoLite2-Country.mmdb 解析客户端 IP → ISO 国家码（如 CN、US）。
func (m *Manager) LookupCountryISO(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return ""
	}
	// 去掉端口 / IPv6 括号
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ipStr = strings.Trim(ipStr, "[]")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return ""
	}
	db := m.openCountryDB()
	if db == nil {
		return ""
	}
	rec, err := db.Country(ip)
	if err != nil || rec == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(rec.Country.IsoCode))
}

// EnrichAttackCountries 为缺少 country 的事件用 MMDB 补全，驱动报表国家热力。
func (m *Manager) EnrichAttackCountries(events []AttackEvent) []AttackEvent {
	if len(events) == 0 {
		return events
	}
	if m.openCountryDB() == nil {
		return events
	}
	cache := map[string]string{}
	for i := range events {
		if events[i].Country != "" {
			continue
		}
		ip := events[i].ClientIP
		if ip == "" {
			continue
		}
		cc, ok := cache[ip]
		if !ok {
			cc = m.LookupCountryISO(ip)
			cache[ip] = cc
		}
		if cc != "" {
			events[i].Country = cc
		}
	}
	return events
}

// CountryDBPath 返回当前加载的 Country MMDB 路径（可能为空）。
func (m *Manager) CountryDBPath() string {
	_ = m.openCountryDB()
	return geoDBPath
}
