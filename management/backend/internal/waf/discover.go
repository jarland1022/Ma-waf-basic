package waf

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

// DiscoveredSite 从访问日志中发现的 Host/端口候选。
type DiscoveredSite struct {
	Host       string `json:"host"`
	Port       string `json:"port,omitempty"`
	Scheme     string `json:"scheme,omitempty"`
	Count      int    `json:"count"`
	Protected  bool   `json:"protected"`
	SampleURI  string `json:"sample_uri,omitempty"`
}

func (m *Manager) DiscoverSites(accessLog string, limit int) ([]DiscoveredSite, error) {
	if limit <= 0 {
		limit = 50
	}
	known := map[string]bool{}
	sites, _ := m.ListSites()
	for _, s := range sites {
		for _, n := range s.ServerName {
			known[strings.ToLower(strings.TrimSpace(n))] = true
		}
		if s.Name != "" {
			known[strings.ToLower(s.Name)] = true
		}
	}

	f, err := os.Open(accessLog)
	if err != nil {
		if os.IsNotExist(err) {
			return []DiscoveredSite{}, nil
		}
		return nil, err
	}
	defer f.Close()

	type agg struct {
		count int
		uri   string
		port  string
		sch   string
	}
	hosts := map[string]*agg{}
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		var row map[string]interface{}
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(strAny(row["host"])))
		if host == "" || host == "_" || host == "localhost" || host == "127.0.0.1" {
			continue
		}
		if i := strings.IndexByte(host, ':'); i > 0 {
			host = host[:i]
		}
		a := hosts[host]
		if a == nil {
			a = &agg{}
			hosts[host] = a
		}
		a.count++
		if a.uri == "" {
			a.uri = strAny(row["uri"])
		}
		if a.sch == "" {
			a.sch = strAny(row["scheme"])
		}
	}
	var out []DiscoveredSite
	for h, a := range hosts {
		out = append(out, DiscoveredSite{
			Host:      h,
			Count:     a.count,
			Protected: known[h],
			SampleURI: a.uri,
			Scheme:    a.sch,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func strAny(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}
