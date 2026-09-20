package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadIPList kind = blacklist | whitelist
func (m *Manager) ReadIPList(kind string) ([]string, error) {
	path, err := m.ipListPath(kind)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			out = append(out, fields[0])
		}
	}
	return out, nil
}

func (m *Manager) WriteIPList(kind string, entries []string, doReload bool) error {
	path, err := m.ipListPath(kind)
	if err != nil {
		return err
	}
	if _, err := m.Backup(); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# managed by ma-waf-api\n")
	seen := map[string]bool{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") || seen[e] {
			continue
		}
		// nginx geo 格式: CIDR 1;
		if !strings.Contains(e, "/") {
			if strings.Contains(e, ":") {
				e += "/128"
			} else {
				e += "/32"
			}
		}
		seen[e] = true
		b.WriteString(e)
		b.WriteString(" 1;\n")
	}
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

// AddIPs 将 IP/CIDR 追加到名单（去重），不覆盖已有条目。
func (m *Manager) AddIPs(kind string, ips []string, doReload bool) (int, error) {
	cur, err := m.ReadIPList(kind)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	var merged []string
	for _, e := range cur {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		merged = append(merged, e)
	}
	added := 0
	for _, e := range ips {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		fields := strings.FieldsFunc(e, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		})
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		merged = append(merged, ip)
		added++
	}
	if added == 0 {
		return 0, nil
	}
	if err := m.WriteIPList(kind, merged, doReload); err != nil {
		return 0, err
	}
	return added, nil
}

func (m *Manager) ipListPath(kind string) (string, error) {
	confDir := filepath.Join(filepath.Dir(m.ModSecConf), "..", "geo")
	confDir = filepath.Clean(confDir)
	switch kind {
	case "blacklist", "black", "deny":
		return filepath.Join(confDir, "blacklist_ips.conf"), nil
	case "whitelist", "white", "allow":
		return filepath.Join(confDir, "whitelist_ips.conf"), nil
	default:
		return "", fmt.Errorf("kind must be blacklist or whitelist")
	}
}
