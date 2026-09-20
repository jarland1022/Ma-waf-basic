package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AddrObject 对象地址簿（对齐企业 WAF「地址簿」可复用对象）。
type AddrObject struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // ipv4|ipv6
	Members     []string `json:"members"`
	Excludes    []string `json:"excludes,omitempty"`
	Description string   `json:"description,omitempty"`
	RefCount    int      `json:"ref_count"`
}

func (m *Manager) addrBookPath() string {
	return filepath.Join(filepath.Dir(m.BackupDir), "var", "lib", "addrbook.json")
}

func DefaultAddrBook() []AddrObject {
	return []AddrObject{
		{Name: "Any", Type: "ipv4", Members: []string{"0.0.0.0/0"}, Description: "全部 IPv4"},
		{Name: "IPv6-any", Type: "ipv6", Members: []string{"::/0"}, Description: "全部 IPv6"},
		{Name: "private_network", Type: "ipv4", Members: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}, Description: "RFC1918 私网"},
	}
}

func (m *Manager) ListAddrBook() ([]AddrObject, error) {
	b, err := os.ReadFile(m.addrBookPath())
	if err != nil {
		if os.IsNotExist(err) {
			defs := DefaultAddrBook()
			_ = m.SaveAddrBook(defs)
			return m.withAddrRefs(defs), nil
		}
		return nil, err
	}
	var list []AddrObject
	if err := json.Unmarshal(b, &list); err != nil {
		return DefaultAddrBook(), nil
	}
	if len(list) == 0 {
		list = DefaultAddrBook()
	}
	return m.withAddrRefs(list), nil
}

func (m *Manager) SaveAddrBook(list []AddrObject) error {
	seen := map[string]bool{}
	for i := range list {
		n := strings.TrimSpace(list[i].Name)
		if n == "" {
			return fmt.Errorf("名称不能为空")
		}
		if seen[n] {
			return fmt.Errorf("重复名称: %s", n)
		}
		seen[n] = true
		list[i].Name = n
		if list[i].Type != "ipv6" {
			list[i].Type = "ipv4"
		}
	}
	path := m.addrBookPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(path, raw, 0o640)
}

func (m *Manager) withAddrRefs(list []AddrObject) []AddrObject {
	bl, _ := m.ReadIPList("blacklist")
	wl, _ := m.ReadIPList("whitelist")
	used := map[string]bool{}
	for _, e := range append(bl, wl...) {
		used[e] = true
	}
	out := make([]AddrObject, len(list))
	copy(out, list)
	for i := range out {
		n := 0
		for _, mem := range out[i].Members {
			if used[mem] || used[strings.TrimSuffix(mem, "/32")] {
				n++
			}
		}
		out[i].RefCount = n
	}
	return out
}

// ApplyAddrToList 将地址簿成员追加到黑/白名单。
func (m *Manager) ApplyAddrToList(name, kind string, doReload bool) (int, error) {
	list, err := m.ListAddrBook()
	if err != nil {
		return 0, err
	}
	var members []string
	for _, o := range list {
		if o.Name == name {
			members = o.Members
			break
		}
	}
	if len(members) == 0 {
		return 0, fmt.Errorf("地址簿不存在或无成员: %s", name)
	}
	return m.AddIPs(kind, members, doReload)
}
