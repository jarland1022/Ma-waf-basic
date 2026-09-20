package waf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type IntelLedgerEntry struct {
	IP         string `json:"ip"`
	Source     string `json:"source"`
	AddedAt    string `json:"added_at"`
	ExpireDays int    `json:"expire_days"`
}

func (m *Manager) intelLedgerPath() string {
	root := filepath.Clean(filepath.Join(m.BackupDir, ".."))
	return filepath.Join(root, "var", "lib", "intel-ledger.json")
}

func (m *Manager) readIntelLedger() []IntelLedgerEntry {
	b, err := os.ReadFile(m.intelLedgerPath())
	if err != nil {
		return nil
	}
	var list []IntelLedgerEntry
	_ = json.Unmarshal(b, &list)
	return list
}

func (m *Manager) writeIntelLedger(list []IntelLedgerEntry) error {
	path := m.intelLedgerPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(path, raw, 0o640)
}

func (m *Manager) RecordIntel(ips []string, source string, expireDays int) {
	if expireDays <= 0 {
		expireDays = 30
	}
	now := time.Now().UTC().Format(time.RFC3339)
	cur := m.readIntelLedger()
	seen := map[string]int{}
	for i, e := range cur {
		seen[e.IP] = i
	}
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		ent := IntelLedgerEntry{IP: ip, Source: source, AddedAt: now, ExpireDays: expireDays}
		if i, ok := seen[ip]; ok {
			cur[i] = ent
		} else {
			seen[ip] = len(cur)
			cur = append(cur, ent)
		}
	}
	_ = m.writeIntelLedger(cur)
}

func (m *Manager) IntelStatus() map[string]interface{} {
	list := m.readIntelLedger()
	now := time.Now().UTC()
	expired := 0
	last := ""
	for _, e := range list {
		if e.AddedAt > last {
			last = e.AddedAt
		}
		if intelExpired(e, now) {
			expired++
		}
	}
	return map[string]interface{}{
		"count":        len(list),
		"expired":      expired,
		"last_sync":    last,
		"ledger_path":  m.intelLedgerPath(),
	}
}

func intelExpired(e IntelLedgerEntry, now time.Time) bool {
	if e.ExpireDays <= 0 {
		return false
	}
	t, err := time.Parse(time.RFC3339, e.AddedAt)
	if err != nil {
		return false
	}
	return now.After(t.Add(time.Duration(e.ExpireDays) * 24 * time.Hour))
}

// ExpireThreatIntel 从黑名单移除账本中已过期 IOC。
func (m *Manager) ExpireThreatIntel(doReload bool) (int, error) {
	now := time.Now().UTC()
	list := m.readIntelLedger()
	var keep []IntelLedgerEntry
	var drop []string
	for _, e := range list {
		if intelExpired(e, now) {
			drop = append(drop, e.IP)
			continue
		}
		keep = append(keep, e)
	}
	if len(drop) == 0 {
		return 0, nil
	}
	cur, err := m.ReadIPList("blacklist")
	if err != nil {
		return 0, err
	}
	dropSet := map[string]bool{}
	for _, ip := range drop {
		dropSet[ip] = true
		if !strings.Contains(ip, "/") {
			if strings.Contains(ip, ":") {
				dropSet[ip+"/128"] = true
			} else {
				dropSet[ip+"/32"] = true
			}
		}
	}
	var remain []string
	for _, e := range cur {
		if dropSet[e] {
			continue
		}
		remain = append(remain, e)
	}
	if err := m.WriteIPList("blacklist", remain, doReload); err != nil {
		return 0, err
	}
	if err := m.writeIntelLedger(keep); err != nil {
		return len(drop), err
	}
	return len(drop), nil
}
