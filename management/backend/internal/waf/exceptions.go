package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Exception 误报放行策略
// Kind: uri_bypass | rule_remove | uri_rule_remove
type Exception struct {
	ID      int    `json:"id"`
	Kind    string `json:"kind"`
	URI     string `json:"uri,omitempty"`
	RuleIDs string `json:"rule_ids,omitempty"` // 逗号分隔或区间 942100-942199
	Note    string `json:"note,omitempty"`
	Enabled bool   `json:"enabled"`
}

func (m *Manager) exceptionsFile() string {
	return filepath.Join(filepath.Dir(m.ModSecConf), "custom", "000-exceptions.conf")
}

func (m *Manager) exceptionsMetaFile() string {
	// 产品 var：BackupDir 的上级目录（…/Ma-waf/backups → …/Ma-waf/var/lib）
	base := filepath.Dir(m.BackupDir)
	return filepath.Join(base, "var", "lib", "exceptions.json")
}

func (m *Manager) ListExceptions() ([]Exception, error) {
	path := m.exceptionsMetaFile()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Exception{}, nil
		}
		return nil, err
	}
	var list []Exception
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (m *Manager) SaveExceptions(list []Exception, doReload bool) error {
	if _, err := m.Backup(); err != nil {
		return err
	}
	// normalize ids 150000+
	next := 150001
	used := map[int]bool{}
	for i := range list {
		if list[i].ID >= 150001 && list[i].ID < 160000 && !used[list[i].ID] {
			used[list[i].ID] = true
			continue
		}
		for used[next] {
			next++
		}
		list[i].ID = next
		used[next] = true
		next++
	}
	metaPath := m.exceptionsMetaFile()
	_ = os.MkdirAll(filepath.Dir(metaPath), 0o750)
	raw, _ := json.MarshalIndent(list, "", "  ")
	if err := os.WriteFile(metaPath, raw, 0o640); err != nil {
		return err
	}
	conf := renderExceptionsConf(list)
	excFile := m.exceptionsFile()
	_ = os.MkdirAll(filepath.Dir(excFile), 0o755)
	if err := os.WriteFile(excFile, []byte(conf), 0o644); err != nil {
		return err
	}
	if doReload {
		return m.Reload()
	}
	return nil
}

func renderExceptionsConf(list []Exception) string {
	var b strings.Builder
	b.WriteString("# managed-by: ma-waf-api — false-positive exceptions\n")
	b.WriteString("# Do not edit by hand; use console 例外策略\n\n")
	for _, e := range list {
		if !e.Enabled {
			b.WriteString(fmt.Sprintf("# disabled id:%d %s\n", e.ID, e.Note))
			continue
		}
		note := strings.ReplaceAll(e.Note, "'", "")
		switch e.Kind {
		case "uri_bypass":
			uri := e.URI
			if uri == "" {
				continue
			}
			b.WriteString(fmt.Sprintf(
				"SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleEngine=Off,tag:'exception',msg:'URI bypass: %s'\"\n",
				escapeModSec(uri), e.ID, note,
			))
		case "rule_remove":
			ids := strings.TrimSpace(e.RuleIDs)
			if ids == "" {
				continue
			}
			for _, part := range strings.Split(ids, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				b.WriteString(fmt.Sprintf("SecRuleRemoveById %s\n", part))
			}
			b.WriteString(fmt.Sprintf("# EXC meta id:%d note:%s\n", e.ID, note))
		case "uri_rule_remove":
			uri := e.URI
			ids := strings.TrimSpace(e.RuleIDs)
			if uri == "" || ids == "" {
				continue
			}
			b.WriteString(fmt.Sprintf(
				"SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,nolog,ctl:ruleRemoveById=%s,tag:'exception',msg:'URI rule remove: %s'\"\n",
				escapeModSec(uri), e.ID, ids, note,
			))
		default:
			continue
		}
	}
	return b.String()
}

func escapeModSec(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func ParseRuleIDList(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("rule_ids 不能为空")
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			if _, err := strconv.Atoi(strings.TrimSpace(ab[0])); err != nil {
				return err
			}
			if _, err := strconv.Atoi(strings.TrimSpace(ab[1])); err != nil {
				return err
			}
			continue
		}
		if _, err := strconv.Atoi(part); err != nil {
			return fmt.Errorf("非法规则 ID: %s", part)
		}
	}
	return nil
}
