package waf

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RulesUpgradeRecord 最近一次规则升级记录。
type RulesUpgradeRecord struct {
	Time       string   `json:"time"`
	Mode       string   `json:"mode"` // local|cli
	Filename   string   `json:"filename,omitempty"`
	CustomN    int      `json:"custom_files"`
	RulesN     int      `json:"rules_files"`
	Promoted   bool     `json:"promoted"`
	SigOK      bool     `json:"sig_verified"`
	User       string   `json:"user,omitempty"`
	Notes      []string `json:"notes,omitempty"`
	Error      string   `json:"error,omitempty"`
}

func (m *Manager) rulesUpgradePath() string {
	return filepath.Join(m.productRoot(), "var", "lib", "rules_upgrade.json")
}

func (m *Manager) LastRulesUpgrade() RulesUpgradeRecord {
	b, err := os.ReadFile(m.rulesUpgradePath())
	if err != nil {
		return RulesUpgradeRecord{}
	}
	var rec RulesUpgradeRecord
	_ = json.Unmarshal(b, &rec)
	return rec
}

func (m *Manager) saveRulesUpgrade(rec RulesUpgradeRecord) {
	_ = os.MkdirAll(filepath.Dir(m.rulesUpgradePath()), 0o750)
	raw, _ := json.MarshalIndent(rec, "", "  ")
	_ = os.WriteFile(m.rulesUpgradePath(), raw, 0o640)
}

// RulesUpgradeStatus 控制台特征库升级页状态。
func (m *Manager) RulesUpgradeStatus() map[string]interface{} {
	stagingN, activeN := 0, 0
	if ents, err := os.ReadDir(m.RulesStaging); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				stagingN++
			}
		}
	}
	if ents, err := os.ReadDir(m.RulesActive); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				activeN++
			}
		}
	}
	pubkey := filepath.Join(m.productRoot(), "conf", "update-pubkey.pem")
	_, pubOK := os.Stat(pubkey)
	script := filepath.Join(m.productRoot(), "scripts", "update_rules.sh")
	_, scriptOK := os.Stat(script)
	return map[string]interface{}{
		"staging_dir":      m.RulesStaging,
		"active_dir":       m.RulesActive,
		"staging_files":    stagingN,
		"active_files":     activeN,
		"last":             m.LastRulesUpgrade(),
		"pubkey_present":   pubOK == nil,
		"pubkey_path":      pubkey,
		"cli_script":       script,
		"cli_script_ok":    scriptOK == nil,
		"bundle_hint":      "支持 .tgz/.tar.gz：含 custom/*.conf（→staging）与/或 rules/*.conf（→ModSecurity rules）。可选同名 .sig + conf/update-pubkey.pem 验签。",
		"max_upload_mb":    64,
	}
}

// LocalRulesUpgradeOptions 本地升级选项。
type LocalRulesUpgradeOptions struct {
	BundlePath string
	SigPath    string // 可选独立签名文件
	Filename   string
	Promote    bool
	User       string
	StrictSig  bool // true 时无签名/公钥则失败（对齐 MA_WAF_STRICT_AUTH）
}

// LocalRulesUpgrade 解包本地规则包并可选 promote+reload。
func (m *Manager) LocalRulesUpgrade(opt LocalRulesUpgradeOptions) (RulesUpgradeRecord, error) {
	rec := RulesUpgradeRecord{
		Time:     time.Now().UTC().Format(time.RFC3339),
		Mode:     "local",
		Filename: opt.Filename,
		Promoted: opt.Promote,
		User:     opt.User,
	}
	if opt.BundlePath == "" {
		rec.Error = "缺少升级包"
		m.saveRulesUpgrade(rec)
		return rec, fmt.Errorf(rec.Error)
	}
	low := strings.ToLower(opt.Filename)
	if !strings.HasSuffix(low, ".tgz") && !strings.HasSuffix(low, ".tar.gz") && !strings.HasSuffix(low, ".tar") {
		rec.Error = "仅支持 .tgz / .tar.gz / .tar"
		m.saveRulesUpgrade(rec)
		return rec, fmt.Errorf(rec.Error)
	}

	sigPath := opt.SigPath
	if sigPath == "" {
		cand := opt.BundlePath + ".sig"
		if _, err := os.Stat(cand); err == nil {
			sigPath = cand
		}
	}
	pubkey := filepath.Join(m.productRoot(), "conf", "update-pubkey.pem")
	if sigPath != "" {
		if err := verifyUpdateSig(opt.BundlePath, sigPath, pubkey); err != nil {
			rec.Error = err.Error()
			m.saveRulesUpgrade(rec)
			return rec, err
		}
		rec.SigOK = true
		rec.Notes = append(rec.Notes, "签名验证通过")
	} else {
		if opt.StrictSig {
			rec.Error = "STRICT: 缺少签名或 conf/update-pubkey.pem"
			m.saveRulesUpgrade(rec)
			return rec, fmt.Errorf(rec.Error)
		}
		if _, err := os.Stat(pubkey); err == nil {
			rec.Notes = append(rec.Notes, "未提供 .sig，跳过验签")
		} else {
			rec.Notes = append(rec.Notes, "未配置 update-pubkey.pem，跳过验签")
		}
	}

	tmp, err := os.MkdirTemp("", "ma-waf-rules-up-*")
	if err != nil {
		return rec, err
	}
	defer os.RemoveAll(tmp)

	if err := extractTarMaybeGzip(opt.BundlePath, tmp); err != nil {
		rec.Error = "解包失败: " + err.Error()
		m.saveRulesUpgrade(rec)
		return rec, fmt.Errorf(rec.Error)
	}

	root := tmp
	// 若包内仅一层目录，下探
	if ents, err := os.ReadDir(tmp); err == nil && len(ents) == 1 && ents[0].IsDir() {
		name := ents[0].Name()
		if name != "custom" && name != "rules" && name != "crs" {
			root = filepath.Join(tmp, name)
		}
	}

	customSrc := filepath.Join(root, "custom")
	rulesSrc := filepath.Join(root, "rules")
	if _, err := os.Stat(customSrc); err != nil {
		// 允许包根直接是 .conf
		if hasConfFiles(root) && !dirExists(filepath.Join(root, "crs")) {
			customSrc = root
		}
	}

	if err := os.MkdirAll(m.RulesStaging, 0o750); err != nil {
		return rec, err
	}
	nCustom, err := copyConfTree(customSrc, m.RulesStaging)
	if err != nil {
		rec.Error = err.Error()
		m.saveRulesUpgrade(rec)
		return rec, err
	}
	rec.CustomN = nCustom

	rulesDest := filepath.Join(filepath.Dir(m.ModSecConf), "rules")
	nRules := 0
	if dirExists(rulesSrc) {
		if err := os.MkdirAll(rulesDest, 0o755); err != nil {
			return rec, err
		}
		nRules, err = copyConfTree(rulesSrc, rulesDest)
		if err != nil {
			rec.Error = err.Error()
			m.saveRulesUpgrade(rec)
			return rec, err
		}
	}
	rec.RulesN = nRules

	if nCustom == 0 && nRules == 0 {
		rec.Error = "包内未找到 custom/*.conf 或 rules/*.conf"
		m.saveRulesUpgrade(rec)
		return rec, fmt.Errorf(rec.Error)
	}
	rec.Notes = append(rec.Notes, fmt.Sprintf("staging+%d custom, rules+%d", nCustom, nRules))

	// 可选：调用 rule_manager validate
	if nCustom > 0 {
		if msg, err := m.validateStagingExternal(); err != nil {
			rec.Notes = append(rec.Notes, "validate: "+msg)
			// 不强制失败：部分环境无 python；仅记录
			if os.Getenv("MA_WAF_STRICT_RULE_VALIDATE") == "1" {
				rec.Error = "staging 校验失败: " + msg
				m.saveRulesUpgrade(rec)
				return rec, fmt.Errorf(rec.Error)
			}
		} else if msg != "" {
			rec.Notes = append(rec.Notes, msg)
		}
	}

	if opt.Promote {
		if _, err := m.Backup(); err != nil {
			rec.Notes = append(rec.Notes, "backup warn: "+err.Error())
		}
		if err := m.PromoteStaging(); err != nil {
			rec.Error = "promote/reload 失败: " + err.Error()
			m.saveRulesUpgrade(rec)
			return rec, fmt.Errorf(rec.Error)
		}
		rec.Promoted = true
		rec.Notes = append(rec.Notes, "已 promote 并 reload")
	} else {
		rec.Notes = append(rec.Notes, "仅写入 staging，未 promote")
	}

	m.saveRulesUpgrade(rec)
	return rec, nil
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func hasConfFiles(dir string) bool {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			return true
		}
	}
	return false
}

func copyConfTree(src, dst string) (int, error) {
	if !dirExists(src) {
		return 0, nil
	}
	n := 0
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".conf") {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		// 仅允许一层或简单相对路径，禁止 ..
		if strings.Contains(rel, "..") {
			return fmt.Errorf("非法路径: %s", rel)
		}
		target := filepath.Join(dst, filepath.Base(path))
		if err := copyFile(path, target); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}

func extractTarMaybeGzip(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	// sniff gzip
	hdr := make([]byte, 2)
	n, _ := f.Read(hdr)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if n >= 2 && hdr[0] == 0x1f && hdr[1] == 0x8b {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(h.Name)
		if name == "." || name == ".." || strings.HasPrefix(name, "..") || strings.Contains(name, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("拒绝危险路径: %s", h.Name)
		}
		target := filepath.Join(dest, name)
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) && target != filepath.Clean(dest) {
			return fmt.Errorf("路径逃逸: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		default:
			// 跳过 symlink 等
			continue
		}
	}
	return nil
}

func verifyUpdateSig(bundle, sig, pubkey string) error {
	if _, err := os.Stat(pubkey); err != nil {
		return fmt.Errorf("缺少公钥 %s", pubkey)
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		return fmt.Errorf("未找到 openssl，无法验签")
	}
	cmd := exec.Command("openssl", "dgst", "-sha256", "-verify", pubkey, "-signature", sig, bundle)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("签名验证失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) validateStagingExternal() (string, error) {
	root := m.productRoot()
	py := filepath.Join(root, "tools", "rule_manager.py")
	if _, err := os.Stat(py); err != nil {
		return "无 rule_manager.py，跳过校验", nil
	}
	if _, err := exec.LookPath("python3"); err != nil {
		return "无 python3，跳过校验", nil
	}
	cmd := exec.Command("python3", py, "validate", "--dir", m.RulesStaging)
	out, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if err != nil {
		return msg, err
	}
	if msg == "" {
		msg = "validate: OK"
	}
	return msg, nil
}
