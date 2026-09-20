package license

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 对齐 allinone sec-platform license_manager / license_daemon

type Payload struct {
	ClientName  string `json:"client_name"`
	IssueDate   string `json:"issue_date"`
	ExpiryDate  string `json:"expiry_date"`
	Fingerprint string `json:"fingerprint"`
	Product     string `json:"product,omitempty"`
}

type Status struct {
	Activated            bool    `json:"activated"`
	Status               string  `json:"status"` // active|grace_period|grace_expired|no_license|invalid
	ClientName           string  `json:"client_name,omitempty"`
	IssueDate            string  `json:"issue_date,omitempty"`
	ExpiryDate           string  `json:"expiry_date,omitempty"`
	DaysRemaining        int     `json:"days_remaining,omitempty"`
	ParseError           string  `json:"parse_error,omitempty"`
	GraceRemainingHours  float64 `json:"grace_remaining_hours,omitempty"`
	GraceElapsedHours    float64 `json:"grace_elapsed_hours,omitempty"`
	GraceExpired         bool    `json:"grace_expired,omitempty"`
	Product              string  `json:"product,omitempty"`
	Hint                 string  `json:"hint,omitempty"`
}

type Manager struct {
	LicenseFile   string
	PublicKeyFile string
	GraceFile     string
	GraceExpired  string
	GraceHours    float64
}

func DefaultManager(productRoot string) *Manager {
	conf := filepath.Join(productRoot, "conf", "license")
	return &Manager{
		LicenseFile:   filepath.Join(conf, "license.lic"),
		PublicKeyFile: filepath.Join(conf, "ma-waf-public.pem"),
		GraceFile:     filepath.Join(conf, ".grace_start"),
		GraceExpired:  filepath.Join(conf, ".grace_expired"),
		GraceHours:    72,
	}
}

func (m *Manager) HardwareFingerprint() (hash string, source string, err error) {
	candidates := []struct {
		path   string
		source string
	}{
		{"/sys/class/dmi/id/product_uuid", "dmi_product_uuid"},
		{"/etc/machine-id", "machine-id"},
	}
	for _, c := range candidates {
		b, e := os.ReadFile(c.path)
		if e != nil {
			continue
		}
		raw := strings.TrimSpace(string(b))
		if raw == "" || strings.EqualFold(raw, "not settable") {
			continue
		}
		sum := sha256.Sum256([]byte(raw))
		return fmt.Sprintf("%x", sum[:]), c.source, nil
	}
	// 开发/Windows 回退：主机名
	host, _ := os.Hostname()
	if host == "" {
		return "", "", errors.New("无法采集硬件指纹")
	}
	sum := sha256.Sum256([]byte("ma-waf-dev:" + host))
	return fmt.Sprintf("%x", sum[:]), "hostname", nil
}

func (m *Manager) FingerprintDetail() (map[string]string, error) {
	h, src, err := m.HardwareFingerprint()
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"fingerprint": h,
		"source":      src,
		"hint":        "将 fingerprint 提供给授权方，使用 tools/license_gen.py 签发 license.lic",
	}, nil
}

func (m *Manager) loadPublicKey() (*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(m.PublicKeyFile)
	if err != nil {
		return nil, fmt.Errorf("公钥不存在: %s", m.PublicKeyFile)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("公钥 PEM 解析失败")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return nil, errors.New("需要 ECDSA P-256 公钥")
	}
	return ecPub, nil
}

func (m *Manager) ParseAndVerify(path string) (*Payload, error) {
	if path == "" {
		path = m.LicenseFile
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("License 文件不存在: %w", err)
	}
	combined, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}
	dot := strings.LastIndex(string(combined), ".")
	if dot < 0 {
		return nil, errors.New("License 结构错误：缺少签名分隔符")
	}
	payloadBytes := combined[:dot]
	sigB64 := combined[dot+1:]
	sig, err := base64.StdEncoding.DecodeString(string(sigB64))
	if err != nil {
		return nil, fmt.Errorf("签名解码失败: %w", err)
	}
	pub, err := m.loadPublicKey()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(payloadBytes)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return nil, errors.New("签名验证失败，文件可能被篡改")
	}
	var p Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("载荷 JSON 解析失败: %w", err)
	}
	for _, f := range []string{p.ClientName, p.IssueDate, p.ExpiryDate, p.Fingerprint} {
		if strings.TrimSpace(f) == "" {
			return nil, errors.New("License 缺少必要字段")
		}
	}
	return &p, nil
}

func (m *Manager) VerifyFull(path string) (*Payload, int, error) {
	p, err := m.ParseAndVerify(path)
	if err != nil {
		return nil, 0, err
	}
	expiry, err := time.ParseInLocation("2006-01-02", p.ExpiryDate, time.Local)
	if err != nil {
		return nil, 0, fmt.Errorf("有效期格式错误: %s", p.ExpiryDate)
	}
	today := time.Now()
	if today.After(expiry.Add(24*time.Hour - time.Second)) {
		return nil, 0, fmt.Errorf("License 已过期（%s）", p.ExpiryDate)
	}
	fp, _, err := m.HardwareFingerprint()
	if err != nil {
		return nil, 0, err
	}
	if !secureEqual(fp, strings.ToLower(p.Fingerprint)) {
		return nil, 0, errors.New("硬件指纹不匹配")
	}
	days := int(expiry.Sub(time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location())).Hours() / 24)
	return p, days, nil
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func (m *Manager) Status() Status {
	info := Status{Activated: false, Status: "inactive", Product: "Ma-WAF"}
	if _, err := os.Stat(m.GraceExpired); err == nil {
		info.Status = "grace_expired"
		info.GraceExpired = true
		info.Hint = "宽限期已结束，请导入有效 license.lic"
		return info
	}
	if _, err := os.Stat(m.LicenseFile); err == nil {
		p, days, err := m.VerifyFull(m.LicenseFile)
		if err == nil {
			info.Activated = true
			info.Status = "active"
			info.ClientName = p.ClientName
			info.IssueDate = p.IssueDate
			info.ExpiryDate = p.ExpiryDate
			info.DaysRemaining = days
			info.Product = p.Product
			if info.Product == "" {
				info.Product = "Ma-WAF"
			}
			_ = os.Remove(m.GraceFile)
			return info
		}
		info.ParseError = err.Error()
		if p2, e2 := m.ParseAndVerify(m.LicenseFile); e2 == nil {
			info.ClientName = p2.ClientName
			info.IssueDate = p2.IssueDate
			info.ExpiryDate = p2.ExpiryDate
		}
	}
	// 宽限期
	if b, err := os.ReadFile(m.GraceFile); err == nil {
		start, e := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(string(b)), time.Local)
		if e != nil {
			start, e = time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
		}
		if e == nil {
			elapsed := time.Since(start).Hours()
			remain := m.GraceHours - elapsed
			info.GraceElapsedHours = float64(int(elapsed*10)) / 10
			if remain > 0 {
				info.Status = "grace_period"
				info.GraceRemainingHours = float64(int(remain*10)) / 10
				info.Hint = "未激活 License，处于试用宽限期"
				return info
			}
			_ = os.WriteFile(m.GraceExpired, []byte(time.Now().Format("2006-01-02 15:04:05")), 0o640)
			info.Status = "grace_expired"
			info.GraceExpired = true
			info.GraceRemainingHours = 0
			return info
		}
	}
	// 首次启动写入宽限期
	_ = os.MkdirAll(filepath.Dir(m.GraceFile), 0o750)
	if _, err := os.Stat(m.GraceFile); err != nil {
		_ = os.WriteFile(m.GraceFile, []byte(time.Now().Format("2006-01-02 15:04:05")), 0o640)
		info.Status = "grace_period"
		info.GraceRemainingHours = m.GraceHours
		info.Hint = "已进入试用宽限期，请尽快导入 License"
		return info
	}
	info.Status = "no_license"
	info.Hint = "请在控制台导入 license.lic，或使用 tools/license_gen.py 签发"
	return info
}

func (m *Manager) AllowOperation() bool {
	s := m.Status()
	return s.Status == "active" || s.Status == "grace_period"
}

func (m *Manager) ImportFile(src string) error {
	_ = os.MkdirAll(filepath.Dir(m.LicenseFile), 0o750)
	if _, err := os.Stat(m.LicenseFile); err == nil {
		_ = os.Rename(m.LicenseFile, m.LicenseFile+".bak")
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.LicenseFile, b, 0o640); err != nil {
		return err
	}
	_, _, err = m.VerifyFull(m.LicenseFile)
	if err != nil {
		return fmt.Errorf("导入成功但验证失败: %w", err)
	}
	_ = os.Remove(m.GraceFile)
	_ = os.Remove(m.GraceExpired)
	return nil
}
