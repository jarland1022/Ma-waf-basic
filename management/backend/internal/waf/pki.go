package waf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (m *Manager) tlsDir() string {
	return filepath.Join(filepath.Dir(m.BackupDir), "conf", "tls")
}

type TLSCertInfo struct {
	Name       string `json:"name"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	Exists     bool   `json:"exists"`
	NotAfter   string `json:"not_after,omitempty"`
	Subject    string `json:"subject,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
}

// ListTLSCerts 列出管理面证书目录。
func (m *Manager) ListTLSCerts() ([]TLSCertInfo, error) {
	dir := m.tlsDir()
	_ = os.MkdirAll(dir, 0o755)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []TLSCertInfo
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".crt"), ".pem")
		if seen[base] {
			continue
		}
		seen[base] = true
		info := TLSCertInfo{
			Name:     base,
			CertPath: filepath.Join(dir, name),
			KeyPath:  filepath.Join(dir, base+".key"),
			Exists:   true,
		}
		if b, err := os.ReadFile(info.CertPath); err == nil {
			if block, _ := pem.Decode(b); block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					info.NotAfter = cert.NotAfter.Format(time.RFC3339)
					info.Subject = cert.Subject.CommonName
					info.SelfSigned = cert.Subject.String() == cert.Issuer.String()
				}
			}
		}
		out = append(out, info)
	}
	// 确保 admin 条目可见（即使尚未生成）
	if !seen["admin"] {
		out = append([]TLSCertInfo{{
			Name: "admin", CertPath: filepath.Join(dir, "admin.crt"),
			KeyPath: filepath.Join(dir, "admin.key"), Exists: false,
		}}, out...)
	}
	return out, nil
}

// EnsureAdminTLSPresent 若管理面证书缺失则自动生成（不覆盖已有证书）。
func (m *Manager) EnsureAdminTLSPresent() error {
	dir := m.tlsDir()
	certPath := filepath.Join(dir, "admin.crt")
	keyPath := filepath.Join(dir, "admin.key")
	_, errC := os.Stat(certPath)
	_, errK := os.Stat(keyPath)
	if errC == nil && errK == nil {
		return nil
	}
	_, err := m.EnsureAdminTLS("waf-admin.local", 3650)
	return err
}

// EnsureAdminTLS 生成管理面自签证书（解决 nginx admin.crt 缺失）。
func (m *Manager) EnsureAdminTLS(cn string, days int) (TLSCertInfo, error) {
	if cn == "" {
		cn = "waf-admin.local"
	}
	if days <= 0 {
		days = 3650
	}
	dir := m.tlsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return TLSCertInfo{}, err
	}
	certPath := filepath.Join(dir, "admin.crt")
	keyPath := filepath.Join(dir, "admin.key")

	// 优先 openssl（Rocky 常见）
	if _, err := exec.LookPath("openssl"); err == nil {
		cmd := exec.Command("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
			"-days", fmt.Sprintf("%d", days),
			"-keyout", keyPath, "-out", certPath,
			"-subj", "/CN="+cn+"/O=Ma-WAF/C=CN")
		if out, err := cmd.CombinedOutput(); err != nil {
			return TLSCertInfo{}, fmt.Errorf("openssl: %s: %w", string(out), err)
		}
		_ = os.Chmod(keyPath, 0o600)
		_ = os.Chmod(certPath, 0o644)
		return TLSCertInfo{Name: "admin", CertPath: certPath, KeyPath: keyPath, Exists: true, Subject: cn}, nil
	}

	// 回退：纯 Go 自签
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return TLSCertInfo{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Ma-WAF"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return TLSCertInfo{}, err
	}
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return TLSCertInfo{}, err
	}
	_ = pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = cf.Close()
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, and0600())
	if err != nil {
		return TLSCertInfo{}, err
	}
	_ = pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_ = kf.Close()
	return TLSCertInfo{Name: "admin", CertPath: certPath, KeyPath: keyPath, Exists: true, Subject: cn, SelfSigned: true}, nil
}

func and0600() os.FileMode { return 0o600 }
