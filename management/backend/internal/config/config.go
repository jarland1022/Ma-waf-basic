package config

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen         string   `yaml:"listen"`
	JWTSecret      string   `yaml:"jwt_secret"`
	AdminUser      string   `yaml:"admin_user"`
	AdminPassHash  string   `yaml:"admin_pass_hash"` // bcrypt
	TOTPSecret     string   `yaml:"totp_secret"`     // 空则仅密码
	NginxBin       string   `yaml:"nginx_bin"`
	ModSecConf     string   `yaml:"modsec_conf"`
	RulesActive    string   `yaml:"rules_active"`
	RulesStaging   string   `yaml:"rules_staging"`
	AuditLog       string   `yaml:"audit_log"`
	AccessLog      string   `yaml:"access_log"`
	BackupDir      string   `yaml:"backup_dir"`
	AllowCIDRs     []string `yaml:"allow_cidrs"`
	MaxLoginFail   int      `yaml:"max_login_fail"`
	LockoutSeconds int      `yaml:"lockout_seconds"`
	SQLitePath     string   `yaml:"sqlite_path"`
	ChainAuditPath string   `yaml:"chain_audit_path"`
	// AgeIdentityFile: 若配置路径以 .age 结尾，用 age -d -i 解密后再解析 YAML
	AgeIdentityFile string `yaml:"age_identity_file"`
	// ConsoleDir: Web 管理界面静态目录
	ConsoleDir string `yaml:"console_dir"`
	// ProductRoot: 产品根目录（License、var 等）
	ProductRoot string `yaml:"product_root"`
	// LicensePublicKey / LicenseFile: 可覆盖默认 conf/license 路径
	LicensePublicKey string `yaml:"license_public_key"`
	LicenseFile      string `yaml:"license_file"`
	// NginxStatusURL: stub_status 地址（主机连接指标）
	NginxStatusURL string `yaml:"nginx_status_url"`
	// AlertWebhook: 可选 HTTP POST 告警
	AlertWebhook string `yaml:"alert_webhook"`
}

const DefaultJWTWeak = "change-me-in-production"

func Defaults() Config {
	root := envOr("MA_WAF_ROOT", "/usr/local/Ma-waf")
	return Config{
		Listen:         "127.0.0.1:9090",
		JWTSecret:      envOr("MA_WAF_JWT_SECRET", DefaultJWTWeak),
		AdminUser:      envOr("MA_WAF_ADMIN_USER", "admin"),
		AdminPassHash:  "", // 生产须用 bcrypt；STRICT_AUTH 下为空则拒绝启动
		NginxBin:       "/usr/local/nginx/sbin/nginx",
		ModSecConf:     "/usr/local/nginx/conf/modsecurity/modsecurity.conf",
		RulesActive:    root + "/rules/active",
		RulesStaging:   root + "/rules/staging",
		AuditLog:       "/data/logs/nginx/modsec_audit.json",
		AccessLog:      "/data/logs/nginx/access.json",
		BackupDir:      root + "/backups",
		AllowCIDRs: []string{
			"127.0.0.1/32",
			"::1/128",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		MaxLoginFail:     5,
		LockoutSeconds:   300,
		SQLitePath:       root + "/var/lib/ma-waf.db",
		ChainAuditPath:   root + "/var/lib/audit-chain.jsonl",
		ConsoleDir:       envOr("MA_WAF_CONSOLE_DIR", root+"/share/console"),
		ProductRoot:      root,
		NginxStatusURL:   "http://127.0.0.1:8081/nginx_status",
		LicensePublicKey: root + "/conf/license/ma-waf-public.pem",
		LicenseFile:      root + "/conf/license/license.lic",
	}
}

// ValidateStrict 生产认证门禁：MA_WAF_STRICT_AUTH=1 时强制强密钥与 bcrypt
func (c Config) ValidateStrict() error {
	if os.Getenv("MA_WAF_STRICT_AUTH") != "1" {
		return nil
	}
	if strings.TrimSpace(c.AdminPassHash) == "" {
		return fmt.Errorf("STRICT_AUTH: admin_pass_hash 不能为空，请用 tools/gen_admin_hash.py 生成")
	}
	sec := strings.TrimSpace(c.JWTSecret)
	if sec == "" || sec == DefaultJWTWeak || strings.HasPrefix(sec, "CHANGE_ME_") || strings.HasPrefix(sec, "REPLACE_WITH_") {
		return fmt.Errorf("STRICT_AUTH: jwt_secret 必须为强随机值，禁止默认/占位密钥")
	}
	if len(sec) < 24 {
		return fmt.Errorf("STRICT_AUTH: jwt_secret 长度至少 24")
	}
	return nil
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	b, err := readConfigBytes(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func readConfigBytes(path string) ([]byte, error) {
	if strings.HasSuffix(path, ".age") || strings.HasSuffix(path, ".enc") {
		identity := envOr("MA_WAF_AGE_IDENTITY", "/usr/local/Ma-waf/conf/age-identity.txt")
		cmd := exec.Command("age", "-d", "-i", identity, path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("age decrypt %s: %w (%s)", path, err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}
	// sops 加密 YAML：以 sops: 标记或环境变量强制
	if os.Getenv("MA_WAF_USE_SOPS") == "1" {
		cmd := exec.Command("sops", "-d", path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("sops decrypt %s: %w (%s)", path, err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	}
	return os.ReadFile(path)
}

func envOr(k, def string) string {
        if v := os.Getenv(k); v != "" {
                return v
        }
        return def
}
