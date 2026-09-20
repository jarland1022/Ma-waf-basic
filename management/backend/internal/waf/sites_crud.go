package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

type SiteSpec struct {
	Name              string `json:"name"`
	ServerName        string `json:"server_name"`
	Listen            string `json:"listen"`
	Upstream          string `json:"upstream"`
	EnableWAF         bool   `json:"enable_waf"`
	SSL               bool   `json:"ssl"`
	CertFile          string `json:"cert_file,omitempty"`
	KeyFile           string `json:"key_file,omitempty"`
	EnableCSP         bool   `json:"enable_csp"`
	EnableGeo         bool   `json:"enable_geo"` // 需已配置 $geo_block
	EnableJSChallenge bool   `json:"enable_js_challenge"`
	// EnableChallengeAuth: auth_request 校验 HMAC Cookie（需 http_auth_request_module）
	EnableChallengeAuth bool `json:"enable_challenge_auth"`
	// EnableAPIProtect: 为 API 前缀启用更严限流/方法限制
	EnableAPIProtect bool   `json:"enable_api_protect"`
	APIPrefix        string `json:"api_prefix,omitempty"` // 默认 /api/
	BurstPerIP       int    `json:"burst_per_ip"`
	BurstPerServer   int    `json:"burst_per_server"`
	ConnLimit        int    `json:"conn_limit"`
	// ProfileID / ProfileName：最近一次套用的策略画像（写入 conf 注释，供列表展示）
	ProfileID   string `json:"profile_id,omitempty"`
	ProfileName string `json:"profile_name,omitempty"`
}

var safeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func (m *Manager) confDDir() string {
	return filepath.Clean(filepath.Join(filepath.Dir(m.ModSecConf), "..", "conf.d"))
}

func (m *Manager) UpsertSite(spec SiteSpec) error {
	name := strings.TrimSpace(spec.Name)
	if !safeNameRe.MatchString(name) {
		return fmt.Errorf("站点名称仅允许字母数字_-，且不能为空")
	}
	if strings.EqualFold(name, "app") {
		return fmt.Errorf("名称 app 为系统保留，请换一个")
	}
	// 普通保存未带画像字段时，保留 conf 里已有的 profile 注释
	if strings.TrimSpace(spec.ProfileID) == "" {
		if old, err := m.GetManagedSite(name); err == nil && old != nil {
			spec.ProfileID = old.ProfileID
			spec.ProfileName = old.ProfileName
		}
	}
	listen := strings.TrimSpace(spec.Listen)
	if listen == "" {
		listen = "80"
	}
	serverName := strings.TrimSpace(spec.ServerName)
	if serverName == "" {
		serverName = "_"
	}
	up := strings.TrimSpace(spec.Upstream)
	if up == "" {
		return fmt.Errorf("upstream 不能为空，例如 127.0.0.1:8080")
	}
	if !strings.HasPrefix(up, "http://") && !strings.HasPrefix(up, "https://") {
		up = "http://" + up
	}
	proxySSL := proxySSLDirectives(up)

	burstIP := spec.BurstPerIP
	if burstIP <= 0 {
		burstIP = 40
	}
	burstSrv := spec.BurstPerServer
	if burstSrv <= 0 {
		burstSrv = 400
	}
	connLim := spec.ConnLimit
	if connLim <= 0 {
		connLim = 50
	}

	modsec := "off"
	rules := ""
	if spec.EnableWAF {
		modsec = "on"
		rules = "\n        modsecurity_rules_file /usr/local/nginx/conf/modsecurity/main.conf;"
	}

	sslBlock := ""
	if spec.SSL {
		if spec.CertFile == "" || spec.KeyFile == "" {
			return fmt.Errorf("启用 SSL 时必须提供 cert_file 与 key_file")
		}
		sslBlock = fmt.Sprintf(`
    ssl_certificate     %s;
    ssl_certificate_key %s;
    ssl_protocols       TLSv1.2 TLSv1.3;`, spec.CertFile, spec.KeyFile)
		if !strings.Contains(listen, "ssl") {
			listen = listen + " ssl"
		}
	}

	csp := ""
	if spec.EnableCSP {
		csp = "\n        include snippets/csp_headers.conf;"
	}
	geo := ""
	if spec.EnableGeo {
		geo = "\n        if ($geo_block) { return 403; }"
	}
	jsChal := ""
	authReq := ""
	effectiveChallengeAuth := false
	effectiveJS := spec.EnableJSChallenge
	var capabilityNotes []string
	if spec.EnableChallengeAuth {
		if m.HasAuthRequestModule() {
			// 硬校验：软 Bot 无有效 HMAC Cookie → 401 → 挑战页
			authReq = `
        auth_request /waf-challenge/verify;
        error_page 401 =302 /waf-challenge.html?r=$request_uri;`
			effectiveChallengeAuth = true
		} else {
			// 无 http_auth_request_module 时自动降级，避免 nginx -t 失败
			jsChal = "\n        if ($need_js_challenge) { return 302 /waf-challenge.html?r=$request_uri; }"
			effectiveJS = true
			capabilityNotes = append(capabilityNotes,
				"当前 Nginx 未编译 http_auth_request_module，HMAC 硬校验已自动降级为 JS 软挑战")
		}
	} else if spec.EnableJSChallenge {
		jsChal = "\n        if ($need_js_challenge) { return 302 /waf-challenge.html?r=$request_uri; }"
		effectiveJS = true
	}
	m.lastSiteUpsertWarning = strings.Join(capabilityNotes, "; ")


	apiLoc := ""
	if spec.EnableAPIProtect {
		prefix := strings.TrimSpace(spec.APIPrefix)
		if prefix == "" {
			prefix = "/api/"
		}
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		if !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		apiLoc = fmt.Sprintf(`
    location ^~ %s {
        if ($waf_blacklist) { return 403; }
        if ($block_bad_bot) { return 403; }
%s%s
        include snippets/api_protect.conf;
        modsecurity %s;%s
%s
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Request-ID $request_id;%s
        proxy_pass %s;
        error_page 403 /waf-block.html;
        error_page 429 /waf-ratelimit.html;
    }
`, prefix, geo, authReq, modsec, rules, csp, proxySSL, up)
	}

	profileLine := ""
	if strings.TrimSpace(spec.ProfileID) != "" {
		pname := strings.TrimSpace(spec.ProfileName)
		if pname == "" {
			pname = spec.ProfileID
		}
		// 注释内避免换行与异常字符
		pname = strings.Map(func(r rune) rune {
			if r < 32 || r == '#' {
				return -1
			}
			return r
		}, pname)
		profileLine = fmt.Sprintf("\n# profile_id=%s profile_name=%s", strings.TrimSpace(spec.ProfileID), pname)
	}

	body := fmt.Sprintf(`# managed-by: ma-waf-api
# site: %s%s
# enable_csp=%t enable_geo=%t enable_js_challenge=%t enable_challenge_auth=%t enable_api=%t burst_ip=%d burst_srv=%d conn=%d
server {
    listen %s;
    server_name %s;
%s
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 10s;

    location = /waf-health {
        access_log off;
        default_type application/json;
        return 200 '{"status":"ok","site":"%s"}';
    }

    # 静态资源跳过 ModSecurity
    location ~* \.(css|js|jpg|jpeg|png|gif|ico|svg|woff2?|ttf|map)$ {
        modsecurity off;
        expires 7d;
        access_log off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;%s
        proxy_pass %s;
    }
%s
    location / {
        if ($waf_blacklist) { return 403; }
%s%s%s
        if ($block_bad_bot) { return 403; }

        limit_req  zone=perip burst=%d nodelay;
        limit_req  zone=perserver burst=%d;
        limit_conn addr %d;

        modsecurity %s;%s
%s
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Request-ID $request_id;
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_next_upstream error timeout http_502 http_503 http_504;%s
        proxy_pass %s;

        error_page 403 /waf-block.html;
        error_page 429 /waf-ratelimit.html;
        error_page 502 503 504 /waf-upstream.html;
    }

    location = /waf-challenge.html {
        modsecurity off;
        root /usr/local/nginx/html/error_pages;
        default_type text/html;
        charset utf-8;
        add_header Cache-Control "no-store" always;
        add_header X-Request-ID $request_id always;
    }
    include snippets/js_challenge_api.conf;
    location = /waf-block.html {
        internal;
        root /usr/local/nginx/html/error_pages;
        default_type text/html;
        add_header X-Request-ID $request_id always;
    }
    location = /waf-ratelimit.html {
        internal;
        root /usr/local/nginx/html/error_pages;
        add_header X-Request-ID $request_id always;
    }
    location = /waf-upstream.html {
        internal;
        root /usr/local/nginx/html/error_pages;
        add_header X-Request-ID $request_id always;
    }
}
`, name, profileLine, spec.EnableCSP, spec.EnableGeo, effectiveJS, effectiveChallengeAuth, spec.EnableAPIProtect, burstIP, burstSrv, connLim,
		listen, serverName, sslBlock, name, proxySSL, up, apiLoc, geo, jsChal, authReq, burstIP, burstSrv, connLim, modsec, rules, csp, proxySSL, up)

	dir := m.confDDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "site-"+name+".conf")
	if _, err := m.Backup(); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Manager) DeleteSite(name string) error {
	name = strings.TrimSpace(name)
	if !safeNameRe.MatchString(name) {
		return fmt.Errorf("非法站点名")
	}
	path := filepath.Join(m.confDDir(), "site-"+name+".conf")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("站点不存在: %s", name)
	}
	if _, err := m.Backup(); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return m.Reload()
}

// GetManagedSite 读取可管理站点配置，供控制台编辑回填。
func (m *Manager) GetManagedSite(name string) (*SiteSpec, error) {
	name = strings.TrimSpace(name)
	if !safeNameRe.MatchString(name) {
		return nil, fmt.Errorf("非法站点名")
	}
	path := filepath.Join(m.confDDir(), "site-"+name+".conf")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("站点不存在: %s", name)
	}
	text := string(b)
	spec := &SiteSpec{
		Name:                name,
		EnableWAF:           strings.Contains(text, "modsecurity on"),
		EnableCSP:           strings.Contains(text, "csp_headers.conf"),
		EnableGeo:           strings.Contains(text, "$geo_block"),
		EnableJSChallenge:   strings.Contains(text, "$need_js_challenge") || strings.Contains(text, "auth_request /waf-challenge/verify"),
		EnableChallengeAuth: strings.Contains(text, "auth_request /waf-challenge/verify"),
		EnableAPIProtect:    strings.Contains(text, "api_protect.conf"),
		APIPrefix:           "/api/",
		SSL:                 strings.Contains(text, "ssl_certificate"),
		BurstPerIP:          40,
		BurstPerServer:      400,
		ConnLimit:           50,
	}
	if m := regexp.MustCompile(`(?i)location\s+\^~\s+(\S+)\s*\{`).FindStringSubmatch(text); m != nil && strings.Contains(text, "api_protect.conf") {
		spec.APIPrefix = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`(?i)server_name\s+([^;]+);`).FindStringSubmatch(text); m != nil {
		spec.ServerName = strings.Join(strings.Fields(m[1]), " ")
	}
	if m := regexp.MustCompile(`(?i)^\s*listen\s+([^;]+);`).FindStringSubmatch(text); m != nil {
		spec.Listen = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`(?i)proxy_pass\s+([^;]+);`).FindStringSubmatch(text); m != nil {
		spec.Upstream = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`(?i)ssl_certificate\s+([^;]+);`).FindStringSubmatch(text); m != nil {
		spec.CertFile = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`(?i)ssl_certificate_key\s+([^;]+);`).FindStringSubmatch(text); m != nil {
		spec.KeyFile = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`(?i)zone=perip\s+burst=(\d+)`).FindStringSubmatch(text); m != nil {
		fmt.Sscanf(m[1], "%d", &spec.BurstPerIP)
	}
	if m := regexp.MustCompile(`(?i)zone=perserver\s+burst=(\d+)`).FindStringSubmatch(text); m != nil {
		fmt.Sscanf(m[1], "%d", &spec.BurstPerServer)
	}
	if m := regexp.MustCompile(`(?i)limit_conn\s+addr\s+(\d+)`).FindStringSubmatch(text); m != nil {
		fmt.Sscanf(m[1], "%d", &spec.ConnLimit)
	}
	if m := regexp.MustCompile(`(?m)^#\s*profile_id=([^\s#]+)\s+profile_name=(.+)$`).FindStringSubmatch(text); m != nil {
		spec.ProfileID = strings.TrimSpace(m[1])
		spec.ProfileName = strings.TrimSpace(m[2])
	}
	return spec, nil
}

func proxySSLDirectives(upstream string) string {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(upstream)), "https://") {
		return ""
	}
	return `
        proxy_ssl_server_name on;
        proxy_ssl_name $host;
        proxy_ssl_verify off;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;`
}

func SanitizeSiteName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
