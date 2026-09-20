package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ma-waf/management/internal/audit"
	"github.com/ma-waf/management/internal/auth"
	"github.com/ma-waf/management/internal/challenge"
	"github.com/ma-waf/management/internal/config"
	"github.com/ma-waf/management/internal/license"
	"github.com/ma-waf/management/internal/metrics"
	"github.com/ma-waf/management/internal/store"
	"github.com/ma-waf/management/internal/waf"
)

type Server struct {
	cfg     config.Config
	auth    *auth.Service
	waf     *waf.Manager
	metrics *metrics.Registry
	chain   *audit.Chain
	lic     *license.Manager
	index   *store.AuditIndex
	stopIdx chan struct{}
}

func NewRouter(cfg config.Config) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	root := cfg.ProductRoot
	if root == "" {
		root = "/usr/local/Ma-waf"
	}
	lic := license.DefaultManager(root)
	if cfg.LicensePublicKey != "" {
		lic.PublicKeyFile = cfg.LicensePublicKey
	}
	if cfg.LicenseFile != "" {
		lic.LicenseFile = cfg.LicenseFile
	}
	s := &Server{
		cfg: cfg,
		auth: auth.New(cfg.JWTSecret, cfg.AdminUser, cfg.AdminPassHash, cfg.TOTPSecret,
			cfg.MaxLoginFail, cfg.LockoutSeconds),
		waf: &waf.Manager{
			NginxBin:     cfg.NginxBin,
			ModSecConf:   cfg.ModSecConf,
			RulesActive:  cfg.RulesActive,
			RulesStaging: cfg.RulesStaging,
			BackupDir:    cfg.BackupDir,
		},
		metrics: metrics.New(),
		chain:   audit.NewChain(cfg.ChainAuditPath),
		lic:     lic,
		stopIdx: make(chan struct{}),
	}
	s.waf.EnsureGoodBotsFile()
	if err := s.waf.EnsureAdminTLSPresent(); err != nil {
		// 不阻断启动：API 仍可提供 PKI 生成；但会打日志提醒
		fmt.Fprintf(os.Stderr, "ma-waf-api: warn ensure admin TLS: %v\n", err)
	} else {
		// 静默成功时无需刷屏；仅在首次生成可感知时可忽略
	}
	if cfg.SQLitePath != "" {
		if idx, err := store.NewAuditIndex(cfg.SQLitePath, cfg.AuditLog); err == nil {
			s.index = idx
			s.index.StartLoop(30*time.Second, s.stopIdx)
		}
	}
	r := gin.New()
	r.MaxMultipartMemory = 64 << 20 // 64 MiB 规则包上传
	// Nginx 反代在 127.0.0.1，信任后 ClientIP 取 X-Real-IP / X-Forwarded-For
	_ = r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	r.Use(gin.Recovery(), s.accessLogMiddleware(), s.clientAllowlist())

	r.GET("/healthz", s.health)
	r.GET("/api/v1/health", s.health)
	// Prometheus 文本指标：仅管理网 CIDR 可访问（与 API allowlist 相同），无需 JWT 便于抓取
	r.GET("/metrics", s.promMetrics)
	r.GET("/api/v1/metrics/prometheus", s.promMetrics)
	// L7 JS Challenge：由 Nginx 反代（数据面），无需 JWT
	r.POST("/challenge/issue", s.challengeIssue)
	r.GET("/challenge/verify", s.challengeVerify)
	r.POST("/challenge/verify", s.challengeVerify)
	// 本机定时任务（loopback + cron_token），无需 JWT
	r.POST("/api/v1/cron/autoblock", s.cronAutoblock)
	r.POST("/api/v1/cron/intel-expire", s.cronIntelExpire)

	v1 := r.Group("/api/v1")
	{
		v1.POST("/auth/login", s.login)
		authz := v1.Group("/")
		authz.Use(s.jwtAuth())
		{
			authz.GET("/status", s.status)
			authz.GET("/dashboard", s.dashboard)
			authz.GET("/metrics", s.getMetrics)
			authz.GET("/mode", s.getMode)
			authz.GET("/rules", s.listRules)
			authz.GET("/attacks", s.listAttacks)
			authz.GET("/attacks/detail", s.attackDetail)
			authz.GET("/attacks/summary", s.attackSummary)
			authz.GET("/attacks/trend", s.attackTrend)
			authz.GET("/reports/export", s.exportReport)
			authz.GET("/sites", s.listSites)
			authz.GET("/sites/discover", s.discoverSites)
			authz.GET("/sites/:name", s.getSite)
			authz.GET("/iplist/:kind", s.getIPList)
			authz.GET("/geo/blocklist", s.getGeoBlock)
			authz.GET("/virtpatches", s.listVirtPatches)
			authz.GET("/exceptions", s.listExceptions)
			authz.GET("/license/status", s.licenseStatus)
			authz.GET("/license/fingerprint", s.licenseFingerprint)
			authz.GET("/backups", s.listBackups)
			authz.GET("/packs", s.listPacks)
			authz.GET("/audit/chain", s.auditChain)
			authz.GET("/ops", s.getOps)
			authz.GET("/openapi/status", s.openAPIStatus)
			authz.GET("/geo/status", s.geoStatus)
			authz.GET("/profiles", s.listProfiles)
			authz.GET("/bots/good", s.getGoodBots)
			authz.GET("/insights", s.attackInsights)
			authz.GET("/insights/fp", s.fpCandidates)
			authz.GET("/ops/golive", s.golive)
			authz.GET("/ops/troubleshoot", s.troubleshoot)
			authz.GET("/crs/paranoia", s.getParanoia)
			authz.GET("/content-policy", s.getContentPolicy)
			authz.GET("/threat-intel/status", s.intelStatus)
			authz.GET("/ha/status", s.haStatus)
			authz.GET("/addrbook", s.listAddrBook)
			authz.GET("/pki/certs", s.listPKICerts)
			authz.GET("/sysinfo", s.sysInfo)
			authz.GET("/rules/upgrade/status", s.rulesUpgradeStatus)
			authz.POST("/rules/validate", s.validateRules)

			// 变更类接口：宽限期结束后拒绝（License 导入除外）
			mutate := authz.Group("/")
			mutate.Use(s.licenseGate())
			{
				mutate.POST("/mode", s.setMode)
				mutate.POST("/reload", s.reload)
				mutate.POST("/rules/promote", s.promoteRules)
				mutate.POST("/rules/:id/enable", s.enableRule)
				mutate.POST("/rules/:id/disable", s.disableRule)
				mutate.POST("/rules/:id/priority", s.setRulePriority)
				mutate.POST("/sites", s.createSite)
				mutate.PUT("/sites/:name", s.updateSite)
				mutate.DELETE("/sites/:name", s.deleteSite)
				mutate.PUT("/iplist/:kind", s.putIPList)
				mutate.POST("/iplist/:kind/add", s.addIPList)
				mutate.PUT("/geo/blocklist", s.putGeoBlock)
				mutate.PUT("/exceptions", s.putExceptions)
				mutate.POST("/backup", s.backup)
				mutate.POST("/rollback", s.rollback)
				mutate.POST("/packs/:id/enable", s.enablePack)
				mutate.POST("/packs/:id/disable", s.disablePack)
				mutate.POST("/virtpatches/expire", s.expireVirtPatches)
				mutate.POST("/threat-intel/merge", s.mergeThreatIntel)
				mutate.POST("/threat-intel/fetch", s.fetchThreatIntel)
				mutate.POST("/openapi/generate", s.generateOpenAPI)
				mutate.PUT("/ops", s.putOps)
				mutate.POST("/ops/test-webhook", s.testWebhook)
				mutate.POST("/autoblock", s.autoBlock)
				mutate.PUT("/profiles", s.putProfiles)
				mutate.POST("/sites/:name/apply-profile", s.applyProfile)
				mutate.PUT("/bots/good", s.putGoodBots)
				mutate.POST("/rules/custom", s.createCustomRule)
				mutate.PUT("/crs/paranoia", s.putParanoia)
				mutate.PUT("/content-policy", s.putContentPolicy)
				mutate.POST("/threat-intel/expire", s.expireIntel)
				mutate.POST("/geo/enforce", s.geoEnforce)
				mutate.POST("/geo/disable-enforce", s.geoDisableEnforce)
				mutate.POST("/ops/siem-test", s.siemTest)
				mutate.POST("/ops/emergency", s.emergency)
				mutate.PUT("/addrbook", s.putAddrBook)
				mutate.POST("/addrbook/:name/apply", s.applyAddrBook)
				mutate.POST("/pki/admin/ensure", s.ensureAdminTLS)
				mutate.POST("/ops/heavy", s.setHeavySecurity)
				mutate.POST("/rules/upgrade/local", s.rulesUpgradeLocal)
			}
			authz.POST("/license/import", s.licenseImport)
		}
	}

	// Web 管理界面（静态文件，由 Nginx :8443 反代到本服务）
	consoleDir := cfg.ConsoleDir
	if consoleDir == "" {
		consoleDir = "/usr/local/Ma-waf/share/console"
	}
	if st, err := os.Stat(consoleDir); err == nil && st.IsDir() {
		assets := consoleDir + "/assets"
		if ast, err2 := os.Stat(assets); err2 == nil && ast.IsDir() {
			r.Static("/assets", assets)
		}
		r.GET("/", func(c *gin.Context) {
			c.File(consoleDir + "/index.html")
		})
		// 用户手册（避免 NoRoute 回退到 SPA index）
		manualPath := consoleDir + "/manual.html"
		if _, err := os.Stat(manualPath); err == nil {
			r.GET("/manual.html", func(c *gin.Context) { c.File(manualPath) })
			r.GET("/manual", func(c *gin.Context) { c.File(manualPath) })
		}
		r.NoRoute(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}
			// SPA / 静态回退
			c.File(consoleDir + "/index.html")
		})
	}

	return r
}

func (s *Server) accessLogMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		s.metrics.Inc()
		start := time.Now()
		c.Next()
		_, _ = s.chain.Append(map[string]interface{}{
			"type":   "api_access",
			"path":   c.Request.URL.Path,
			"method": c.Request.Method,
			"status": c.Writer.Status(),
			"ip":     c.ClientIP(),
			"ms":     time.Since(start).Milliseconds(),
		})
	}
}

func (s *Server) clientAllowlist() gin.HandlerFunc {
	var nets []*net.IPNet
	for _, cidr := range s.cfg.AllowCIDRs {
		if !strings.Contains(cidr, "/") {
			cidr += "/32"
		}
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return func(c *gin.Context) {
		if len(nets) == 0 {
			c.Next()
			return
		}
		ip := net.ParseIP(c.ClientIP())
		if ip == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden", "client_ip": c.ClientIP()})
			return
		}
		for _, n := range nets {
			if n.Contains(ip) {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":     "source ip not allowed",
			"client_ip": c.ClientIP(),
			"hint":      "add your CIDR to conf/api.yaml allow_cidrs and restart ma-waf-api",
		})
	}
}

func (s *Server) jwtAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}
		claims, err := s.auth.ParseToken(strings.TrimPrefix(h, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("user", claims.User)
		c.Next()
	}
}

func (s *Server) licenseGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.lic == nil || s.lic.AllowOperation() {
			c.Next()
			return
		}
		st := s.lic.Status()
		c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
			"error":   "license_required",
			"status":  st.Status,
			"hint":    st.Hint,
			"license": st,
		})
	}
}

func (s *Server) health(c *gin.Context) {
	mode, _ := s.waf.GetEngineMode()
	c.JSON(http.StatusOK, gin.H{
		"status":          "ok",
		"component":       "ma-waf-api",
		"sec_rule_engine": mode,
		"time":            time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) login(c *gin.Context) {
	ip := c.ClientIP()
	if s.auth.Locked(ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "auth_lockout"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if req.Username != s.cfg.AdminUser || !s.auth.CheckPassword(req.Password) || !s.auth.VerifyTOTP(req.TOTP) {
		s.auth.RegisterFail(ip)
		_, _ = s.chain.Append(map[string]interface{}{"type": "login_fail", "ip": ip, "user": req.Username})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	s.auth.RegisterSuccess(ip)
	tok, err := s.auth.IssueToken(req.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token issue failed"})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "login_ok", "ip": ip, "user": req.Username})
	c.JSON(http.StatusOK, gin.H{"token": tok, "expires_in": 28800})
}

func (s *Server) status(c *gin.Context) {
	mode, err := s.waf.GetEngineMode()
	rules, _ := s.waf.ListRuleFiles()
	c.JSON(http.StatusOK, gin.H{
		"engine_mode": mode,
		"engine_err":  errString(err),
		"rule_files":  rules,
		"nginx_caps":  s.waf.NginxCapabilities(),
	})
}

func (s *Server) getMetrics(c *gin.Context) {
	c.JSON(http.StatusOK, s.metrics.Snapshot(s.cfg.AccessLog, s.cfg.NginxStatusURL))
}

func (s *Server) promMetrics(c *gin.Context) {
	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(http.StatusOK, s.metrics.PrometheusText(s.cfg.AccessLog, s.cfg.NginxStatusURL))
}

func (s *Server) dashboard(c *gin.Context) {
	mode, _ := s.waf.GetEngineMode()
	rules, _ := s.waf.ListRuleFiles()
	detail, _ := s.waf.ListRulesDetailed()
	enabled, disabled := 0, 0
	for _, r := range detail {
		if r.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	items := s.recentAttacks(500)
	sum := waf.AttackSummary(items)
	bl, _ := s.waf.ReadIPList("blacklist")
	wl, _ := s.waf.ReadIPList("whitelist")
	m := s.metrics.Snapshot(s.cfg.AccessLog, s.cfg.NginxStatusURL)
	licSt := s.lic.Status()
	exc, _ := s.waf.ListExceptions()
	pl := s.waf.GetParanoiaLevel()
	ha := s.waf.HAStatus()
	fpN := len(waf.SuggestFalsePositives(items, exc, 5))
	goliveReady := mode == "On" && fpN == 0
	c.JSON(http.StatusOK, gin.H{
		"engine_mode":       mode,
		"metrics":           m,
		"attack_summary":    sum,
		"rule_files":        rules,
		"rules_enabled":     enabled,
		"rules_disabled":    disabled,
		"blacklist_count":   len(bl),
		"whitelist_count":   len(wl),
		"license":           licSt,
		"attack_index":      s.index != nil,
		"paranoia_level":    pl,
		"paranoia_hint":     waf.ParanoiaHint(pl),
		"golive_ready":      goliveReady,
		"ha":                ha,
		"features": []string{
			"waf_engine", "owasp_crs", "custom_rules", "virtual_patch",
			"ip_reputation", "bot_mitigation", "good_bot_allow", "rate_limit", "geo_acl",
			"pii_leakage", "upload_guard", "audit_trail", "compliance_report",
			"site_mgmt", "site_discovery", "exception_policy", "license", "host_metrics",
			"openapi_api_security", "policy_profiles", "ato_protection", "attack_insights",
			"fp_suggest", "golive_checklist", "siem_cef", "ha_status", "emergency_bypass",
			"addrbook", "pki_admin_tls", "sysinfo_signature", "heavy_security",
			"rules_upgrade_local", "ops_troubleshoot",
		},
		"insights": waf.AttackInsights(items),
		"fp_count": fpN,
	})
}

func (s *Server) getMode(c *gin.Context) {
	mode, err := s.waf.GetEngineMode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"mode": mode})
}

func (s *Server) setMode(c *gin.Context) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.SetEngineMode(req.Mode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "mode_change", "mode": req.Mode, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"mode": req.Mode})
}

func (s *Server) reload(c *gin.Context) {
	// 先 -t，再异步 -s reload：避免管理面经 Nginx :8443 反代时，
	// reload 瞬间掐断连接导致浏览器 “Failed to fetch”。
	if err := s.waf.TestConfig(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "reload", "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true, "async": true})
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(250 * time.Millisecond)
		if err := s.waf.SignalReload(); err != nil {
			fmt.Fprintf(os.Stderr, "ma-waf-api: async nginx reload: %v\n", err)
		}
	}()
}

func (s *Server) backup(c *gin.Context) {
	ts, err := s.waf.Backup()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "backup", "id": ts, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": ts})
}

func (s *Server) rollback(c *gin.Context) {
	var req struct {
		ID string `json:"id"`
	}
	_ = c.ShouldBindJSON(&req)
	if err := s.waf.Rollback(req.ID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "rollback", "id": req.ID, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": req.ID})
}

func (s *Server) listBackups(c *gin.Context) {
	list, err := s.waf.ListBackups()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"backups": list})
}

func (s *Server) listRules(c *gin.Context) {
	detailed := c.Query("detailed") == "1" || c.Query("detailed") == "true"
	if detailed {
		rules, err := s.waf.ListRulesDetailed()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"rules": rules})
		return
	}
	files, err := s.waf.ListRuleFiles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func (s *Server) promoteRules(c *gin.Context) {
	if err := s.waf.PromoteStaging(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "rules_promote", "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) enableRule(c *gin.Context) {
	id := c.Param("id")
	if err := s.waf.SetRuleEnabled(id, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "rule_enable", "id": id, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": true})
}

func (s *Server) disableRule(c *gin.Context) {
	id := c.Param("id")
	if err := s.waf.SetRuleEnabled(id, false); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "rule_disable", "id": id, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": false})
}

func (s *Server) setRulePriority(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Priority int `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.SetRulePriority(id, req.Priority); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "rule_priority", "id": id, "priority": req.Priority, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"id": id, "priority": req.Priority})
}

func (s *Server) listAttacks(c *gin.Context) {
	limit := 100
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	items := s.recentAttacks(limit)
	src := "tail"
	if s.index != nil {
		src = "jsonl_index"
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "source": src})
}

func (s *Server) attackDetail(c *gin.Context) {
	id := strings.TrimSpace(c.Query("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 id（ModSecurity unique_id / request_id）"})
		return
	}
	ev, raw, ok := waf.FindAttackByID(s.cfg.AuditLog, id, 3000)
	if !ok {
		// 回退：从最近列表匹配
		for _, it := range s.recentAttacks(500) {
			if it.RequestID == id {
				c.JSON(http.StatusOK, gin.H{"ok": true, "event": it, "source": "index"})
				return
			}
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到该事件（可能已轮转）", "id": id})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "event": ev, "raw": raw, "source": "audit_log"})
}

func (s *Server) attackSummary(c *gin.Context) {
	items := s.recentAttacks(500)
	sum := waf.AttackSummary(items)
	c.JSON(http.StatusOK, sum)
}

func (s *Server) attackTrend(c *gin.Context) {
	hours := 24
	if v := c.Query("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}
	items := s.recentAttacks(2000)
	c.JSON(http.StatusOK, gin.H{"hours": hours, "trend": waf.AttackTrend(items, hours)})
}

// complianceFramework 描述单框架专属报告内容（运营映射参考，非认证结论）。
type complianceFramework struct {
	ID       string
	Title    string
	Short    string
	Standard string
	Controls []string // 控制点 / 条款
	WAFMaps  []string // WAF 能力如何支撑
	Evidence []string // 本报告引用的证据类型
}

func complianceFrameworks() map[string]complianceFramework {
	return map[string]complianceFramework{
		"dsl2": {
			ID: "dsl2", Title: "等保 2.0 合规运营报告", Short: "等保 2.0",
			Standard: "网络安全等级保护基本要求（第二级及以上常见条款映射）",
			Controls: []string{
				"安全审计：应对网络边界、重要节点的访问与操作进行审计，审计记录应受保护",
				"入侵防范：应在关键网络节点处检测、防止或限制从外部发起的网络攻击",
				"恶意代码防范 / Web 应用防护：对恶意请求进行检测与处置",
				"安全运维管理：策略变更、应急处置与记录可追溯",
			},
			WAFMaps: []string{
				"ModSecurity + OWASP CRS 对 SQLi/XSS/RCE 等攻击拦截与审计",
				"JSON 审计日志、安全事件检索与攻击趋势报表",
				"引擎模式切换（On / DetectionOnly / Off）与紧急旁路留痕",
				"规则/站点/例外变更经管理 API 与审计链记录",
			},
			Evidence: []string{"攻击事件总量与严重级别", "攻击源 IP Top", "规则命中 Top", "源国家分布（若已启用 Geo）"},
		},
		"iso27001": {
			ID: "iso27001", Title: "ISO/IEC 27001 合规运营报告", Short: "ISO 27001",
			Standard: "ISO/IEC 27001 控制域参考映射（A.8 资产/技术 · A.12 运行安全等）",
			Controls: []string{
				"A.8 技术脆弱性管理 / 应用安全相关控制（防护与检测）",
				"A.12 运行安全：日志记录、监控、恶意软件与技术操作程序",
				"访问控制与变更管理的支撑证据（策略配置与审计）",
				"事件管理：安全事件的发现、记录与响应支撑",
			},
			WAFMaps: []string{
				"虚拟补丁与自定义规则降低已知漏洞利用窗口",
				"审计日志、攻击摘要、合规 HTML/CSV 导出支撑运行监控",
				"规则热加载、备份回滚、配置完整性校验",
				"限流/Bot/IP 名单等运行层防护措施",
			},
			Evidence: []string{"攻击事件总量与严重级别", "规则命中 Top（脆弱性利用尝试）", "攻击源与国家分布", "防护策略持续运行证据"},
		},
		"gdpr": {
			ID: "gdpr", Title: "GDPR Art.32 技术措施运营报告", Short: "GDPR",
			Standard: "GDPR Article 32 — Security of processing（技术与组织措施）参考映射",
			Controls: []string{
				"确保处理系统与服务的持续保密性、完整性、可用性与韧性",
				"及时恢复可用性与访问的能力（业务连续性相关）",
				"定期测试、评估技术措施有效性的过程",
				"与风险相适应的安全水平（含传输/处理环境的防护）",
			},
			WAFMaps: []string{
				"Web 应用层拦截异常访问，降低未授权处理与数据泄露风险",
				"PII / 敏感信息相关规则与上传防护（按策略启用）",
				"审计与报表支撑「措施有效性」的运营评估",
				"紧急旁路与 DetectionOnly 磨合，平衡可用性与防护",
			},
			Evidence: []string{"拦截/检测事件统计", "高危规则命中", "异常源 IP 与地理分布", "管理面操作可追溯（审计链）"},
		},
		"sox": {
			ID: "sox", Title: "SOX IT 一般控制运营报告", Short: "SOX",
			Standard: "SOX 相关 IT 一般控制（ITGC）参考映射 — 访问控制与变更管理",
			Controls: []string{
				"访问控制：限制对关键系统与数据的未授权访问",
				"变更管理：程序/配置变更可审批、可追溯",
				"运维与监控：安全事件与异常访问有记录",
				"职责分离与管理入口保护（管理面认证与网络 ACL）",
			},
			WAFMaps: []string{
				"对业务站点的未授权/攻击性访问进行拦截与留痕",
				"站点/规则/例外变更经 API，支持备份与回滚",
				"管理控制台鉴权、防暴破、可选 2FA 与来源 IP 限制",
				"攻击报表与安全事件支撑 IT 监控证据",
			},
			Evidence: []string{"安全事件与严重级别", "攻击源 Top（未授权访问尝试）", "规则命中（异常请求模式）", "配置变更相关审计链摘要"},
		},
		"all": {
			ID: "all", Title: "Ma-WAF 合规运营综合报告", Short: "综合",
			Standard: "多框架控制域汇总映射",
			Controls: []string{
				"等保 2.0 — 安全审计 / 入侵防范",
				"ISO 27001 — A.8 / A.12",
				"GDPR — Art.32 技术与组织措施",
				"SOX — IT 一般控制（访问与变更）",
			},
			WAFMaps: []string{
				"统一数据面防护 + 管理面审计与报表",
				"本报告为运营映射参考，不构成任一框架的认证结论",
			},
			Evidence: []string{"攻击事件总量与严重级别", "攻击源 IP Top", "规则命中 Top", "国家分布"},
		},
	}
}

func resolveComplianceFramework(id string) complianceFramework {
	id = strings.ToLower(strings.TrimSpace(id))
	switch id {
	case "", "all", "summary":
		id = "all"
	case "dj", "dengbao", "等保", "等保2.0", "dsl", "mlps":
		id = "dsl2"
	case "iso", "iso27001", "27001":
		id = "iso27001"
	case "gdpr32", "art32":
		id = "gdpr"
	case "sox404", "itgc":
		id = "sox"
	}
	m := complianceFrameworks()
	if fw, ok := m[id]; ok {
		return fw
	}
	return m["all"]
}

func (s *Server) exportReport(c *gin.Context) {
	items := s.recentAttacks(1000)
	sum := waf.AttackSummary(items)
	format := strings.ToLower(c.Query("format"))
	if format == "" {
		format = "csv"
	}
	fw := resolveComplianceFramework(c.Query("framework"))
	switch format {
	case "csv":
		var b strings.Builder
		b.WriteString("section,key,count\n")
		b.WriteString(fmt.Sprintf("framework,id,%s\n", csvEsc(fw.ID)))
		b.WriteString(fmt.Sprintf("framework,title,%s\n", csvEsc(fw.Title)))
		b.WriteString(fmt.Sprintf("summary,total,%v\n", sum["total"]))
		for _, row := range asKV(sum["by_ip"]) {
			b.WriteString(fmt.Sprintf("by_ip,%s,%v\n", csvEsc(row["key"]), row["count"]))
		}
		for _, row := range asKV(sum["by_rule"]) {
			b.WriteString(fmt.Sprintf("by_rule,%s,%v\n", csvEsc(row["key"]), row["count"]))
		}
		for _, row := range asKV(sum["by_country"]) {
			b.WriteString(fmt.Sprintf("by_country,%s,%v\n", csvEsc(row["key"]), row["count"]))
		}
		if sev, ok := sum["by_severity"].(map[string]int); ok {
			for k, v := range sev {
				b.WriteString(fmt.Sprintf("by_severity,%s,%d\n", csvEsc(k), v))
			}
		}
		for _, ctrl := range fw.Controls {
			b.WriteString(fmt.Sprintf("control,%s,mapped\n", csvEsc(ctrl)))
		}
		for _, m := range fw.WAFMaps {
			b.WriteString(fmt.Sprintf("waf_mapping,%s,mapped\n", csvEsc(m)))
		}
		fname := fmt.Sprintf("ma-waf-%s-report.csv", fw.ID)
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", "attachment; filename="+fname)
		c.String(http.StatusOK, b.String())
	case "html", "pdf":
		// pdf：返回可打印 HTML，浏览器「另存为 PDF」即可（服务端不强制嵌入 PDF 引擎）
		html := buildComplianceHTML(sum, fw)
		fname := fmt.Sprintf("ma-waf-%s-compliance.html", fw.ID)
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", "inline; filename="+fname)
		c.Header("X-Report-Framework", fw.ID)
		c.Header("X-Report-PDF-Hint", "use browser print to save as PDF")
		c.String(http.StatusOK, html)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "format 支持 csv|html|pdf；framework 支持 dsl2|iso27001|gdpr|sox|all"})
	}
}

func buildComplianceHTML(sum map[string]interface{}, fw complianceFramework) string {
	esc := func(v interface{}) string {
		s := fmt.Sprint(v)
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		return s
	}
	ul := func(title string, items []string) string {
		var b strings.Builder
		b.WriteString("<h2>" + esc(title) + "</h2><ul>")
		for _, it := range items {
			b.WriteString("<li>" + esc(it) + "</li>")
		}
		b.WriteString("</ul>")
		return b.String()
	}
	row := func(title string, rows []map[string]interface{}) string {
		var b strings.Builder
		b.WriteString("<h2>" + title + "</h2><table><tr><th>项</th><th>次数</th></tr>")
		if len(rows) == 0 {
			b.WriteString("<tr><td colspan=2>暂无</td></tr>")
		}
		for _, r := range rows {
			b.WriteString("<tr><td>" + esc(r["key"]) + "</td><td>" + esc(r["count"]) + "</td></tr>")
		}
		b.WriteString("</table>")
		return b.String()
	}
	sev := ""
	if m, ok := sum["by_severity"].(map[string]int); ok {
		sev = "<h2>严重级别分布</h2><table><tr><th>级别</th><th>次数</th></tr>"
		for k, v := range m {
			sev += "<tr><td>" + esc(k) + "</td><td>" + esc(v) + "</td></tr>"
		}
		sev += "</table>"
	}
	evidenceNote := strings.Join(fw.Evidence, "；")
	return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"/>
<title>` + esc(fw.Title) + `</title>
<style>
body{font-family:"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;max-width:920px;margin:2rem auto;color:#111;padding:0 1rem;line-height:1.5}
h1{font-size:1.45rem;margin-bottom:.35rem}h2{font-size:1.1rem;margin-top:1.5rem;border-bottom:1px solid #ddd;padding-bottom:.3rem}
.badge{display:inline-block;background:#e8f1fb;color:#1e4a7a;padding:.15rem .55rem;border-radius:4px;font-size:.85rem;margin-right:.4rem}
table{width:100%;border-collapse:collapse;margin:.5rem 0}th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}
.muted{color:#666;font-size:.9rem}.toolbar{margin-bottom:1rem;display:flex;gap:.5rem;flex-wrap:wrap}
button{cursor:pointer;padding:.45rem .9rem;border:1px solid #ccc;border-radius:6px;background:#f8fafc}
button.primary{background:#1d4ed8;color:#fff;border-color:#1d4ed8}
.box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:.85rem 1rem;margin:.75rem 0}
@media print{button,.toolbar{display:none}body{margin:0}}
</style></head><body>
<div class="toolbar">
  <button class="primary" onclick="window.print()">打印 / 另存为 PDF</button>
  <button type="button" onclick="window.close()">关闭</button>
</div>
<span class="badge">` + esc(fw.Short) + `</span>
<span class="badge">framework=` + esc(fw.ID) + `</span>
<h1>` + esc(fw.Title) + `</h1>
<p class="muted">生成时间：` + time.Now().Format("2006-01-02 15:04:05") + ` · 样本事件：` + esc(sum["total"]) + ` · <b>运营映射参考，不构成认证或审计结论</b>。</p>
<div class="box"><b>适用标准（参考）</b><br/>` + esc(fw.Standard) + `</div>
` + ul("控制域 / 条款映射", fw.Controls) + ul("Ma-WAF 能力支撑", fw.WAFMaps) + `
<h2>本报告证据范围</h2>
<p class="muted">` + esc(evidenceNote) + `</p>
` + sev + row("攻击源 Top", asKV(sum["by_ip"])) + row("规则命中 Top", asKV(sum["by_rule"])) + row("国家分布", asKV(sum["by_country"])) + `
<p class="muted" style="margin-top:2rem">导出提示：点击「打印 / 另存为 PDF」即可生成 PDF 文件。数据来源：ModSecurity 审计经管理 API 聚合。</p>
</body></html>`
}

func asKV(v interface{}) []map[string]interface{} {
	if rows, ok := v.([]map[string]interface{}); ok {
		return rows
	}
	return nil
}

func csvEsc(v interface{}) string {
	s := fmt.Sprint(v)
	s = strings.ReplaceAll(s, `"`, `""`)
	if strings.ContainsAny(s, ",\n\"") {
		return `"` + s + `"`
	}
	return s
}

func (s *Server) getGeoBlock(c *gin.Context) {
	list, err := s.waf.ReadGeoBlock()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"countries": []string{}, "warning": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"countries": list})
}

func (s *Server) putGeoBlock(c *gin.Context) {
	var req struct {
		Countries []string `json:"countries"`
		Reload    bool     `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.WriteGeoBlock(req.Countries, req.Reload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "geo_block_update", "count": len(req.Countries), "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(req.Countries)})
}

func (s *Server) listVirtPatches(c *gin.Context) {
	list, err := s.waf.ListVirtPatches()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"patches": []interface{}{}, "warning": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"patches": list})
}

func (s *Server) listPacks(c *gin.Context) {
	list, err := s.waf.ListProtectionPacks()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"packs": []interface{}{}, "warning": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"packs": list})
}

func (s *Server) enablePack(c *gin.Context) {
	id := c.Param("id")
	if err := s.waf.SetProtectionPack(id, true, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "pack_enable", "id": id, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id, "enabled": true})
}

func (s *Server) disablePack(c *gin.Context) {
	id := c.Param("id")
	if err := s.waf.SetProtectionPack(id, false, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "pack_disable", "id": id, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id, "enabled": false})
}

func (s *Server) validateRules(c *gin.Context) {
	res, err := s.waf.ValidateRules()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, res)
}

func (s *Server) expireVirtPatches(c *gin.Context) {
	n, err := s.waf.DisableExpiredVirtPatches()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "virtpatch_expire", "count": n, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true, "disabled": n})
}

func (s *Server) mergeThreatIntel(c *gin.Context) {
	var req struct {
		Entries []string `json:"entries"`
		Reload  bool     `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	n, err := s.waf.MergeThreatIntel(req.Entries, req.Reload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "threat_intel_merge", "added": n, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": n})
}

func (s *Server) fetchThreatIntel(c *gin.Context) {
	var req struct {
		URL    string `json:"url"`
		Reload bool   `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	n, err := s.waf.FetchThreatIntelURL(req.URL, req.Reload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "threat_intel_fetch", "url": req.URL, "added": n, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": n})
}

func (s *Server) generateOpenAPI(c *gin.Context) {
	var req struct {
		Content string `json:"content"`
		Enable  bool   `json:"enable"`
		Reload  bool   `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	content := strings.TrimSpace(req.Content)
	if content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content 不能为空（OpenAPI JSON）"})
		return
	}
	n, err := s.waf.GenerateOpenAPIRules([]byte(content), req.Enable, req.Reload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "openapi_generate", "paths": n, "enable": req.Enable, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "paths": n, "enabled": req.Enable})
}

func (s *Server) auditChain(c *gin.Context) {
	count, ok, detail := s.chain.Verify()
	c.JSON(http.StatusOK, gin.H{
		"ok": ok, "count": count, "detail": detail, "path": s.cfg.ChainAuditPath,
	})
}

func (s *Server) recentAttacks(limit int) []waf.AttackEvent {
	var items []waf.AttackEvent
	if s.index != nil {
		if list, err := s.index.List(limit); err == nil && len(list) > 0 {
			items = list
		}
	}
	if len(items) == 0 {
		items, _ = waf.TailAuditParsed(s.cfg.AuditLog, limit)
	}
	return s.waf.EnrichAttackCountries(items)
}

func (s *Server) listSites(c *gin.Context) {
	sites, err := s.waf.ListSites()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"sites": []interface{}{}, "warning": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sites": sites})
}

func (s *Server) getSite(c *gin.Context) {
	spec, err := s.waf.GetManagedSite(c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"site": spec})
}

func (s *Server) createSite(c *gin.Context) {
	var spec waf.SiteSpec
	if err := c.ShouldBindJSON(&spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.UpsertSite(spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "site_create", "name": spec.Name, "user": c.GetString("user"),
	})
	resp := gin.H{"ok": true, "name": spec.Name, "nginx_caps": s.waf.NginxCapabilities()}
	if w := s.waf.LastSiteUpsertWarning(); w != "" {
		resp["warning"] = w
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) updateSite(c *gin.Context) {
	var spec waf.SiteSpec
	if err := c.ShouldBindJSON(&spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	spec.Name = c.Param("name")
	if err := s.waf.UpsertSite(spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "site_update", "name": spec.Name, "user": c.GetString("user"),
	})
	resp := gin.H{"ok": true, "name": spec.Name, "nginx_caps": s.waf.NginxCapabilities()}
	if w := s.waf.LastSiteUpsertWarning(); w != "" {
		resp["warning"] = w
	}
	c.JSON(http.StatusOK, resp)
}

func (s *Server) deleteSite(c *gin.Context) {
	name := c.Param("name")
	if err := s.waf.DeleteSite(name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "site_delete", "name": name, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) listExceptions(c *gin.Context) {
	list, err := s.waf.ListExceptions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"exceptions": list})
}

func (s *Server) putExceptions(c *gin.Context) {
	var req struct {
		Exceptions []waf.Exception `json:"exceptions"`
		Reload     bool            `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	for i, e := range req.Exceptions {
		switch e.Kind {
		case "uri_bypass", "rule_remove", "uri_rule_remove":
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "非法 kind: " + e.Kind})
			return
		}
		if e.Kind != "rule_remove" && strings.TrimSpace(e.URI) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "uri_bypass/uri_rule_remove 需要 uri"})
			return
		}
		if e.Kind != "uri_bypass" {
			if err := waf.ParseRuleIDList(e.RuleIDs); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "index": i})
				return
			}
		}
	}
	if err := s.waf.SaveExceptions(req.Exceptions, req.Reload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "exceptions_update", "count": len(req.Exceptions), "user": c.GetString("user"),
	})
	list, _ := s.waf.ListExceptions()
	c.JSON(http.StatusOK, gin.H{"ok": true, "exceptions": list})
}

func (s *Server) licenseStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"license": s.lic.Status()})
}

func (s *Server) licenseFingerprint(c *gin.Context) {
	detail, err := s.lic.FingerprintDetail()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, detail)
}

func (s *Server) licenseImport(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "请上传 .lic 文件（字段名 file）"})
		return
	}
	if !strings.HasSuffix(strings.ToLower(fh.Filename), ".lic") {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "文件必须以 .lic 结尾"})
		return
	}
	tmp := filepath.Join(os.TempDir(), "ma-waf-import-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".lic")
	if err := c.SaveUploadedFile(fh, tmp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": err.Error()})
		return
	}
	defer os.Remove(tmp)
	if err := s.lic.ImportFile(tmp); err != nil {
		_, _ = s.chain.Append(map[string]interface{}{
			"type": "license_import", "success": false, "user": c.GetString("user"), "error": err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error(), "license": s.lic.Status()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "license_import", "success": true, "user": c.GetString("user"), "file": fh.Filename,
	})
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "License 导入成功", "license": s.lic.Status()})
}

func (s *Server) getIPList(c *gin.Context) {
	kind := c.Param("kind")
	entries, err := s.waf.ReadIPList(kind)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"kind": kind, "entries": entries})
}

func (s *Server) putIPList(c *gin.Context) {
	kind := c.Param("kind")
	var req struct {
		Entries []string `json:"entries"`
		Reload  bool     `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.WriteIPList(kind, req.Entries, req.Reload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "iplist_update", "kind": kind, "count": len(req.Entries), "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(req.Entries)})
}

func (s *Server) addIPList(c *gin.Context) {
	kind := c.Param("kind")
	var req struct {
		Entries []string `json:"entries"`
		IPs     []string `json:"ips"`
		Reload  bool     `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	entries := req.Entries
	if len(entries) == 0 {
		entries = req.IPs
	}
	n, err := s.waf.AddIPs(kind, entries, req.Reload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "iplist_add", "kind": kind, "added": n, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": n})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) challengeIssue(c *gin.Context) {
	val, maxAge, err := challenge.Issue(s.cfg.JWTSecret, challenge.DefaultTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.SetCookie(challenge.CookieName, val, maxAge, "/", "", false, false)
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"ok": true, "cookie": challenge.CookieName, "value": val, "max_age": maxAge,
	})
}

func (s *Server) challengeVerify(c *gin.Context) {
	ua := c.GetHeader("User-Agent")
	raw, _ := c.Cookie(challenge.CookieName)
	if raw == "" {
		raw = c.GetHeader("X-Ma-Waf-Challenge")
	}
	ok := challenge.Verify(s.cfg.JWTSecret, raw)
	// auth_request：软 Bot 必须通过；普通 UA 直接放行
	if challenge.SoftBotUA(ua) && !ok {
		c.Status(http.StatusUnauthorized)
		return
	}
	c.Status(http.StatusOK)
}

func (s *Server) openAPIStatus(c *gin.Context) {
	exists, enabled, path := s.waf.OpenAPIStatus()
	c.JSON(http.StatusOK, gin.H{"exists": exists, "enabled": enabled, "path": path})
}

func (s *Server) getOps(c *gin.Context) {
	ops, err := s.waf.ReadOps()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ops.AlertWebhook == "" {
		ops.AlertWebhook = s.cfg.AlertWebhook
	}
	c.JSON(http.StatusOK, gin.H{
		"ops":                 ops,
		"challenge_fp":        challenge.HexFingerprint(s.cfg.JWTSecret),
		"cfg_alert_webhook":   s.cfg.AlertWebhook != "",
	})
}

func (s *Server) putOps(c *gin.Context) {
	var req waf.OpsSettings
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.WriteOps(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "ops_update", "user": c.GetString("user"),
		"autoblock_threshold": req.AutoblockThreshold,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "ops": req})
}

func (s *Server) testWebhook(c *gin.Context) {
	ops, _ := s.waf.ReadOps()
	url := strings.TrimSpace(ops.AlertWebhook)
	if url == "" {
		url = strings.TrimSpace(s.cfg.AlertWebhook)
	}
	if url == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未配置 alert_webhook"})
		return
	}
	body := `{"text":"Ma-WAF test webhook from console"}`
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	c.JSON(http.StatusOK, gin.H{"ok": resp.StatusCode >= 200 && resp.StatusCode < 300, "status": resp.StatusCode})
	if ops.SIEMAddr != "" {
		_ = waf.SendSIEM(ops.SIEMAddr, ops.SIEMProto, "Ma-WAF test webhook from console")
	}
}

func (s *Server) autoBlock(c *gin.Context) {
	var req struct {
		Threshold int  `json:"threshold"`
		TopN      int  `json:"top_n"`
		Reload    bool `json:"reload"`
	}
	_ = c.ShouldBindJSON(&req)
	ops, _ := s.waf.ReadOps()
	th := req.Threshold
	if th <= 0 {
		th = ops.AutoblockThreshold
	}
	topN := req.TopN
	if topN <= 0 {
		topN = ops.AutoblockTopN
	}
	items := s.recentAttacks(2000)
	counts := map[string]int{}
	for _, e := range items {
		if e.ClientIP != "" {
			counts[e.ClientIP]++
		}
	}
	added, blocked, err := s.waf.AutoBlockIPs(counts, th, topN, req.Reload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "autoblock", "threshold": th, "top_n": topN, "added": added, "ips": blocked, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "threshold": th, "top_n": topN, "added": added, "blocked": blocked})
}

func (s *Server) cronAutoblock(c *gin.Context) {
	ip := net.ParseIP(c.ClientIP())
	if ip == nil || !ip.IsLoopback() {
		c.JSON(http.StatusForbidden, gin.H{"error": "cron only from loopback"})
		return
	}
	ops, err := s.waf.ReadOps()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	tok := strings.TrimSpace(c.GetHeader("X-Ma-Waf-Cron"))
	if ops.CronToken == "" || tok == "" || tok != ops.CronToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid cron token"})
		return
	}
	if !ops.AutoblockEnabled {
		c.JSON(http.StatusOK, gin.H{"ok": true, "skipped": true, "reason": "autoblock_enabled=false"})
		return
	}
	items := s.recentAttacks(2000)
	counts := map[string]int{}
	for _, e := range items {
		if e.ClientIP != "" {
			counts[e.ClientIP]++
		}
	}
	added, blocked, err := s.waf.AutoBlockIPs(counts, ops.AutoblockThreshold, ops.AutoblockTopN, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "cron_autoblock", "added": added, "ips": blocked,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": added, "blocked": blocked})
}

func (s *Server) geoStatus(c *gin.Context) {
	c.JSON(http.StatusOK, s.waf.GeoStatus())
}

func (s *Server) listProfiles(c *gin.Context) {
	list, err := s.waf.ListProfiles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"profiles": list})
}

func (s *Server) putProfiles(c *gin.Context) {
	var req struct {
		Profiles []waf.PolicyProfile `json:"profiles"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Profiles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "profiles 不能为空"})
		return
	}
	if err := s.waf.SaveProfiles(req.Profiles); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(req.Profiles)})
}

func (s *Server) applyProfile(c *gin.Context) {
	var req struct {
		ProfileID string `json:"profile_id"`
		SetEngine bool   `json:"set_engine"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.ProfileID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "profile_id required"})
		return
	}
	name := c.Param("name")
	if err := s.waf.ApplyProfileToSite(name, req.ProfileID, req.SetEngine); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "apply_profile", "site": name, "profile": req.ProfileID, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) getGoodBots(c *gin.Context) {
	list, err := s.waf.ReadGoodBots()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"patterns": list})
}

func (s *Server) putGoodBots(c *gin.Context) {
	var req struct {
		Patterns []string `json:"patterns"`
		Reload   bool     `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.WriteGoodBots(req.Patterns, req.Reload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "count": len(req.Patterns)})
}

func (s *Server) attackInsights(c *gin.Context) {
	items := s.recentAttacks(2000)
	c.JSON(http.StatusOK, waf.AttackInsights(items))
}

func (s *Server) createCustomRule(c *gin.Context) {
	var spec waf.CustomRuleSpec
	if err := c.ShouldBindJSON(&spec); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	fname, err := s.waf.CreateCustomRule(spec, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "custom_rule", "file": fname, "id": spec.ID, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "file": fname})
}

func (s *Server) fpCandidates(c *gin.Context) {
	exc, _ := s.waf.ListExceptions()
	items := s.recentAttacks(2000)
	c.JSON(http.StatusOK, gin.H{"candidates": waf.SuggestFalsePositives(items, exc, 5)})
}

func (s *Server) golive(c *gin.Context) {
	mode, _ := s.waf.GetEngineMode()
	exc, _ := s.waf.ListExceptions()
	fp := waf.SuggestFalsePositives(s.recentAttacks(2000), exc, 5)
	geo := s.waf.GeoStatus()
	lic := s.lic.Status()
	pl := s.waf.GetParanoiaLevel()
	val, _ := s.waf.ValidateRules()
	nginxOK, _ := val["ok"].(bool)
	licOK := lic.Status == "active" || strings.Contains(lic.Status, "grace")
	checks := []map[string]interface{}{
		{"id": "engine", "ok": mode == "On" || mode == "DetectionOnly", "detail": "当前模式 " + mode + "（上线拦截需 On）"},
		{"id": "block_mode", "ok": mode == "On", "detail": "拦截模式"},
		{"id": "nginx_t", "ok": nginxOK, "detail": fmt.Sprint(val["nginx_msg"])},
		{"id": "fp_backlog", "ok": len(fp) == 0, "detail": fmt.Sprintf("误报候选 %d 条（≥5 次同 URI+规则）", len(fp))},
		{"id": "exceptions", "ok": true, "detail": fmt.Sprintf("已配置例外 %d 条", len(exc))},
		{"id": "paranoia", "ok": pl >= 1 && pl <= 4, "detail": fmt.Sprintf("CRS PL%d %s", pl, waf.ParanoiaHint(pl))},
		{"id": "geo", "ok": true, "detail": fmt.Sprintf("MMDB=%v 模块=%v 执法=%v", geo["mmdb_found"], geo["module_loaded"], geo["enforced"])},
		{"id": "license", "ok": licOK, "detail": lic.Status},
	}
	ready := mode == "On" && nginxOK && len(fp) == 0 && licOK
	c.JSON(http.StatusOK, gin.H{"ready": ready, "engine_mode": mode, "checks": checks, "fp_count": len(fp)})
}

func (s *Server) troubleshoot(c *gin.Context) {
	lic := s.lic.Status()
	licOK := lic.Status == "active" || strings.Contains(lic.Status, "grace")
	out := s.waf.Troubleshoot(waf.TroubleshootOpts{
		ConsoleDir: s.cfg.ConsoleDir,
		AuditLog:   s.cfg.AuditLog,
		LicenseOK:  licOK,
		LicenseMsg: lic.Status,
	})
	c.JSON(http.StatusOK, out)
}

func (s *Server) getParanoia(c *gin.Context) {
	n := s.waf.GetParanoiaLevel()
	c.JSON(http.StatusOK, gin.H{"level": n, "hint": waf.ParanoiaHint(n)})
}

func (s *Server) putParanoia(c *gin.Context) {
	var req struct {
		Level  int  `json:"level"`
		Reload bool `json:"reload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.SetParanoiaLevel(req.Level, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "level": req.Level, "hint": waf.ParanoiaHint(req.Level)})
}

func (s *Server) getContentPolicy(c *gin.Context) {
	p, err := s.waf.ReadContentPolicy()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"policy": p})
}

func (s *Server) putContentPolicy(c *gin.Context) {
	var p waf.ContentPolicy
	if err := c.ShouldBindJSON(&p); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.WriteContentPolicy(p, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "policy": p})
}

func (s *Server) intelStatus(c *gin.Context) {
	c.JSON(http.StatusOK, s.waf.IntelStatus())
}

func (s *Server) expireIntel(c *gin.Context) {
	n, err := s.waf.ExpireThreatIntel(true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "expired": n})
}

func (s *Server) geoEnforce(c *gin.Context) {
	if err := s.waf.EnableGeoEnforcement(true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "geo": s.waf.GeoStatus()})
}

func (s *Server) geoDisableEnforce(c *gin.Context) {
	if err := s.waf.DisableGeoEnforcement(true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) siemTest(c *gin.Context) {
	ops, _ := s.waf.ReadOps()
	items := s.recentAttacks(1)
	msg := "Ma-WAF SIEM test"
	if len(items) > 0 {
		msg = waf.FormatAttackCEF(items[0])
	}
	if err := waf.SendSIEM(ops.SIEMAddr, ops.SIEMProto, msg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) haStatus(c *gin.Context) {
	c.JSON(http.StatusOK, s.waf.HAStatus())
}

func (s *Server) emergency(c *gin.Context) {
	var req struct {
		Mode   string `json:"mode"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if req.Mode == "" {
		req.Mode = "DetectionOnly"
	}
	if strings.TrimSpace(req.Reason) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason 必填（审计追溯）"})
		return
	}
	if err := s.waf.EmergencyBypass(req.Mode, req.Reason, c.GetString("user")); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "emergency", "mode": req.Mode, "reason": req.Reason, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "mode": req.Mode})
}

func (s *Server) discoverSites(c *gin.Context) {
	limit := 50
	items, err := s.waf.DiscoverSites(s.cfg.AccessLog, limit)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "access_log": s.cfg.AccessLog})
}

func (s *Server) listAddrBook(c *gin.Context) {
	items, err := s.waf.ListAddrBook()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *Server) putAddrBook(c *gin.Context) {
	var req struct {
		Items []waf.AddrObject `json:"items"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if err := s.waf.SaveAddrBook(req.Items); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "addrbook_save", "user": c.GetString("user"), "n": len(req.Items)})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) applyAddrBook(c *gin.Context) {
	name := c.Param("name")
	var req struct {
		Kind string `json:"kind"` // blacklist|whitelist
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.Kind != "blacklist" && req.Kind != "whitelist") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "kind 须为 blacklist 或 whitelist"})
		return
	}
	n, err := s.waf.ApplyAddrToList(name, req.Kind, true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "addrbook_apply", "name": name, "kind": req.Kind, "added": n, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "added": n})
}

func (s *Server) listPKICerts(c *gin.Context) {
	items, err := s.waf.ListTLSCerts()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *Server) ensureAdminTLS(c *gin.Context) {
	var req struct {
		CN   string `json:"cn"`
		Days int    `json:"days"`
	}
	_ = c.ShouldBindJSON(&req)
	info, err := s.waf.EnsureAdminTLS(req.CN, req.Days)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "pki_admin_ensure", "cn": info.Subject, "user": c.GetString("user")})
	c.JSON(http.StatusOK, gin.H{"ok": true, "cert": info})
}

func (s *Server) sysInfo(c *gin.Context) {
	c.JSON(http.StatusOK, s.waf.SysInfo())
}

func (s *Server) setHeavySecurity(c *gin.Context) {
	var req struct {
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}
	if strings.TrimSpace(req.Reason) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason 必填"})
		return
	}
	if err := s.waf.SetHeavySecurity(req.On, req.Reason); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "heavy_security", "on": req.On, "reason": req.Reason, "user": c.GetString("user"),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "heavy_security": req.On})
}

func (s *Server) rulesUpgradeStatus(c *gin.Context) {
	c.JSON(http.StatusOK, s.waf.RulesUpgradeStatus())
}

func (s *Server) rulesUpgradeLocal(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请上传规则包（字段名 file，.tgz/.tar.gz）"})
		return
	}
	if fh.Size > 64<<20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "文件超过 64MB 限制"})
		return
	}
	tmp := filepath.Join(os.TempDir(), "ma-waf-rules-"+strconv.FormatInt(time.Now().UnixNano(), 10)+filepath.Ext(fh.Filename))
	if strings.HasSuffix(strings.ToLower(fh.Filename), ".tar.gz") {
		tmp = filepath.Join(os.TempDir(), "ma-waf-rules-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".tar.gz")
	}
	if err := c.SaveUploadedFile(fh, tmp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer os.Remove(tmp)

	sigPath := ""
	if sf, err := c.FormFile("sig"); err == nil && sf != nil {
		sigPath = tmp + ".sig"
		if err := c.SaveUploadedFile(sf, sigPath); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "签名文件保存失败: " + err.Error()})
			return
		}
		defer os.Remove(sigPath)
	}

	promote := true
	if v := strings.TrimSpace(c.PostForm("promote")); v == "0" || strings.EqualFold(v, "false") {
		promote = false
	}
	strict := os.Getenv("MA_WAF_STRICT_AUTH") == "1"

	rec, err := s.waf.LocalRulesUpgrade(waf.LocalRulesUpgradeOptions{
		BundlePath: tmp,
		SigPath:    sigPath,
		Filename:   fh.Filename,
		Promote:    promote,
		User:       c.GetString("user"),
		StrictSig:  strict,
	})
	_, _ = s.chain.Append(map[string]interface{}{
		"type": "rules_upgrade_local", "user": c.GetString("user"),
		"file": fh.Filename, "ok": err == nil, "custom": rec.CustomN, "rules": rec.RulesN,
		"promoted": rec.Promoted, "error": rec.Error,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": err.Error(), "result": rec})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "result": rec})
}

func (s *Server) cronIntelExpire(c *gin.Context) {
	ip := net.ParseIP(c.ClientIP())
	if ip == nil || !ip.IsLoopback() {
		c.JSON(http.StatusForbidden, gin.H{"error": "cron only from loopback"})
		return
	}
	ops, err := s.waf.ReadOps()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	tok := strings.TrimSpace(c.GetHeader("X-Ma-Waf-Cron"))
	if ops.CronToken == "" || tok == "" || tok != ops.CronToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid cron token"})
		return
	}
	n, err := s.waf.ExpireThreatIntel(true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, _ = s.chain.Append(map[string]interface{}{"type": "cron_intel_expire", "expired": n})
	c.JSON(http.StatusOK, gin.H{"ok": true, "expired": n})
}

