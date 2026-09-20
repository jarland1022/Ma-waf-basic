package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AttackInsights Imperva 类攻击洞察聚合。
func AttackInsights(events []AttackEvent) map[string]interface{} {
	byTag := map[string]int{}
	byFamily := map[string]int{}
	campaign := map[string]int{}
	atoIP := map[string]int{}
	loginURI := regexp.MustCompile(`(?i)/(?:login|signin|auth|oauth|token|password|passwd|reset)`)

	for _, e := range events {
		blob := strings.ToLower(strings.Join(e.Messages, " ") + " " + e.RawPreview)
		tags := inferTags(blob, e)
		for _, t := range tags {
			byTag[t]++
			if i := strings.IndexByte(t, '/'); i > 0 {
				byFamily[t[:i]]++
			} else if strings.HasPrefix(t, "ma-waf-") {
				byFamily[t]++
			}
		}
		key := e.ClientIP + "|" + truncateURI(e.URI, 64)
		if e.ClientIP != "" {
			campaign[key]++
		}
		if e.ClientIP != "" && (containsAny(blob, "login rate", "session-protect", "ma-waf-session", "credential") ||
			loginURI.MatchString(e.URI)) {
			atoIP[e.ClientIP]++
		}
	}
	return map[string]interface{}{
		"total":          len(events),
		"by_tag":         topN(byTag, 15),
		"by_family":      topN(byFamily, 10),
		"campaigns":      topN(campaign, 15),
		"ato_sources":    topN(atoIP, 10),
		"generated_at":   time.Now().Format(time.RFC3339),
	}
}

func inferTags(blob string, e AttackEvent) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	// 从消息中抽 tag:'...'
	re := regexp.MustCompile(`tag['\":\s]+['\"]?([a-zA-Z0-9_./-]+)`)
	for _, m := range re.FindAllStringSubmatch(blob, 12) {
		add(m[1])
	}
	switch {
	case strings.Contains(blob, "openapi"), strings.Contains(blob, "ma-waf/openapi"):
		add("ma-waf/openapi")
	case strings.Contains(blob, "session-protect"), strings.Contains(blob, "login rate"):
		add("ma-waf-session")
	case strings.Contains(blob, "attack-bot"), strings.Contains(blob, "ma-waf-bot"):
		add("ma-waf-bot")
	case strings.Contains(blob, "sql"), strings.Contains(blob, "injection"):
		add("attack-sqli")
	case strings.Contains(blob, "xss"), strings.Contains(blob, "script"):
		add("attack-xss")
	case strings.Contains(blob, "rce"), strings.Contains(blob, "command"):
		add("attack-rce")
	case strings.Contains(blob, "lfi"), strings.Contains(blob, "traversal"):
		add("attack-lfi")
	}
	for _, id := range e.RuleIDs {
		n, _ := strconv.Atoi(id)
		switch {
		case n >= 130000 && n < 131000:
			add("ma-waf/openapi")
		case n >= 110300 && n < 110400:
			add("ma-waf-session")
		case n >= 110200 && n < 110300:
			add("ma-waf-bot")
		case n >= 120000 && n < 121000:
			add("ma-waf/virtpatch")
		}
	}
	if len(out) == 0 {
		add("uncategorized")
	}
	return out
}

func truncateURI(u string, n int) string {
	u = strings.TrimSpace(u)
	if len(u) <= n {
		return u
	}
	return u[:n] + "…"
}

func containsAny(s string, parts ...string) bool {
	for _, p := range parts {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// CustomRuleSpec 控制台创建的自定义/虚补规则。
type CustomRuleSpec struct {
	ID       int    `json:"id"`
	Message  string `json:"message"`
	Pattern  string `json:"pattern"`
	Phase    int    `json:"phase"`
	Action   string `json:"action"` // pass|deny
	Severity string `json:"severity"`
	CVE      string `json:"cve,omitempty"`
	Expire   string `json:"expire,omitempty"` // YYYY-MM-DD
	Target   string `json:"target"`         // REQUEST_URI|ARGS|REQUEST_HEADERS
	VirtPatch bool  `json:"virtpatch"`
}

var safeRxMeta = regexp.MustCompile(`^[A-Za-z0-9:./_\- ]{0,64}$`)

func (m *Manager) CreateCustomRule(spec CustomRuleSpec, doReload bool) (string, error) {
	if spec.ID < 140000 || spec.ID > 149999 {
		return "", fmt.Errorf("自定义规则 ID 须在 140000-149999")
	}
	if strings.TrimSpace(spec.Pattern) == "" || strings.TrimSpace(spec.Message) == "" {
		return "", fmt.Errorf("pattern 与 message 必填")
	}
	if spec.Phase <= 0 {
		spec.Phase = 2
	}
	if spec.Action != "deny" {
		spec.Action = "pass"
	}
	if spec.Severity == "" {
		spec.Severity = "WARNING"
	}
	if spec.Target == "" {
		spec.Target = "REQUEST_URI"
	}
	allowed := map[string]bool{"REQUEST_URI": true, "ARGS": true, "REQUEST_HEADERS": true, "REQUEST_BODY": true}
	if !allowed[spec.Target] {
		return "", fmt.Errorf("不支持的 target")
	}
	if spec.CVE != "" && !safeRxMeta.MatchString(spec.CVE) {
		return "", fmt.Errorf("非法 CVE 字段")
	}
	// 粗防注入：禁止未转义引号破坏规则串
	if strings.ContainsAny(spec.Pattern, `"`) || strings.ContainsAny(spec.Message, `"`) {
		return "", fmt.Errorf("pattern/message 不能包含双引号")
	}
	// msg:'...' 内单引号会破坏动作串
	if strings.Contains(spec.Message, "'") || strings.Contains(spec.Pattern, "'") {
		return "", fmt.Errorf("pattern/message 不能包含单引号")
	}

	meta := "enabled=true; priority=40"
	if spec.CVE != "" {
		meta += "; cve=" + spec.CVE
	}
	if spec.Expire != "" {
		meta += "; expire=" + spec.Expire
	}
	action := "pass,nolog,auditlog"
	if spec.Action == "deny" {
		action = "deny,status:403,auditlog"
	}
	tag := "ma-waf/custom"
	fname := fmt.Sprintf("140000-user-%d.conf", spec.ID)
	if spec.VirtPatch {
		tag = "ma-waf/virtpatch"
		fname = fmt.Sprintf("120100-vp-%d.conf", spec.ID)
		if spec.ID < 120100 || spec.ID > 129999 {
			// virtpatch 仍用 140000 段文件名但 tag 虚补；或强制 ID
			fname = fmt.Sprintf("140100-vp-%d.conf", spec.ID)
		}
	}
	// 注意：动作串必须以双引号闭合，否则 ValidateRules 会报「引号可能未闭合」
	body := fmt.Sprintf(`# META: %s
# managed-by: ma-waf-api

SecRule %s "@rx %s" \
    "id:%d,phase:%d,%s,\
    msg:'%s',\
    tag:'%s',severity:'%s'"
`, meta, spec.Target, spec.Pattern, spec.ID, spec.Phase, action, spec.Message, tag, strings.ToUpper(spec.Severity))

	custom := filepath.Join(filepath.Dir(m.ModSecConf), "custom")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		return "", err
	}
	out := filepath.Join(custom, fname)
	if _, err := os.Stat(out); err == nil {
		return "", fmt.Errorf("规则文件已存在: %s", fname)
	}
	if _, err := m.Backup(); err != nil {
		return "", err
	}
	if err := os.WriteFile(out, []byte(body), 0o644); err != nil {
		return "", err
	}
	if err := validateCustomBeforeKeep(m, out); err != nil {
		return "", err
	}
	if doReload {
		if err := m.Reload(); err != nil {
			return fname, err
		}
	}
	return fname, nil
}

func validateCustomBeforeKeep(m *Manager, out string) error {
	res, err := m.ValidateRules()
	if err != nil {
		_ = os.Remove(out)
		return err
	}
	if ok, _ := res["ok"].(bool); !ok {
		_ = os.Remove(out)
		return fmt.Errorf("校验失败: %v", res["issues"])
	}
	if nginxOK, _ := res["nginx_ok"].(bool); !nginxOK {
		_ = os.Remove(out)
		return fmt.Errorf("nginx -t 失败: %v", res["nginx_msg"])
	}
	return nil
}
