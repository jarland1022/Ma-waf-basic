package waf

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MatchHit 单条规则命中（含攻击载荷/变量，便于展示 POST body 中的字段）。
type MatchHit struct {
	RuleID   string   `json:"rule_id,omitempty"`
	Message  string   `json:"message,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Data     string   `json:"data,omitempty"`
	Match    string   `json:"match,omitempty"`
	Variable string   `json:"variable,omitempty"` // 如 ARGS_POST:username
	Field    string   `json:"field,omitempty"`    // 如 username
	Tags     []string `json:"tags,omitempty"`
}

type AttackEvent struct {
	Time         string     `json:"time"`
	ClientIP     string     `json:"client_ip"`
	Method       string     `json:"method"`
	URI          string     `json:"uri"`
	Host         string     `json:"host"`
	Status       int        `json:"status"`
	ReqLen       int        `json:"req_len"`
	RespLen      int        `json:"resp_len"`
	RuleIDs      []string   `json:"rule_ids"`
	Messages     []string   `json:"messages"`
	Matches      []MatchHit `json:"matches,omitempty"`
	AttackFields []string   `json:"attack_fields,omitempty"`
	BodyPreview  string     `json:"body_preview,omitempty"`
	Severity     string     `json:"severity"`
	Country      string     `json:"country,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
	RequestID    string     `json:"request_id,omitempty"`
	RawPreview   string     `json:"raw_preview,omitempty"`
}

var (
	ruleIDBlobRe = regexp.MustCompile(`(?i)\bid["'=\s:]+(\d{4,7})`)
	// o0,12vARGS_POST:username 或 ARGS:id / REQUEST_BODY
	varRefRe = regexp.MustCompile(`(?i)(?:^|[;,\s]|v)((?:ARGS(?:_POST|_GET|_NAMES)?|REQUEST_BODY|REQUEST_HEADERS|REQUEST_COOKIES|XML)(?::([A-Za-z0-9_.\-[\]%]+))?)`)
	fieldInMsgRe = regexp.MustCompile(`(?i)(?:within|against|found within)\s+((?:ARGS(?:_POST|_GET|_NAMES)?|REQUEST_BODY|REQUEST_HEADERS|REQUEST_COOKIES)(?::([^\s,;"']+))?)`)
	matchedDataRe = regexp.MustCompile(`(?i)Matched Data:\s*(.+?)\s+found within\s+(\S+)`)
)

// TailAuditParsed 解析 ModSecurity JSON 审计尾部。
func TailAuditParsed(path string, limit int) ([]AttackEvent, error) {
	raw, err := TailAudit(path, limit)
	if err != nil {
		return nil, err
	}
	out := make([]AttackEvent, 0, len(raw))
	for _, item := range raw {
		s, _ := item["raw"].(string)
		ev := parseAuditLine(s)
		out = append(out, ev)
	}
	return out, nil
}

// ParseAuditLineForIndex 导出单行解析供 JSONL 索引使用。
func ParseAuditLineForIndex(line string) AttackEvent {
	return parseAuditLine(line)
}

// FindAttackByID 在审计日志尾部按 unique_id 查找并返回完整解析（含 body 预览）。
func FindAttackByID(path, id string, searchLimit int) (AttackEvent, string, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return AttackEvent{}, "", false
	}
	if searchLimit <= 0 {
		searchLimit = 2000
	}
	lines, err := TailAuditRawLines(path, searchLimit)
	if err != nil {
		return AttackEvent{}, "", false
	}
	for i := len(lines) - 1; i >= 0; i-- {
		ev := parseAuditLine(lines[i])
		if ev.RequestID == id {
			raw := lines[i]
			if len(raw) > 256*1024 {
				raw = raw[:256*1024] + "…"
			}
			return ev, raw, true
		}
	}
	return AttackEvent{}, "", false
}

func parseAuditLine(line string) AttackEvent {
	ev := AttackEvent{Severity: "INFO", RawPreview: truncate(line, 240)}
	var root map[string]interface{}
	if err := json.Unmarshal([]byte(line), &root); err != nil {
		return ev
	}

	tx, _ := root["transaction"].(map[string]interface{})
	if tx == nil {
		tx = root
	}

	ev.Time = strField(tx, "time_stamp", "timestamp", "time")
	ev.ClientIP = strField(tx, "client_ip", "remote_address", "remote_addr")
	ev.RequestID = strField(tx, "unique_id", "request_id", "id")
	ev.Country = strField(tx, "country", "geoip_country_code")
	ev.Host = strField(tx, "host", "server_id", "host_ip")

	var req map[string]interface{}
	if r, ok := tx["request"].(map[string]interface{}); ok {
		req = r
	}
	var resp map[string]interface{}
	if r, ok := tx["response"].(map[string]interface{}); ok {
		resp = r
	}

	if req != nil {
		ev.Method = strField(req, "method")
		ev.URI = strField(req, "uri", "http_request_line")
		hdrs := normalizeHeaders(req["headers"])
		if ev.Host == "" || looksLikeIP(ev.Host) {
			if h := headerGet(hdrs, "Host", "host"); h != "" {
				ev.Host = h
			}
		}
		ev.UserAgent = headerGet(hdrs, "User-Agent", "user-agent")
		if cl := headerGet(hdrs, "Content-Length", "content-length"); cl != "" {
			ev.ReqLen, _ = strconv.Atoi(strings.TrimSpace(cl))
		}
		if n := intField(req, "body_length", "request_body_length", "content_length"); n > 0 && ev.ReqLen <= 0 {
			ev.ReqLen = n
		}
		body := requestBodyString(req)
		if body != "" {
			if ev.ReqLen <= 0 {
				ev.ReqLen = len(body)
			}
			ev.BodyPreview = truncate(sanitizePreview(body), 512)
		}
	}
	if ev.Host == "" || looksLikeIP(ev.Host) {
		if h := strField(tx, "server_name", "hostname"); h != "" && !looksLikeIP(h) {
			ev.Host = h
		}
	}

	if resp != nil {
		ev.Status = intField(resp, "http_code", "status", "code")
		rh := normalizeHeaders(resp["headers"])
		if cl := headerGet(rh, "Content-Length", "content-length"); cl != "" {
			ev.RespLen, _ = strconv.Atoi(strings.TrimSpace(cl))
		}
		if n := intField(resp, "body_length", "content_length", "bytes_sent"); n > 0 && ev.RespLen <= 0 {
			ev.RespLen = n
		}
		if b := requestBodyString(resp); b != "" && ev.RespLen <= 0 {
			ev.RespLen = len(b)
		}
	}
	if ev.Status == 0 {
		ev.Status = intField(tx, "http_code", "status", "response_code")
	}
	if n := intField(tx, "bytes_sent", "response_body_length"); n > 0 && ev.RespLen <= 0 {
		ev.RespLen = n
	}

	var msgs []string
	var ids []string
	idSet := map[string]bool{}
	var hits []MatchHit
	fieldSet := map[string]bool{}

	collectMessages := func(arr []interface{}) {
		for _, it := range arr {
			switch v := it.(type) {
			case string:
				msgs = append(msgs, v)
			case map[string]interface{}:
				hit := MatchHit{
					Message:  strField(v, "message", "msg"),
					RuleID:   strField(v, "ruleId", "rule_id", "id"),
					Severity: strings.ToUpper(strField(v, "severity")),
					Data:     strField(v, "data"),
					Match:    strField(v, "match"),
				}
				if det, ok := v["details"].(map[string]interface{}); ok {
					if hit.RuleID == "" {
						hit.RuleID = strField(det, "ruleId", "rule_id", "id")
					}
					if hit.Data == "" {
						hit.Data = strField(det, "data")
					}
					if hit.Match == "" {
						hit.Match = strField(det, "match")
					}
					if hit.Severity == "" {
						hit.Severity = strings.ToUpper(strField(det, "severity"))
					}
					if hit.Message == "" {
						hit.Message = strField(det, "msg", "message")
					}
					ref := strField(det, "reference", "ref")
					hit.Variable, hit.Field = parseVarRef(ref)
					if hit.Variable == "" {
						hit.Variable, hit.Field = parseVarRef(hit.Match + " " + hit.Data)
					}
					if tags, ok := det["tags"].([]interface{}); ok {
						for _, t := range tags {
							if s, ok := t.(string); ok && s != "" {
								hit.Tags = append(hit.Tags, s)
							}
						}
					}
				}
				if hit.Variable == "" {
					hit.Variable, hit.Field = parseVarRef(hit.Message + " " + hit.Match + " " + hit.Data)
				}
				// CRS logdata: "Matched Data: … found within ARGS_POST:x"
				if hit.Match == "" || hit.Data == "" || hit.Variable == "" {
					blob := hit.Message + " " + hit.Data + " " + hit.Match
					if m := matchedDataRe.FindStringSubmatch(blob); len(m) >= 3 {
						if hit.Match == "" {
							hit.Match = strings.TrimSpace(m[1])
						}
						if hit.Data == "" {
							hit.Data = truncate("Matched Data: "+strings.TrimSpace(m[1]), 400)
						}
						if hit.Variable == "" {
							hit.Variable, hit.Field = parseVarRef(m[2])
							if hit.Variable == "" {
								hit.Variable = m[2]
								if i := strings.IndexByte(m[2], ':'); i >= 0 && i+1 < len(m[2]) {
									hit.Field = m[2][i+1:]
								}
							}
						}
					}
				}
				if hit.Message != "" {
					msgs = append(msgs, hit.Message)
				} else if hit.Data != "" {
					msgs = append(msgs, hit.Data)
				}
				if hit.RuleID != "" && !idSet[hit.RuleID] {
					idSet[hit.RuleID] = true
					ids = append(ids, hit.RuleID)
				}
				if hit.Severity != "" {
					ev.Severity = NormalizeSeverity(hit.Severity)
				}
				if hit.Field != "" && !fieldSet[hit.Field] {
					fieldSet[hit.Field] = true
					ev.AttackFields = append(ev.AttackFields, hit.Field)
				} else if hit.Variable != "" && !fieldSet[hit.Variable] {
					fieldSet[hit.Variable] = true
					ev.AttackFields = append(ev.AttackFields, hit.Variable)
				}
				if hit.RuleID != "" || hit.Message != "" || hit.Data != "" || hit.Variable != "" {
					hit.Data = truncate(hit.Data, 400)
					hit.Match = truncate(hit.Match, 400)
					hit.Message = truncate(hit.Message, 300)
					hits = append(hits, hit)
				}
			}
		}
	}

	if m, ok := tx["messages"].([]interface{}); ok {
		collectMessages(m)
	}
	if ad, ok := tx["audit_data"].(map[string]interface{}); ok {
		if m, ok := ad["messages"].([]interface{}); ok {
			collectMessages(m)
		}
	}
	if m, ok := root["messages"].([]interface{}); ok {
		collectMessages(m)
	}

	if len(ids) == 0 {
		for _, m := range ruleIDBlobRe.FindAllStringSubmatch(line, 8) {
			if !idSet[m[1]] {
				idSet[m[1]] = true
				ids = append(ids, m[1])
			}
		}
	}
	ev.RuleIDs = ids
	if len(msgs) > 8 {
		msgs = msgs[:8]
	}
	ev.Messages = msgs
	if len(hits) > 12 {
		hits = hits[:12]
	}
	ev.Matches = hits
	if ev.Severity == "" || NormalizeSeverity(ev.Severity) == "INFO" {
		low := strings.ToLower(line)
		switch {
		case strings.Contains(low, "critical"):
			ev.Severity = "CRITICAL"
		case strings.Contains(low, "warning"), strings.Contains(low, "error"):
			ev.Severity = "WARNING"
		case strings.Contains(low, "notice"):
			ev.Severity = "NOTICE"
		}
	}
	ev.Severity = NormalizeSeverity(ev.Severity)
	return ev
}

func looksLikeIP(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Count(s, ".") == 3 {
		ok := true
		for _, p := range strings.Split(s, ".") {
			if _, err := strconv.Atoi(p); err != nil {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return strings.Contains(s, ":") && !strings.Contains(s, ".")
}

func normalizeHeaders(raw interface{}) map[string]string {
	out := map[string]string{}
	switch h := raw.(type) {
	case map[string]interface{}:
		for k, v := range h {
			switch t := v.(type) {
			case string:
				out[k] = t
			case float64:
				out[k] = strconv.FormatInt(int64(t), 10)
			case []interface{}:
				if len(t) > 0 {
					if s, ok := t[0].(string); ok {
						out[k] = s
					}
				}
			}
		}
	case []interface{}:
		for _, it := range h {
			m, ok := it.(map[string]interface{})
			if !ok {
				continue
			}
			name := strField(m, "name", "key", "header")
			val := strField(m, "value", "val")
			if name != "" && val != "" {
				out[name] = val
			}
		}
	}
	return out
}

func headerGet(h map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := h[k]; v != "" {
			return v
		}
	}
	lower := map[string]string{}
	for k, v := range h {
		lower[strings.ToLower(k)] = v
	}
	for _, k := range keys {
		if v := lower[strings.ToLower(k)]; v != "" {
			return v
		}
	}
	return ""
}

func requestBodyString(m map[string]interface{}) string {
	for _, k := range []string{"body", "request_body", "body_base64"} {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				return t
			case []interface{}:
				var b strings.Builder
				for _, x := range t {
					if s, ok := x.(string); ok {
						b.WriteString(s)
					}
				}
				return b.String()
			}
		}
	}
	return ""
}

func sanitizePreview(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

func parseVarRef(blob string) (variable, field string) {
	blob = strings.TrimSpace(blob)
	if blob == "" {
		return "", ""
	}
	if m := matchedDataRe.FindStringSubmatch(blob); len(m) >= 3 {
		variable = m[2]
		if i := strings.IndexByte(variable, ':'); i >= 0 && i+1 < len(variable) {
			field = variable[i+1:]
		}
		return variable, field
	}
	if m := varRefRe.FindStringSubmatch(blob); len(m) >= 2 {
		variable = m[1]
		if len(m) >= 3 && m[2] != "" {
			field = m[2]
		}
		return variable, field
	}
	if m := fieldInMsgRe.FindStringSubmatch(blob); len(m) >= 2 {
		variable = m[1]
		if len(m) >= 3 && m[2] != "" {
			field = m[2]
		} else if i := strings.IndexByte(variable, ':'); i >= 0 && i+1 < len(variable) {
			field = variable[i+1:]
		}
		return variable, field
	}
	return "", ""
}

func AttackSummary(events []AttackEvent) map[string]interface{} {
	byIP := map[string]int{}
	byRule := map[string]int{}
	bySev := map[string]int{}
	byCountry := map[string]int{}
	for _, e := range events {
		if e.ClientIP != "" {
			byIP[e.ClientIP]++
		}
		sev := NormalizeSeverity(e.Severity)
		if sev != "" {
			bySev[sev]++
		}
		if e.Country != "" {
			byCountry[e.Country]++
		}
		for _, id := range e.RuleIDs {
			label := RuleAttackLabel(id)
			if label != "" && label != id {
				byRule[id+" · "+label]++
			} else {
				byRule[id]++
			}
		}
	}
	return map[string]interface{}{
		"total":       len(events),
		"by_ip":       topN(byIP, 10),
		"by_rule":     topN(byRule, 10),
		"by_severity": bySev,
		"by_country":  topN(byCountry, 15),
		"trend":       AttackTrend(events, 24),
	}
}

// NormalizeSeverity 将 ModSecurity 数字级别统一为名称，避免总览出现 0/2 与 CRITICAL 混排。
func NormalizeSeverity(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	switch strings.ToUpper(s) {
	case "0", "EMERGENCY":
		return "EMERGENCY"
	case "1", "ALERT":
		return "ALERT"
	case "2", "CRITICAL":
		return "CRITICAL"
	case "3", "ERROR":
		return "ERROR"
	case "4", "WARNING":
		return "WARNING"
	case "5", "NOTICE":
		return "NOTICE"
	case "6", "INFO":
		return "INFO"
	case "7", "DEBUG":
		return "DEBUG"
	default:
		return strings.ToUpper(s)
	}
}

// RuleAttackLabel 按 CRS / Ma-WAF 规则号段给出可读攻击类型。
func RuleAttackLabel(id string) string {
	id = strings.TrimSpace(id)
	n, err := strconv.Atoi(id)
	if err != nil {
		return id
	}
	switch {
	case n >= 942000 && n < 943000:
		return "SQL注入"
	case n >= 941000 && n < 942000:
		return "XSS"
	case n >= 930000 && n < 931000:
		return "路径穿越/LFI"
	case n >= 931000 && n < 932000:
		return "远程文件包含"
	case n >= 932000 && n < 933000:
		return "命令注入/RCE"
	case n >= 933000 && n < 934000:
		return "PHP注入"
	case n >= 934000 && n < 935000:
		return "NodeJS注入"
	case n >= 943000 && n < 944000:
		return "会话固定"
	case n >= 944000 && n < 945000:
		return "Java攻击"
	case n >= 920000 && n < 921000:
		return "协议违规"
	case n >= 921000 && n < 922000:
		return "协议攻击"
	case n >= 913000 && n < 914000:
		return "扫描器探测"
	case n >= 110000 && n < 110100:
		return "上传策略"
	case n >= 110100 && n < 110200:
		return "PII策略"
	case n >= 110200 && n < 110300:
		return "Bot防护"
	case n >= 110300 && n < 110400:
		return "会话/登录防护"
	case n >= 120000 && n < 130000:
		return "虚拟补丁"
	case n >= 130000 && n < 131000:
		return "OpenAPI"
	case n >= 140000 && n < 150000:
		return "自定义规则"
	default:
		return ""
	}
}

// AttackTrend 按小时桶聚合最近 hours 小时（不足则按事件时间推导）。
func AttackTrend(events []AttackEvent, hours int) []map[string]interface{} {
	if hours <= 0 {
		hours = 24
	}
	now := time.Now().Truncate(time.Hour)
	buckets := map[string]int{}
	labels := make([]string, 0, hours)
	for i := hours - 1; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		lab := t.Format("2006-01-02T15")
		labels = append(labels, lab)
		buckets[lab] = 0
	}
	for _, e := range events {
		t := parseEventTime(e.Time)
		if t.IsZero() {
			continue
		}
		lab := t.Truncate(time.Hour).Format("2006-01-02T15")
		if _, ok := buckets[lab]; ok {
			buckets[lab]++
		}
	}
	out := make([]map[string]interface{}, 0, len(labels))
	for _, lab := range labels {
		out = append(out, map[string]interface{}{"key": lab, "count": buckets[lab]})
	}
	return out
}

func parseEventTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"Mon Jan 2 15:04:05 2006",
		"02/Jan/2006:15:04:05 -0700",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t
		}
	}
	return time.Time{}
}

func topN(m map[string]int, n int) []map[string]interface{} {
	type kv struct {
		k string
		v int
	}
	arr := make([]kv, 0, len(m))
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[j].v > arr[i].v {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([]map[string]interface{}, 0, len(arr))
	for _, x := range arr {
		out = append(out, map[string]interface{}{"key": x.k, "count": x.v})
	}
	return out
}

func strField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if strings.Contains(k, ".") {
			parts := strings.SplitN(k, ".", 2)
			if nested, ok := m[parts[0]].(map[string]interface{}); ok {
				if s := strField(nested, parts[1]); s != "" {
					return s
				}
			}
			continue
		}
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return strconv.FormatInt(int64(t), 10)
			}
		}
	}
	return ""
}

func intField(m map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case float64:
				return int(t)
			case int:
				return t
			case string:
				n, _ := strconv.Atoi(t)
				return n
			}
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TailAuditRawLines 供内部复用
func TailAuditRawLines(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > limit*2 {
			lines = lines[len(lines)-limit:]
		}
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, sc.Err()
}
