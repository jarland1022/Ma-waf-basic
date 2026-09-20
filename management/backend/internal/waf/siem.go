package waf

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SendSIEM 向 syslog 发送一条 CEF（Imperva 类 SIEM 对接最小实现）。
func SendSIEM(addr, proto, text string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return fmt.Errorf("未配置 siem_addr")
	}
	if proto == "" {
		proto = "udp"
	}
	proto = strings.ToLower(proto)
	if proto != "udp" && proto != "tcp" {
		return fmt.Errorf("siem_proto 须为 udp 或 tcp")
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial(proto, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	cef := fmt.Sprintf("CEF:0|Ma-WAF|WAF|1.0|100|%s|5|msg=%s\n",
		escapeCEF(text), escapeCEF(text))
	_, err = conn.Write([]byte(cef))
	return err
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}

func FormatAttackCEF(ev AttackEvent) string {
	return fmt.Sprintf("CEF:0|Ma-WAF|WAF|1.0|%s|WAF Hit|%s|src=%s request=%s %s cs1=%s",
		firstRule(ev), sevScore(ev.Severity), ev.ClientIP, ev.Method, ev.URI, strings.Join(ev.RuleIDs, ","))
}

func firstRule(ev AttackEvent) string {
	if len(ev.RuleIDs) > 0 {
		return ev.RuleIDs[0]
	}
	return "0"
}

func sevScore(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "10"
	case "WARNING", "ERROR":
		return "6"
	default:
		return "3"
	}
}
