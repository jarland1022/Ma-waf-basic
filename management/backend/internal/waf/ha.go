package waf

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// HAStatus 双机 VIP / keepalived 只读视图（模板级 HA 的可观测补齐）。
type HAStatus struct {
	KeepalivedRunning bool     `json:"keepalived_running"`
	ConfigPresent     bool     `json:"config_present"`
	ConfigPath        string   `json:"config_path,omitempty"`
	VIPs              []string `json:"vips"`
	LocalHasVIP       bool     `json:"local_has_vip"`
	HealthOK          bool     `json:"health_ok"`
	HealthDetail      string   `json:"health_detail"`
	RoleGuess         string   `json:"role_guess"` // master|backup|unknown|standalone
	Hint              string   `json:"hint"`
}

func (m *Manager) productRoot() string {
	return filepath.Clean(filepath.Join(m.BackupDir, ".."))
}

func (m *Manager) HAStatus() HAStatus {
	st := HAStatus{
		Hint:      "双机需部署 configs/ha/keepalived.conf.example；管理面勿挂 VIP",
		RoleGuess: "standalone",
		VIPs:      []string{},
	}
	candidates := []string{
		"/etc/keepalived/keepalived.conf",
		filepath.Join(m.productRoot(), "conf", "keepalived.conf"),
		filepath.Join(m.productRoot(), "configs", "ha", "keepalived.conf"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			st.ConfigPresent = true
			st.ConfigPath = p
			st.VIPs = parseKeepalivedVIPs(p)
			break
		}
	}
	st.KeepalivedRunning = processRunning("keepalived")
	if len(st.VIPs) > 0 {
		st.LocalHasVIP = localHasAnyIP(st.VIPs)
	}
	ok, detail := m.localDataPlaneHealth()
	st.HealthOK = ok
	st.HealthDetail = detail
	switch {
	case !st.ConfigPresent && !st.KeepalivedRunning:
		st.RoleGuess = "standalone"
	case st.LocalHasVIP && st.KeepalivedRunning:
		st.RoleGuess = "master"
	case st.KeepalivedRunning && !st.LocalHasVIP:
		st.RoleGuess = "backup"
	default:
		st.RoleGuess = "unknown"
	}
	return st
}

func processRunning(name string) bool {
	out, err := exec.Command("pgrep", "-x", name).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) != ""
}

var vipLineRe = regexp.MustCompile(`(?i)^\s*([0-9a-fA-F:.]+)(?:/\d+)?\s*$`)

func parseKeepalivedVIPs(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	inVIP := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "virtual_ipaddress") {
			inVIP = true
			continue
		}
		if inVIP {
			if strings.HasPrefix(line, "}") {
				inVIP = false
				continue
			}
			if m := vipLineRe.FindStringSubmatch(line); len(m) == 2 {
				out = append(out, m[1])
			}
		}
	}
	return out
}

func localHasAnyIP(ips []string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	want := map[string]bool{}
	for _, ip := range ips {
		want[ip] = true
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if want[ip.String()] {
				return true
			}
		}
	}
	return false
}

func (m *Manager) localDataPlaneHealth() (bool, string) {
	if !processRunning("nginx") {
		return false, "nginx 未运行"
	}
	if err := m.TestConfig(); err != nil {
		return false, "nginx -t 失败"
	}
	client := &net.Dialer{Timeout: 2 * time.Second}
	targets := []string{"127.0.0.1:80", "127.0.0.1:8081"}
	for _, t := range targets {
		conn, err := client.Dial("tcp", t)
		if err == nil {
			_ = conn.Close()
			return true, "本机数据面端口可达 (" + t + ")"
		}
	}
	return false, "本机 80/8081 均不可达"
}

// EmergencyBypass 紧急旁路：切引擎模式并写入审计旁路记录。
func (m *Manager) EmergencyBypass(mode, reason, user string) error {
	if err := m.SetEngineMode(mode); err != nil {
		return err
	}
	rec := map[string]string{
		"time":   time.Now().UTC().Format(time.RFC3339),
		"mode":   mode,
		"reason": reason,
		"user":   user,
	}
	path := filepath.Join(m.productRoot(), "var", "lib", "emergency.jsonl")
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	b, _ := json.Marshal(rec)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
	return nil
}
