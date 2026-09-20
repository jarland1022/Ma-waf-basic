package metrics

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	Goroutines   int     `json:"goroutines"`
	UptimeSec    float64 `json:"uptime_sec"`
	Requests     uint64  `json:"api_requests"`
	BlockApprox  int     `json:"block_approx_403"`
	Samples      int     `json:"access_samples"`
	AvgLatency   float64 `json:"avg_request_time"`
	InterceptPct float64 `json:"intercept_rate_pct"`

	// 主机
	Load1        float64 `json:"load1,omitempty"`
	MemTotalMB   float64 `json:"mem_total_mb,omitempty"`
	MemAvailMB   float64 `json:"mem_avail_mb,omitempty"`
	MemUsedPct   float64 `json:"mem_used_pct,omitempty"`
	CPUCores     int     `json:"cpu_cores,omitempty"`

	// Nginx stub_status
	NginxActive   int    `json:"nginx_active,omitempty"`
	NginxReading  int    `json:"nginx_reading,omitempty"`
	NginxWriting  int    `json:"nginx_writing,omitempty"`
	NginxWaiting  int    `json:"nginx_waiting,omitempty"`
	NginxRequests uint64 `json:"nginx_accepts,omitempty"`
	NginxStatusOK bool   `json:"nginx_status_ok"`
	NginxStatusErr string `json:"nginx_status_err,omitempty"`
}

type Registry struct {
	start    time.Time
	requests uint64
}

func New() *Registry {
	return &Registry{start: time.Now()}
}

func (r *Registry) Inc() { atomic.AddUint64(&r.requests, 1) }

func (r *Registry) Snapshot(accessLog, nginxStatusURL string) Snapshot {
	s := Snapshot{
		Goroutines: runtime.NumGoroutine(),
		UptimeSec:  time.Since(r.start).Seconds(),
		Requests:   atomic.LoadUint64(&r.requests),
		CPUCores:   runtime.NumCPU(),
	}
	fillAccess(&s, accessLog)
	fillHost(&s)
	fillNginxStatus(&s, nginxStatusURL)
	return s
}

// PrometheusText OpenMetrics/Prometheus 文本格式。
func (r *Registry) PrometheusText(accessLog, nginxStatusURL string) string {
	s := r.Snapshot(accessLog, nginxStatusURL)
	var b strings.Builder
	w := func(name, help, typ string, val float64) {
		b.WriteString("# HELP " + name + " " + help + "\n")
		b.WriteString("# TYPE " + name + " " + typ + "\n")
		b.WriteString(fmt.Sprintf("%s %g\n", name, val))
	}
	w("ma_waf_api_up", "API process up", "gauge", 1)
	w("ma_waf_api_uptime_seconds", "API uptime", "gauge", s.UptimeSec)
	w("ma_waf_api_requests_total", "API requests handled", "counter", float64(s.Requests))
	w("ma_waf_goroutines", "Go goroutines", "gauge", float64(s.Goroutines))
	w("ma_waf_access_samples", "Access log samples", "gauge", float64(s.Samples))
	w("ma_waf_intercept_rate_pct", "Approx intercept rate percent", "gauge", s.InterceptPct)
	w("ma_waf_avg_request_time_seconds", "Avg request time from access log", "gauge", s.AvgLatency)
	w("ma_waf_host_load1", "Host load average 1m", "gauge", s.Load1)
	w("ma_waf_host_mem_used_pct", "Host memory used percent", "gauge", s.MemUsedPct)
	w("ma_waf_nginx_active_connections", "Nginx active connections", "gauge", float64(s.NginxActive))
	w("ma_waf_nginx_reading", "Nginx reading", "gauge", float64(s.NginxReading))
	w("ma_waf_nginx_writing", "Nginx writing", "gauge", float64(s.NginxWriting))
	w("ma_waf_nginx_waiting", "Nginx waiting", "gauge", float64(s.NginxWaiting))
	ok := 0.0
	if s.NginxStatusOK {
		ok = 1
	}
	w("ma_waf_nginx_status_up", "Nginx stub_status reachable", "gauge", ok)
	return b.String()
}

func fillAccess(s *Snapshot, accessLog string) {
	f, err := os.Open(accessLog)
	if err != nil {
		return
	}
	defer f.Close()
	var n int
	var sum float64
	var blocked int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var o map[string]interface{}
		if json.Unmarshal(sc.Bytes(), &o) != nil {
			continue
		}
		n++
		if st, ok := o["status"].(float64); ok {
			if int(st) == 403 || int(st) == 429 {
				blocked++
			}
		}
		if rt, ok := o["request_time"].(float64); ok {
			sum += rt
		}
	}
	s.Samples = n
	s.BlockApprox = blocked
	if n > 0 {
		s.AvgLatency = sum / float64(n)
		s.InterceptPct = float64(blocked) * 100 / float64(n)
	}
}

func fillHost(s *Snapshot) {
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail float64
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			v, _ := strconv.ParseFloat(fields[1], 64) // kB
			switch fields[0] {
			case "MemTotal:":
				total = v / 1024
			case "MemAvailable:":
				avail = v / 1024
			}
		}
		s.MemTotalMB = total
		s.MemAvailMB = avail
		if total > 0 {
			s.MemUsedPct = (total - avail) * 100 / total
		}
	}
}

func fillNginxStatus(s *Snapshot, url string) {
	if strings.TrimSpace(url) == "" {
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		s.NginxStatusErr = err.Error()
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		s.NginxStatusErr = err.Error()
		return
	}
	// Active connections: N
	// server accepts handled requests
	//  Reading: X Writing: Y Waiting: Z
	text := string(body)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Active connections:") {
			s.NginxActive, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Active connections:")))
		}
		if strings.HasPrefix(line, "Reading:") {
			// Reading: 0 Writing: 1 Waiting: 2
			parts := strings.Fields(line)
			for i := 0; i+1 < len(parts); i++ {
				switch parts[i] {
				case "Reading:":
					s.NginxReading, _ = strconv.Atoi(parts[i+1])
				case "Writing:":
					s.NginxWriting, _ = strconv.Atoi(parts[i+1])
				case "Waiting:":
					s.NginxWaiting, _ = strconv.Atoi(parts[i+1])
				}
			}
		}
		fields := strings.Fields(line)
		if len(fields) == 3 {
			if a, e1 := strconv.ParseUint(fields[0], 10, 64); e1 == nil {
				if _, e2 := strconv.ParseUint(fields[1], 10, 64); e2 == nil {
					if c, e3 := strconv.ParseUint(fields[2], 10, 64); e3 == nil {
						s.NginxRequests = a
						_ = c
					}
				}
			}
		}
	}
	s.NginxStatusOK = true
}
