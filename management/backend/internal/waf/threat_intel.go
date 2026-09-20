package waf

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchThreatIntelURL 从 URL 拉取 IOC 文本并合并进黑名单。
func (m *Manager) FetchThreatIntelURL(url string, doReload bool) (int, error) {
	url = strings.TrimSpace(url)
	if url == "" || !(strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")) {
		return 0, fmt.Errorf("url 须为 http(s)")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("拉取失败 HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, err
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return 0, fmt.Errorf("URL 内容无有效 IOC")
	}
	return m.MergeThreatIntel(lines, doReload)
}
