package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ma-waf/management/internal/waf"
)

// AuditIndex 用 JSONL + 字节偏移做审计增量索引（纯标准库，无需 CGO / modernc sqlite）。
// 数据文件与 api.yaml 的 sqlite_path 同目录：ma-waf.db.attacks.jsonl / .offset
type AuditIndex struct {
	basePath  string // 原 sqlite_path，用作索引文件前缀
	auditPath string
	mu        sync.Mutex
}

func NewAuditIndex(dbPath, auditPath string) (*AuditIndex, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("index path empty")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o750); err != nil {
		return nil, err
	}
	return &AuditIndex{basePath: dbPath, auditPath: auditPath}, nil
}

func (a *AuditIndex) Close() error { return nil }

func (a *AuditIndex) indexFile() string  { return a.basePath + ".attacks.jsonl" }
func (a *AuditIndex) offsetFile() string { return a.basePath + ".offset" }

func (a *AuditIndex) getOffset() int64 {
	b, err := os.ReadFile(a.offsetFile())
	if err != nil {
		return 0
	}
	var n int64
	_, _ = fmt.Sscanf(string(b), "%d", &n)
	return n
}

func (a *AuditIndex) setOffset(n int64) {
	_ = os.WriteFile(a.offsetFile(), []byte(fmt.Sprintf("%d\n", n)), 0o640)
}

// Sync 从审计日志当前 offset 增量追加到索引。
func (a *AuditIndex) Sync() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.Open(a.auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	off := a.getOffset()
	if st.Size() < off {
		off = 0 // 日志轮转
		_ = os.WriteFile(a.indexFile(), nil, 0o640)
	}
	if _, err := f.Seek(off, 0); err != nil {
		return 0, err
	}

	out, err := os.OpenFile(a.indexFile(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	enc := json.NewEncoder(out)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		ev := waf.ParseAuditLineForIndex(line)
		if err := enc.Encode(ev); err != nil {
			return n, err
		}
		n++
	}
	if err := sc.Err(); err != nil {
		return n, err
	}
	newOff, _ := f.Seek(0, 1)
	a.setOffset(newOff)
	if n > 0 {
		a.trimLocked(20000)
	}
	return n, nil
}

func (a *AuditIndex) trimLocked(keep int) {
	if keep <= 0 {
		return
	}
	path := a.indexFile()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	_ = f.Close()
	if len(lines) <= keep {
		return
	}
	lines = lines[len(lines)-keep:]
	tmp := path + ".tmp"
	w, err := os.Create(tmp)
	if err != nil {
		return
	}
	for _, ln := range lines {
		_, _ = w.WriteString(ln + "\n")
	}
	_ = w.Close()
	_ = os.Rename(tmp, path)
}

// List 返回最近 limit 条（文件尾部，新在前）。
func (a *AuditIndex) List(limit int) ([]waf.AttackEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	_, _ = a.Sync()

	f, err := os.Open(a.indexFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > limit*2 {
			lines = lines[len(lines)-limit:]
		}
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	out := make([]waf.AttackEvent, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		var ev waf.AttackEvent
		if json.Unmarshal([]byte(lines[i]), &ev) != nil {
			continue
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

func (a *AuditIndex) StartLoop(every time.Duration, stop <-chan struct{}) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		_, _ = a.Sync()
		for {
			select {
			case <-t.C:
				_, _ = a.Sync()
			case <-stop:
				return
			}
		}
	}()
}

func (a *AuditIndex) Count() int {
	f, err := os.Open(a.indexFile())
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	return n
}
