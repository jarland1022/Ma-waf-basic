package audit

import (
        "crypto/sha256"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "os"
        "sync"
        "time"
)

// Chain 审计防篡改链式哈希
type Chain struct {
        path string
        mu   sync.Mutex
}

func NewChain(path string) *Chain {
        return &Chain{path: path}
}

func (c *Chain) Append(event map[string]interface{}) (string, error) {
        c.mu.Lock()
        defer c.mu.Unlock()
        prev := hex.EncodeToString(make([]byte, 32))
        if b, err := os.ReadFile(c.path); err == nil && len(b) > 0 {
                lines := splitLastNonEmpty(string(b))
                if lines != "" {
                        var last map[string]interface{}
                        if json.Unmarshal([]byte(lines), &last) == nil {
                                if h, ok := last["hash"].(string); ok {
                                        prev = h
                                }
                        }
                }
        }
        ts := time.Now().UTC().Format(time.RFC3339)
        payload, _ := json.Marshal(event)
        sum := sha256.Sum256([]byte(prev + "|" + string(payload) + "|" + ts))
        digest := hex.EncodeToString(sum[:])
        rec := map[string]interface{}{
                "ts":    ts,
                "prev":  prev,
                "hash":  digest,
                "event": event,
        }
        line, _ := json.Marshal(rec)
        f, err := os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
        if err != nil {
                return "", err
        }
        defer f.Close()
        if _, err := f.Write(append(line, '\n')); err != nil {
                return "", err
        }
        return digest, nil
}

// Verify 校验链式哈希完整性；返回记录数与首个错误位置。
func (c *Chain) Verify() (count int, ok bool, detail string) {
        c.mu.Lock()
        defer c.mu.Unlock()
        b, err := os.ReadFile(c.path)
        if err != nil {
                if os.IsNotExist(err) {
                        return 0, true, "chain empty"
                }
                return 0, false, err.Error()
        }
        prev := hex.EncodeToString(make([]byte, 32))
        lines := 0
        start := 0
        s := string(b)
        for i := 0; i <= len(s); i++ {
                if i < len(s) && s[i] != '\n' {
                        continue
                }
                line := s[start:i]
                start = i + 1
                if line == "" {
                        continue
                }
                lines++
                var rec map[string]interface{}
                if json.Unmarshal([]byte(line), &rec) != nil {
                        return lines, false, fmt.Sprintf("line %d: invalid json", lines)
                }
                p, _ := rec["prev"].(string)
                h, _ := rec["hash"].(string)
                ts, _ := rec["ts"].(string)
                ev, _ := json.Marshal(rec["event"])
                if p != prev {
                        return lines, false, fmt.Sprintf("line %d: prev mismatch", lines)
                }
                sum := sha256.Sum256([]byte(prev + "|" + string(ev) + "|" + ts))
                expect := hex.EncodeToString(sum[:])
                if h != expect {
                        return lines, false, fmt.Sprintf("line %d: hash mismatch", lines)
                }
                prev = h
        }
        return lines, true, "ok"
}

func splitLastNonEmpty(s string) string {
        var last string
        start := 0
        for i := 0; i < len(s); i++ {
                if s[i] == '\n' {
                        line := s[start:i]
                        if line != "" {
                                last = line
                        }
                        start = i + 1
                }
        }
        if start < len(s) && s[start:] != "" {
                last = s[start:]
        }
        return last
}
