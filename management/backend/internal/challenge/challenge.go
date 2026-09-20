package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const CookieName = "ma_waf_js"
const DefaultTTL = 3600

// Issue 签发 HMAC 挑战 Cookie：v1.<exp>.<mac>
func Issue(secret string, ttlSec int) (value string, maxAge int, err error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", 0, fmt.Errorf("challenge secret empty")
	}
	if ttlSec <= 0 {
		ttlSec = DefaultTTL
	}
	exp := time.Now().Add(time.Duration(ttlSec) * time.Second).Unix()
	mac := sign(secret, exp)
	return fmt.Sprintf("v1.%d.%s", exp, mac), ttlSec, nil
}

// Verify 校验 Cookie 值（兼容旧值 "1"：视为弱通过，仅挡无 JS）。
func Verify(secret, raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	if raw == "1" {
		return true
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || exp < time.Now().Unix() {
		return false
	}
	want := sign(strings.TrimSpace(secret), exp)
	return hmac.Equal([]byte(want), []byte(parts[2]))
}

func sign(secret string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("ma-waf-js|" + strconv.FormatInt(exp, 10)))
	sum := mac.Sum(nil)
	// URL-safe 短签名
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// SoftBotUA 与 nginx map 中 soft bot 启发式对齐（供 verify 使用）。
func SoftBotUA(ua string) bool {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return true
	}
	low := strings.ToLower(ua)
	prefixes := []string{"curl/", "wget/", "python-requests", "go-http-client", "java/", "libwww"}
	for _, p := range prefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// HexFingerprint 用于运维展示（不暴露完整密钥）。
func HexFingerprint(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:4])
}
