package auth

import (
        "errors"
        "net"
        "sync"
        "time"

        "github.com/golang-jwt/jwt/v5"
        "github.com/pquerna/otp/totp"
        "golang.org/x/crypto/bcrypt"
)

type Service struct {
        secret         []byte
        adminUser      string
        adminHash      string
        totpSecret     string
        maxFail        int
        lockout        time.Duration
        mu             sync.Mutex
        fails          map[string]int
        lockedUntil    map[string]time.Time
}

func New(secret, user, hash, totpSecret string, maxFail, lockoutSec int) *Service {
        return &Service{
                secret:      []byte(secret),
                adminUser:   user,
                adminHash:   hash,
                totpSecret:  totpSecret,
                maxFail:     maxFail,
                lockout:     time.Duration(lockoutSec) * time.Second,
                fails:       map[string]int{},
                lockedUntil: map[string]time.Time{},
        }
}

func (s *Service) BootstrapHash(plain string) (string, error) {
        b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
        return string(b), err
}

func (s *Service) CheckPassword(plain string) bool {
        if s.adminHash == "" {
                // 开发默认：仅当环境未配置时接受 admin/admin（生产必须设置 hash）
                return plain == "admin" && s.adminUser == "admin"
        }
        return bcrypt.CompareHashAndPassword([]byte(s.adminHash), []byte(plain)) == nil
}

func (s *Service) Locked(ip string) bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        until, ok := s.lockedUntil[ip]
        return ok && time.Now().Before(until)
}

func (s *Service) RegisterFail(ip string) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.fails[ip]++
        if s.fails[ip] >= s.maxFail {
                s.lockedUntil[ip] = time.Now().Add(s.lockout)
                s.fails[ip] = 0
        }
}

func (s *Service) RegisterSuccess(ip string) {
        s.mu.Lock()
        defer s.mu.Unlock()
        delete(s.fails, ip)
        delete(s.lockedUntil, ip)
}

func (s *Service) VerifyTOTP(code string) bool {
        if s.totpSecret == "" {
                return true // 未启用 2FA
        }
        return totp.Validate(code, s.totpSecret)
}

type Claims struct {
        User string `json:"user"`
        jwt.RegisteredClaims
}

func (s *Service) IssueToken(user string) (string, error) {
        claims := Claims{
                User: user,
                RegisteredClaims: jwt.RegisteredClaims{
                        ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
                        IssuedAt:  jwt.NewNumericDate(time.Now()),
                },
        }
        t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        return t.SignedString(s.secret)
}

func (s *Service) ParseToken(tokenStr string) (*Claims, error) {
        t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
                return s.secret, nil
        })
        if err != nil {
                return nil, err
        }
        c, ok := t.Claims.(*Claims)
        if !ok || !t.Valid {
                return nil, errors.New("invalid token")
        }
        return c, nil
}

func ClientIP(remote string) string {
        host, _, err := net.SplitHostPort(remote)
        if err != nil {
                return remote
        }
        return host
}
