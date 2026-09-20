package main

import (
	"log"
	"os"

	"github.com/ma-waf/management/internal/api"
	"github.com/ma-waf/management/internal/config"
)

func main() {
	cfgPath := os.Getenv("MA_WAF_API_CONFIG")
	if cfgPath == "" {
		for _, p := range []string{
			"/usr/local/Ma-waf/conf/api.yaml",
			"/usr/local/ma-waf/conf/api.yaml",
		} {
			if _, err := os.Stat(p); err == nil {
				cfgPath = p
				break
			}
		}
		if cfgPath == "" {
			cfgPath = "/usr/local/Ma-waf/conf/api.yaml"
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("config load warning: %v, using defaults", err)
		cfg = config.Defaults()
	}
	normalizePaths(&cfg)
	if err := cfg.ValidateStrict(); err != nil {
		log.Fatalf("refusing to start: %v", err)
	}
	r := api.NewRouter(cfg)
	addr := cfg.Listen
	log.Printf("ma-waf-api listening on %s (config=%s console=%s root=%s)", addr, cfgPath, cfg.ConsoleDir, cfg.ProductRoot)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func normalizePaths(cfg *config.Config) {
	if cfg.ProductRoot == "" || cfg.ProductRoot == "/usr/local/ma-waf" {
		for _, p := range []string{"/usr/local/Ma-waf", "/usr/local/ma-waf"} {
			if _, err := os.Stat(p); err == nil {
				cfg.ProductRoot = p
				break
			}
		}
		if cfg.ProductRoot == "" {
			cfg.ProductRoot = "/usr/local/Ma-waf"
		}
	}
	root := cfg.ProductRoot
	rewrite := func(cur, suffix string) string {
		if cur == "" || cur == "/usr/local/ma-waf"+suffix {
			cand := root + suffix
			if _, err := os.Stat(cand); err == nil || cur == "" {
				return cand
			}
		}
		return cur
	}
	cfg.ConsoleDir = rewrite(cfg.ConsoleDir, "/share/console")
	if cfg.ConsoleDir == "/usr/local/ma-waf/share/console" {
		if _, err := os.Stat(root + "/share/console"); err == nil {
			cfg.ConsoleDir = root + "/share/console"
		}
	}
	cfg.BackupDir = rewrite(cfg.BackupDir, "/backups")
	cfg.RulesActive = rewrite(cfg.RulesActive, "/rules/active")
	cfg.RulesStaging = rewrite(cfg.RulesStaging, "/rules/staging")
	cfg.SQLitePath = rewrite(cfg.SQLitePath, "/var/lib/ma-waf.db")
	cfg.ChainAuditPath = rewrite(cfg.ChainAuditPath, "/var/lib/audit-chain.jsonl")
}
