# 故障排查手册

## 1. 服务无法启动

```bash
sudo /usr/local/ma-waf/scripts/waf_ctl.sh status
sudo journalctl -u nginx -u ma-waf-api -n 100 --no-pager
sudo /usr/local/nginx/sbin/nginx -t
```

常见原因：
- 配置语法错误 → 用备份回滚：`waf_ctl.sh rollback`
- 端口占用 → `ss -lntp | grep -E ':80|:443|:8443'`
- 模块路径错误 → 检查 `load_module` 与 `modsecurity` 动态库

## 2. reload 失败

```bash
sudo nginx -t
# 查看 staging 规则校验日志
sudo python3 /usr/local/ma-waf/tools/rule_manager.py validate --dir /usr/local/ma-waf/rules/staging
sudo /usr/local/ma-waf/scripts/waf_ctl.sh rollback
```

## 3. CPU / 内存飙高

- 检查 CRS 是否对静态资源误检：确认静态白名单 location
- 调低 `SecPcreMatchLimit` / `SecPcreMatchLimitRecursion`（见 modsecurity.conf）
- `worker_processes` 与 `worker_connections` 按 CPU/内存重评
- 查看是否遭 CC：`waf_ctl.sh metrics`

## 4. 误报过多

1. 短期：`SecRuleEngine DetectionOnly`
2. 对误报规则 ID 做 `SecRuleRemoveById` 或更新 exclusions
3. 使用虚拟补丁/自定义规则前先 DetectionOnly 观察 24–72h

## 5. 完整性校验失败

```bash
sudo /usr/local/ma-waf/scripts/verify_waf.sh
```

若核心二进制或规则哈希变化且非变更窗口：
1. 隔离管理网络
2. 从签名更新包或已知良好备份恢复
3. 审查 auditd / 管理 API 登录日志

## 6. 管理接口无法访问

- 确认仅绑定管理地址
- 检查源 IP 白名单与 firewalld
- 查看暴力破解锁定：`ma-waf-api` 日志中的 `auth_lockout`
