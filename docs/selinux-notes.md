# SELinux 加固说明（Rocky / openEuler）

## 1. 基础

```bash
getenforce
setenforce 1
```

## 2. Nginx 自定义路径 file context

```bash
semanage fcontext -a -t httpd_exec_t '/usr/local/nginx/sbin/nginx'
semanage fcontext -a -t httpd_config_t '/usr/local/nginx/conf(/.*)?'
semanage fcontext -a -t httpd_log_t '/data/logs/nginx(/.*)?'
semanage fcontext -a -t bin_t '/usr/local/Ma-waf/bin(/.*)?'
semanage fcontext -a -t etc_t '/usr/local/Ma-waf/conf(/.*)?'
semanage fcontext -a -t var_t '/usr/local/Ma-waf/var(/.*)?'
restorecon -Rv /usr/local/nginx /usr/local/Ma-waf /data/logs/nginx
setsebool -P httpd_can_network_connect 1
```

## 3. 策略模块草案

见 [`packaging/selinux/ma_waf.te`](../packaging/selinux/ma_waf.te)。

```bash
cd /usr/local/Ma-waf/packaging/selinux
checkmodule -M -m -o ma_waf.mod ma_waf.te
semodule_package -o ma_waf.pp -m ma_waf.mod
semodule -i ma_waf.pp
```

若编译失败，以 `audit2allow -M ma_waf_local` 从 AVC 生成后**人工审计**再导入。

## 4. 排障

```bash
ausearch -m avc -ts recent | audit2allow
# 临时排查可用 permissive，生产必须回到 enforcing
```

## 5. 与 systemd 的关系

当前 `ma-waf-api.service` 默认关闭 `ProtectSystem=strict`，避免路径缺失导致 `226/NAMESPACE`。  
SELinux enforcing + 正确 fcontext 是主机级隔离的主路径；systemd 沙箱可在路径稳定后再逐步加回。
