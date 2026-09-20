# Ma-WAF 性能压测步骤与记录表

本文给出可重复的压测方法，以及建议采购的工控机、云主机档位。  
**表中“目标区间”是容量规划参考，不是已测承诺。** 填表前以当次 `wrk` 结果为准。

禁止对公网业务（含 `https://www.mingansec.com`）做压力测试。被测流量必须打到实验上游。

---

## 1. 建议机型（自行选定，购买前以实测为准）

### 1.1 工控机（无风扇盒式，千兆起步）

| 代号 | 参考配置 | 典型整机方向 | 规划用途 | 规划目标（小对象、CRS 开启，未实测） |
|------|----------|--------------|----------|--------------------------------------|
| IPC-A | Intel N100 或 J6412，4 核，8 GB，双千兆，128 GB SSD | 研华 / 华北工控一类无风扇盒式，约 4 核低功耗 | 演示、单官网 | 约 100 Mbps，约 800–2,000 RPS |
| IPC-B | Intel i5-12400，6 核 12 线程，16 GB，双千兆，256 GB NVMe | 上架式工控机，带 AES-NI | 数个业务站 | 约 200–500 Mbps，约 2,000–5,000 RPS |
| IPC-C | Intel i7-12700 或同级 16 线程以上，32 GB，千兆 + 可选万兆，512 GB NVMe | 性能型工控机 | 多站点并留余量 | 约 0.5–1 Gbps，约 5,000–12,000 RPS |

不要用无 AES-NI 的老 Atom 去对标千兆检查吞吐。工控机压测时接显示器或串口，确认不是降频到最低。

### 1.2 云服务器（通用计算型，非突发实例）

以阿里云 ecs.c7 / 腾讯云 S5 同规格为参照，其他云按 vCPU 与内存对齐即可。

| 代号 | 规格 | 系统盘 | 带宽 | 规划用途 | 规划目标（同上，未实测） |
|------|------|--------|------|----------|--------------------------|
| CLD-A | 2 vCPU / 4 GB | 40 GB+ | 按量或 5 Mbps 以上 | 功能演示 | 约 50 Mbps，约 300–800 RPS |
| CLD-B | 4 vCPU / 8 GB | 80 GB | 建议 ≥100 Mbps | 公司官网 | 约 100–200 Mbps，约 800–2,000 RPS |
| CLD-C | 8 vCPU / 16 GB | 100 GB | 建议 ≥200 Mbps | 多站点 | 约 200–500 Mbps，约 2,000–5,000 RPS |
| CLD-D | 16 vCPU / 32 GB | 200 GB | 建议 ≥1 Gbps 内网 | 容量上限摸底 | 约 0.5–1 Gbps，约 5,000–12,000 RPS |

云上压测机与 WAF 放在同一 VPC、同一可用区，避免把公网带宽当成 WAF 性能。

---

## 2. 拓扑

```text
压测机 (wrk)  --HTTP-->  Ma-WAF:80  --proxy-->  本机 127.0.0.1:18080 模拟业务
                              |
                         管理口 :8443（不参与压测）
```

要求：

- 引擎 `SecRuleEngine On`，CRS 已加载，偏执级与生产一致（建议先记 PL2）。
- 站点 `server_name` 使用 `bench.local`，上游为 `http://127.0.0.1:18080`，不要指公网。
- 静态场景关闭 ModSecurity；动态场景开启。
- 压测期间不要开 JS Challenge（否则 wrk 被 302 到挑战页，RPS 无意义）。

---

## 3. 准备

### 3.1 模拟上游（在 WAF 本机）

```bash
mkdir -p /tmp/bench-www
dd if=/dev/zero of=/tmp/bench-www/10k.bin bs=1024 count=10 status=none
printf '<html><body>ok</body></html>\n' > /tmp/bench-www/index.html

# 仅监听本机，避免暴露
python3 - <<'PY' &
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import os
os.chdir("/tmp/bench-www")
ThreadingHTTPServer(("127.0.0.1", 18080), SimpleHTTPRequestHandler).serve_forever()
PY
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18080/index.html
```

### 3.2 压测专用站点

在控制台新建站点，或手写 `/usr/local/nginx/conf/conf.d/site-bench.conf`：

- `server_name bench.local`
- `listen 80`
- `upstream http://127.0.0.1:18080`
- 启用 ModSecurity
- 关闭 JS Challenge、关闭 HMAC

然后：

```bash
/usr/local/nginx/sbin/nginx -t && systemctl reload nginx
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: bench.local" http://127.0.0.1/index.html
curl -s http://127.0.0.1/waf-health
```

### 3.3 压测机安装 wrk

压测机不要和 WAF 抢同一颗 CPU。工控机单机验收时，可暂时在另一台 Linux 上跑 wrk，通过内网 IP 访问 WAF。

```bash
# Rocky / 通用
sudo dnf install -y git gcc make openssl-devel
git clone https://github.com/wg/wrk.git /tmp/wrk && make -C /tmp/wrk -j
sudo install -m 755 /tmp/wrk/wrk /usr/local/bin/wrk
wrk --version
```

POST 体文件（压测机上）：

```bash
printf 'a=1&b=benchmark-body-padding-%s\n' "$(head -c 800 /dev/urandom | base64 | head -c 800)" > /tmp/post_1k.txt
```

---

## 4. 场景

每档机器、每个场景都跑。连接数按机器从小到大，出现错误率 >1% 或 P99 明显抬升即停，不要继续加并发。

| 编号 | 场景 | URL | 说明 |
|------|------|-----|------|
| S0 | 预热 | `GET /index.html` | 30 秒，结果不填入正式表 |
| S1 | 静态旁路 | `GET /10k.bin` | 若站点对静态关了 ModSecurity，代表转发能力上限 |
| S2 | 动态全检 | `GET /index.html` | 主指标：CRS 开启后的页面 RPS |
| S3 | 小 POST 全检 | `POST /index.html` | 约 1 KB 表单体，更接近表单业务 |
| S4 | 连接扩展 | S2，提高 `-c` | 找错误率拐点 |

统一参数：

- 时长：`60s`（正式）；预热 `30s`
- 线程：`-t` 等于压测机核数，且不超过 8
- Host：`bench.local`

将下面命令里的 `WAF_IP` 换成工控机或云主机内网地址。

### S0 预热

```bash
wrk -t4 -c50 -d30s -H "Host: bench.local" "http://WAF_IP/index.html"
```

### S1 静态 10KB

```bash
wrk -t4 -c100 -d60s -H "Host: bench.local" "http://WAF_IP/10k.bin"
wrk -t4 -c300 -d60s -H "Host: bench.local" "http://WAF_IP/10k.bin"
```

### S2 动态全检

```bash
wrk -t4 -c50  -d60s -H "Host: bench.local" "http://WAF_IP/index.html"
wrk -t4 -c100 -d60s -H "Host: bench.local" "http://WAF_IP/index.html"
wrk -t4 -c300 -d60s -H "Host: bench.local" "http://WAF_IP/index.html"
```

### S3 POST 1KB

```bash
wrk -t4 -c100 -d60s -H "Host: bench.local" -H "Content-Type: application/x-www-form-urlencoded" \
  -s /dev/stdin "http://WAF_IP/index.html" <<'LUA'
wrk.method = "POST"
wrk.body   = io.open("/tmp/post_1k.txt"):read("*a")
request = function()
  return wrk.format(nil, nil, nil, wrk.body)
end
LUA
```

### S4 只在 S2 的 `-c100` 错误率 <1% 时再跑

```bash
wrk -t8 -c500 -d60s -H "Host: bench.local" "http://WAF_IP/index.html"
```

### 同步采集（WAF 本机，另开终端）

压测开始后 10 秒执行，每场景各记一次：

```bash
date
nproc
free -h | head -2
mpstat 1 5 | tail -5          # 无 mpstat 时用: top -bn1 | head -20
curl -s http://127.0.0.1:8081/nginx_status || echo "8081 未监听"
```

记录：`%idle` 换算 CPU 使用率 ≈ `100 - idle`。内存看 `used`。

---

## 5. 怎么读 wrk 输出

关注这几行：

- `Requests/sec` → 填 RPS
- `Transfer/sec` → 填吞吐（B/s 可换算 Mbps：数值 × 8 / 1e6）
- `Latency` 的 `99%` → 填 P99
- `Non-2xx or 3xx`、`Socket errors` → 错误率 ≈ 失败请求 / 总请求

判定（单场景）：

| 结果 | 条件 |
|------|------|
| 通过 | 错误率 < 1%，且 CPU 未长期 100%，P99 < 200 ms（内网） |
| 临界 | 错误率 < 1%，但 CPU > 85% 或 P99 200–500 ms |
| 失败 | 错误率 ≥ 1%，或大量 timeout / 502，或 P99 > 500 ms |

某档机器的“可用容量”取 **S2 动态全检** 里最后一个“通过”或“临界”的 `-c` 所对应 RPS，不要用 S1 静态数字对外宣传。

---

## 6. 记录表

每台机器复制一节。日期、内核、CRS 版本、PL 必填。

### 6.1 环境

| 项 | 填写 |
|----|------|
| 代号 | IPC-A / IPC-B / IPC-C / CLD-A / CLD-B / CLD-C / CLD-D |
| 品牌型号或云实例 ID | |
| CPU 型号 / 核数 | |
| 内存 | |
| 网卡 | |
| OS | |
| Ma-WAF / Nginx 版本 | |
| CRS 版本 / 规则条数 | |
| SecRuleEngine / PL | On / PL2 |
| 压测日期 / 执行人 | |
| 压测机规格（与 WAF 分离） | |
| 备注（是否关 JS Challenge） | 必须关闭 |

### 6.2 结果

| 场景 | 并发 -c | RPS | 吞吐 Mbps | 平均时延 ms | P99 ms | 错误率 % | CPU % | 内存 | 判定 | 备注 |
|------|---------|-----|-----------|-------------|--------|----------|-------|------|------|------|
| S1 静态 | 100 | | | | | | | | | |
| S1 静态 | 300 | | | | | | | | | |
| S2 动态 | 50 | | | | | | | | | |
| S2 动态 | 100 | | | | | | | | | |
| S2 动态 | 300 | | | | | | | | | |
| S3 POST | 100 | | | | | | | | | |
| S4 动态 | 500 | | | | | | | | 可选 | |

### 6.3 汇总（对外只用这一行，且注明“实测”）

| 代号 | S2 推荐并发 | S2 可用 RPS | S2 可用 Mbps | 是否达到第 1 节规划目标 | 结论 |
|------|-------------|-------------|--------------|-------------------------|------|
| | | | | 是 / 否 | 可上线该流量档 / 需加 CPU / 仅适合演示 |

---

## 7. 四台云 + 三台工控机的执行顺序

1. 先做 **CLD-B（4C8G）** 或 **IPC-A**，把脚本和站点跑通。  
2. 再做 CLD-A，确认演示档下限。  
3. 做 IPC-B、CLD-C。  
4. 最后做 IPC-C、CLD-D。高档机器若 S2 在 `-c100` 已失败，先查上游 18080 是否打满，再查 WAF CPU。  
5. 同一场景重复 2 次，RPS 相差超过 15% 时再跑第 3 次，取中位数填表。

---

## 8. 常见失真

| 现象 | 处理 |
|------|------|
| RPS 极低且全是 302 | JS Challenge 未关 |
| 大量 502 | 上游 18080 挂了，或 `proxy_pass` 仍指向公网 |
| 压测机 CPU 先到 100% | 换更强的压测机，结果无效 |
| 云上 Mbps 卡在带宽上限 | 改走内网，或临时升带宽 |
| S1 很高、S2 很低 | 正常，对外引用 S2 |
| 8081 connection refused | 不影响压测；连接数栏留空即可 |

测完删除 `site-bench.conf` 并 `nginx -t && systemctl reload nginx`，避免实验站留在生产配置里。
