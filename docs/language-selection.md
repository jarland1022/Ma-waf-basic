# 开发语言选型建议

## 结论（推荐组合）

| 组件 | 推荐语言 | 理由 |
|------|----------|------|
| WAF 数据平面 | C/C++（Nginx + ModSecurity） | 已有成熟引擎，不重写 |
| 管理控制台后端 | **Go 1.21+** | 高并发、静态二进制、易离线交付 |
| 管理控制台前端 | React + TypeScript + Tailwind | 工程生态成熟，适合复杂仪表盘 |
| 运维/部署脚本 | Bash | 目标 OS 原生、无额外运行时 |
| 规则校验/日志处理/报表 | **Python 3.9+** | 文本处理强、CRS/正则生态好 |
| Nginx 内动态逻辑 | Lua（ngx_http_lua / OpenResty） | 限速、Bot、会话保护热路径 |

本仓库默认：**Go 管理 API + Python 辅助工具 + Bash 运维脚本**。

---

## 1. 若选 Go 做管理后端

### 优势

- **性能与并发**：goroutine 适合大量日志查询、WebSocket 推送、健康探测
- **单二进制交付**：`CGO_ENABLED=0 go build` 产出无依赖二进制，完美匹配**离线部署**
- **运维友好**：内存占用可控，systemd 管理简单，崩溃面小于解释型长驻进程
- **类型安全**：API/配置结构体清晰，减少配置错误
- **生态**：Gin/Fiber、JWT、TOTP、Prometheus client 齐全

### 与现有系统集成难度

| 集成点 | 难度 | 做法 |
|--------|------|------|
| 触发 nginx reload | 低 | `exec.Command("nginx","-s","reload")` + 配置语法预检 |
| 读写 ModSecurity 规则文件 | 低 | 文件 I/O + 原子 rename；规则元数据存 SQLite |
| 解析 audit log | 中 | 行式 JSON；大文件用 bufio + 索引表 |
| GeoIP / 情报库更新 | 低 | 定时任务写文件，nginx map/GeoIP 热读或 reload |
| 共享运行状态 | 中 | unix socket / 本地 HTTP；勿让管理面暴露公网 |

**结论**：Go 与 Nginx/ModSecurity **文件与进程级集成**即可，无需嵌入引擎，集成难度**中低**。

---

## 2. 若选 Python（FastAPI）做管理后端

### 优势

- 开发速度快，规则语法校验、报表、机器学习类扩展更方便
- 团队若已有 Python 安全工程经验，上手成本低

### 必须注意

1. **性能**：API 本身通常够用；瓶颈在日志全量扫描与同步 subprocess。需：
   - uvicorn/gunicorn + 多 worker
   - 日志入库（SQLite/PostgreSQL）而非每次 grep
   - CPU 密集任务（报表、全量校验）放后台队列
2. **部署**：Rocky/openEuler 自带 Python 3.9，需 **venv + requirements 锁定**；离线包用 `pip download` 或打包 wheelhouse
3. **并发写配置**：多 worker 下必须文件锁 / 单 writer 进程，避免规则文件竞态
4. **与 nginx 同机**：注意 Gunicorn 内存；管理面与数据面资源隔离（cgroup）

### 如何保证性能

- 审计日志异步消费写入 DB，查询走索引
- 热路径（模式切换、健康检查）保持 O(1) 文件/内存操作
- 避免在请求路径做 CRS 全量解析
- 可选：核心控制面仍用 Go，Python 只做分析与报表微服务

---

## 3. 其他可选语言？

| 语言 | 适用性 | 说明 |
|------|--------|------|
| Rust | 可选（代理旁路组件） | 性能极佳，但管理面开发效率低于 Go；人才成本更高 |
| Java/Spring | 不优先 | 内存与交付体积偏大，边缘设备不友好 |
| Node.js | 仅前端构建 | 不建议做与 nginx 同机的主控制面 |
| C++ 扩展 Nginx 模块 | 仅特殊能力 | 开发/维护成本高，优先 Lua 或独立 sidecar |

**不建议**用 Java/Node 作为默认管理后端；**不建议**重写 ModSecurity 引擎。

---

## 4. 本项目落地策略

```
management/backend/   → Go（Gin）：REST、认证、规则、模式、指标、健康检查
tools/*.py            → Python 3.9：规则语法校验、哈希链、合规报表、离线规则包
scripts/*.sh          → Bash：部署、加固、ctl、完整性校验
nginx/ + Lua 片段     → 限速、Bot UA、会话相关轻逻辑
management/frontend/  → React + TS + Tailwind
```

双运行时（Go + Python）职责清晰：Go 管「控制与在线」，Python 管「分析与批处理」，Bash 管「安装与加固」。
