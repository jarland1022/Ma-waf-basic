# 运行时配置目录（勿当仓库模板用）

本目录在**安装机**上由 `deploy.sh` / `init_api_config.sh` 创建。

| 文件 | 说明 |
|------|------|
| `api.yaml` | 管理 API 必需配置（审计日志路径、JWT、控制台目录等） |
| `tls/` | 管理口 8443 证书 |
| `license/` | License 公钥与许可文件 |

仓库里的模板在 `configs/templates/api.yaml`。若更新代码后这里没有 `api.yaml`：

```bash
sudo /usr/local/Ma-waf/scripts/init_api_config.sh
```
