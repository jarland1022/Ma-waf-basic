Ma-WAF 配置模板说明
====================

本目录是「模板」，不是运行时配置。

  configs/templates/api.yaml  →  部署时复制/生成为：
  /usr/local/Ma-waf/conf/api.yaml

管理 API（ma-waf-api）只读取 conf/api.yaml，不读取本目录下的模板。

首次或更新后若 conf/api.yaml 缺失，请在目标机执行：

  sudo /usr/local/Ma-waf/scripts/init_api_config.sh

或重新部署（仅在 conf/api.yaml 不存在时会从本模板生成，已有文件不会覆盖）：

  sudo /usr/local/Ma-waf/scripts/deploy.sh --skip-build

注意：用 rsync/scp 把仓库整树覆盖到 /usr/local/Ma-waf 时，
若使用 --delete，会删掉 conf/ 下运行时文件（含 api.yaml、TLS、License）。
更新请保留 conf/、var/、backups/，或更新后立刻跑 init_api_config.sh。
