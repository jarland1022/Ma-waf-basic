# Ma-WAF License

对齐 allinone sec-platform：ECDSA P-256 + SHA-256，文件格式
`base64(json_payload + "." + base64(asn1_signature))`。

## 签发机（离线）

```bash
python3 tools/license_gen.py --genkey
# 私钥 configs/license/ma-waf-private.pem 仅留在签发机

python3 tools/license_gen.py \
  --client "客户名称" \
  --expiry 2027-12-31 \
  --fingerprint-hash <控制台复制的 fingerprint> \
  -o license.lic
```

## 部署到 WAF 节点

```bash
mkdir -p /usr/local/Ma-waf/conf/license
cp configs/license/ma-waf-public.pem /usr/local/Ma-waf/conf/license/
# 控制台 「License」页上传 license.lic，或：
# cp license.lic /usr/local/Ma-waf/conf/license/license.lic
systemctl restart ma-waf-api
```

## 状态

| status | 含义 |
|--------|------|
| active | 已激活且未过期 |
| grace_period | 未激活 / 校验失败，72h 试用 |
| grace_expired | 宽限期结束，变更类 API 返回 402 |
| no_license / invalid | 其它异常 |

指纹优先取 `/sys/class/dmi/id/product_uuid` 的 SHA-256，其次 `/etc/machine-id`。
