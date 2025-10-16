# VMP Auth Service (FastAPI)

## 环境要求
- Python 3.10+（示例：安装在 `C:\Python313`）
- Windows Server 2012 (Tencent Cloud) 或本地 Windows/Linux 测试环境
- 建议使用虚拟环境 `python -m venv .venv`

## 安装依赖
```powershell
C:\Python313\python.exe -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 初始化数据库
```powershell
python manage.py init-db
```

## 创建卡密
```powershell
python manage.py create-license --card DEMO-0001 --ttl 30
```

## 管理卡密
- 查看最近 20 条卡密（按创建时间倒序）：
	```powershell
	python manage.py list-licenses
	```
- 仅查看已激活卡密并显示 50 条：
	```powershell
	python manage.py list-licenses --status active --limit 50
	```
- 撤销指定卡密：
	```powershell
	python manage.py revoke-license DEMO-0001
	```
	撤销后客户端心跳将返回 `license_not_found`，需重新发放卡密。

## 启动服务
```powershell
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

服务启动后，可访问 `http://127.0.0.1:8000/docs` 查看 Swagger 文档。

> 若需将服务部署到 Windows Server 2012 并作为系统服务运行，请参考新增文档《[WinServer 2012 部署指南](../docs/deployment/winserver2012.md)》或使用 `tools/winserver2012_deploy.ps1` 一键部署脚本。

## API 快速参考

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/v1/ping` | 健康检查，客户端 `AuthClient::testConnection` 会调用此接口。 |
| `POST` | `/api/v1/license/activate` | 传入卡密、设备指纹与 HMAC 签名，返回授权 token 与心跳周期。 |
| `POST` | `/api/v1/license/heartbeat` | 传入 token、指纹、签名，刷新激活记录 `last_seen`。 |
| `POST` | `/api/v1/license/offline` | 生成离线授权文件与签名，供断网模式使用。 |
| `POST` | `/api/v1/license/revoke` | 撤销指定卡密的授权状态。 |

签名格式统一为：`base64(HMAC_SHA256(card_code|fingerprint|timestamp, license_secret))`，`timestamp` 为 Unix 秒级时间戳，避免重放攻击。

## 运行测试

```powershell
Set-Location -Path 'd:\old\projects\VMPSelf\server'
D:/old/projects/VMPSelf/.venv/Scripts/python.exe -m pytest
```

CI 测试覆盖核心授权流程（激活/心跳/撤销）、离线许可与 CDN 配置生成，确保核心逻辑在修改后依然稳定。

## 配置项
`VMP_ENV`、`VMP_SQLITE_PATH`、`VMP_HMAC_SECRET` 等环境变量可在 `.env` 文件中配置。

| 变量 | 说明 |
| --- | --- |
| `VMP_CDN_ENFORCED` | 是否强制要求来自 CDN 的访问（默认 false，生产建议打开）。 |
| `VMP_CDN_TOKEN` | CDN 回源时附带的共享密钥，写入腾讯云 CDN 或 Cloudflare 自定义 Header。 |
| `VMP_CDN_HEADER` | 存放共享密钥的 Header 名称，默认 `X-Edge-Token`。 |
| `VMP_CDN_IP_HEADER` | 读取真实客户端 IP 的 Header，默认 `X-Forwarded-For`。 |
| `VMP_CDN_IP_WHITELIST` | 允许的 CDN 回源 IP 列表，逗号分隔。 |
| `VMP_CDN_EXEMPT_PATHS` | 允许绕过 CDN 鉴权的接口（例如心跳或健康检查），逗号分隔。 |
| `VMP_ADMIN_USER` | 管理后台 HTTP Basic 用户名。 |
| `VMP_ADMIN_PASS` | 管理后台 HTTP Basic 密码，建议使用高强度随机值。 |

## Web 管理页面
- 启动服务后访问 `http://<服务器地址>:8000/admin/licenses`。
- 浏览器会弹出 HTTP Basic 登录框，用户名/密码来自 `.env` 中的 `VMP_ADMIN_USER`、`VMP_ADMIN_PASS`。
- 页面功能：
	- 按状态筛选卡密，支持设置返回条数。
	- 查看卡密绑定指纹、失效时间、最近心跳时间等信息。
	- 一键撤销卡密，撤销后客户端心跳将返回 `license_not_found`。
- 若要通过 HTTPS 暴露到公网，请置于 CDN 或反向代理之后（参见下文 CDN 防护示例）。

## CDN 防护示例
1. 在腾讯云 CDN 创建域名，源站指向授权服务器内网 IP，仅开放 HTTPS。
2. 在 CDN 规则中添加自定义 Header `X-Edge-Token: <你的共享密钥>`，并限制回源 IP。
3. 在服务器 `.env` 中开启：
	```powershell
	VMP_CDN_ENFORCED=true
	VMP_CDN_TOKEN=edge-shared-secret
	VMP_CDN_IP_WHITELIST=203.0.113.10,203.0.113.11
	```
4. 重启服务后，所有 API（除豁免路径）均会校验共享密钥和 CDN 回源 IP，直接访问源站会得到 403。

## CDN 节点自动化部署
- 示例配置：复制 `tools/cdn_deploy_config.example.json` 并修改为实际主机、凭据、共享密钥。
- 执行部署（默认从仓库根目录运行）：

	```powershell
	D:\old\projects\VMPSelf\.venv\Scripts\python.exe server/tools/deploy_cdn.py --config server/tools/cdn_deploy_config.json
	```

- 支持 `--dry-run` 输出 Nginx 配置，或追加 `extra_packages` 安装 `certbot`、`rsync` 等工具。
- 每个节点需要 sudo 权限以安装软件包、写入 `/etc/nginx/conf.d/vmp_edge.conf` 并开放防火墙端口。
