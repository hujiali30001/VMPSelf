# VMP Auth Service (FastAPI)

## 部署快速开始（开发/测试环境）

1. 克隆或解压仓库到目标目录（示例 `D:\old\projects\VMPSelf`）。
2. 创建虚拟环境并安装依赖：
	```powershell
	C:\Python313\python.exe -m venv .venv
	.\.venv\Scripts\Activate.ps1
	python -m pip install --upgrade pip
	python -m pip install -r requirements.txt
	```
3. 复制环境变量模板并写入关键信息：
	```powershell
	Copy-Item .env.example .env -Force
	notepad .env
	```
	建议至少配置 `VMP_ENV=development`、`VMP_ADMIN_USER`、`VMP_ADMIN_PASS`、`VMP_HMAC_SECRET`。
4. 初始化数据库并准备示例卡密：
	```powershell
	python manage.py init-db
	python manage.py create-license --card DEMO-0001 --ttl 30
	```
5. 启动服务验证（开发模式可使用 `--reload`）：
	```powershell
	uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env --reload
	```
	打开 `http://127.0.0.1:8000/docs` 确认 API 可用，再访问 `http://127.0.0.1:8000/admin/` 查看统一控制台；通过侧边导航可进入卡密、用户等管理页面。

## 管理后台模块总览

后台首页采用统一的侧边导航，当前版本已经提供如下模块：

- **总览面板**：汇总卡密、用户、激活等关键指标，展示最近创建的账号与卡密。
- **卡密中心**：支持卡密筛选、明细查看与批量生成，列表页可直接跳转到类型管理。
- **用户管理**：提供注册、密码重置、卡密重新绑定等日常操作，同时展示激活状态统计。
- **软件位管理**：用于维护各产品线/渠道的软件位，支持创建槽位、上传安装包、一键发布或下线，并可查看灰度比例与当前版本。
- **CDN 管理**：集中展示 CDN 节点状态，支持新增节点、保存 SSH 凭据、切换启用/暂停、发起刷新或预取任务，并可从后台一键部署/重部署 CentOS 7 边缘节点；最新版本支持展示回源 IP 白名单建议、切换 PROXY protocol，以及自动化健康巡检与告警审计。
- **系统设置**：管理后台管理员账号，支持新增成员、启用/停用以及重置密码，同时展示由环境变量注入的超级管理员信息。

所有操作均通过 Flash 消息反馈结果，并保持返回原页面便于继续操作。

## 环境要求
- Python 3.10 及以上版本（官方环境使用 3.13.7）
- Windows Server 2012 / 2016、Windows 10+ 或常见 Linux 发行版（Ubuntu 22.04、Debian 12 等）
- 具备外网访问以安装依赖，可选 Git 客户端
- 建议始终使用虚拟环境隔离依赖：`python -m venv .venv`

## 安装依赖
```powershell
C:\Python313\python.exe -m venv .venv
\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 初始化数据库
```powershell
python manage.py init-db
```

## 数据库迁移
- 默认执行 `python manage.py init-db` 会自动调用 Alembic，将数据库结构迁移到最新版本。
- 如需单独运行迁移，可执行：
	```powershell
	.\.venv\Scripts\python -m alembic upgrade head
	```
- 开发新特性时，建议使用 Alembic 生成迁移文件并提交。例如：
	```powershell
	.\.venv\Scripts\python -m alembic revision --autogenerate -m "describe change"
	```

## 创建卡密
```powershell
# 生成 10 张月卡（使用默认天数与前缀）
python manage.py create-license --type month --quantity 10

# 自定义卡号与有效期（单张）
python manage.py create-license --card DEMO-0001 --ttl 45

# 指定类型同时覆盖前缀与天数
python manage.py create-license --type enterprise --prefix VIP- --custom-ttl 180 --quantity 5
```

> `create-license` 默认回退到 30 天有效期；如果指定 `--type`，将优先使用类型的默认配置，可通过 `--custom-ttl` 与 `--prefix` 覆盖。

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
# 开发环境：热重载 + 本地访问
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 --env-file .env

# 生产环境推荐：禁用 reload、增加 worker、显式加载 .env
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4 --env-file .env
```

服务启动后，可访问 `http://127.0.0.1:8000/docs` 查看 Swagger 文档。

> 若需将服务部署到 Windows Server 2012 并作为系统服务运行，请参考《[WinServer 2012 部署指南](../docs/deployment/winserver2012.md)》或使用 `tools/winserver2012_deploy.ps1` 一键部署脚本（自动生成后台密码/HMAC，并输出登录信息）。

### Linux / systemd 示例

在 Linux 服务器上，可结合 systemd 编排服务（示例以 `/opt/vmpself/server` 为根目录）：

```ini
# /etc/systemd/system/vmp-auth.service
[Unit]
Description=VMP Auth Service (FastAPI)
After=network.target

[Service]
WorkingDirectory=/opt/vmpself/server
EnvironmentFile=/opt/vmpself/server/.env
ExecStart=/opt/vmpself/server/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

部署步骤概览：

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env  # 修改其中的密钥/数据库路径
python manage.py init-db
systemctl daemon-reload
systemctl enable --now vmp-auth.service
```

### Windows 一键部署脚本

如需在 Windows Server 2012/2016 上常驻运行，仓库提供自动化脚本：

```powershell
cd C:\Services\VMPSelf
powershell -ExecutionPolicy Bypass -File tools\winserver2012_deploy.ps1 -InstallRoot "C:\Services\VMPSelf\server" -PythonExe "C:\Python313\python.exe" -Port 8000 -AdminUser "ops-admin"
```

> 建议始终在安装目录的上一级（例如仓库根目录 `C:\Services\VMPSelf`）执行脚本，避免 PowerShell 当前工作目录仍指向 `server` 导致无法删除旧版本文件。脚本已在内部增加防护——当安装目录与源码目录相同时，它会仅清理运行时资产并保留源代码——但提前切换目录能减少权限占用带来的重试次数，也方便将部署目标指向专用目录（如 `C:\Services\VMPSelf\production`）。

首次执行脚本会询问部署模式，可直接在交互菜单中选择：

- **全新部署 (Fresh)**：移除现有服务、`.venv`、日志、`data/`、`.env`，并重新创建安装目录；适用于首次安装或需要重置环境的场景。
- **升级部署 (Upgrade)**：停止服务、清理虚拟环境与日志，但保留 `data/` 与 `.env`，随后重新安装依赖并迁移数据库；适用于代码或依赖更新时的平滑升级。
- **卸载 (Uninstall)**：停止服务、清理所有文件并退出脚本，不会重新部署。

如需在无人值守或 CI 场景中运行，可通过 `-DeploymentMode Fresh|Upgrade|Uninstall` 显式指定模式，跳过交互提示。

脚本将自动创建虚拟环境、安装依赖、生成/更新 `.env`、注册 NSSM 服务并输出后台访问信息。更多参数说明见《[WinServer 2012 部署指南](../docs/deployment/winserver2012.md)》。

> 脚本内部调用 `python manage.py init-db`（已包含 Alembic 升级），因此无需再单独执行 `alembic upgrade head`；若需要独立排查迁移，可手动运行该命令。

## 发布前检查
- 执行回归测试，确保核心授权流程以及新增后台模块可用：
  ```powershell
		D:/old/projects/VMPSelf/.venv/Scripts/python.exe -m pytest tests/test_admin_api_crud.py tests/test_admin_service.py tests/test_admin_modules.py
  ```
- 确认 `.env` 中的 `VMP_ADMIN_PASS`、`VMP_HMAC_SECRET`、`VMP_SQLITE_PATH` 等已替换为生产值。
- 备份 `data/license.db` 与生成的离线授权 JSON，必要时配置异地备份。
- 若启用 CDN 校验，在正式发布前使用 `tools/deploy_cdn.py --dry-run` 验证配置。

## API 快速参考

| Method | Path | 说明 |
| --- | --- | --- |
| `POST` | `/api/v1/users/register` | 提交用户名、密码与卡密，创建账号并绑定卡密。 |
| `GET` | `/api/v1/ping` | 健康检查，客户端 `AuthClient::testConnection` 会调用此接口。 |
| `POST` | `/api/v1/license/activate` | 传入卡密、设备指纹与 HMAC 签名，返回授权 token 与心跳周期。 |
| `POST` | `/api/v1/license/heartbeat` | 传入 token、指纹、签名，刷新激活记录 `last_seen`。 |
| `POST` | `/api/v1/license/offline` | 生成离线授权文件与签名，供断网模式使用。 |
| `POST` | `/api/v1/license/revoke` | 撤销指定卡密的授权状态。 |

签名格式统一为：`base64(HMAC_SHA256(card_code|fingerprint|timestamp, license_secret))`，`timestamp` 为 Unix 秒级时间戳，避免重放攻击。

### 后台 JSON API（需 HTTP Basic）

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/admin/api/users` | 分页列出注册用户，支持 `search`、`offset`、`limit` 查询参数。 |
| `GET` | `/admin/api/users/{user_id}` | 查看指定用户与其所绑定的卡密信息。 |
| `PATCH` | `/admin/api/users/{user_id}` | 更新用户名、密码或重新绑定卡密。 |
| `DELETE` | `/admin/api/users/{user_id}` | 移除用户并自动回收绑定卡密。 |
| `GET` | `/admin/api/licenses` | 分页列出卡密，支持按状态和关键字搜索。 |
| `POST` | `/admin/api/licenses` | 创建新卡密，可指定自定义卡号与有效期。 |
| `GET` | `/admin/api/licenses/{card_code}` | 查看单个卡密详情及其绑定用户。 |
| `PATCH` | `/admin/api/licenses/{card_code}` | 更新卡密状态、到期时间或绑定指纹。 |
| `DELETE` | `/admin/api/licenses/{card_code}` | 删除卡密，若处于激活状态需加上 `force=true`。 |

### 用户注册流程

客户端注册页在提交表单时需携带：

```json
{
	"username": "demo_user",
	"password": "ChangeMe!234",
	"card_code": "DEMO-0001"
}
```

服务端在 `/api/v1/users/register` 中会：

1. 校验用户名、密码长度并检查卡密是否存在且未过期/未撤销；
2. 检测该卡密是否已绑定其他账号；
3. 使用 `PBKDF2-SHA256` 哈希存储密码，并绑定卡密；
4. 写入审计日志（`user_register`），便于后台追踪。

成功时返回：

```json
{
	"user_id": 12,
	"username": "demo_user",
	"card_code": "DEMO-0001",
	"license_status": "unused",
	"message": "registered"
}
```

客户端注册完成后即可进入激活流程，复用相同卡密配合设备指纹获取运行 token。

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
| `VMP_CDN_CREDENTIALS_KEY` | 用于加密存储 CDN 节点 SSH 凭据的主密钥，默认回退到 `VMP_HMAC_SECRET`。 |
| `VMP_CDN_HEALTH_MONITOR_ENABLED` | 是否启用后台自动健康巡检与告警（默认 `true`，测试环境会自动跳过）。 |
| `VMP_CDN_HEALTH_MONITOR_INTERVAL` | 健康巡检间隔秒数，默认 `300`，建议 60～300 秒之间。 |
| `VMP_ADMIN_USER` | 管理后台 HTTP Basic 用户名。 |
| `VMP_ADMIN_PASS` | 管理后台 HTTP Basic 密码，建议使用高强度随机值。 |

## Web 管理页面
- 启动服务后访问 `http://<服务器地址>:8000/admin/licenses`。
- 浏览器会弹出 HTTP Basic 登录框，用户名/密码来自 `.env` 中的 `VMP_ADMIN_USER`、`VMP_ADMIN_PASS`。
- 页面功能：
	- 快速创建新卡密，可自定义卡号并设置有效期（支持永久有效）。
	- 按状态与关键字组合筛选，分页浏览卡密列表。
	- 查看绑定指纹、激活次数、到期时间、最近心跳等实时指标。
	- 快速查看卡密对应的注册用户与注册时间，支持排查账号归属。
	- 新增用户列表页 `/admin/users`，支持搜索账号、浏览关联卡密与激活次数，并可一键删除或跳转详情。
	- 用户详情页展示审计日志、激活设备、卡密信息，并提供改密、重新绑定或删除账号等操作。
	- 进入详情页审计变更历史、查看所有激活设备，并支持延期或重置卡密。
	- 针对无法联网的终端生成离线授权包，可直接复制授权数据与签名文本分发给用户。
	- 一键下载包含授权数据与签名的 JSON 文件，便于线下备份或通过脚本导入客户端。
	- 一键撤销卡密，撤销后客户端心跳将返回 `license_not_found`。
	- 即将上线的客户端注册页可复用后台生成的卡密，后台可通过审计日志追踪注册行为。
	- 更详细的后台门户布局、权限模型与交互流程，参见《[License Card Type Extensions – Admin UI](../docs/design/license_card_types.md#admin-ui)》章节。
	- CDN 管理控制台：现已支持维护节点清单、保存 SSH 凭据、一键触发 `deploy_cdn.py` 部署、轮换共享密钥与查看部署结果，详细需求与后续规划见《[License Card Type Extensions – CDN 管理模块](../docs/design/license_card_types.md#cdn-管理模块详解)》。
- 若要通过 HTTPS 暴露到公网，请置于 CDN 或反向代理之后（参见下文 CDN 防护示例）。

### Roadmap

- **卡密类型体系**：正在设计支持天卡/月卡/季卡/年卡等可配置类型的功能，允许自定义卡号前缀与默认有效期，详见《[License Card Type Extensions](../docs/design/license_card_types.md)》设计文档。
- **后台管理门户 2.0**：将引入仪表盘、批量任务、审计日志、角色权限等模块，布局与交互要求见《[License Card Type Extensions – Admin UI](../docs/design/license_card_types.md#admin-ui)》。
- **CDN 管理与部署编排**：后台已集成 `deploy_cdn.py` 并支持节点凭据管理、即时代码部署与状态回写，后续将继续完善蓝绿发布、批量滚动策略与部署告警，详见《[License Card Type Extensions – CDN 管理模块](../docs/design/license_card_types.md#cdn-管理模块详解)》。
- **多产品与租户管理**：计划引入软件目录、套餐与租户模型，满足多产品授权与渠道运营需求。
- **自动化与告警**：未来会增加离线报表、告警通知、批量操作等运营能力。

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
- 示例配置：复制 `tools/cdn_deploy_config.example.json`，根据实际情况填写 `listen_port`、`mode`（`http`/`tcp`）、共享密钥以及节点的 SSH 凭据。
- 执行部署（默认从仓库根目录运行）：

	```powershell
	D:\old\projects\VMPSelf\.venv\Scripts\python.exe server/tools/deploy_cdn.py --config server/tools/cdn_deploy_config.json
	```

- 支持 `--dry-run` 输出 Nginx 配置，或追加 `extra_packages` 安装 `certbot`、`rsync` 等工具。
- 每个节点需要 sudo 权限以安装软件包、写入 `/etc/nginx/conf.d/vmp_edge.conf` 并开放防火墙端口。
- 管理后台的 “CDN 管理” 中可直接维护节点清单并点击 “一键部署”，后台会调用同一套部署逻辑（支持 CentOS 7、TCP/HTTP 模式），执行结果与日志会回写到节点状态与任务列表，方便在线追踪。
- 后台同页还提供实时健康探测按钮，可按需触发 HTTPS/TCP 探活，并在节点卡片中展示最近一次延迟、返回码与故障信息，便于快速定位异常。
