# WinServer 2012 部署指南（VMP Auth Service）

本文面向将授权主服务器部署到 Windows Server 2012 的场景，示例环境：内网 IP `192.168.132.132`、Python 安装在 `C:\Python313\python.exe`。如果你的环境不同，可按需调整目录或端口。

> **最近更新（2025-10）**
> - 新版后台提供统一仪表盘（`/admin/`），可在部署后快速了解用户、卡密与即将过期提醒。
> - 部署脚本 `tools/winserver2012_deploy.ps1` 会自动生成后台凭据与仪表盘入口提示，请在控制台记录脚本输出。
> - CDN 管理页面现已上线，可直接新增加速节点、创建刷新/预取任务。
> - 脚本新增本地健康检查与 CDN 管理入口提示，部署完成后可立即验证服务可用性。
> - 一键部署脚本支持交互式部署模式选择，可在全新部署、升级或卸载之间切换，并进行数据保留控制。
> - 新增“仪表盘巡检”章节，帮助你在上线前核查各模块卡片与关键指标。

---

## Step 0. 准备与检查清单

| 项目 | 检查项 |
| --- | --- |
| 管理权限 | 使用管理员账号登录服务器（推荐 RDP）。 |
| 网络 | 服务器需访问 GitHub（下载依赖、NSSM）以及 PyPI；客户端需能访问服务暴露的端口。 |
| 运行时 | 安装 64 位 Python 3.10+，安装时勾选 “Add Python to PATH”。示例路径 `C:\Python313\python.exe`。 |
| PowerShell | 以管理员身份启动 PowerShell，会话内执行 `Set-ExecutionPolicy RemoteSigned -Scope Process` 允许脚本运行。 |
| Git（可选） | 若要直接 `git clone` 仓库，请安装 Git for Windows。没有 Git 时可上传压缩包。 |
| 防火墙 | 预留 TCP 8000（或自定义端口）入站访问。 |
| 证书/密码 | 准备好管理后台账号、HMAC 密钥等强随机密码。 |

> 若需要把服务长期运行为 Windows 服务，文末提供自动化脚本和 NSSM 相关步骤。

---

## Step 1. 拉取代码到服务器

以下示例目标目录为 `C:\Services\VMPSelf`，可按需修改。

### 方法 A：使用 Git 克隆（推荐）
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
mkdir C:\Services
cd C:\Services
git clone https://github.com/hujiali30001/VMPSelf.git
```

### 方法 B：手工上传压缩包
1. 在本地执行 `git archive --format zip HEAD -o VMPSelf.zip`；
2. 通过 RDP 剪贴板、SMB 或云盘上传到服务器；
3. 在服务器解压到 `C:\Services\VMPSelf`。

---

## Step 2. 准备 Python 虚拟环境

```powershell
cd C:\Services\VMPSelf\server
C:\Python313\python.exe -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> 第一次执行会拉取依赖（FastAPI、Uvicorn、SQLAlchemy、Jinja2 等），请保持网络畅通。

---

## Step 3. 生成并编辑 `.env`

复制示例文件并填写关键信息：

```powershell
Copy-Item .env.example .env -Force
notepad .env
```

建议设置：

- `VMP_ENV=production`
- `VMP_SQLITE_PATH=C:/Services/VMPSelf/server/data/license.db`
- `VMP_HMAC_SECRET=<强随机密钥>`
- `VMP_ADMIN_USER=<后台用户名>`
- `VMP_ADMIN_PASS=<后台密码>`
- 若暂不接入 CDN，可保持默认的 `VMP_CDN_*` 配置。

可以通过 PowerShell 快速生成随机密钥：

```powershell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
```

保存 `.env` 后继续下一步。

---

## Step 4. 初始化数据库并本地试运行

```powershell
python manage.py init-db
# 可选：仅在排查或 CI 场景手动执行 Alembic 迁移（init-db 已自动完成同样操作）
alembic upgrade head
python manage.py create-license --card DEMO-0001 --ttl 30
uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env
```

- `python manage.py init-db` 会在 SQLite 中创建/升级基础表结构，并自动触发 Alembic 迁移到最新版本（包括新引入的 `software_slot_current_packages` 关联表以消除软件位循环外键告警）。
- 如果你希望单独检查迁移日志，可执行 `alembic upgrade head`（若命令未命中，可改用 `..\.venv\Scripts\alembic.exe upgrade head`），其效果与 `init-db` 内部调用一致。
- 打开浏览器访问 `http://192.168.132.132:8000/docs`，查看 Swagger 文档确认接口可访问。
- 访问 `http://192.168.132.132:8000/admin/`，进入统一控制台查看核心统计、即将到期提醒，并从卡片快速跳转到各管理模块。
- 访问 `http://192.168.132.132:8000/admin/licenses`，浏览器会弹出 HTTP Basic 登录框，使用 `.env` 中的 `VMP_ADMIN_USER` / `VMP_ADMIN_PASS` 登录。新版模块化卡密管理界面支持快速创建卡密、批量筛选、快捷导向详情页以延期或重置授权。
- 访问 `http://192.168.132.132:8000/admin/users`，查看全新的用户列表：支持关键字搜索、快速跳转到用户详情（含审计日志与激活设备），可直接解绑或删除账号。
- 访问 `http://192.168.132.132:8000/admin/card-types`，管理卡密类型与时长模板；界面与其他后台页面采用统一布局，便于后续扩展。
- 访问 `http://192.168.132.132:8000/admin/cdn`，可新增加速节点、创建刷新或预取任务，并查看最近执行记录与各状态统计。
- 在仪表盘「功能模块一览」区域核对卡片状态：卡密管理、用户中心、卡密类型、CDN 管理应显示“前往页面”；软件位与系统设置仍标记为“规划中”属正常现象。
- 验证完毕后在终端按 `Ctrl+C` 停止 Uvicorn。
- 可选：保持虚拟环境激活状态执行 `python -m pytest tests/test_admin_api_crud.py tests/test_admin_service.py`，快速确认后台接口的关键用例与仪表盘 HTML。

---

## Step 5. 一键部署为 Windows 服务（可选）

- 项目内提供 `server/tools/winserver2012_deploy.ps1`，脚本现已全英文输出，并可自动完成以下操作：

1. 创建/更新虚拟环境并安装依赖；
2. 初始化数据库并执行 Alembic 迁移（若已存在则升级到最新 schema）；
3. 强制启用 TLS 1.2 后下载并解压 NSSM；
4. 注册名为 `VMPAuthService` 的 Windows 服务，使用 Uvicorn 启动 API；
5. 创建日志目录 `logs/`，将 stdout/stderr 轮转写入；
6. 设置防火墙规则放行指定端口；
7. 自动把 `.env` 调整为生产配置（写入绝对路径的 SQLite、生成随机 HMAC/后台密码），并输出最终服务访问信息。

脚本完成后还会主动请求 `http://127.0.0.1:<端口>/api/v1/ping` 做本地健康检查，并在输出中给出仪表盘、卡密管理、CDN 管理等入口。当监听地址为 `0.0.0.0` 或 `::` 时，控制台会提示将 `<server-ip>` 替换为服务器的实际地址后再访问。

常用参数：

| 参数 | 说明 |
| --- | --- |
| `-InstallRoot` | 服务端代码所在目录，默认取脚本所在仓库的 `server/`。 |
| `-PythonExe` | 指向目标主机上的 Python 可执行文件。 |
| `-ServiceName` | Windows 服务名称，默认 `VMPAuthService`。 |
| `-Port` | Uvicorn 监听端口。 |
| `-Host` / `-ListenHost` | 绑定监听地址，默认 `0.0.0.0`；`-Host` 为向后兼容别名。 |
| `-AdminUser` | （可选）指定后台 HTTP Basic 用户名，未提供时沿用 `.env` 或默认 `admin`。 |
| `-AdminPassword` | （可选）自定义后台密码，未提供时脚本会自动生成高强度随机值。 |
| `-HmacSecret` | （可选）自定义授权 HMAC 密钥，未提供时若检测到默认占位值将自动生成。 |
| `-SqlitePath` | （可选）自定义数据库文件位置，默认写入 `InstallRoot/data/license.db`。 |
| `-DeploymentMode` | （可选）指定执行模式：`Fresh` 全新部署、`Upgrade` 保留 `data/` 与 `.env` 升级现有服务、`Uninstall` 仅移除服务与文件后退出。默认 `Prompt`，进入交互选择。 |

执行示例（让脚本生成随机密码与 HMAC，端口 8000）：

```powershell
cd C:\Services\VMPSelf
powershell -ExecutionPolicy Bypass -File server\tools\winserver2012_deploy.ps1 -InstallRoot "C:\Services\VMPSelf\server" -PythonExe "C:\Python313\python.exe" -ServiceName "VMPAuthService" -Port 8000 -ListenHost "0.0.0.0" -AdminUser "ops-admin"
```

> 提示：脚本会在存在生成/变更操作时打印醒目的英文提示。若不传 `-AdminPassword`，会生成高强度密码并在终端显示；同理，检测到默认占位值时会生成新的 `VMP_HMAC_SECRET`。请在窗口关闭前妥善记录这些值。

> **目录建议**：请确保在安装目录的上一级（例如 `C:\Services\VMPSelf`）运行脚本，以免 PowerShell 会话仍锁定 `server` 目录导致旧文件无法删除。脚本内部已加入保护逻辑：若检测到安装目录与源码目录相同，会仅清理 `.venv`、`logs`、`data` 等运行时资产并保留源代码。但仍推荐将 `-InstallRoot` 指向独立目录（如 `C:\Services\VMPSelf\production`），以便与源代码分离并减少权限占用带来的干扰。

运行脚本时若选择：

- **Fresh**：停止并删除旧服务，清空 `.venv`、`logs/`、`data/`、`.env` 以及 NSSM 目录，随后重新创建安装目录并全量部署；适用于首次上线或需要重置环境的情况。
- **Upgrade**：停止服务并移除 `.venv`、`logs/`、`tools\nssm`，但保留 `data/` 与 `.env`，随后重建虚拟环境、安装依赖并运行迁移；适用于版本更新或依赖升级。
- **Uninstall**：停止服务后移除上述所有目录并删除安装根目录，然后退出脚本，不会重新部署；适用于彻底卸载或迁移至其他主机。

> 运行脚本前请以管理员身份打开 PowerShell（右键“以管理员身份运行”），否则 NSSM 安装与防火墙规则写入会失败。

脚本执行成功后，服务将自动启动并设置为开机自启。控制台会输出后台地址、用户管理入口、HTTP Basic 凭据以及是否生成新的 HMAC 密钥，同时在安装目录保留更新后的 `.env`。日志位于 `C:\Services\VMPSelf\server\logs\`，已启用 NSSM 轮转（单文件 10 MB）。

> 若从历史版本升级，请先执行 `git pull` 确认脚本更新到最新提交（含 `-ListenHost` 参数），再运行上述命令；脚本会运行 `manage.py init-db`（内部已包含 `alembic upgrade head`），从而迁移已有数据库，同时复用 `.env` 与 `data\license.db` 等数据文件。

---

## Step 6. 服务日常管理

```powershell
# 查看服务状态
nssm status VMPAuthService

# 启动 / 停止
nssm start VMPAuthService
nssm stop VMPAuthService

# 实时查看日志
Get-Content -Path "C:\Services\VMPSelf\server\logs\uvicorn.log" -Wait
```

若需调整端口或环境变量，可执行 `nssm edit VMPAuthService`，修改后再 `nssm restart VMPAuthService` 生效。后台入口统一采用新版界面：`/admin/licenses` 管理卡密、`/admin/users` 维护账号、`/admin/card-types` 配置卡密类型、`/admin/cdn` 管理加速节点，可随时手动解绑账号或删除异常用户。

---

## Step 7. 防火墙与安全建议

- 默认脚本已放行 TCP 8000。如需手动添加：

	```powershell
	New-NetFirewallRule -DisplayName "VMP Auth API" -Direction Inbound -Profile Any -Action Allow -Protocol TCP -LocalPort 8000
	```

- 如果要公网访问，建议通过 IIS、Nginx 或 CDN（腾讯云、Cloudflare 等）做 HTTPS 反向代理，并在 `.env` 中启用 `VMP_CDN_ENFORCED=true` 及共享密钥校验。
- 定期备份 `data/license.db`，并妥善管理 HMAC 密钥、后台密码。
- 服务器开启 Windows Update，禁用弱口令和不必要的服务（如 SMBv1）。

---

## Step 8. 快速自检

服务或脚本运行完毕后，可执行以下命令确认接口可用（自动化脚本已在 127.0.0.1 上执行一次同样的检查，若需从运维终端复核可再次运行）：

```powershell
Invoke-RestMethod -Uri "http://192.168.132.132:8000/api/v1/ping"
```

返回示例：

```text
message server_time
------- -----------
pong    2025-10-16T19:28:29.680446+00:00
```

若能看到 `pong` 与时间戳，表示授权服务已正常工作。

---

## Step 9. 常见问题

| 现象 | 排查建议 |
| --- | --- |
| `AssertionError: Jinja2 must be installed to use Jinja2Templates` | 确认已执行 `pip install -r requirements.txt`，或手动安装 `python -m pip install Jinja2==3.1.4`。 |
| 启动时报 SQLite 无法写入 | 检查 `VMP_SQLITE_PATH` 目录权限，确保服务账户有写权限，或改为其他路径。 |
| 浏览器访问后台提示 401 | 确认使用 `.env` 中的 `VMP_ADMIN_USER`、`VMP_ADMIN_PASS`，区分大小写。 |
| 端口被占用 | 修改脚本参数和 `.env` 中的端口，或释放正在占用端口的程序。 |

---

## Step 10. 发布前复核清单

- 检查 `.env` 中的 `VMP_ADMIN_PASS`、`VMP_HMAC_SECRET`、`VMP_SQLITE_PATH` 等关键字段是否已替换为生产值，并将该文件纳入受控备份。
- 在虚拟环境内执行核心回归测试（覆盖统一仪表盘、CDN 守卫及软件位关联逻辑）：
	```powershell
	.\.venv\Scripts\Activate.ps1
	python -m pytest tests/test_admin_api_crud.py tests/test_admin_service.py tests/test_cdn_guard.py
	```
- 定期备份 `data\license.db` 与导出的离线授权文件，可结合计划任务 `schtasks` 或 `robocopy` 实现多副本。
- 若启用 CDN 校验，可先在测试环境执行 `python tools\deploy_cdn.py --dry-run`（需在仓库根目录运行），核对 CDN 配置与密钥。
- 记录自动化脚本输出的后台密码与 HMAC，确保交接人员握有最新凭据。

---

## Step 11. 仪表盘巡检与后续扩展

- 登录 `http://<服务器IP>:8000/admin/`，确认首页顶部统计（注册用户、卡密总量、激活中的卡密等）与数据库数据一致，如无数据可忽略统计空值。
- 「即将过期」列表默认展示未来 7 天内到期的卡密，若列表为空说明近期无即将过期的记录；可通过创建临时期卡密来验证提醒功能。
- 「最新注册用户」与「最新创建卡密」分别抓取最近 6 条记录，如需查看更多可跳转到对应模块页面进行分页查询。
- CDN 管理卡片应显示“前往页面”，并能跳转到节点列表与任务面板；软件位与系统设置仍标记为“规划中”，后续迭代上线时会在同一仪表盘解锁。
- 建议在每次发布或脚本重装后重复上述巡检，确保后台入口与导航指向正确；如遇模板渲染异常，可重新运行 `python -m pytest -k dashboard` 协助定位。

---

部署过程中若需重新安装或更新服务，可再次运行自动化脚本；脚本会尝试保留现有数据库和 `.env` 配置。祝部署顺利！
