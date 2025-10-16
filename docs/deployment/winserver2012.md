# WinServer 2012 部署指南（VMP Auth Service）

本文档记录将授权主服务器部署到 Windows Server 2012（IP: `192.168.132.132`）的完整流程。核心服务基于 FastAPI + Uvicorn，默认使用 SQLite 存储授权数据。

## 1. 准备工作

| 项目 | 说明 |
| --- | --- |
| 管理权限 | 以管理员身份登录服务器，推荐使用远程桌面。 |
| 网络 | 服务器需要访问 GitHub（下载依赖、NSSM），客户端网络需能访问服务器暴露端口。 |
| Python | 安装 64 位 Python 3.10+（示例路径 `C:\Python313\python.exe`），安装时勾选 “Add Python to PATH”。 |
| Git (可选) | 若直接 `git clone` 代码，可安装 Git for Windows；否则可手动上传压缩包。 |
| NSSM | 用于将 Uvicorn 注册为 Windows 服务，脚本会自动下载。 |
| 防火墙 | 需允许 TCP 8000（或自定义端口）的入站访问。 |

## 2. 获取代码

> 以下示例假定目标路径为 `C:\Services\VMPSelf`。

### 方式 A：Git 克隆
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
mkdir C:\Services
cd C:\Services
git clone https://github.com/hujiali30001/VMPSelf.git
```

### 方式 B：手动上传
1. 在本地执行 `git archive` 或压缩仓库。
2. 通过 RDP 剪贴板/SMB 上传到服务器。
3. 解压到 `C:\Services\VMPSelf`。

## 3. 配置虚拟环境

```powershell
cd C:\Services\VMPSelf\server
C:\Python313\python.exe -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 4. 配置环境变量（.env）

复制示例文件并根据需要调整：
```powershell
Copy-Item .env.example .env -Force
notepad .env
```

重点字段：
- `VMP_ENV=production`
- `VMP_SQLITE_PATH=C:/Services/VMPSelf/server/data/license.db`
- `VMP_HMAC_SECRET=<生成的强密码>`
- `VMP_ADMIN_USER=<后台用户名>`
- `VMP_ADMIN_PASS=<后台密码>`
- CDN 防护参数如不需要可保持默认。

## 5. 初始化数据库与测试运行

```powershell
python manage.py init-db
python manage.py create-license --card DEMO-0001 --ttl 30
uvicorn app.main:app --host 0.0.0.0 --port 8000 --env-file .env
```

> 打开浏览器访问 `http://192.168.132.132:8000/docs`，确认 API 正常后 `Ctrl+C` 停止。
> 若需图形化管理卡密，可访问 `http://192.168.132.132:8000/admin/licenses` 并使用上述后台账号登录。

## 6. 使用脚本自动部署为服务

项目内提供 `server/tools/winserver2012_deploy.ps1` 以自动化完成以下任务：
- 创建/更新虚拟环境并安装依赖
- 初始化数据库
- 下载 NSSM 并注册 `VMPAuthService` Windows 服务
- 配置服务自动重启
- 添加防火墙规则

执行方式：
```powershell
cd C:\Services\VMPSelf\server
.\.venv\Scripts\Activate.ps1
powershell -ExecutionPolicy Bypass -File tools\winserver2012_deploy.ps1 \
    -InstallRoot "C:\Services\VMPSelf\server" \
    -PythonExe "C:\Python313\python.exe" \
    -ServiceName "VMPAuthService" \
    -Port 8000
```

脚本运行结束后服务会以 NSSM 托管的方式常驻，安装路径 `C:\Services\VMPSelf\server`。

## 7. 服务管理

```powershell
# 查看状态
nssm status VMPAuthService

# 启动/停止
nssm start VMPAuthService
nssm stop VMPAuthService

# 查看实时日志
Get-Content -Path "C:\Services\VMPSelf\server\logs\uvicorn.log" -Wait
```

若需修改启动参数（端口、环境变量等），执行：
```powershell
nssm edit VMPAuthService
```
修改完成后重启服务。

## 8. 防火墙与安全

```powershell
New-NetFirewallRule -DisplayName "VMP Auth API" -Direction Inbound -Profile Any -Action Allow -Protocol TCP -LocalPort 8000
```

建议：
- 若公网开放，使用反向代理（IIS / Nginx）加 TLS。
- 生产环境务必设置强随机 `VMP_HMAC_SECRET`。
- 定期备份 `data/license.db`。

## 9. 验证

```powershell
Invoke-RestMethod -Uri "http://192.168.132.132:8000/api/v1/ping"
```
返回 `{"status":"ok"}` 表示服务工作正常。

---

如需恢复或更新服务，可重新运行部署脚本；脚本会尝试保留现有数据库和 `.env` 设置。
