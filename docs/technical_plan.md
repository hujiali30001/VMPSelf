# Qt 5.12.12 VMP-Style Protector – Technical Specification & Development Plan

## 1. 项目概览
- **目标**：构建一个自用的 VMP 风格壳工具，支持 32/64 位 Windows 可执行文件保护，涵盖 Ring3 与 Ring0 防护，同时接入自建网络授权系统。
- **主要平台**：Windows 10/11 客户端；授权服务器部署在腾讯云 Windows Server 2012 实例。
- **框架与语言**：Qt 5.12.12 + C++14，CMake 组织，MSVC 2017/2019 工具链；内核驱动使用 WDK；授权服务可选 ASP.NET Core 6 或 FastAPI（Python 3.10）。
- **数据库**：SQLite3（WAL 模式），单文件部署。

## 2. 关键需求与约束
1. **保护能力**
   - 解析并重建 PE32/PE32+ 程序。
   - 代码虚拟化、加壳、指令混淆、反调试、反虚拟机检测。
   - Ring0 驱动实现内核层调试防护、进程保护。
2. **授权系统**
   - 本地壳工具生成卡密，云端验证、心跳续期、离线许可。
   - 服务部署在腾讯云 WinServer 2012，使用 HTTPS（TLS1.2+）。
   - SQLite3 存储卡密、授权、心跳信息。
3. **使用场景**
   - 个人自用，非商业发行。
   - 允许离线运行的宽限策略。
4. **安全与合规**
   - Qt LGPL 动态链接；驱动可使用自签证书并在测试模式运行。
   - 服务器需进行系统加固、启用防火墙、定期补丁。

## 3. 系统架构
### 3.1 客户端壳工具（Qt）
- **UI 层**：Qt Widgets（或 Qt Quick 2.12）构建向导式界面，支持配置模板和实时日志。
- **核心模块**：
  1. **PE 解析器**：读取节、导入表、重定位信息；支持 32/64 位；可复用 `pe-parse` 或自研。
  2. **虚拟化引擎**：定义自有字节码指令集，含算术、逻辑、控制流、API 调用抽象；提供 JIT/解释器组合。
  3. **保护 Pass 管线**：插件化设计（初期内建），包含：控制流平坦化、API 动态解析、字符串加密、数据混淆。
  4. **反调试模块**（Ring3）：检查硬件断点、DbgPresent、异常处理链；可选延迟检测。
  5. **授权客户端 SDK**：
     - 设备指纹生成（CPU 序列、主板 UUID、MAC）→ SHA256。
    - 首次注册：输入用户名、密码与卡密，提交至服务器校验卡密有效性并建立账号；注册成功后获取初始 token 并绑定卡密。
     - 首次激活：提交卡密 + 指纹，获取 JWT/token。
     - 心跳：定期带签名参数向服务器汇报状态。
     - 离线许可：本地存储签名文件，验证有效期。
  6. **驱动通信层**：封装 DeviceIoControl，与内核驱动交换指令、密钥，维持自保护。

### 3.2 内核驱动
- **功能**：
  - 反调试（DbgBreakPoint Hook、KPCR 检测）。
  - 进程/线程保护（ObRegisterCallbacks）。
  - 代码段保护（EPT Hook、虚拟内存改写保护）；遇到 PatchGuard 冲突时降级。
- **自保护**：驱动完整性校验，防卸载，通信加密。
- **开发要点**：
  - 使用 KMDF/WDK；测试证书签名并启用测试模式。
  - 需提供版本兼容 Win10 x86/x64。

### 3.3 授权服务（Tencent Cloud WinServer 2012）
- **运行环境**：安装 .NET Hosting Bundle 6.0 或 Python 3.10；配置 TLS1.2。
- **SQLite3 数据库**：
  - 开启 WAL，路径示例：`C:\AuthService\data\license.db`。
  - 设置 NTFS 权限，仅服务账户可写。
  - 定期使用 PowerShell `.backup` 任务备份。
- **网络拓扑**：
  - 通过腾讯云 CDN / 边缘安全加速（或 Cloudflare）暴露公共入口，仅允许 CDN 回源访问源站。
  - CDN 回源配置使用 HTTPS + 源站鉴权 Header（例如 `X-Edge-Token`），并绑定固定的回源 IP 白名单。
  - CDN 启用 Web 应用防火墙（WAF）、DDoS 基础防护，对恶意流量进行速率限制和黑名单封禁。
  - 主服务器提供自动化部署脚本（`server/tools/deploy_cdn.py`）与后台编排入口，根据 JSON 配置或 Web 表单批量推送 Nginx 代理、开放防火墙端口并重启服务，支持 HTTP 反向代理或 TCP 四层转发，实现快速上线/扩容 CDN 节点。
  - 每个 CDN 节点保存于后台的 SSH 凭据采用应用内 Fernet 加密（由 `VMP_CDN_CREDENTIALS_KEY` 派生密钥），可一键发起部署；节点失效时后台能即时重放部署或新建节点，保障任何单节点宕机都不会影响整体运营。
  - 节点配置默认使用 443 端口监听，可选开启 80 端口回退；通过多节点 + 共享负载策略实现 TCP 层级的故障转移，主服务器始终保持在内网环境并通过令牌/IP 双因子校验阻断外部直接访问。
- **API 设计**：
  - `/api/v1/users/register`：校验卡密有效性并创建账号，返回安全令牌及后续激活指引。
  - `/api/v1/license/activate`：验证卡密 + 指纹，返回 token 和策略。
  - `/api/v1/license/heartbeat`：心跳续期，更新 `last_seen`。
  - `/api/v1/license/offline`：生成离线授权文件。
  - `/api/v1/license/revoke`：撤销授权。
  - 所有请求需 HMAC 签名（共享密钥），响应使用服务器私钥签名。
- **管理工具**：
  - CLI 或轻量 Web 控制台，用于生成/冻结卡密，查看日志。
- **安全措施**：
  - HTTPS 证书部署（腾讯云 SSL 免费证书）。
  - 安全组仅放行 80/443 和管理端口；启用主机安全。
  - 定期打补丁、关闭 SMBv1、配置 RDP 限制。

## 4. 数据库结构（SQLite）
```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_code TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unused',
    bound_fingerprint TEXT,
    expire_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  license_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (license_id) REFERENCES licenses(id)
);

CREATE TABLE activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id INTEGER NOT NULL,
    device_fingerprint TEXT NOT NULL,
    activated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME,
    token TEXT,
    FOREIGN KEY (license_id) REFERENCES licenses(id)
);

CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    license_id INTEGER,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 5. 安全与加固策略
- **客户端**：
  - 加入证书 Pinning、防抓包、异常网络行为告警。
  - 授权 token 使用 DPAPI + 自定义加密存储。
  - 代码混淆和多层解密（运行时生成密钥）。
- **服务器**：
  - HMAC 请求签名防重放；请求体包含 timestamp、nonce。
  - 日志监控异常失败次数，自动封禁 IP。
  - 仅接受来自 CDN 回源的请求：校验 `X-Edge-Token`、`X-Forwarded-For`，拒绝直连源站。
  - RDP/SSH 采用强密码 + 二次验证。
- **驱动**：
  - 通信数据加密、校验；防止被驱动分析工具截获。
  - 监测驱动加载来源，必要时限制只允许壳工具拉起。

## 6. 开发步骤与里程碑
### 阶段 0：预研与环境搭建（1-2 周）
- 安装 VS2019 + Qt 5.12.12 + CMake + Ninja。
- 搭建 WDK 环境，验证测试签名驱动加载。
- 在本地搭建 WinServer 2012 虚拟机，安装 .NET/Python、SQLite。
- 完成威胁建模（STRIDE）、需求规格文档。

### 阶段 1：核心 PoC（3-4 周）
1. **PE 解析 + 重建骨架**。
2. **基本虚拟化引擎**：实现算术/逻辑指令映射；完成一个 demo 函数加壳。
3. **授权服务初版**：实现卡密激活 + token 返回；SQLite schema 初始化脚本。
4. **Qt UI 原型**：配置向导、日志面板。
5. **驱动样例**：空驱动加载/卸载测试。
- 验收：成功给样例 exe 加壳并通过授权验证运行。

### 阶段 2：功能完善（4-6 周）
- 扩展虚拟机指令集，支持控制流、API 调用虚拟化。
- 增加反调试策略、反虚拟机检测。
- 授权服务增加心跳、离线许可、卡密管理 CLI。
- 实现客户端授权 SDK 与壳工具集成。
- 完成驱动与用户态通信（IOCTL），实现调试器检测。
- CDN 集成：配置源站鉴权 Header、编写中间件校验 `X-Edge-Token` 并记录审计日志。
- 编写单元测试（PE 操作、虚拟机指令）、集成测试（授权流程）。

### 阶段 3：Ring0 与安全加固（4-5 周）
- 驱动实现进程保护、内存保护；PatchGuard 兼容性测试。
- 增加通信加密、驱动自保护机制。
- 客户端实现证书 Pinning、token 加密存储、反注入防护。
- 服务器端添加 HMAC 验证、日志审计、速率限制。
- 完成安全测试（漏洞扫描、手动渗透）。

### 阶段 4：用户体验与运维（3-4 周）
- 完善 UI（模板管理、配置导入导出、结果报表）。
- 编写文档：
  - 构建指南、配置说明、故障排查。
  - 授权服务部署手册（包含 WinServer 2012 TLS 设置、备份脚本）。
- 搭建自动备份、监控报警脚本（PowerShell 定时任务）。
- 准备发布包（Qt IFW 或 NSIS），包含依赖运行库。

### 阶段 5：稳定性验证与优化（2-3 周）
- 压力测试授权接口（模拟并发激活、心跳）。
- 大范围兼容测试：Win7/Win10/Win11、x86/x64。
- 性能评估：壳加载时间、虚拟机执行开销。
- 整理后续迭代计划（多语言支持、插件 API 等）。

## 7. 测试与交付标准
- **单元测试**：PE 重建、虚拟机指令转换、授权逻辑。
- **集成测试**：端到端授权激活、心跳、离线许可。
- **驱动测试**：在 Win10/Win11 x86/x64 确认加载稳定，无蓝屏。
- **安全测试**：最少执行一次漏洞扫描 + 手工绕过尝试。
- **文档**：README、部署手册、API 文档。
- **交付物**：壳工具可执行文件、驱动 INF/ SYS、授权服务部署包、示例配置、测试报告。

## 8. 维护与未来扩展
- 定期更新虚拟机指令集和反调试策略。
- 评估未来迁移至 Qt 6 / Linux 服务器的可行性。
- 预留插件接口，方便未来添加新保护 Pass 或授权策略。
- 考虑引入自动更新模块，推送壳工具和驱动补丁。
