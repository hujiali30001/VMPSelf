# VMPSelf 管理后台详细设计

> 目标：在保持现有 FastAPI + SQLAlchemy + Jinja 架构的基础上，建设一个模块化、可扩展的专业管理后台，覆盖卡密管理、用户管理、软件位管理、CDN 管理等核心业务域，并为后续权限、审计与指标扩展打下基础。

---

## 当前迭代交付概览（Sprint A）

- **管理员认证**：后台已接入数据库驱动的管理员账号（`admin_users`），支持账户停用与密码重置；仍保留 `.env` 中的超级管理员作为后门。
- **CDN 管理**：实现节点列表、状态切换、刷新/预取任务提交及最近任务追踪，模板位于 `templates/admin/cdn/index.html`。
- **软件位管理**：完成槽位维护、安装包上传、发布/下线流程，可在单页内查看当前版本与历史版本。
- **系统设置**：提供管理员账号管理面板和基础运行信息，支撑后续角色扩展。
- **测试覆盖**：新增 `tests/test_admin_modules.py` 覆盖上述核心流程。

## 1. 范围与基线

- **执行阶段**：以 Sprint A 为起点，优先重构导航骨架、权限模型和通用 UI 组件，并迁移/扩展卡密与用户模块。
- **既有能力**：
  - 卡密：类型定义、批量生成、状态流转、离线授权、审计日志。
  - 用户：注册、绑定卡密、重置操作（API+服务已有但 UI 待模块化）。
  - 技术栈：FastAPI (admin router) + SQLAlchemy (models/services) + Jinja2 模板。
- **约束假设**：
  - 短期内继续使用 Jinja 模板；允许引入局部 JS（Alpine/HTMX）提升交互。
  - 认证沿用 HTTP Basic，后续会扩展角色/权限。
  - 数据存储使用现有 PostgreSQL/MySQL（取决于部署环境），支持 Alembic 迁移。

---

## 2. 系统架构细化（Todo#2）

### 2.1 逻辑分层

```
┌───────────────────────────────────────────┐
│ Presentation (Jinja Templates + HTMX/JS)  │
├───────────────────────────────────────────┤
│ FastAPI Admin Routers (模块化)            │
│   • admin.dashboard                       │
│   • admin.licenses                        │
│   • admin.users                           │
│   • admin.software_slots                  │
│   • admin.cdn                             │
│   • admin.settings                        │
├───────────────────────────────────────────┤
│ Services / Use-Cases                      │
│   • LicenseService, LicenseCardTypeService│
│   • UserService                           │
│   • SoftwareSlotService (新)              │
│   • PackageService (新)                   │
│   • CDNService (新)                       │
│   • AuditService, AuthService (新)        │
├───────────────────────────────────────────┤
│ Data Access (SQLAlchemy ORM + Repos)      │
├───────────────────────────────────────────┤
│ Persistence (PostgreSQL/MySQL)            │
└───────────────────────────────────────────┘
```

- **模板层**：使用基础布局（`admin/layout.html`）统一导航、面包屑、Flash 消息。各模块通过 block 机制插入主内容。
- **Router 层**：按模块拆分，统一挂载到 `/admin/...`。公共依赖（认证、Breadcrumb、权限校验）在 `admin/deps.py`。
- **Service 层**：抽象业务逻辑，保持 API/模板调用一致；新服务需内聚审计与权限检查。
- **数据层**：新增模型放置在 `app/db/models.py` 或拆分子模块文件（推荐）。

### 2.2 依赖关系 & 数据流

| 触发来源             | 主要流转                                                                                                         |
|----------------------|------------------------------------------------------------------------------------------------------------------|
| 管理员访问页面       | 浏览器 → 认证 → FastAPI Router → Service → ORM → 渲染模板 → 返回 HTML                                             |
| 页面内交互（操作）   | 表单 / HTMX 请求 → FastAPI Router → Service → AuditService 记录日志 → ORM → 重定向/局部刷新 → UI 展示消息         |
| 批量/异步任务        | 管理员操作 → 任务表记录 → Celery/后台任务（后续扩展） → 更新状态 → 后台页面轮询或 Webhook 通知                 |
| 指标与仪表盘         | FastAPI Router → Service 聚合统计（SQL/缓存） → 模板渲染为图表（可引入 Chart.js）                               |

### 2.3 横切关注点
- **权限/认证**：
  - 短期：扩展 HTTP Basic，加入管理员表（用户名/密码哈希/角色）。
  - 中期：基于角色的权限装饰器；在 Router 中使用 `Depends(require_role("xxx"))`。
- **审计日志**：统一 `AuditService.log(actor, action, object, payload)`；在关键 Service 操作中调用。
- **错误处理**：标准化错误码/信息，结合 Flash 消息组件展示；API 返回 JSON 错误。
- **国际化**：模板/消息保留中文为主，可使用 Jinja 宏统一管理。

---

## 3. 模块详细方案（Todo#3）

### 3.1 导航与布局（Sprint A 核心）
- 新建 `templates/admin/layout.html`：
  - 顶部栏：LOGO、环境标签、管理员信息、快速搜索、通知入口。
  - 左侧侧边栏：可折叠模块列表（Dashboard、卡密中心、用户中心、软件位、CDN、系统设置）。
  - 内容区：`{% block content %}`；面包屑、Flash 消息组件、主内容。
- 公共部件：
  - `partials/flash_messages.html`
  - `partials/breadcrumb.html`
  - `partials/table_filters.html`

### 3.2 卡密中心
- **页面**：
  1. 类型列表（已有 `card_types.html`，迁移到布局，并引入 tab/统计）。
  2. 卡密列表（现有 `licenses.html`，适配新导航，增加批次、导出按钮）。
  3. 批次详情/导出页面（新增）。
  4. 审计日志视图（引用 AuditService 数据）。
- **API/Router**：拆分为 `admin/licenses.py`，保留 JSON API 与 HTML，在 `APIRouter(prefix="/licenses")` 下：
  - GET `/`：列表 + 筛选。
  - POST `/create-batch`：批量生成。
  - GET `/batches/{id}`：批次详情。
  - POST `/revoke`, `/reset`, `/extend` 等已存在操作。
- **Service 拓展**：
  - `LicenseService.create_batch(...)` 返回批次信息；引入 `LicenseBatch` 模型（见数据模型）。
  - 审计：所有操作调用 `AuditService`。

### 3.3 用户中心
- **页面**：
  1. 用户列表：查询条件（用户名、绑定卡密、渠道、时间段、状态）。
  2. 用户详情：基本信息、卡密、设备、操作历史、备注。
  3. 分群列表（后续迭代）：自定义群组配置。
- **API/Router** (`admin/users.py`)：
  - GET `/`：分页列表。
  - GET `/{id}`：详情。
  - POST `/create`、`/{id}/update`、`/{id}/reset-password` 等。
  - POST `/segments`（后续）：新增群组。
- **Service 需求**：
  - 扩展 `UserService` 支持搜索、分群、批量操作（CSV 导入/导出）。
  - 记录关键操作（重置密码、解绑卡密）。

### 3.4 软件位管理（新增）
- **业务定义**：软件位 = 某产品/渠道的版本投放配置，如桌面客户端、代理节点等。
- **页面**：
  1. 软件位列表：展示产品线、渠道、当前版本、灰度比例、状态。
  2. 软件包仓库：版本上传、签名验证、依赖说明。
  3. 发布流水：灰度计划、上线/回滚历史。
- **API/Router** (`admin/software.py`)：
  - GET `/slots`：列表。
  - POST `/slots`：创建/更新软件位。
  - POST `/slots/{id}/activate|deactivate`。
  - GET `/packages`、POST `/packages/upload` 等。
  - POST `/deployments`：发起灰度/发布任务。
- **Service**：`SoftwareSlotService`, `PackageService`, `DeploymentService`。
  - 负责版本管理、文件校验、状态变更。
  - 与后台任务/Celery 集成（后续）。

### 3.5 CDN 管理（新增）
- **页面**：
  1. 节点监控：状态、流量、命中率、健康检查。
  2. 配置管理：域名、源站、缓存策略。
  3. 刷新/预热：任务列表、状态、失败重试。
  4. 日志与告警：集成第三方 API（如阿里云/Cloudflare）。
- **API/Router** (`admin/cdn.py`)：
  - GET `/endpoints`、`/endpoints/{id}`。
  - POST `/endpoints`（配置 CRUD）。
  - POST `/purge`, `/prefetch`（刷新、预热）。
  - GET `/logs`，支持时间/节点过滤。
- **Service**：`CDNService`，负责调用 CDN Provider SDK/HTTP API，统一结果和错误。
  - 设计 Provider 抽象：`ICDNProvider` 接口，支持多家厂商。
  - 审计/告警：刷新失败、节点异常时记录。

### 3.6 系统设置/通用功能
- **管理员与角色**：
  - 页面：管理员列表、角色配置、登录历史。
  - 模型：`AdminUser`（用户名、密码哈希、角色、状态）、`Role`、`RolePermission`。
- **审计日志**：统一页面，支持按模块/操作人/时间过滤。
- **集成配置**：SMTP、Webhook、告警渠道等。

---

## 4. 数据模型与迁移（Todo#4）

### 4.1 现有模型回顾
- `License`, `LicenseCardType`, `LicenseBatch(缺失)`, `Activation`, `AuditLog`, `User`。
- 待扩展字段：
  - License：`batch_id`、`notes`。
  - LicenseCardType：`metadata` JSON 扩展（可选）。

### 4.2 新增/修改表设计

| 表名/模型                | 字段 & 类型                                                                                                                         | 说明                                             |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| `license_batches`        | `id`, `batch_code`, `type_id`, `quantity`, `created_by`, `created_at`, `metadata(JSON)`                                            | 记录批量生成信息                                |
| `admin_users`            | `id`, `username`, `password_hash`, `role_id`, `is_active`, `last_login_at`, `created_at`, `updated_at`                              | 管理员账号                                      |
| `roles`                  | `id`, `code`, `display_name`, `description`                                                                                         | 角色定义（admin/operator/viewer 等）            |
| `role_permissions`       | `id`, `role_id`, `module`, `action`                                                                                                 | RBAC 权限表                                     |
| `software_slots`         | `id`, `code`, `name`, `product_line`, `channel`, `status`, `gray_ratio`, `notes`, `created_at`, `updated_at`                       | 软件位主体，当前版本由关联表维护                |
| `software_slot_current_packages` | `slot_id`, `package_id`, `assigned_at`                                                                                    | 软件位当前上线版本指针，消除双向外键循环       |
| `package_versions`       | `id`, `slot_id`, `version`, `file_path`, `checksum`, `size`, `release_notes`, `uploaded_by`, `uploaded_at`, `status`                | 版本仓库记录                                    |
| `deployments`            | `id`, `slot_id`, `version_id`, `strategy`, `status`, `progress`, `scheduled_at`, `started_at`, `finished_at`, `rollback_from_id`   | 灰度/发布流程                                   |
| `cdn_endpoints`          | `id`, `domain`, `provider`, `origin`, `cache_rules(JSON)`, `status`, `notes`, `created_at`, `updated_at`                           | CDN 节点配置                                    |
| `cdn_tasks`              | `id`, `endpoint_id`, `task_type(purge/prefetch)`, `payload(JSON)`, `status`, `created_at`, `finished_at`, `message`               | 刷新/预热任务                                   |
| `cdn_metrics`            | `id`, `endpoint_id`, `timestamp`, `bandwidth`, `requests`, `hit_rate`, `errors`                                                     | 指标采样（可选，或存储在时序库）               |
| `audit_logs` 增强        | `actor_id`, `actor_type`, `module`, `action`, `object_type`, `object_id`, `payload(JSON)`                                           | 支持管理员主体、模块维度                        |

> 注：部分表（如 `cdn_metrics`）可根据实际存储成本改存外部系统；当前设计用于界面展示基础数据。

### 4.3 迁移策略
- 使用 Alembic 创建迁移脚本，分阶段执行：
  1. Sprint A：新增 `admin_users`, `roles`, `role_permissions`, `license_batches`, `audit_logs` 调整。
  2. Sprint B：`software_slots`, `package_versions`, `deployments`。
  3. Sprint C：`cdn` 相关表。
- 对于 existing 数据迁移：
  - 以默认角色/权限（超级管理员）回填历史账号。
  - 为历史 License 生成批次记录（可选，以日期+类型作为批次）。
  - Audit 日志保持兼容（新增字段允许 NULL）。

### 4.4 数据访问层
- 推荐为新增模型提供 Repository 或 Service 方法：
  - `SoftwareSlotRepository`：列表、过滤、分页。
  - `CDNTaskRepository`：任务状态查询。
  - `AuditLogRepository`：按条件查询。
- 统一分页/筛选 helpers，减少重复代码。

---

## 5. 实施蓝图与风险（Todo#5）

### 5.1 阶段拆分

| 阶段 | 目标 & 关键交付物                                                                                                   | 验收指标                                                 |
|------|----------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Sprint A | 导航+布局重构、RBAC 基础、卡密/用户页面迁移、批次模型与审计强化                                         | 新 UI 可用；权限控制生效；pytest 全量通过               |
| Sprint B | 软件位管理 MVP：模型+上传+灰度配置 UI；仪表盘初版（卡密/用户/版本指标）                                   | 软件位 CRUD & 发布流程可操作；指标卡展示准确            |
| Sprint C | CDN 管理 MVP：节点列表、刷新/预热任务、配置同步；审计与告警联动                                          | CDN 操作可用且审计可查；失败任务可重试                  |
| Sprint D | 通用增强：仪表盘图表、通知中心、批量导入导出、异步任务框架（Celery/Redis）                                | 关键操作可异步；通知中心触达；仪表盘实时刷新            |
| Sprint E | 质量巩固：端到端测试、性能优化、文档+运维手册                                                               | E2E 测试通过；性能指标达标；文档覆盖场景                |

### 5.2 风险与缓解

| 风险                                      | 影响                            | 缓解措施                                                                              |
|-------------------------------------------|---------------------------------|---------------------------------------------------------------------------------------|
| 模块拆分导致模板/路由冲突                 | 页面崩溃、路由冲突             | 先重构 layout & router；逐模块迁移；引入路由前缀常量                                  |
| 权限模型不完善                           | 安全风险                        | Sprint A 强制引入 RBAC；关键操作二次确认；审计留痕                                    |
| 新模块数据模型复杂导致开发周期拉长       | 迭代延期                        | 分阶段上线（先最小功能集）；编写详细用例；优先打通主流程                              |
| CDN/软件位依赖外部系统或文件存储         | 接口不稳定                      | 设计 Provider 抽象；Mock 服务；预留失败重试与超时机制                                  |
| 大量统计/列表导致查询性能下降             | 页面加载慢                      | 引入分页/索引；考虑缓存/物化视图；关键指标异步聚合                                     |
| UI 复杂度提高（Jinja 难以维护）          | 开发效率降低                    | 封装组件（宏）、引入轻量 JS 框架；中期评估前端框架迁移                                 |

### 5.3 下一步行动
1. 评审本设计文档并根据反馈细化/调整。
2. 准备 Sprint A 需求拆解与任务排期：
   - Layout & 导航重构
   - RBAC 数据模型与登录流程
   - 卡密/用户模块迁移 & 批次模型实现
   - 审计日志增强
3. 编写 UI 原型稿（Figma/Sketch 或手稿）确保交互一致。
4. 整理 Alembic 迁移脚本草案与数据库回滚策略。

---

## 附录：接口与页面示意

### A.1 模板结构
```
templates/
  admin/
    layout.html
    dashboard.html
    licenses/
      index.html
      batches.html
      type_list.html
    users/
      index.html
      detail.html
    software/
      slots.html
      packages.html
      deployments.html
    cdn/
      endpoints.html
      tasks.html
      logs.html
    settings/
      admins.html
      roles.html
      audit_logs.html
  partials/
    sidebar.html
    topbar.html
    flash_messages.html
```

### A.2 API 命名规范
- RESTful：`GET /admin/api/licenses`, `POST /admin/api/licenses/batches`。
- 模块前缀：`/admin/api/software/slots`, `/admin/api/cdn/tasks`。
- 使用 `Pydantic` Schemas 定义请求/响应，放置于 `app/schemas/admin/*.py`。

### A.3 审计日志格式
```json
{
  "actor_id": 1,
  "actor_name": "super_admin",
  "module": "license",
  "action": "create_batch",
  "object_type": "license_batch",
  "object_id": 123,
  "payload": {
    "type_code": "month",
    "quantity": 50,
    "custom_prefix": "VIP-"
  },
  "created_at": "2025-10-17T10:15:00Z"
}
```

---

> 本设计文档将作为后续开发和迭代的蓝图，实际开发中发现新的需求或约束时需同步更新。