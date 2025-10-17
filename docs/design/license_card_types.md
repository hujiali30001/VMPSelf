# License Card Type Extensions

## Goals

- 支持灵活配置卡密类型（如天卡、月卡、季卡、年卡、企业定制等），并允许运营同学拓展新的类型。
- 允许为每种卡密类型定义默认有效期、卡号前缀、标签颜色等展示属性。
- 在后台创建卡密时，可批量选择类型并覆写默认设置；发放后的卡密保留类型信息，便于统计与筛选。
- 保持现有授权流程兼容（老卡密无需迁移即可继续激活），同时为 JSON API 暴露新的查询字段。

## Scope

1. **数据模型扩展**：引入卡密类型配置表，并在 `licenses` 表记录关联。
2. **后台管理 UI**：新增“卡密类型”管理页，以及在卡密创建/列表中展示与过滤类型。
3. **API 扩展**：管理 API 支持卡密类型 CRUD，卡密列表与创建接口增加类型字段。
4. **运维支持**：脚本与批量导入（未来）可感知类型；部署脚本默认生成基础类型。

## Data Model

### 新表：`license_card_types`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | `Integer` (PK) | 主键 |
| `code` | `String(32)` | 类型唯一标识（例如 `day`, `month`, `enterprise`），用于引用 |
| `display_name` | `String(64)` | 后台显示名称 |
| `default_duration_days` | `Integer` | 默认有效期（天），允许 0 表示永久 |
| `card_prefix` | `String(16)` | 默认卡号前缀（如 `D-`, `M-`），可为空 |
| `description` | `Text` | 运营文案说明 |
| `color` | `String(16)` | UI 标签颜色（例如 `#2563EB`）|
| `is_active` | `Boolean` | 控制是否可选 |
| `sort_order` | `Integer` | 排序 |
| `created_at` / `updated_at` | `DateTime` | 时间戳 |

- `code` 建议使用 slug 样式，前端与 API 使用它作为引用键。
- `card_prefix` 将作为默认前缀，通过创建卡密的 API 可以覆盖。
- 建议在数据库层面对 `code` 建唯一索引，避免重复。

#### 预置类型种子

部署迁移时写入以下示例配置，运营可在后台继续扩展：

| code | display_name | default_duration_days | card_prefix | color | 说明 |
| --- | --- | --- | --- | --- | --- |
| `day` | 天卡 | 1 | `D-` | `#38bdf8` | 适用于体验/试用 |
| `week` | 周卡 | 7 | `W-` | `#22d3ee` | 可选（是否启用由运营决定） |
| `month` | 月卡 | 30 | `M-` | `#6366f1` | 标准订阅 |
| `quarter` | 季卡 | 90 | `Q-` | `#f97316` | 适中折扣 |
| `year` | 年卡 | 365 | `Y-` | `#16a34a` | 长期授权 |

> 以上仅作为默认值，新增类型如“企业授权”“渠道专属”等可在后台自定义。

### 修改表：`licenses`

新增字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `card_type_id` | `Integer` (FK->`license_card_types.id`) | 引用卡密类型，可为空（兼容老数据） |
| `custom_duration_days` | `Integer` | 如果创建时覆写了有效期，记录差异，便于统计 |
| `card_prefix` | `String(16)` | 实际使用的前缀副本，便于历史追溯 |

变更注意：
- 原有 `expire_at` 字段保留；根据类型默认值和自定义 TTL 计算。
- 老卡密迁移时 `card_type_id=NULL`，UI 展示为“Legacy/未分类”。

## Backend Changes

1. **SQLAlchemy 模型 & Alembic 迁移**
   - 创建 `LicenseCardType` ORM（在 `app/db/models.py`）。
   - `License` 模型增加外键与新字段。
   - 提供初始数据迁移，插入默认类型：`DAY`, `MONTH`, `QUARTER`, `YEAR`，并可保留内置前缀 `D-`, `M-`, `Q-`, `Y-`。

2. **服务层 (`LicenseService`)**
   - `create_license` 签名扩展：`def create_license(self, *, type_code: str, quantity: int = 1, custom_prefix: str | None = None, custom_ttl_days: int | None = None)`。
   - 支持批量创建（返回列表与批次 ID）。
   - 根据类型默认有效期与前缀填充 `expire_at` / `card_prefix`。若提供 `custom_ttl_days`，记录到 `custom_duration_days` 并覆盖。
   - 更新审计日志记录类型信息。

3. **API 层 (`/admin/api`)**
   - `POST /admin/api/license-types` / `GET` / `PATCH` / `DELETE`。
   - `GET /admin/api/licenses` 支持 `type_code` 过滤，响应包含 `type`（code、name）。
   - `POST /admin/api/licenses` 接受 `type_code`, `quantity`, `custom_prefix`, `custom_ttl_days`，返回批量结果。

4. **验证**
   - 校验类型存在且启用。
   - `custom_prefix` 合法性（仅字母数字及 `-` `_`），与类型默认前缀组合生成最终卡号（例如 `VIP-XXXXX`）。
   - 多线程/并发生成卡号时确保唯一性，可将核心逻辑放到事务内并重试。

## Admin UI

1. **卡密类型管理页**
   - 左侧列表 + 右侧编辑面板，支持排序拖拽。
   - 字段：名称、标识、默认有效期、前缀、颜色、启用开关、描述。
   - 添加“测试生成预览”按钮展示示例卡号和到期时间。

2. **创建卡密弹窗**
   - 第一行选择“授权产品”（未来）与“卡密类型”。
   - 根据类型显示默认有效期、前缀，可覆盖。
   - 支持输入生成数量（默认 1）和附加标签/备注。

3. **列表页增强**
   - 新增类型筛选器、在表格中显示类型徽标。
   - 批量操作时可按类型导出。

4. **详情页**
   - 展示类型与创建来源、实际生效期限（数学表达：`base_duration + custom_duration`）。

## CLI / 脚本

- `manage.py create-license` 增加 `--type` 与 `--prefix`、`--quantity` 参数。
- 部署脚本（`tools/winserver2012_deploy.ps1`）在初始化数据库后检测类型表是否为空，若为空插入默认类型并输出提示。

## Migration Plan

1. 编写 Alembic 迁移：
   - 创建 `license_card_types`。
   - `licenses` 表添加新字段（允许空值）。
   - 填充默认类型并将 `licenses.card_prefix` 设为旧卡号拆分结果（可解析 `card_code` 中的前缀，若无则留空）。
2. 后续迭代可提供命令 `python manage.py migrate-legacy-license-types` 将老卡密归类。

## Testing Strategy

- 单元测试覆盖：
  - 类型创建/禁用流程。
  - 使用不同类型生成卡密、验证默认 TTL、卡号前缀。

### 布局与全局交互

- 顶部水平导航包含 Logo、环境标识（Prod/Stage）、全局搜索框、快速操作（创建卡密、导出）、通知中心与管理员头像菜单。
- 左侧固定纵向菜单包含“概览仪表盘”“卡密类型”“卡密管理”“用户与设备”“批量任务”“审计日志”“系统设置”七大一级栏目，支持根据角色动态收敛（只读角色隐藏写操作栏目）。
- 所有页面保持 12 栅格布局，主体宽度自适应 1280px 以上大屏，768px 以下切换为折叠菜单 + 顶部选项卡模式。
- 支持全局快捷键：`Ctrl+K` 打开命令面板、`Ctrl+Shift+N` 新建卡密批次、`?` 打开帮助抽屉。

### 页面模块与主用例

| 模块 | 目标 | 关键视图/组件 | 核心操作 | 后端依赖 |
| --- | --- | --- | --- | --- |
| 概览仪表盘 | 当日运营概况 | KPI 卡片、趋势图、告警列表 | 查看异常、跳转关联详情 | `/admin/api/licenses?aggregate=true`、事件流 | 
| 卡密类型 | 维护类型配置 | 可排序表格、详情抽屉、颜色选择器 | 新增/编辑/禁用类型，实时预览生成规则 | `/admin/api/license-types` | 
| 卡密管理 | 批量发放和维护卡密 | 高级搜索栏、结果表、批量工具栏 | 生成卡密、导出 CSV、批量撤销/延期 | `/admin/api/licenses` | 
| 用户与设备 | 账号运营与排查 | 列表 + 详情侧栏、设备折叠面板 | 重置密码、解绑设备、手动续期 | `/admin/api/users`、`/admin/api/licenses/{card_code}` | 
| 批量任务 | 查看后台自动化状态 | 时间线、进度条、运行日志 | 启动/停止任务，查看导入/导出结果 | `/admin/api/batch-jobs`（新） |
| 审计日志 | 合规追踪 | 可筛选日志流、Diff 视图 | 导出日志、按对象筛选 | `/admin/api/audit-logs`（扩展原接口） |
| 系统设置 | 参数与安全策略 | 表单、密钥管理、白名单列表 | 轮换管理员密码、配置 CDN、安全开关 | `/admin/api/settings`（新） |
| CDN 管理 | 管理边缘节点与密钥 | 节点总览卡片、拓扑图、节点列表、推送面板 | 发布/回滚 CDN 节点配置、轮换共享密钥、滚动更新 | `/admin/api/cdn-nodes`、`/admin/api/cdn-deployments`（新） |

### 角色与权限

- 初始化角色：`owner`（全部权限）、`operator`（查看 + 创建/更新类型/卡密）、`analyst`（查看 + 导出）、`auditor`（只读 + 下载审计日志）。
- 支持自定义角色模板，最小粒度到模块级别的 CRUD 权限；权限配置保存在 `admin_roles` 与 `admin_role_permissions`（后续迭代）。
- HTTP Basic 继续作为网关校验，登录后在 Session 中绑定角色信息，前端根据角色隐藏按钮、后端再次校验。

### 交互细节与状态管理

- 表格视图支持多重筛选：文本搜索（卡号/用户/备注）、状态多选、类型筛选、创建时间范围、到期时间范围；筛选条件序列化进 URL，便于分享链接。
- 所有关键操作弹出确认对话框，需输入一次性确认词（例如撤销操作输入 `REVOKE`）。
- 表单校验规则在前后端一致复用：使用 JSON Schema 定义字段约束，前端通过 Zod/JSON Schema 驱动即时校验。
- 实时反馈：使用 Server-Sent Events（SSE）或 HTMX `hx-trigger="sse:event"`，在批量任务完成时推送通知。

### UI 设计约束

- 样式基于 Tailwind 配色，但统一提取成 Design Token：`--color-primary = #2563EB`、`--color-success = #16a34a`、`--color-warning = #f97316`、`--color-danger = #dc2626`、`--color-surface = #0f172a`。
- 深色模式优先：默认渲染暗色主题，并提供快捷切换明亮主题。
- 图标统一使用 Lucide 图标集，尺寸 18px，注意 Hover/Active 态。
- 列表支持“密集/舒适”两种密度；默认舒适态，密集态适合运营同学批量处理。
- 所有颜色在 WCAG 2.1 AA 对比度 ≥ 4.5:1。

### 性能与可用性目标

- 常用列表查询（卡密、用户）在 10 万条数据下，分页请求首屏响应时间 ≤ 1.2s。
- 表格组件启用虚拟滚动，保证 500 行以内滚动流畅。
- 后端接口超时阈值 5s，前端 3s 未响应提示“后台处理中”，并允许在通知中心查看最终结果。
- 支持操作回滚：例如误撤销卡密，可在 5 分钟内通过“最近操作”面板撤销。

### 可观测性与审计

- 每个变更写入审计日志：记录操作者、角色、旧值、新值、来源页面、请求 ID。
- 仪表盘展示最近 24 小时的高危操作统计（撤销、批量导入、权限变更）。
- 管理端事件发送至 `audit_admin_events` Kafka Topic（长期目标），现阶段可落地 SQLite `admin_events`。

### 里程碑拆分

1. **MVP (Sprint 1)**：完成卡密类型管理页、卡密列表类型筛选/创建、概览仪表盘占位、基于角色的导航隐藏。
2. **Sprint 2**：上线用户与设备视图、批量任务队列（仅导出）、审计日志筛选组件、通知中心。
3. **Sprint 3**：引入系统设置页、任务实时推送、操作回滚、深色主题完善、可观测性仪表。

### CDN 管理模块详解

1. **节点总览与状态监控**
   - 首页展示 CDN 节点数量、在线/离线比例、最近部署批次状态。
   - 拓扑图按地域聚合节点，颜色指示健康状态（绿色=正常、黄色=警告、红色=离线）。
   - 节点详情面板显示：主机名、IP、地域、最近心跳时间、部署脚本版本、`nginx` 配置校验结果。

2. **节点管理**
   - 支持批量导入节点（CSV/JSON），字段包括：`region`、`hostname`、`ssh_user`、`jump_host`、`tags`。
   - 节点记录与后端 `cdn_nodes` 表关联，状态字段包含 `registered`、`deploying`、`active`、`error`、`decommissioned`。
   - 节点操作：启用/禁用、设为维护模式、分配标签（如 `edge`, `origin`, `staging`）。

3. **部署策略与流水线**
   - 集成现有脚本 `server/tools/deploy_cdn.py`：后台触发后异步执行，部署状态通过 SSE/通知中心反馈。
   - 支持蓝绿/分批发布，配置策略：`percentage rollout`、`region-first` 等；前端提供策略选择器。
   - 部署流水线包括：生成配置 -> 分发 -> 验证 -> 切换流量 -> 回调结果。每个阶段在 UI 中可展开查看详细日志。
   - 支持回滚：保留最近 5 个部署版本，选择版本后自动重发旧配置并记录审计日志。

4. **密钥与证书管理**
   - 管理共享密钥 `X-Edge-Token`：提供一键轮换向导，生成新密钥 -> 推送 CDN 节点 -> 更新源站 -> 二次确认失效旧密钥。
   - 支持上传/生成 TLS 证书，记录到期时间，提前 30 天发送预警通知。
   - 密钥/证书变更需双人确认（可配置），支持添加审批流程（提交 -> 审批 -> 执行）。

5. **可观测性与告警**
   - 节点心跳失败或返回错误日志时，触发告警卡片并在通知中心列出；可配置重试与自愈脚本。
   - 集成运行日志：对接 `cdn_deployments` 表，存储执行输出，支持关键字搜索与下载。
   - 与审计日志联动，记录操作人、命令摘要、受影响节点列表。

6. **权限模型**
   - 新增 `cdn_admin`（可部署与轮换密钥）与 `cdn_observer`（只读）角色模板。
   - 在自定义权限界面增加粒度：`cdn.nodes.read`、`cdn.nodes.write`、`cdn.deployments.execute`、`cdn.keys.rotate`。
   - 所有危害性操作（部署、轮换、回滚）需要输入二级认证（TOTP 或命令确认词）。

7. **API 设计草案**
   - `GET /admin/api/cdn-nodes`：分页查询节点列表，支持按状态、标签过滤。
   - `POST /admin/api/cdn-nodes`：新增节点，触发可选的连通性测试。
   - `POST /admin/api/cdn-deployments`：创建部署批次，请求体含策略、目标节点列表、配置模板引用。
   - `GET /admin/api/cdn-deployments/{id}`：查看部署进度、阶段日志。
   - `POST /admin/api/cdn-keys/rotate`：发起共享密钥轮换。

8. **前端实现建议**
   - 复用 HTMX + Tailwind 组合：部署列表支持实时刷新（`hx-trigger="sse:deployment_update"`）。
   - 使用 `Monaco Editor` 嵌入 YAML/JSON 配置预览，提供语法高亮与校验。
   - 节点拓扑图可采用轻量级库（如 `D3.js` 或 `flowchart.ts`），支持节点点击展开详情。

9. **后续扩展**
   - 与监控平台整合（Prometheus/Grafana），展示延迟、错误率、带宽等指标。
   - 计划支持 API 触发第三方运维平台（如 Ansible Tower）执行更复杂任务。
   - 引入 `cdn_webhooks`，在部署完成后通知外部系统（Slack、企业微信）。

  - 批量创建结果唯一性。
  - API 输入校验。
- 集成测试：`/admin/licenses` 页面在选择类型时是否正确提交。
- 数据迁移测试：在 SQLite 内存或临时文件上运行迁移并断言字段存在。

## Open Questions

- 是否需要支持“共享型”卡密（多设备同时在线），将通过未来的套餐模型解决。
- 卡号格式是否需要校验长度与校验码？目前计划保持随机 hex + 前缀。
- 类型是否与销售渠道/租户关联？暂不在 MVP 内实现。

## Timeline (建议)

1. **Sprint 1**：完成后端数据模型与 API；更新管理脚本；提供基础 UI 可选类型。
2. **Sprint 2**：上线类型管理页、批量创建、列表筛选；完善测试与文档。
3. **Sprint 3**：整合自动化（例如按类型自动续期）、完善统计报表。

## Deliverables

- Alembic 迁移脚本 & ORM 更新。
- 扩展的 `LicenseService` + API + CLI。
- 新增/改进的管理模板与前端脚本。
- 设计文档（本文）与用户指南更新。
