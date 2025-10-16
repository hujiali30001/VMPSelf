# VMPSelf

该项目为自研 VMP 风格保护器的实验性实现，包含 Qt 5.12.12 客户端与 FastAPI 授权服务脚手架。

## 目录结构
- `client/` Qt C++ 壳工具源码。
- `server/` FastAPI + SQLite 授权服务。
- `docs/` 需求与技术文档。

## 快速开始
1. 根据 `docs/technical_plan.md` 配置开发环境。
2. 构建客户端：
   ```powershell
   mkdir build
   cd build
   cmake -G "Ninja" -DCMAKE_PREFIX_PATH="C:/Qt/Qt5.12.12/5.12.12/msvc2017_64" ..
   cmake --build .
   ```
3. 服务端：参考 `server/README.md` 安装依赖、初始化数据库并启动 `uvicorn`。

## 下一步
- 完善 PE 解析与虚拟化实现。
- 补齐授权服务签名/安全策略。
- 实现驱动通信与 Ring0 防护。
- 根据需要开启 CDN 守护（共享密钥 + IP 白名单），阻断对源站的直接攻击流量。
