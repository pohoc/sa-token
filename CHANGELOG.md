# 变更日志

本文件由脚本自动生成，基于 git tag 和 commit 记录。

## [v0.1.0] - 2026-05-12

### 修复
- 安全修复 - 自动锁定/签名算法/域名白名单/密钥回退/默认密钥警告
- 修复 SM4 密钥派生及清理硬编码密钥
- 修复测试文件 PHPStan 静态分析错误
- 修复 PHPStan level max 静态分析错误

### 新增
- Token 指纹绑定 + Token 黑名单机制
- 新增 SaLoginResult 标准化登录返回格式
- 实现 Refresh Token 双令牌机制
- 增加安全功能模块
- 新增会话自动清理 + 防暴力破解机制
- 新增 PHP Attribute 注解机制 + RPC 鉴权状态传递
- 补齐改进项 - 新增测试、JWT混合模式、SSO NoSdk/跨Redis
- 补齐14项功能，对齐 Java sa-token 核心能力
- 全面增强安全性及功能完善
- 初始提交

### 变更
- 代码质量优化 - 新增健康检查、性能指标、配置构建器、OAuth2 Strategy模式
- DAO 前缀索引、Token 前缀标识、login 拆分、批量清理优化
- StpLogic 拆分为 4 个 Trait 降低类复杂度
- DAO 批量删除接口与实现、SCAN 迭代限制
- 忽略 phpunit 缓存目录
- GitHub Actions 支持 PHP 8.5
- 升级 PHPStan 从 level 5 到 level max

### 文档
- 更新 README 和框架集成文档
- 更新 README PHP 版本徽章至 8.5
- 完善项目文档
- 更新变更日志 v0.0.1

## [v0.0.1] - 2026-04-09

### 新增
- 初始提交


[v0.0.1]: https://github.com/pohoc/sa-token/releases/tag/v0.0.1
[v0.1.0]: https://github.com/pohoc/sa-token/compare/v0.0.1...v0.1.0
