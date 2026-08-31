# 变更日志

本文件由脚本自动生成，基于 git tag 和 commit 记录。

## [v0.2.0] - 2026-08-31

### 修复
- (ci+test) PHP 8.1-8.3 兼容修复与 workflow 修正
- (security) 安全组件原子化与注解继承修复
- (sso) 登录 CSRF 强制校验、响应验签与回调防伪
- (oauth2) 授权绑定、令牌族撤销与暴力破解防护
- (crypto) 存储加密完整性与签名协议加固
- (core) 会话终止闭环、并发竞态与多账号隔离

### 新增
- (storage) DAO 原子原语、本地文件存储与配置驱动自动装配

### 变更
- 完善 CI/CD 流水线
- chore(qa)+docs: 移除 PHPStan 泛型压制并同步全部文档
- (deps) 升级 pohoc/crypto-sm 至 ^0.3 并完善工程配置

### 测试
- (security) 80 项安全行为回归测试与既有测试适配

## [v0.1.2] - 2026-05-21

### 变更
- 完善框架集成文档与上下文处理

## [v0.1.1] - 2026-05-14

### 修复
- (security) 移除Token框架识别前缀、修正ticket拼写并增加随机熵
- (security) OAuth2数据加密存储、redirect_uri严格校验、客户端信息持久化
- (security) SSO添加State参数防CSRF、同域模式CSRF校验、注销回调域名白名单
- (security) 登录分布式锁防竞态、Session Fixation防护、URL参数读取Token安全警告
- (security) IP欺骗防护、JWT算法白名单校验、移除默认加密密钥、Cookie安全属性默认启用

### 变更
- 安全加固认证配置与锁释放

### 文档
- 更新变更日志 v0.1.0

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

_无显著变更_


[v0.0.1]: https://github.com/pohoc/sa-token/releases/tag/v0.0.1
[v0.1.0]: https://github.com/pohoc/sa-token/compare/v0.0.1...v0.1.0
[v0.1.1]: https://github.com/pohoc/sa-token/compare/v0.1.0...v0.1.1
[v0.1.2]: https://github.com/pohoc/sa-token/compare/v0.1.1...v0.1.2
[v0.2.0]: https://github.com/pohoc/sa-token/compare/v0.1.2...v0.2.0
