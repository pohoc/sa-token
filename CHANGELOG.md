# 变更日志

本文件由脚本自动生成，基于 git tag 和 commit 记录。

## [v0.0.1] - 2026-04-09

初始发布版本。

### 新增
- 核心：StpLogic、StpUtil、SaToken、SaRouter、SaSession
- 认证：登录/注销/踢下线/身份切换/二级认证
- 权限校验：角色/权限验证、路由式鉴权（SaRouter 链式匹配）
- OAuth2.0：授权码、隐式、密码、客户端凭证四种模式
- SSO 单点登录：同域 Cookie / 跨域认证中心 / 前后端分离三种模式
- DAO：内存、文件、Redis、PSR-16 适配器
- 插件：国密加密 SaTokenSmCrypto（SM2/SM3/SM4）、JWT、AES/RSA/HMAC
- 配置、异常、监听器、动作、工具模块
- 测试：412 个测试，853 个断言
- CI：GitHub Actions（php.yml、release.yml）
- 工具链：PHPStan、PHP-CS-Fixer、变更日志脚本
- 文档：CONTRIBUTING.md、SECURITY.md、LICENSE

[v0.0.1]: https://github.com/pohoc/sa-token/releases/tag/v0.0.1
