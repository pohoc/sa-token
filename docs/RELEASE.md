# Release Process

正式发布顺序为：**main CI 全绿 → 创建版本 tag → tag 触发 Release workflow → 生成并回写变更日志 → 发布 GitHub Release**。

## 一键发布

开发期间，将需要出现在版本日志中的用户可见变更整理到 `CHANGELOG.md` 的 `## 未发布` 区域；没有待发布条目时，不保留空标题。Release workflow 会在 tag 创建后将该区域归档到版本标题并移除空占位；没有条目时会写入“无显著变更”。

1. 确认待发布代码已合并到 `main`。
2. 在 GitHub Actions 运行 **Start Release**，选择 `main`，输入不带 `v` 的 SemVer，例如 `0.3.1`。

   命令行也可一键启动：

   ```bash
   gh workflow run "Start Release" --ref main -f version=0.3.1
   ```

3. 工作流运行完整 CI。通过后会确认 `main` 未变化，创建不可变的 `v0.3.1` tag，并启动 tag 对应的 **Release** workflow。
4. **Release** 校验 tag 确实位于 `main`，并确认 PHP 8.2–8.5、最低/最高依赖、真实 Redis、静态分析和 Composer 检查全部成功。
5. `release` 环境需要审批后，Release workflow 调用 `php scripts/changelog.php --tag v0.3.1`，把人工整理的“未发布”条目归档到对应版本，保留历史内容并更新 tag 比较链接，再从该版本生成 Release notes。归档后会移除空的“未发布”区。
6. 由于 `main` 要求通过 PR，workflow 会创建只包含变更日志的 PR，在该分支运行 CI；CI 通过后自动合并 PR，再创建 GitHub Release。
7. 检查最终 tag、`CHANGELOG.md` 和 GitHub Release 是否指向同一版本并且内容一致。

版本号输入示例：`0.3.1`；工作流会自动补 `v` 前缀。一次点击会启动整个流程。仓库现有的 `release` 环境审批仍然生效；如 CI、变更日志 PR 或环境审批失败，Release 不会发布。

## 直接推送 tag

已有成功的 main CI 时，也可以直接推送 tag：

```bash
git tag -a v0.3.1 -m "Release v0.3.1"
git push origin v0.3.1
```

人工推送的 `v*` tag 会直接触发 **Release** workflow。直接推送前必须确认 main 上完整 CI 已通过；当前 tag 规则本身只阻止删除和重指，Release workflow 会在发布前复核所有必需检查。若检查缺失或失败，tag 已不可移动，需修复后从 **Release** workflow 用同一 tag 恢复。

## 失败后恢复

- 若 tag 已创建但 Release workflow 未启动，可在 Actions 手动运行 **Release** workflow，选择 `main` 并输入已存在的 tag（例如 `v0.3.1`）继续；不要再次创建 tag。
- 若变更日志 PR 已合并但创建 Release 失败，可用同一 tag 重新运行 **Release**。工作流会确认日志已存在并继续发布。
- 如果 tag、变更日志或 Release 内容有误，不要移动或删除已发布 tag；使用新的修正版版本号。

## 工作流实现说明

- `start-release.yml` 是一键入口：先完整验证，再创建 tag。由于 GitHub 不会让 `GITHUB_TOKEN` 推送的 tag 自动启动另一个 push workflow，它会在 tag 创建后显式发送 `repository_dispatch` 来启动 **Release**。人工推送 tag 则由 `push.tags` 触发。
- `release.yml` 只处理已存在的 tag：校验 CI、运行 changelog 脚本、通过 PR 更新 `main`，然后发布 Release。
- `scripts/changelog.php` 不从数百条提交标题重建日志；它将人工整理的“未发布”内容归档到新 tag，保留已有版本说明并更新比较链接。
