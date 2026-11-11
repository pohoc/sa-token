# Release Process

正式发布顺序为：**main CI 全绿 → 唯一的 Release workflow 创建或接收版本 tag → 自动生成并回写变更日志 → 发布 GitHub Release**。

## 一键发布

不需要手工编辑 `CHANGELOG.md`。开发提交使用 Conventional Commits 标题；Release workflow 会读取上一个版本 tag 到当前 tag 之间的提交，自动生成版本日志和 GitHub Release notes，再通过 PR 更新 `main` 上的 `CHANGELOG.md`。

1. 确认待发布代码已合并到 `main`。
2. 在 GitHub Actions 运行唯一的 **Release** workflow，选择 `main`，输入不带 `v` 的 SemVer，例如 `0.3.2`。

   命令行也可一键启动：

   ```bash
   gh workflow run "Release" --ref main -f version=0.3.2
   ```

3. **Release** 等待 `main` 合并后自动触发的 CI 全部通过，再创建不可变版本 tag。创建 tag 和发布在同一次 workflow run 中完成，不会启动第二个 Release workflow，也不会在 main push CI 之外再跑一遍完整矩阵。
4. `release` 环境需要审批后，workflow 调用 `php scripts/changelog.php --tag v0.3.2`，自动汇总两个版本 tag 之间的用户可见 Conventional Commits，更新 tag 比较链接并生成 Release notes。
5. 因为 `main` 要求通过 PR，workflow 会创建只包含变更日志的 PR。它先等待 PR 自动触发的 CI；仅当 GitHub 未启动该 CI，或将其标记为 `action_required` 且没有 job 时，才回退到一次手动 CI。CI 成功后自动合并 PR，再创建 GitHub Release。
6. 检查最终 tag、`CHANGELOG.md` 和 GitHub Release 是否指向同一版本并且内容一致。

版本号输入示例：`0.3.2`；工作流会自动补 `v` 前缀。已创建 tag 但发布失败时，可在同一个 **Release** workflow 输入相同版本恢复；工作流会复用 tag 和 changelog PR。仓库现有 `release` 环境审批仍然生效。

## 直接推送 tag

已有成功的 main CI 时，也可以直接推送 tag：

```bash
git tag -a v0.3.2 -m "Release v0.3.2"
git push origin v0.3.2
```

人工推送的 `v*` tag 会触发同一个 **Release** workflow。直接推送前必须确认 main 上完整 CI 已通过；tag 规则禁止删除和重指，Release workflow 会在发布前复核所有必需检查。

## 失败后恢复

- 若 tag 已创建但发布未完成，在 Actions 运行同一个 **Release** workflow，选择 `main` 并输入已存在版本（例如 `0.3.2`）继续；不要再次创建 tag。
- 若变更日志 PR 已合并但创建 Release 失败，可用相同版本重跑 **Release**。工作流会确认日志已存在并继续发布。
- 如果 tag、变更日志或 Release 内容有误，不要移动或删除已发布 tag；使用新的修正版版本号。

## 工作流实现说明

- `.github/workflows/release.yml` 是唯一发布 workflow：手动运行时校验并等待 main 上已有 CI，创建 tag 后在同一次 run 中继续发布；人工推送 tag 时也由此 workflow 处理。
- 手动创建的 tag 由同一 workflow 继续处理，不依赖 `GITHUB_TOKEN` 再触发另一个 workflow，也不使用额外的 `repository_dispatch`。
- changelog PR 优先复用成功的自动 `pull_request` CI；只有自动 CI 未启动或被 GitHub 阻止启动时才手动运行一次，避免无条件重复检查相同提交。
- `scripts/changelog.php` 根据前后版本 tag 之间的 `feat`、`fix`、`security`、`perf`、`deps`、`build`、`refactor` 和 `docs` 提交自动生成日志；CI、测试、维护和发布流程提交不会进入用户版本日志。历史版本说明会保留，比较链接会自动更新。
