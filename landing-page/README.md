# landing-page/

自包含单页官网原型（PEA-Landing-Page）。

- `index.html` —— 单文件页面：内联 CSS/JS，无 CDN、无外部字体、无运行时网络请求。
- `index.html` —— 同一页面的源副本；仓库根 `index.html` 是 GitHub Pages 首页。**两份必须逐字节一致**（`tests/test_landing_page.py` 会因不一致而失败；改完跑 `make sync-landing` 一键同步，以本目录的 `index.html` 为准覆盖根副本）。
- 页面“先在一个小项目上试试 PEA”区的下载按钮指向 **GitHub Release 附件** `pea-<版本>-release.zip`：由 `make release-pkg` 生成（`git archive`，只含跟踪文件）后上传为 Release 附件。
  URL 形如 `https://github.com/haothtrteen/pea/releases/download/<tag>/pea-<版本>-release.zip`；若该 Release 是正式发布（非 prerelease），可改用 `…/releases/latest/download/pea-<版本>-release.zip`（换版本无需改页）。
  **注意**：包不在仓库树里，`…/raw/main/…` 路径不存在——早期版本曾因此 404。包名与 `pyproject.toml` 版本同源，由 `tests/test_landing_page.py` 钉死。
- `downloads/PEA-Design-Kit-v0.5.0.zip` —— 0.5.0 时期的设计资料包（历史留存；当前页面按钮**不再**指向它。远端 `landing-page/downloads/` 为空，相对路径会 404，这也是按钮改用绝对 URL 的原因）。
- `DESIGN-MAPPING.md` / `NOTICE.md` —— 区块对照与项目独立性声明。
- `LICENSE.txt` —— 本页面自有材料的 MIT 许可（Copyright (c) 2026 haothtrteen）。

页面中的 CLI 命令写作 `python -m pea.cli ...`，与下载包及仓库本体的当前命令一致（安装后亦可直接使用 `pea ...` 入口，见根目录 README）。

直接浏览器打开 `index.html` 即可预览。
