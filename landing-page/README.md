# landing-page/

自包含单页官网原型（PEA-Landing-Page）。

- `index.html` —— 单文件页面：内联 CSS/JS，无 CDN、无外部字体、无运行时网络请求。
- `index.html` —— 同一页面的源副本；仓库根 `index.html` 是 GitHub Pages 首页。**两份必须逐字节一致**（`tests/test_landing_page.py` 会因不一致而失败）。
- 页面“先在一个小项目上试试 PEA”区的下载按钮指向**仓库根目录的发布包** `pea-<版本>-release.zip`：由 `make release-pkg` 生成（`git archive`，只含跟踪文件），上传到仓库根目录后按钮即可下载（URL 形如 `https://github.com/haothtrteen/pea/raw/main/pea-<版本>-release.zip`）。包名与 `pyproject.toml` 的版本号同源，页面链接与包名的一致性由测试钉死。
- `downloads/PEA-Design-Kit-v0.5.0.zip` —— 0.5.0 时期的设计资料包（历史留存；当前页面按钮**不再**指向它。远端 `landing-page/downloads/` 为空，相对路径会 404，这也是按钮改用绝对 URL 的原因）。
- `DESIGN-MAPPING.md` / `NOTICE.md` —— 区块对照与项目独立性声明。
- `LICENSE.txt` —— 本页面自有材料的 MIT 许可（Copyright (c) 2026 haothtrteen）。

页面中的 CLI 命令写作 `python -m pea.cli ...`，与下载包及仓库本体的当前命令一致（安装后亦可直接使用 `pea ...` 入口，见根目录 README）。

直接浏览器打开 `index.html` 即可预览。
