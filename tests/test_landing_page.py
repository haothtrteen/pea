"""落地页与发布包的一致性门（漂移即失败）。

下载按钮指向**发布包**（`pea-<版本>-release.zip`，由 `make release-pkg`
生成、作为 GitHub Release 附件上传）。这里把四件事钉死：

1. 两份页面逐字节一致——仓库根 `index.html` 是 GitHub Pages 首页，
   `landing-page/index.html` 是它的源；改一处忘另一处即失败
   （同步命令：`make sync-landing`，以 `landing-page/` 那份为准）；
2. 下载链接是 **Release 附件**的绝对 URL。包不在仓库树里，`…/raw/main/…`
   路径不存在——曾因此 404，这正是这个门存在的原因；相对路径
   `./downloads/…` 同样不可用（远端该目录为空，Web 上传跳过了二进制）；
3. URL 里的包名 == `pea-<pyproject 版本>-release.zip`——与 Makefile 的
   `release-pkg` 目标派生出的包名、以及 `pyproject.toml` 的版本号同源；
4. 跨源锚点不带 `download` 属性（会被浏览器忽略，留着是误导）。

改页面后跑 `python -m pytest tests/test_landing_page.py -q` 即可自检。
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROOT_PAGE = ROOT / "index.html"
SOURCE_PAGE = ROOT / "landing-page" / "index.html"
REPO_URL = "https://github.com/haothtrteen/pea"


def _version() -> str:
    """pyproject 的版本号（与 Makefile 同一解析方式，兼容 3.10）。"""
    match = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M)
    assert match, "pyproject.toml 里找不到 version"
    return match.group(1)


class LandingPageConsistencyTests(unittest.TestCase):
    def test_both_page_copies_are_identical(self):
        self.assertTrue(ROOT_PAGE.is_file(), "仓库根缺少 index.html（GitHub Pages 首页）")
        self.assertEqual(
            ROOT_PAGE.read_bytes(),
            SOURCE_PAGE.read_bytes(),
            "index.html 与 landing-page/index.html 不一致——改完请同步另一份：make sync-landing"
            "（以 landing-page/index.html 为准覆盖根 index.html）",
        )

    def test_download_button_points_at_the_release_asset(self):
        """发布包是 Release 附件，不在仓库树里——raw/main 路径不存在（曾因此 404）。"""
        page = ROOT_PAGE.read_text(encoding="utf-8")
        match = re.search(r'href="(https://github\.com/haothtrteen/pea/releases/(?:download/[^/]+|latest/download)/[^"]+)"', page)
        self.assertIsNotNone(match, "下载按钮应指向 GitHub Release 附件")
        url = match.group(1)
        filename = url.rsplit("/", 1)[-1]
        self.assertEqual(filename, f"pea-{_version()}-release.zip", f"附件名应与版本同源：{url}")
        self.assertNotIn("/raw/main/pea-", page, "不得混用仓库树 raw 路径（包不在仓库树里）")

    def test_no_relative_downloads_path_remains(self):
        """相对路径 ./downloads/ 在远端是空目录（404）——不得回归。"""
        page = ROOT_PAGE.read_text(encoding="utf-8")
        self.assertNotIn('href="./downloads/', page, "下载链接不得回退到相对 downloads/ 路径")

    def test_cross_origin_link_carries_no_meaningless_download_attribute(self):
        """跨源链接上的 download 属性会被浏览器忽略，留着是误导。"""
        page = ROOT_PAGE.read_text(encoding="utf-8")
        anchor = re.search(r"<a [^>]*pea-\d+\.\d+\.\d+-release\.zip[^>]*>", page)
        self.assertIsNotNone(anchor, "找不到下载锚点")
        # 只检查「属性」位置的 download；URL 路径里的 /releases/download/ 是地址的一部分，不是属性
        self.assertIsNone(
            re.search(r"\sdownload(?=[\s>=])", anchor.group(0)),
            f"锚点不应带 download 属性：{anchor.group(0)}",
        )

    def test_button_label_names_the_current_version(self):
        page = ROOT_PAGE.read_text(encoding="utf-8")
        anchor = re.search(r"<a [^>]*pea-[^>]*>([^<]*)</a>", page)
        self.assertIsNotNone(anchor)
        self.assertIn(_version(), anchor.group(1), "按钮文案应写明当前版本，便于读者判断包的新旧")

    def test_release_target_is_documented_in_makefile(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("release-pkg", makefile)
        self.assertIn("RELEASE_PKG := pea-$(VERSION)-release.zip", makefile)


if __name__ == "__main__":
    unittest.main()
