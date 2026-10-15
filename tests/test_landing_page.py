"""落地页与发布包的一致性门（漂移即失败）。

下载按钮指向**仓库根目录的发布包**（`pea-<版本>-release.zip`，由
`make release-pkg` 生成并上传到仓库根）。这里把三件事钉死：

1. 两份页面逐字节一致——仓库根 `index.html` 是 GitHub Pages 首页，
   `landing-page/index.html` 是它的源；改一处忘另一处即失败；
2. 下载链接是仓库根包的绝对 URL。回到 `./downloads/…` 相对路径会 404：
   远端 `landing-page/downloads/` 是空的（Web 上传跳过了二进制），这正是
   这个门存在的原因；
3. URL 里的包名 == `pea-<pyproject 版本>-release.zip`——与 Makefile 的
   `release-pkg` 目标派生出的包名、以及 `pyproject.toml` 的版本号同源。
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
            "index.html 与 landing-page/index.html 不一致——改一处后请同步另一份",
        )

    def test_download_button_points_at_the_repo_root_package(self):
        page = ROOT_PAGE.read_text(encoding="utf-8")
        expected = f"{REPO_URL}/raw/main/pea-{_version()}-release.zip"
        self.assertIn(f'href="{expected}"', page, f"下载按钮应指向仓库根发布包：{expected}")

    def test_no_relative_downloads_path_remains(self):
        """相对路径 ./downloads/ 在远端是空目录（404）——不得回归。"""
        page = ROOT_PAGE.read_text(encoding="utf-8")
        self.assertNotIn('href="./downloads/', page, "下载链接不得回退到相对 downloads/ 路径")

    def test_cross_origin_link_carries_no_meaningless_download_attribute(self):
        """跨源链接上的 download 属性会被浏览器忽略，留着是误导。"""
        page = ROOT_PAGE.read_text(encoding="utf-8")
        anchor = re.search(r"<a [^>]*pea-\d+\.\d+\.\d+-release\.zip[^>]*>", page)
        self.assertIsNotNone(anchor, "找不到下载锚点")
        self.assertNotIn("download", anchor.group(0), f"锚点不应带 download 属性：{anchor.group(0)}")

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
