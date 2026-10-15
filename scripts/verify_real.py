"""L2 真实工兵层 CLI：把源码 canary 与合成产物拼成带构建输出的树，跑真实域。

用法::

    python3 scripts/verify_real.py                 # 全量七层验证
    python3 scripts/verify_real.py --json          # JSON 结果（机器可读）
    python3 scripts/verify_real.py --digests-only  # 只核对产物摘要与清单
    python3 scripts/verify_real.py --keep          # 保留暂存树便于复查
    python3 scripts/verify_real.py --out PATH      # 报告写出到文件

退出码：0=全部通过，1=有失败，2=有未评估（无失败）。未评估不是通过——
这一层的绿灯只属于全量实测通过。按 REA 纪律，本脚本单独触发，不进默认
CI（Makefile 的 ``verify-real`` target 同样不在 ``check`` 里）。

合成形态声明：产物由 ``scripts/build_canary_artifacts.py`` 逐字节合成，
ELF 头部与埋标字符串是真实字节，但不是 Flutter 构建（本环境无 Flutter
SDK）；Dart AOT 恢复率保持 unknown，本脚本不给任何恢复率结论。
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pea import l2verify  # noqa: E402


def _digests_only(args: argparse.Namespace) -> int:
    checks = l2verify.verify_digests(args.root / "demo" / "canary-artifacts", args.root / "demo" / "canary-artifacts.manifest.json")
    failed = [c for c in checks if c.status != "pass"]
    if args.json:
        print(json.dumps({"layer": "L2-digests", "status": "fail" if failed else "pass", "checks": [
            {"name": c.name, "status": c.status, "detail": c.detail} for c in checks
        ]}, ensure_ascii=False, indent=2))
    else:
        print("L2 digests-only: checked-in artifacts vs manifest")
        for check in checks:
            mark = "PASS" if check.status == "pass" else "FAIL"
            print(f"  [{mark}] {check.name}  {check.detail}")
        print(f"status: {'fail' if failed else 'pass'} ({len(checks)} files)")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_real",
        description="L2 真实工兵层：对合成形态 canary 产物跑真实域，三态判定（退出码 0/1/2）。",
    )
    parser.add_argument("--root", default=str(ROOT), help="仓库根目录（默认：本脚本所在仓库）")
    parser.add_argument("--json", action="store_true", help="输出 JSON 而非 Markdown")
    parser.add_argument("--digests-only", action="store_true", help="只核对 checked-in 产物与清单的摘要，不跑域")
    parser.add_argument("--keep", action="store_true", help="暂存树保留在 build/l2-stage 下便于复查")
    parser.add_argument("--out", help="报告写出路径（缺省打印到 stdout）")
    parser.add_argument("--now", help="固定时间戳（测试用）")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if args.digests_only:
        args.root = root
        return _digests_only(args)

    source_canary = root / "demo" / "canary-flutter-licensing"
    artifact_fixture = root / "demo" / "canary-artifacts"
    artifact_manifest = root / "demo" / "canary-artifacts.manifest.json"
    request = root / "examples" / "protection-request.flutter-licensing.example.json"
    for path in (source_canary, artifact_fixture, artifact_manifest, request):
        if not path.exists():
            print(f"verify-real: missing {path}", file=sys.stderr)
            return 1

    if args.keep:
        scratch = root / "build" / "l2-stage"
        scratch.mkdir(parents=True, exist_ok=True)
        staged = l2verify.stage_project(source_canary, artifact_fixture, scratch)
        report = l2verify.verify_l2(
            staged,
            request_path=request,
            artifact_manifest=artifact_manifest,
            now=args.now,
            cli_out_dir=scratch / "cli-out",
        )
    else:
        with tempfile.TemporaryDirectory(prefix="pea-l2-") as tmp:
            staged = l2verify.stage_project(source_canary, artifact_fixture, Path(tmp))
            report = l2verify.verify_l2(
                staged,
                request_path=request,
                artifact_manifest=artifact_manifest,
                now=args.now,
                cli_out_dir=Path(tmp) / "cli-out",
            )

    payload = report.to_dict()
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) if args.json else report.to_markdown()
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"verify-real: report written to {args.out} (status: {report.status})")
    else:
        print(rendered)
    return l2verify.EXIT_CODES[report.status]


if __name__ == "__main__":
    sys.exit(main())
