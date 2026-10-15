# demo/ — PEA 原型 1.0 演示材料

本目录承载原型 1.0 的端到端演示材料：

| 路径 | 说明 |
| --- | --- |
| `build_canary.py` | 重建 canary 项目的脚本（幂等，仓库内 canary 必须与它逐字节一致，由 `tests/test_demo_e2e.py` 断言） |
| `canary-flutter-licensing/` | 自建、有意埋标的 Flutter 形态源码树（静态结构，非可构建应用） |
| `build_canary_artifacts.py`（`../scripts/`） | 重建**合成形态产物**的脚本：ELF/zip 逐字节合成、固定时间戳、可确定重建（仓库内产物必须与它逐字节一致，由 `test_canary_artifacts_match_builder` 断言，摘要由 `verify_real.py --digests-only` 核对） |
| `canary-artifacts/` | 合成形态产物 fixture：`libapp.so`×3 ABI + `libflutter.so` + APK + AAB。**不是 Flutter 构建**（本环境无 Flutter SDK），ELF 头部与埋标字符串是真实字节，供 L2 真实工兵层使用 |
| `canary-artifacts.manifest.json` | 产物清单：路径/类型/SHA-256/字节数，L2 的 manifest 层逐字节钉住 |

运行方式见 [`../docs/Prototype-1.0-Demo-zh-CN.md`](../docs/Prototype-1.0-Demo-zh-CN.md)。

```bash
PYTHONPATH=src python3 -m pea.cli demo \
  --request examples/protection-request.flutter-licensing.example.json \
  --project demo/canary-flutter-licensing \
  --out /tmp/pea-demo-out
```

canary 的安全属性：所有埋标值使用 `.invalid` 保留 TLD 与 `CANARY-` 前缀，
即使扫描输出意外泄漏也不含可用信息；源码 canary 不含任何构建产物，因此
release 级暴露面在 demo 中诚实地呈现为 unknown。L2 真实工兵层
（`../scripts/verify_real.py`）另用 `canary-artifacts/` 里的**合成形态**
产物（非 Flutter 构建）把七个域放到真实字节上验证——合成形态声明随每份
L2 报告一起输出，恢复率类结论在真实构建存在前恒为 unknown。

**这个场景是模拟，不是范本。** Flutter 授权场景（含 canary 的埋标位置与
命中结果）用来说明流水线如何运转，**不对应任何真实项目，也不预设真实
项目的形态**。真实应用的判断依据只有两个：域扫描实际观察到的**项目
状态**（语言/产物/秘密命中等，逐域以 coverage + unknowns 呈现），以及
能力映射地图级 `research_date`（2026-10-13，附“运行时确认”注记）的**社区实时状态**（工具在进化，
T1 评级随之变化——见 `docs/Exposure-Tier-Model-zh-CN.md` 的时效性注意
事项）。把 demo 的命中结果当作"典型项目结论"来依赖，恰是这套系统要
防止的误用。
