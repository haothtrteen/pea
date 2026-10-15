# 上游参考来源记录（Provenance）

| 项 | 值 |
|---|---|
| 项目 | REA（Reverse Engineering Assistant） |
| 官方仓库 | https://github.com/morluto/rea |
| 拉取方式 | 从官方仓库浅克隆（2026-10-13） |
| 完整 upstream URL | https://github.com/morluto/rea.git |
| 克隆深度 | `--depth 1`（浅克隆） |
| **HEAD commit** | `bb96afdbe32f5318d57fcb00099191c5a7712f53` |
| 提交日期 | 2026-10-12 22:29:09 -0700 |
| 提交说明 | fix(pcap): name the host tool to configure in capability refusals (#2507) |
| 分支 | main |
| 完整性校验 | HEAD 与 `git ls-remote https://github.com/morluto/rea.git` 直连返回值一致，内容未被篡改 |
| 跟踪文件数 | 3270（不含 .git） |
| 语言/构建 | TypeScript + Node，turbo monorepo，npm，vitest |

## 本地路径

- `/workspace/references/rea` — 上游只读参考（**不作为 PEA 的代码依赖**）

## 已知未完成项

1. **Submodules 未初始化**（`git submodule update --init --recursive` 未执行，体积大且非只读审计必需）：
   - `third_party/jadx-headless-mcp` — https://github.com/1013503897/jadx-headless-mcp.git
   - `third_party/binwalk` — https://github.com/ReFirmLabs/binwalk.git
   - `third_party/unblob` — https://github.com/onekey-sec/unblob.git
   - `third_party/ghidra-nativeaot` — https://github.com/Washi1337/ghidra-nativeaot.git
   - `third_party/wakaru` — https://github.com/pionxzh/wakaru.git
2. **浅克隆无历史**：如需按时间追溯某个能力的引入/变更，需 `git fetch --unshallow`。
3. PEA 早期文档记载的「执行容器无法解析 github.com，clone 失败」在**当前沙箱已不成立**——本次已成功克隆，相关状态应从 `unknown` 更新为 `source_reviewed` 的前提已具备。
4. 许可证：见上游 `LICENSE` 与 `THIRD_PARTY_NOTICES.md`；PEA 只做只读审计，不复制、不链接、不分发其代码。

## 证据状态

- `documentation_reviewed` ✅（此前已达成）
- `source_reviewed` ⏳ 本次已取得源码，路径/行号级审计待做（PEA-070）
