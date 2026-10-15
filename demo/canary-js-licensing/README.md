# canary: js-licensing (WP4)

PEA 保护管线端到端闭环的测量载体（`scripts/verify_loop.py` 的被测对象）。

**诚实声明（先读再下结论）**：

1. 这是保护管线的**测量载体，不是安全授权实现**——客户端签名校验混淆后
   仍是客户端校验，不因混淆变权威；服务端执法属架构建议（PEA 报告的
   `logic_extraction` 建议）。
2. `license.js` 中的签名密钥是**埋设的 canary**（`canary` 标记，不是真实
   凭据）；它的存在让管线能对保护前后"秘密形态材料是否仍可见"做测量。
3. 基线测试**故意不含明文秘密**：前后暴露面差分因此隔离生产文件——计数
   变化可归因于被测变换，不被验证基础设施稀释。
4. 运行时开销不在本 canary 的测量范围内（上游文档警示部分配置减速
   15–80%）：verify_loop 只测体积（精确），运行时记 unknown。

## 结构

| 文件 | 作用 |
| --- | --- |
| `license.js` | 生产模块：HMAC 签名/校验 + 埋设 canary 秘密 |
| `license.test.js` | 基线测试（`node --test`）：无明文秘密 |
| `package.json` | `npm test` → `node --test`（执行器的测试命令检测依据） |

## 用法

```bash
node --test demo/canary-js-licensing   # 基线测试（须在目录内跑：node --test）
python3 scripts/verify_loop.py         # 七步闭环 + 八条判据（单独触发，不进默认 CI）
```
