# DVEF-001 复算回执（模板）

> 请如实填写。任何一项留空，本回执只能按 CL1 以下记录，不参与互认。

| 字段 | 你的填写 |
|---|---|
| `spec_version`（被复算的规范版本） | v0.3 |
| `rule_id` + `rule_version`（覆盖到的规则） | 例：R-DRIFT-THRESHOLD / 1.0.0（可多行） |
| 样本库版本 + 文件 SHA-256 | 例：vectors_v0.2.json / `<sha256>` |
| `recomputed_by`（复算方标识：个人或机构 + 实现名与版本） | |
| `recomputed_at`（UTC，ISO-8601） | |
| 每条 `verdict` + `score` 与声明值是否一致 | 一致 / 不一致（不一致请附明细） |
| `diff_class`（差异类别） | `D-NONE` / `D-ENV` / `D-SPEC` / `D-IMPL` / `D-TAMPER` |
| `environment`（语言、运行时、OS、浮点声明） | 例：python 3.11.9 / Linux x86_64 / ieee754-binary64 |

## 复算结果摘要（请粘贴你的实际输出）

```
（粘贴 verify_stdlib.py 与/或 verify_vectors_node.mjs 的完整输出）
```

## 反向测试结果（判别力）

```
（粘贴 --reverse 那一行：应形如「反向测试 N/N 检出」）
```

## 若不一致：最小复现

```
（输入 + 参数 + 你的输出 + 你期望的输出 + 你依据的规范条款号）
```

## 声明

- [ ] 我未修改样本库、复算器或清单文件中的任何字节（`MANIFEST.sha256` 全部匹配）。
- [ ] 我独立完成复算，未参考对方的实现代码。
- [ ] 我理解本回执会被公开记录（如需匿名，请在此说明）。
