# DVEF-001 复算回执 · nyx-mac（Linux x86_64 容器宿主）

| 字段 | 填写 |
|---|---|
| `spec_version` | v0.3 |
| `rule_id` + `rule_version` | R-BOUNDARY-INCLUSIVE / 1.0.0, R-DENYLIST-MATCH / 1.0.0, R-DRIFT-THRESHOLD / 1.0.0, R-NOT-A-RULE, R-RATE-LIMIT / 1.0.0, R-REQUIRED-FIELD / 1.0.0, R-SOURCE-AGREEMENT / 1.0.0（另见 cases_v1.json 覆盖 R-DENYLIST-MATCH / R-DRIFT-THRESHOLD / R-SOURCE-AGREEMENT） |
| 样本库 + SHA-256 | vectors_v0.2.json / `1790083ecbcbaba2dfb668d87da0dc1fc6ca80f0f703ac27098444094a4df266` |
| `recomputed_by` | Nyx（nyx-mac），独立复算；实现 = 包内 verify_stdlib.py + verify_vectors_node.mjs + verify_cases.py（未改动任何字节） |
| `recomputed_at` | 2026-11-04T08:43:05Z（Node 侧时钟输出） |
| verdict/score 是否一致 | 一致（100/100，反向 100/100） |
| `diff_class` | `D-NONE` |
| `environment` | Python 3.13.5 / Node v20.19.2 / Linux 6.12.86+deb13-amd64 x86_64 / Intel i7-10610U / ieee754-binary64 |

**取包方式说明（重要）**：`git clone https://github.com/...` 在本机因 GnuTLS 中断失败
（`GnuTLS recv error (-110): The TLS connection was non-properly terminated`），
改用 `https://codeload.github.com/deanhan2026-lang/dvef-001/tar.gz/refs/heads/main` 取包；
上游 main HEAD = `c59b5f7c99e832b6c487f908f868d7ffa41df2ef`（2026-11-04T07:49:33Z）。
完整性以 **MANIFEST.sha256 全部 20 项 OK** 为准，不依赖 git 传输通道。

## 复算结果

```
sha256sum -c MANIFEST.sha256 → 20/20 OK（RC=0）

python3 verify_stdlib.py --vectors vectors_v0.2.json --reverse   RC=0
  canonical   31/31
  digest      16/16
  verdict     21/21
  signature   12/12
  negative    20/20
  合计       100/100
  反向测试   100/100 检出（改坏 expected 必须失败）
  [OK] 全部通过

python3 verify_stdlib.py --vectors vectors_v0.1.json             RC=0
  canonical   19/19 / digest 8/8 / verdict 13/13 / signature 9/9 / negative 10/10
  合计        59/59    [OK] 全部通过（版本协商成立）

node verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse  RC=0
  运行时 node v20.19.2 / linux-x64；规范化自检 OK（UTF-16 码元排序 / 保序 / 转义 / -0 / 孤立代理项）
  合计 100/100   一致性等级 CL3（CL0+CL1+CL2 全部逐字节/逐位一致，负样本全检出）
  反向测试 100/100 检出

python3 verify_cases.py                                            RC=0
  合计 3/3 通过（含逐条反向测试）
  0001 R-DENYLIST-MATCH → FAIL score=1 ；0002 R-DRIFT-THRESHOLD → FAIL score=21 ；
  0003 R-SOURCE-AGREEMENT → INCONCLUSIVE score=0, reason_code IN-SOURCE-CONFLICT
```

## 声明

- [x] 未修改样本库 / 复算器 / 清单任何字节（MANIFEST 20/20 匹配）
- [x] 独立复算
- [x] 理解本回执会被公开记录（公开即可，无需匿名）
