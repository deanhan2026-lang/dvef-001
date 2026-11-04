# 复算回执登记（Reproducibility receipts）

**这份文件记录"别人跑我们的东西"的真实结果。**
截至 2026-11-04，共收到 **2 份回执**，均判定 `D-NONE`（无差异）。

> ⚠️ 诚实边界，先写在最前面：这 2 份回执来自**同组织内的异构宿主**，**不构成独立第三方验证**。
> 外部无归属节点回执数 = **0**。本文件证明的是「换机器、换语言、换版本还能算出同一结果」（可复现性），
> 不是「有个我们控制不了的机构替我们背书」。

## 一、回执一览

| # | 复算方 | 宿主 / 运行时 | 结论 | 回执时间 |
|---|---|---|---|---|
| R1 | `iris-openclaw` | WLMHAN · Windows x86_64 · **Python 3.11.9**<br>M6 · **macOS arm64 · Python 3.9.6**<br>Node **v24.19.0** | `D-NONE` · 100/100 · 反向 100/100 | 2026-11-04 15:27 |
| R2 | `kronos-shun` | Windows 11 26200 · **CPython 3.14.3** · **Node v24.15.0** · x86_64 | `D-NONE` · 100/100 · 反向 100/100 | 2026-11-04 15:33 |

两方独立下载的 `vectors_v0.2.json` 得同一份字节流：
`sha256 1790083ecbcbaba2dfb668d87da0dc1fc6ca80f0f703ac27098444094a4df266`。

### 覆盖到的运行时版本（这是回执的真正价值）

| 维度 | 已覆盖 |
|---|---|
| Python | **3.9.6** / **3.11.9** / **3.14.3** |
| Node | **v24.15.0** / **v24.19.0**（另加维护方 v22.22.3） |
| 平台 | Windows x86_64 / **macOS arm64** |
| 数值 | ieee754-binary64（各方均声明一致） |

## 二、R2 额外做的两件事（值得单独记）

1. **git blob-sha1 交叉**：对 21 个 blob 重算 `sha1("blob <len>\0" + bytes)` 与 GitHub tree API 声明值比对，
   **21/21 一致** ⇒ 本地副本能自证 byte-exact，**不依赖下载通道可信**。这比"sha256 清单匹配"更强一层：
   清单本身也可能被篡改，而 blob-sha1 的期望值来自平台侧独立计算。
2. **确定性复跑**：`PYTHONHASHSEED=0/1/2` 三次运行 stdout 的 SHA-256 **完全相同**（`342bd9c8b7ecd08f…`）
   ⇒ 输出不依赖哈希种子。

## 三、回执发现的问题与修复（提问题的一方更有价值）

| 来源 | 问题 | 处置 |
|---|---|---|
| R1 | Windows 上若环境带 `safe_path`/受限 `PYTHONPATH`，`verify_stdlib.py` 会因 `ed25519_pure` 不在 `sys.path` 报 `ModuleNotFoundError` | **已修**：启动时把脚本目录插入 `sys.path` 首位；复测：异 cwd + 污染 `PYTHONPATH` 下仍 100/100 |
| R2 | `verify_stdlib.py` 读取样本库时 `io.open` 未关闭，`-W error` 下抛 `ResourceWarning` | **已修**：改 `with`；复测 `-W error::ResourceWarning` 全绿 |
| R2 | Node 复算器标题恒写「v0.1 样本库独立复算」，跑 v0.2 时也不变 → 审计时易误读 | **已修**：改为读取样本库自身 `spec_version` / `vectors_version` 输出 |
| R2 | 指出自己 **不构成异构**：其 CPython 3.14.3 与样本库生成器版本相同 | 采纳并记录：该回执的异构性只来自 Node v24.15.0 |

> 第 4 条是我们最看重的一条：**复算方主动声明自己证据的边界**，比多跑通一个版本更有价值。

## 四、怎么提交你的回执

见 `RECEIPT_TEMPLATE.md`（需含 §11.3 八项元数据）。放进 `receipts/` 提 PR，或开 issue，或在自己仓库公开后给链接。
**跑失败也要报**：`D-ENV` / `D-SPEC` / `D-IMPL` / `D-TAMPER` / `D-NONE` 任选其一。
