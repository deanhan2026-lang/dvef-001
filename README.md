# DVEF-001 · 判定依据格式（Deterministic Verdict Evidence Format）

**一句话**：让「智能体做了什么判定、凭什么这么判、别人能不能复算出来」变成一件**格式化、可复算**的事。

本仓库是 DVEF-001 提案草案（v0.3）的公开复算件：
**规范文本 + 100 条正负样本库 + 零依赖独立复算器 + 回执模板**。

> 面向《智能体全链路动态风险评测方法》（中国互联网协会团体标准，2026-10-26 立项）的格式建议件。
> 提交单位：灵元星辰科技（深圳）有限公司 · 状态：**草案，讨论中**（征集截止 2026-11-30）。

---

## 三十秒跑完（不需要 pip / npm / 联网）

```bash
git clone https://github.com/deanhan2026-lang/dvef-001 && cd dvef-001
sha256sum -c MANIFEST.sha256                 # 第 0 步：校验包完整性（macOS: shasum -a 256 -c）
python3 verify_stdlib.py --vectors vectors_v0.2.json --reverse
node    verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse   # 可选：第二语言交叉核对
```

**你应该看到**：

```
  canonical   31/31      digest      16/16
  verdict     21/21      signature   12/12      negative    20/20
  合计       100/100
  反向测试   100/100 检出（改坏 expected 必须失败）
```

再跑一次历史版本（验证**版本协商**）：`python3 verify_stdlib.py --vectors vectors_v0.1.json --reverse` → `59/59`。

### 这两个数字分别证明什么

| 数字 | 证明的事 |
|---|---|
| `100/100` | 五类样本在同一套判据下逐字节/逐摘要/逐位一致（canonical · digest · verdict · signature · negative） |
| `反向测试 100/100` | **判别力**：把每条样本的 `expected` 人为改坏后，复算器必须报失败。永远返回"通过"的橡皮图章在这里得 0 分 |

> 只有"能通过"不算可复算，**必须同时能失败**。

## 这个格式解决什么问题

智能体治理最常见的失败不是"没有判定"，而是**判定无法被复核**：

1. **判定时机与输入对不上** —— 事后无法确认当时看到了什么、用了什么参数；
2. **三态被压成两态** —— "不知道"被写成"通过"或"不通过"，治理后果完全相反；
3. **换个实现就换个数** —— 两边都能自称合规，却产出不同字节；
4. **结论不可推翻** —— 判据本身不能改、改了不留痕，长期退化成"只报通过率"的量具。

DVEF-001 逐条对应：证据件摘要化（①）、`PASS/FAIL/INCONCLUSIVE` 三态且 `INCONCLUSIVE` 强制携带 `reason_code`（②）、
RFC 8785 规范化 + 摘要 + Ed25519 签名 + CL0–CL3 一致性等级（③）、版本协商与"历史结论不可篡改只可标注失效"（④）。

## 包内有什么

| 文件 | 说明 |
|---|---|
| `DVEF-001_v0.3_判定依据格式.md` | 规范正文。16 节 + 3 附录：数据模型、规范化、摘要与签名、规则约束、CL0–CL3、外部复算可实现性（§11.4）、错误码、上限 |
| `vectors_v0.2.json` | **样本库 100 条**：canonical 31 / digest 16 / verdict 21 / signature 12 / negative 20 |
| `vectors_v0.1.json` | 历史样本库 59 条，**原样保留不得修改**（append-only，用于演示版本协商） |
| `verify_stdlib.py` | 独立复算器（Python，**纯标准库**，无需 pip install） |
| `ed25519_pure.py` | 纯标准库 Ed25519（RFC 8032 §5.1.5 公钥派生 / §5.1.7 验签） |
| `verify_vectors_node.mjs` | 独立复算器（Node，**零依赖**，用 `node:crypto`） |
| `EXTERNAL_RECOMPUTE_KIT.md` | 外部复算说明：三步、期望输出、五类差异（`D-ENV`/`D-SPEC`/`D-IMPL`/`D-TAMPER`/`D-NONE`） |
| `RECEIPT_TEMPLATE.md` | 回执模板（§11.3 八项互认元数据） |
| `MANIFEST.sha256` | 全包校验清单（第 0 步必跑） |
| `run_kit.sh` / `run_kit.cmd` | 一键脚本（先校清单，再跑复算 + 反向测试） |

## 我们主张什么、不主张什么（写在前面，免得误读）

**主张**：可复算性已由**异构宿主上的独立实现验证** —— Python 与 Node 两套从零实现、互不共享代码，
在同一批 100 条样本上逐字节一致（一致性等级 **CL3**），且都能通过反向测试。

**不主张**：
- 我们**没有**完成"无归属第三方独立复算"。**外部无归属节点数 = 0**。
  所以本仓库不是"已被第三方验证"，而是"**把第三方验证变成任何人今天就能做的一件事**"。
- 不主张评测方法本体（风险分类是否合理、阈值是否恰当）—— 那是评测方案的事，本格式只管**判定结果的记录与复算方式**。
- 不主张"填补空白"或"应当由谁牵头"。本格式不设机构、不要求权限：**我们做格式，不做机构。**


## 真实事故 → 判定单元（`cases/`）

三个案例来自**我们自己的真实事故**，脱敏后按本格式表达为判定单元，可被任何人复算：

```bash
python3 verify_cases.py          # → 合计 3/3 通过（含逐条反向测试）
```

| # | 规则 | 结论 | 说的是什么 |
|---|---|---|---|
| 1 | `R-DENYLIST-MATCH` | `FAIL` / 1 | 越权工具调用：运行时工具集命中禁用清单 |
| 2 | `R-DRIFT-THRESHOLD` | `FAIL` / 21 | 凭据暴露 21 天，超出 7 天上限 |
| 3 | `R-SOURCE-AGREEMENT` | `INCONCLUSIVE` / `IN-SOURCE-CONFLICT` | 身份不绑定令牌：客户端自报主体 ≠ 令牌绑定主体 |

第 3 条是重点：**真源冲突时正确结论不是"通过/不通过"，而是"判不了，并说明为什么判不了"。**
详见 `cases/README.md`（含脱敏规则与"签名用固定演示密钥、不构成身份声明"的声明）。

## 怎么给我们回执（我们更欢迎公开的）

1. 按 `EXTERNAL_RECOMPUTE_KIT.md` 跑完；
2. 填 `RECEIPT_TEMPLATE.md`；
3. 任选其一：开 issue / 提 PR 把你的回执放进 `receipts/` / 在你自己的仓库或博客公开回执并把链接发给我们。

**跑失败也要报**。五类差异任选其一填（`D-ENV`/`D-SPEC`/`D-IMPL`/`D-TAMPER`/`D-NONE`），
我们只做一件事：把差异归类并公开记录。不会要求你"再试一次直到通过"。

## 已知缺口（不藏）

- 样本 100 条，覆盖"判定格式"而非"风险分类完备性"；decimal/定点实现、门限签名聚合、Rust/Go 第三语言尚未覆盖；
- 一致性等级 CL3 目前由 Python + Node 自证，尚无第三方机构回执；
- 规范为草案，条款编号与措辞仍会变动（变更记录见规范附录 C）。

## 许可与联系

- 代码（`*.py` / `*.mjs` / `*.sh` / `*.cmd`）：**MIT**
- 规范文本与样本库（`*.md` / `*.json`）：**CC BY 4.0**
- 版权：灵元星辰科技（深圳）有限公司（ANIMASTELLAR TECHNOLOGY (SHENZHEN) CO., LTD.）
- 回执与讨论：GitHub Issues；或邮件 `nyx@anima.org`

---

**一句话收束**：合规不是"我说我合规"，是"**换个人、换套实现、照样算得出同一结论**"。
这个仓库就是那件事的最小可运行证明。
"""

LICENSE_MIT = """MIT License

Copyright (c) 2026 ANIMASTELLAR TECHNOLOGY (SHENZHEN) CO., LTD.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

NOTICE = """DVEF-001 判定依据格式（草案）
Copyright (c) 2026 灵元星辰科技（深圳）有限公司 / ANIMASTELLAR TECHNOLOGY (SHENZHEN) CO., LTD.

许可分层：
- 代码文件（*.py / *.mjs / *.sh / *.cmd）：MIT（见 LICENSE）
- 规范文本与样本库（*.md / *.json）：Creative Commons Attribution 4.0 International (CC BY 4.0)
  https://creativecommons.org/licenses/by/4.0/

引用时请注明：
  DVEF-001 Deterministic Verdict Evidence Format v0.3 (draft), ANIMASTELLAR,
  https://github.com/deanhan2026-lang/dvef-001

本仓库为提案草案，不代表任何标准组织已采纳；文中出现的标准名称仅用于说明适用场景。
"""

CI = """name: verify

on:
  push:
  pull_request:
  workflow_dispatch:

jobs:
  recompute:
    name: 独立复算 + 反向测试 + 清单自校验
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: 第 0 步 · 清单自校验
        run: sha256sum -c MANIFEST.sha256

      - name: Python 复算（样本库 v0.2，含反向测试）
        run: python verify_stdlib.py --vectors vectors_v0.2.json --reverse

      - name: Python 复算（样本库 v0.1，版本协商）
        run: python verify_stdlib.py --vectors vectors_v0.1.json --reverse

      - name: Node 复算（第二语言交叉核对）
        run: node verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse
"""

GITIGNORE = """__pycache__/
*.pyc
.DS_Store
receipts/**/.keep
"""
