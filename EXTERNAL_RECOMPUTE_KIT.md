# DVEF-001 外部复算包（零依赖 · 可离线）

**目的**：让**任何**第三方在不接触我们代码库、不安装任何第三方包的前提下，
独立判定我们的样本库与判定输出「是否可复算」。

> 我们不要求你相信任何结论。我们只要求你**跑一遍**，然后把结果和差异类别告诉我们。

---

## 一、你需要什么

| 项 | 要求 |
|---|---|
| Python | ≥ 3.8（**不需要** pip install；`cryptography`/`base58` 一律不用） |
| Node（可选，第二语言交叉核对） | ≥ 18（用 `node:crypto`，**不需要** npm install） |
| 网络 | 只在下载本包时需要，之后**可完全离线** |

包内文件：

```
EXTERNAL_RECOMPUTE_KIT.md   本说明
RECEIPT_TEMPLATE.md         回执模板（填完发回即可）
verify_stdlib.py            独立复算器（Python，零依赖）
ed25519_pure.py             纯标准库 Ed25519（RFC 8032 §5.1.5 派生 + §5.1.7 验签）
verify_vectors_node.mjs     独立复算器（Node，零依赖）
vectors_v0.2.json           样本库 v0.2（100 条，对应规范 v0.3）
vectors_v0.1.json           样本库 v0.1（59 条，历史版本，用于验证版本协商）
MANIFEST.sha256             上述文件的 SHA-256 清单
run_kit.sh / run_kit.cmd    一键脚本（先校验清单，再跑复算 + 反向测试）
```

## 二、三步复算

```bash
# 第 0 步：先校验包完整性（任何一项不匹配就停，不要继续）
sha256sum -c MANIFEST.sha256 || shasum -a 256 -c MANIFEST.sha256

# 第 1 步：Python 复算（含反向测试）
python3 verify_stdlib.py --vectors vectors_v0.2.json --reverse

# 第 2 步：Node 复算（第二语言交叉核对，可选但建议）
node verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse
```

Windows：

```powershell
certutil -hashfile vectors_v0.2.json SHA256      # 与 MANIFEST.sha256 对照
python verify_stdlib.py --vectors vectors_v0.2.json --reverse
node verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse
```

## 三、你应该看到什么（这就是判据）

```
  canonical   31/31
  digest      16/16
  verdict     21/21
  signature   12/12
  negative    20/20
  合计       100/100
  反向测试   100/100 检出（改坏 expected 必须失败）
```

- **`100/100`**：五类样本全部按预期复算一致（canonical 逐字节、digest 逐摘要、verdict 逐判定、signature 验签通过、negative 全部被检出）。
- **`反向测试 100/100`**：把每条样本的 `expected` 人为改坏后，复算器必须报失败。这一项是**判别力**证明：
  一个永远返回"通过"的橡皮图章，在这里会拿 0/100。
- 再跑一次 `--vectors vectors_v0.1.json`：应得 `59/59`（**版本协商**：v0.1 的 `expected` 不含 `reason_code`，
  复算器按样本库声明的 `spec_version` 选择语义，不得改写历史样本）。

## 四、如果你跑不出上面的数字

**请照实回报，这比"通过"更有价值。** 我们准备了五类差异，请你择一填写（规范 §11.2）：

| 差异类别 | 含义 | 你要做什么 |
|---|---|---|
| `D-ENV` | 环境差异（解释器版本、浮点、排序实现） | 附 `python3 -V` / `node -v` / OS 版本 |
| `D-SPEC` | 规范歧义（我们的写法允许多种理解） | 附规范条款号 + 你的两种理解 |
| `D-IMPL` | 实现缺陷（我们算错或你算错） | 附最小复现输入 + 两侧输出 |
| `D-TAMPER` | 证据被改动（清单不匹配） | 立即停手，不要采信任何结论 |
| `D-NONE` | 无差异 | 填回执即可 |

> 我们不会因为你跑失败而否定你的结论，也不会要求你"再试一次直到通过"。
> 我们只做一件事：把你的差异归类，然后公开记录归类结果。

## 五、回执

填 `RECEIPT_TEMPLATE.md` 后发回（任选其一）：
- 邮件：见一页纸联系方式
- 或直接在你自己的仓库/博客公开回执并给我们链接（**我们更欢迎这种**，因为可被第三方复核）

回执必须含 §11.3 八项元数据：`spec_version`、`rule_id`+`rule_version`、样本库版本、复算方标识、
复算时间、`verdict`+`score`、差异类别、环境声明。缺任一项，一致性等级只能记 **CL1 以下**，不参与互认。

## 六、我们不提供什么（先说清楚）

1. **不提供"结论一致性"承诺**。我们要的是可复算性：你跑出的 `verdict`/`score` 必须与我们一致，
   但**你不需要同意我们的风险评估是否合理**——那是评测方法本体，不是格式层的事。
2. **不要求你采信我们的样本库正确**。你可以只把自己当作"复算器实现者"：
   如果 `expected` 与你的独立计算不符，那就是 `D-SPEC` 或 `D-IMPL`，照实报。
3. **不隐藏已知缺口**：样本库当前 100 条，只覆盖"判定格式"而非"风险分类完备性"；
   decimal/定点实现、门限签名聚合、Rust/Go 第三人语言尚未覆盖。

## 七、当前已知的诚实边界（我们不主张的）

- 我们**没有**完成"无归属第三方独立复算"。已完成的只是**异构宿主上的独立实现复算**
  （Python / Node 两套从零实现，逐字节一致，CL3）。
- 因此本文档的定位是：**把外部复算变成一件任何人都能做的事**，而不是宣称"已经被第三方验证"。
  你跑通之后的回执，才是那份声明成立的第一天。
