# -*- coding: utf-8 -*-
"""DVEF 判定单元复算器（零依赖）：校验 cases_v1.json 里每条真实事故判定单元。

对每条判定单元做六件事：
  ① inputs_digest / params_digest / output_digest 与对象是否一致
  ② 按 rule_id + params 重跑规则，verdict/score/reason_code 是否与声明一致
  ③ §7.1 的 E-REASON：INCONCLUSIVE 必须带 reason_code，PASS/FAIL 不得带
  ④ 签名验证（Ed25519，domain 必须等于 DVEF-001-v1）
  ⑤ message_sha256 与本地重算是否一致（无公钥方可先核这一层）
  ⑥ 反向测试：把 output 改坏后，本校验必须失败

用法：
  python3 verify_cases.py                 # 校验 cases/cases_v1.json
  python3 verify_cases.py --json <path>
退出码：0 全部通过；1 有失败
"""
import argparse
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ed25519_pure  # noqa: E402
from verify_stdlib import canonical, dg, judge3  # noqa: E402

DOMAIN = "DVEF-001-v1"
DEFAULT = os.path.join(HERE, "cases", "cases_v1.json")


def sha_uri(obj):
    return "sha256:" + dg(obj)


def check_unit(unit):
    """返回 (ok, 逐项说明列表)"""
    notes = []
    ok = True

    for field, obj in (("inputs_digest", unit["inputs"]),
                       ("params_digest", unit["params"]),
                       ("output_digest", unit["output"])):
        want = unit[field]
        got = sha_uri(obj)
        good = want == got
        ok = ok and good
        notes.append("%s %s" % (field, "ok" if good else "MISMATCH got=%s want=%s" % (got[:16], want[:16])))

    verdict, score, rcode = judge3(unit["rule_id"], unit["rule_version"],
                                   unit["params"], unit["inputs"])
    out = unit["output"]
    rule_ok = out["verdict"] == verdict and out["score"] == score
    ok = ok and rule_ok
    notes.append("rule %s/%s -> %s score=%s" % (unit["rule_id"], unit["rule_version"], verdict, score))

    # ③ E-REASON
    has_rc = "reason_code" in out
    if out["verdict"] == "INCONCLUSIVE":
        reason_ok = has_rc and out["reason_code"] == rcode
        notes.append("reason_code %s (want %s)" % (out.get("reason_code"), rcode))
    else:
        reason_ok = not has_rc
        notes.append("reason_code absent=%s (PASS/FAIL 不得带)" % (not has_rc))
    ok = ok and reason_ok

    # ④ 签名
    payload = {k: v for k, v in unit.items() if k != "signature"}
    sig = unit.get("signature")
    sig_ok = False
    if isinstance(sig, dict) and sig.get("domain") == DOMAIN:
        msg = DOMAIN.encode() + b"\x00" + bytes.fromhex(dg(payload))
        try:
            sig_ok = ed25519_pure.verify(bytes.fromhex(sig["pubkey"]), msg,
                                         bytes.fromhex(sig["sig"]))
        except Exception:  # noqa: BLE001
            sig_ok = False
        # ⑤ message_sha256
        msg_ok = hashlib.sha256(msg).hexdigest() == sig.get("message_sha256")
        notes.append("signature %s | message_sha256 %s" % (sig_ok, msg_ok))
        ok = ok and sig_ok and msg_ok
    else:
        notes.append("signature 缺失或 domain 非 %s" % DOMAIN)
        ok = False

    return ok, notes


def reverse_check(unit):
    """⑥ 反向：把 output 的 score 改坏，校验必须失败"""
    bad = json.loads(json.dumps(unit))
    bad["output"]["score"] = (bad["output"]["score"] or 0) + 1
    ok, _ = check_unit(bad)
    return not ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=DEFAULT)
    a = ap.parse_args()

    doc = json.load(io.open(a.json, encoding="utf-8"))
    cases = doc["cases"]
    print("DVEF 判定单元复算（真实事故脱敏样例）  spec %s  cases=%d" % (doc["spec_version"], len(cases)))
    print("=" * 68)
    fails = 0
    for c in cases:
        u = c["unit"]
        ok, notes = check_unit(u)
        rev = reverse_check(u)
        ok = ok and rev
        if not ok:
            fails += 1
        print("%s %s  %s" % ("PASS" if ok else "FAIL", u["verdict_id"][-4:], c["case_meta"]["title"]))
        for n in notes:
            print("     · %s" % n)
        print("     · 反向测试（改坏 output 必须失败）: %s" % ("ok" if rev else "FAIL 未检出"))
    print("=" * 68)
    print("合计 %d/%d 通过（含逐条反向测试）" % (len(cases) - fails, len(cases)))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
