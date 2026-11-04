# -*- coding: utf-8 -*-
"""DVEF-001 独立复算器 · 零依赖版（供外部复算方使用）

与官方复算器 vectors/verify_vectors.py 判据完全相同，唯一差别：
密码学部分改用同目录 ed25519_pure.py（纯标准库实现），**不需要 pip install 任何包**。

用法：
  python3 verify_stdlib.py --vectors vectors_v0.2.json --reverse
  python3 verify_stdlib.py --vectors vectors_v0.2.json --reverse --cross <参考实现目录>

退出码：0 全部通过；1 有失败项
本文件由 tools 生成，勿手改；如需修改请改 vectors/verify_vectors.py 后重新生成。
"""
import argparse
import hashlib
import io
import json
import math
import os
import sys

# Windows 控制台 cp936 会让 emoji/生僧字抛 UnicodeEncodeError，结论对但退出码变 1。
# 强制 UTF-8 且错误不抛，保证“结论=退出码”这一不变式。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "vectors_v0.1.json")

# ────────────────────────── ① 独立规范化实现
def es_number(v):
    """ECMAScript Number::toString（RFC 8785 §3.2.2.3）"""
    if isinstance(v, bool):
        raise TypeError("bool is not a number")
    if isinstance(v, int):
        return str(v)
    if math.isnan(v) or math.isinf(v):
        raise ValueError("NaN/Infinity")
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    a = abs(v)
    t = repr(a)
    if "e" in t:
        m, e = t.split("e")
        e = int(e)
    else:
        m, e = t, 0
    whole, _, frac = m.partition(".")
    ds = (whole + frac).lstrip("0")
    if ds == "":
        return "0"
    point = (len(whole.lstrip("0")) + e) if whole.lstrip("0") else (e - (len(frac) - len(frac.lstrip("0"))))
    ds = ds.rstrip("0") or "0"
    k = len(ds)
    if k <= point <= 21:
        body = ds + "0" * (point - k)
    elif 0 < point <= 21:
        body = ds[:point] + "." + ds[point:]
    elif -6 < point <= 0:
        body = "0." + "0" * (-point) + ds
    else:
        ex = point - 1
        body = ds[0] + ("." + ds[1:] if k > 1 else "") + "e" + ("+" if ex >= 0 else "-") + str(abs(ex))
    return sign + body


def canonical(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (int, float)):
        return es_number(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(str(k), ensure_ascii=False) + ":" + canonical(v[k])
                              for k in sorted(v, key=lambda s: s.encode("utf-16-be"))) + "}"
    raise TypeError(str(type(v)))


def dg(v):
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()


# ────────────────────────── ② 独立判定规则
def judge(rule_id, version, params, inputs):
    """返回 (verdict, score)。规范硬约束：缺必需字段必须 INCONCLUSIVE，禁止 PASS。"""
    def need(*names):
        return all(n in locals()["src"] for n in names)

    src = dict(inputs or {})
    src.update({"__params": params or {}})
    p = params or {}
    if rule_id == "R-DRIFT-THRESHOLD":
        if "score" not in src or "threshold" not in p:
            return "INCONCLUSIVE", 0
        return ("FAIL" if src["score"] > p["threshold"] else "PASS"), src["score"]
    if rule_id == "R-BOUNDARY-INCLUSIVE":
        if "score" not in src or "threshold" not in p:
            return "INCONCLUSIVE", 0
        return ("FAIL" if src["score"] >= p["threshold"] else "PASS"), src["score"]
    if rule_id == "R-DENYLIST-MATCH":
        if "tools" not in src or "denylist" not in p:
            return "INCONCLUSIVE", 0
        return ("FAIL" if any(t in p["denylist"] for t in src["tools"]) else "PASS"), \
            sum(1 for t in src["tools"] if t in p["denylist"])
    if rule_id == "R-RATE-LIMIT":
        if "count" not in src or "limit" not in p:
            return "INCONCLUSIVE", 0
        return ("FAIL" if src["count"] > p["limit"] else "PASS"), src["count"]
    if rule_id == "R-REQUIRED-FIELD":
        miss = [f for f in p.get("required", []) if f not in src]
        return ("INCONCLUSIVE", len(miss)) if miss else ("PASS", 0)
    return "INCONCLUSIVE", 0


# ────────────────────────── ③ 签名
def verify_sig(pub_hex, payload, domain, sig_hex):
    """零依赖验签：Ed25519 用本目录 ed25519_pure.py（纯标准库，RFC 8032 §5.1.7）"""
    import ed25519_pure
    msg = domain.encode() + b"\x00" + bytes.fromhex(dg(payload))
    try:
        return ed25519_pure.verify(bytes.fromhex(pub_hex), msg, bytes.fromhex(sig_hex))
    except Exception:  # noqa: BLE001  非法点/非法长度一律判失败
        return False


def sk_from_seed(seed_hex):
    """零依赖：只返回 seed 原始字节，公钥派生交给 pk_of"""
    return bytes.fromhex(seed_hex)


def pk_of(sk):
    """零依赖：seed -> 公钥（RFC 8032 §5.1.5）"""
    import ed25519_pure
    return ed25519_pure.public_key_from_seed(sk).hex()


REASON_DATA = "IN-DATA-MISSING"
REASON_PARAM = "IN-PARAM-AMBIGUOUS"
REASON_RULE = "IN-RULE-NA"
REASON_CONFLICT = "IN-SOURCE-CONFLICT"


def judge3(rule_id, version, params, inputs):
    """规范 v0.3：返回 (verdict, score, reason_code)。reason_code 仅 INCONCLUSIVE 时非 None。"""
    p = dict(params or {})
    src = dict(inputs or {})

    if rule_id == "R-DRIFT-THRESHOLD":
        if "score" not in src:
            return "INCONCLUSIVE", 0, REASON_DATA
        if "threshold" not in p:
            return "INCONCLUSIVE", 0, REASON_PARAM
        return ("FAIL" if src["score"] > p["threshold"] else "PASS"), src["score"], None

    if rule_id == "R-BOUNDARY-INCLUSIVE":
        if "score" not in src:
            return "INCONCLUSIVE", 0, REASON_DATA
        if "threshold" not in p:
            return "INCONCLUSIVE", 0, REASON_PARAM
        return ("FAIL" if src["score"] >= p["threshold"] else "PASS"), src["score"], None

    if rule_id == "R-DENYLIST-MATCH":
        if "tools" not in src:
            return "INCONCLUSIVE", 0, REASON_DATA
        if "denylist" not in p:
            return "INCONCLUSIVE", 0, REASON_PARAM
        hits = [t for t in src["tools"] if t in p["denylist"]]
        return ("FAIL" if hits else "PASS"), len(hits), None

    if rule_id == "R-RATE-LIMIT":
        if "count" not in src:
            return "INCONCLUSIVE", 0, REASON_DATA
        if "limit" not in p:
            return "INCONCLUSIVE", 0, REASON_PARAM
        return ("FAIL" if src["count"] > p["limit"] else "PASS"), src["count"], None

    if rule_id == "R-REQUIRED-FIELD":
        req = p.get("required")
        if req is None:
            return "INCONCLUSIVE", 0, REASON_PARAM
        missing = [f for f in req if f not in src]
        if missing:
            return "INCONCLUSIVE", len(missing), REASON_DATA
        return "PASS", 0, None

    if rule_id == "R-SOURCE-AGREEMENT":
        sv = src.get("source_values")
        if not isinstance(sv, dict) or len(sv) < 2:
            return "INCONCLUSIVE", 0, REASON_DATA
        if "min_sources" not in p:
            return "INCONCLUSIVE", 0, REASON_PARAM
        if len(sv) < p["min_sources"]:
            return "INCONCLUSIVE", 0, REASON_DATA
        if len({str(v) for v in sv.values()}) > 1:
            return "INCONCLUSIVE", 0, REASON_CONFLICT
        return "PASS", len(sv), None

    return "INCONCLUSIVE", 0, REASON_RULE


# 已登记规则版本台账（版本不在册 → E10 可被真实检出，而不是靠字符串硬匹配）
RULE_REGISTRY = {
    "R-DRIFT-THRESHOLD": ["1.0.0"],
    "R-BOUNDARY-INCLUSIVE": ["1.0.0"],
    "R-DENYLIST-MATCH": ["1.0.0"],
    "R-RATE-LIMIT": ["1.0.0"],
    "R-REQUIRED-FIELD": ["1.0.0"],
    "R-SOURCE-AGREEMENT": ["1.0.0"],
}


def _set_path(obj, path, value):
    """按 /a/b/c 写值（path 第一段相对向量上下文）"""
    parts = [p for p in path.split("/") if p]
    cur = obj
    for p in parts[:-1]:
        if isinstance(cur, list):
            cur = cur[int(p)]
        else:
            cur = cur.setdefault(p, {})
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def apply_mutation(vec, tgt):
    """按 mutation_spec（结构化 patch）构造篡改产物，返回 (reason, detected, detail)"""
    spec = vec.get("mutation_spec") or {}
    reason = vec["expected"]["reason"]
    op = spec.get("op")
    path = spec.get("path", "")

    if reason == "canonical_mismatch":
        base = tgt["expected"]["canonical"]
        if op == "insert":
            bad = base.replace(",", "," + spec.get("value", " "), 1)
        else:
            find, value = spec.get("find", ""), spec.get("value", "")
            if find not in base:
                return reason, False, "样本基准未包含 find=%r" % find
            bad = base.replace(find, value, 1)
        # 必须同时满足：篡改后串 ≠ 规范串，且真实实现输出 = 规范串
        detected = bad != base and canonical(tgt["input"]) == base
        return reason, detected, "bad≠base=%s impl==base=%s" % (bad != base, canonical(tgt["input"]) == base)

    if reason == "digest_mismatch":
        obj = {"input": json.loads(json.dumps(tgt["input"])),
               "output": json.loads(json.dumps(tgt.get("expected", {})))}
        _set_path(obj, path, spec.get("value"))
        # 篡改后的摘要必须不再等于原摘要
        orig_dg = tgt["expected"].get("digest") or tgt["expected"].get("output_digest")
        mutated = obj["output"] if path.startswith("/output") else obj["input"]
        if path.startswith("/output"):
            # output 向量的 expected 是摘要素描，改后用同构对象计算
            base_out = {"verdict": tgt["expected"]["verdict"], "score": tgt["expected"]["score"],
                        "rule_id": tgt["rule_id"], "rule_version": tgt["rule_version"]}
            _set_path({"o": base_out}, path.replace("/output", "/o"), spec.get("value"))
            mutated = base_out
        detected = dg(mutated) != orig_dg
        return reason, detected, "mutated_digest_differs=%s" % detected

    if reason == "signature_invalid":
        if path == "/domain":
            detected = not verify_sig(tgt["expected"]["pubkey_hex"], tgt["payload"],
                                      spec.get("value"), tgt["expected"]["signature_hex"])
            return reason, detected, "wrong_domain_rejected=%s" % detected
        if path == "/signer_seed_hex":
            other = pk_of(sk_from_seed(spec.get("value")))
            detected = not verify_sig(other, tgt["payload"], tgt["domain"],
                                      tgt["expected"]["signature_hex"])
            return reason, detected, "wrong_key_rejected=%s" % detected
        # 载荷篡改
        payload = json.loads(json.dumps(tgt["payload"]))
        _set_path({"p": payload}, path.replace("/payload", "/p"), spec.get("value"))
        detected = not verify_sig(tgt["expected"]["pubkey_hex"], payload, tgt["domain"],
                                  tgt["expected"]["signature_hex"])
        return reason, detected, "tampered_payload_rejected=%s" % detected

    if reason == "verdict_violation":
        real, _ = judge(tgt["rule_id"], tgt["rule_version"], tgt["params"], tgt["input"])
        claimed = (spec.get("value") or "PASS")
        detected = real != claimed          # 规则真值不允许等于被声称的 PASS
        return reason, detected, "rule_says=%s claimed=%s" % (real, claimed)

    if reason == "version_mismatch":
        claimed = spec.get("value")
        known = RULE_REGISTRY.get(tgt["rule_id"], [])
        detected = claimed not in known
        return reason, detected, "claimed=%s known=%s" % (claimed, known)

    return reason, False, "未知 reason"



def check_one(v, byid, want_reason=False):
    """单条样本复算 -> (ok, why)。主流程与反向测试共用同一判据。

    want_reason：样本库 spec_version >= 0.3 时为 True —— INCONCLUSIVE 必须带 reason_code
    且参与 output_digest（§7.1 / §14 版本协商）。"""
    cat = v["category"]
    ok, why = True, ""

    if cat == "canonical":
        got = canonical(v["input"])
        ok = got == v["expected"]["canonical"]
        why = "got=%r want=%r" % (got, v["expected"]["canonical"])

    elif cat == "digest":
        got = dg(v["input"])
        ok = got == v["expected"]["digest"]
        why = "got=%s want=%s" % (got[:16], v["expected"]["digest"][:16])

    elif cat == "verdict":
        verdict, score, rcode = judge3(v["rule_id"], v["rule_version"], v["params"], v["input"])
        out = {"verdict": verdict, "score": score,
               "rule_id": v["rule_id"], "rule_version": v["rule_version"]}
        if want_reason and verdict == "INCONCLUSIVE":
            out["reason_code"] = rcode
        exp_rc = v["expected"].get("reason_code")
        ok = (verdict == v["expected"]["verdict"] and score == v["expected"]["score"]
              and dg(out) == v["expected"]["output_digest"])
        if want_reason:
            ok = ok and rcode == exp_rc
        why = "verdict=%s score=%s reason=%s(want %s) digest_ok=%s" % (
            verdict, score, rcode, exp_rc, dg(out) == v["expected"]["output_digest"])

    elif cat == "signature":
        p = pk_of(sk_from_seed(v["seed_hex"]))
        ok_sig = verify_sig(p, v["payload"], v["domain"], v["expected"]["signature_hex"])
        ok_key = p == v["expected"]["pubkey_hex"]
        ok = ok_sig and ok_key
        why = "sig_ok=%s key_ok=%s" % (ok_sig, ok_key)

    elif cat == "negative":
        tgt = byid.get(v["target"])
        if not tgt:
            ok, why = False, "target %s 不存在" % v["target"]
        else:
            reason, detected, detail = apply_mutation(v, tgt)
            ok = detected
            why = "%s | %s" % (reason, detail)

    return ok, why


def corrupt_expected(v):
    """把一条样本的 expected 改坏（反向测试用）。返回深拷贝，不动原样本库。"""
    v2 = json.loads(json.dumps(v))
    cat = v2["category"]
    e = v2["expected"]

    def flip(s):
        return ("0" if s[0] != "0" else "1") + s[1:]

    if cat == "canonical":
        e["canonical"] = e["canonical"] + " "
    elif cat == "digest":
        e["digest"] = flip(e["digest"])
    elif cat == "verdict":
        e["output_digest"] = flip(e["output_digest"])
    elif cat == "signature":
        e["signature_hex"] = e["signature_hex"][:-1] + ("0" if e["signature_hex"][-1] != "0" else "1")
    elif cat == "negative":
        e["reason"] = "__REVERSE_BUMP__"
    return v2


def reverse_test(vectors, byid, want_reason=False):
    """§10.1-2：把 expected 改坏后判据必须失败，否则本复算器不具备判别力（等橡皮图章）。"""
    bad = []
    for v in vectors:
        ok, why = check_one(corrupt_expected(v), byid, want_reason)
        if ok:
            bad.append((v["id"], v["category"], "改坏 expected 后仍判通过"))
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cross", default=None, help="参考实现目录（含 canonical.py），做交叉比对")
    ap.add_argument("--vectors", default=VECTORS,
                    help="样本库路径（默认同目录 vectors_v0.1.json）")
    ap.add_argument("--reverse", action="store_true",
                    help="反向测试：把 expected 改坏后判据必须失败（§10.1-2）")
    a = ap.parse_args()

    doc = json.load(io.open(a.vectors, encoding="utf-8"))
    vectors = doc["vectors"]
    byid = {v["id"]: v for v in vectors}

    # §14 版本协商：0.3 起 INCONCLUSIVE 必须带 reason_code；旧样本库按旧语义复算
    try:
        _sv = tuple(int(x) for x in str(doc.get("spec_version", "0.1")).split("."))
    except ValueError:
        _sv = (0, 1)
    want_reason = _sv >= (0, 3)
    fails = []
    stat = {"canonical": 0, "digest": 0, "verdict": 0, "signature": 0, "negative": 0}
    total = {"canonical": 0, "digest": 0, "verdict": 0, "signature": 0, "negative": 0}

    for v in vectors:
        cat = v["category"]
        total[cat] += 1
        ok, why = check_one(v, byid, want_reason)

        if ok:
            stat[cat] += 1
        else:
            fails.append((v["id"], cat, why))

    # 交叉比对：与 ASG-RS-001 参考实现（若指定）
    cross_note = "未做（未指定 --cross）"
    if a.cross and os.path.isdir(a.cross):
        sys.path.insert(0, a.cross)
        try:
            import canonical as ref  # noqa: N813
            cross_ok = cross_bad = 0
            for v in vectors:
                if v["category"] == "canonical":
                    if ref.canonical_json(v["input"]) == v["expected"]["canonical"]:
                        cross_ok += 1
                    else:
                        cross_bad += 1
                elif v["category"] == "digest":
                    if ref.sha256_hex(v["input"]) == v["expected"]["digest"]:
                        cross_ok += 1
                    else:
                        cross_bad += 1
            cross_note = "参考实现一致 %d 条，不一致 %d 条" % (cross_ok, cross_bad)
            if cross_bad:
                fails.append(("CROSS", "cross", "参考实现与样本库不一致 %d 条" % cross_bad))
        except Exception as e:  # noqa: BLE001
            cross_note = "交叉比对失败：%r" % e
            fails.append(("CROSS", "cross", cross_note))

    print("DVEF-001 样本库独立复算（spec %s / vectors %s）" % (
        doc.get("spec_version"), doc.get("vectors_version", "?")))
    print("=" * 56)
    for cat in ("canonical", "digest", "verdict", "signature", "negative"):
        print("  %-10s %3d/%-3d" % (cat, stat[cat], total[cat]))
    print("  合计       %3d/%-3d" % (sum(stat.values()), sum(total.values())))
    print("  交叉比对   %s" % cross_note)
    if fails:
        print("\n失败项：")
        for fid, cat, why in fails[:12]:
            print("  %-6s %-10s %s" % (fid, cat, why))
        return 1
    if a.reverse:
        bad = reverse_test(vectors, byid, want_reason)
        print("  反向测试   %d/%d 检出（改坏 expected 必须失败）" % (
            len(vectors) - len(bad), len(vectors)))
        if bad:
            print("\n反向测试失败项（判据无判别力）：")
            for bid, bcat, bwhy in bad[:12]:
                print("  %-6s %-10s %s" % (bid, bcat, bwhy))
            return 1

    print("\n[OK] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
