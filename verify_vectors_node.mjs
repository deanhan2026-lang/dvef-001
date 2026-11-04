#!/usr/bin/env node
/**
 * DVEF-001 v0.1 独立复算器 —— Node.js / ESM 实现
 * ============================================================
 * 目的：跨语言一致性验证（CL0/CL1/CL2/CL3）。
 * 本文件不复用、不翻译任何 Python 实现；按 DVEF-001 v0.1 §5~§9 从零实现。
 *
 * 关键设计：数值序列化**直接使用 JS 原生 Number -> String 语义**
 *   （即 JSON.stringify(number) 的行为），不自行编写数字格式化算法。
 *   这正是本次交叉验证要验证的对象：规范要求的就是 ECMAScript
 *   Number::toString，那么 JS 运行时的原生行为应当天然正确。
 *
 * 依赖：仅 Node 内置模块（node:crypto / node:fs / node:path / node:url）。
 *
 * 用法：
 *   node verify_vectors.mjs [--vectors <path>] [--verbose]
 * 退出码：0 = 全部通过；1 = 有失败项。
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify as cryptoVerify,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DEFAULT_VECTORS = resolve(HERE, '..', 'vectors', 'vectors_v0.1.json');

const DOMAIN = 'DVEF-001-v1'; // §8 格式级域分隔，由规范固定

// ══════════════════════════════════════════════════════════════
// ① 规范化 JSON（§5）
//    1. 键按 Unicode 码点升序递归排序；数组保序
//    2. 紧凑输出，无多余空白；UTF-8 无 BOM
//    3. 数值按 ECMAScript Number::toString
//    4. null/true/false 小写不带引号
//    5. 字符串不做 Unicode 规范化，仅做 JSON 必需转义
// ══════════════════════════════════════════════════════════════

const SURROGATE_PAIR = /^[\uD800-\uDBFF][\uDC00-\uDFFF]$/;

/**
 * 按键的「码点序列」比较两个字符串（§5.1 要求 Unicode 码点升序）。
 *
 * 为什么不直接用 a < b：JS 的字符串比较按 UTF-16 码元（code unit）进行。
 * 对 BMP 内的字符两者等价；但当键里出现补充平面字符（码点 > 0xFFFF，
 * 以代理对形式存储，码元落在 0xD800~0xDFFF）时，码元序会把 U+10000 排到
 * U+FFFD 之前，与码点序相反。所以这里显式按码点遍历比较。
 */
function compareByCodePoint(a, b) {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const ra = ia.next();
    const rb = ib.next();
    if (ra.done && rb.done) return 0;
    if (ra.done) return -1;
    if (rb.done) return 1;
    const ca = ra.value.codePointAt(0);
    const cb = rb.value.codePointAt(0);
    if (ca !== cb) return ca < cb ? -1 : 1;
  }
}

/**
 * 数值序列化：直接委托给引擎的 Number::toString。
 *
 * 规范 §5.3 要求的就是 ECMAScript Number::toString，而 JSON.stringify 对
 * number 的序列化正是该抽象操作——所以这里不重写格式化逻辑，反而刻意依赖它。
 * 只需自行处理两个 JS 语义与规范的交界处：
 *   · -0 必须输出 "0"（Number::toString(-0) 本身就是 "0"，但 Object.is 判断更直白）
 *   · NaN / ±Infinity 不是合法 JSON 值，规范未定义，直接报错
 */
function serializeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new TypeError(`非法数值（JSON 不支持 NaN/Infinity）：${String(n)}`);
  }
  if (Object.is(n, -0)) return '0';
  return JSON.stringify(n);
}

/**
 * 字符串序列化：JSON 必需转义（\" \\ \b \f \n \r \t 与 U+0000..U+001F
 * 的 \u00xx），非 ASCII 原样输出（§5.5 不做 NFC 折叠，也不转义）。
 * JSON.stringify(string) 的行为恰好就是这套规则。
 */
function serializeString(s) {
  // 孤立代理项（lone surrogate）无法编码为合法 UTF-8。RFC 8785 要求报错，
  // 这里保持一致：拒绝而不是静默替换成 U+FFFD。
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError('字符串含孤立高位代理项，无法序列化为 UTF-8');
      }
      i++; // 跳过配对低位
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new TypeError('字符串含孤立低位代理项，无法序列化为 UTF-8');
    }
  }
  return JSON.stringify(s);
}

/**
 * canonicalJSON(value) -> string（紧凑、键有序、无 BOM 的规范化串）
 */
function canonicalJSON(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'; // §5.4 小写不带引号
    case 'string':
      return serializeString(value);
    case 'number':
      return serializeNumber(value);
    case 'object':
      break;
    default:
      // undefined / bigint / function / symbol 都不是合法 JSON 值
      throw new TypeError(`不支持的值类型：${typeof value}`);
  }

  if (Array.isArray(value)) {
    // §5.1 数组保序，不排序
    const parts = [];
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      if (item === undefined) {
        // 数组里的 undefined 不是合法 JSON；不静默变成 null
        throw new TypeError(`数组下标 ${i} 为 undefined，不是合法 JSON 值`);
      }
      parts.push(canonicalJSON(item));
    }
    return `[${parts.join(',')}]`;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new TypeError('仅支持纯对象（plain object）');
  }

  const keys = Object.keys(value);
  for (const k of keys) {
    if (value[k] === undefined) {
      throw new TypeError(`对象键 "${k}" 的值为 undefined，不是合法 JSON 值`);
    }
  }
  keys.sort(); // RFC 8785 §3.2.3 = UTF-16 码元序（JS 默认 sort 即此语义）；码点序是错的

  const parts = [];
  for (const k of keys) {
    parts.push(`${serializeString(k)}:${canonicalJSON(value[k])}`);
  }
  return `{${parts.join(',')}}`;
}

// ══════════════════════════════════════════════════════════════
// ② 摘要（§6）：sha256: + lower_hex(SHA-256(canonical_json(obj)))
// ══════════════════════════════════════════════════════════════

function sha256Hex(bytesOrString) {
  const h = createHash('sha256');
  if (typeof bytesOrString === 'string') {
    h.update(Buffer.from(bytesOrString, 'utf8')); // UTF-8 无 BOM
  } else {
    h.update(bytesOrString);
  }
  return h.digest('hex');
}

/** 证据摘要：对对象取 canonical 后的 SHA-256（hex，不带 "sha256:" 前缀，与样本库一致） */
function digestOf(value) {
  return sha256Hex(canonicalJSON(value));
}

/** 规范写法带前缀（供报告/互认元数据使用） */
function digestUri(value) {
  return `sha256:${digestOf(value)}`;
}

// ══════════════════════════════════════════════════════════════
// ③ 判定规则（§7）—— 5 条参考规则，边界语义按版本固定
//    硬约束：缺必需字段一律 INCONCLUSIVE，禁止 PASS
// ══════════════════════════════════════════════════════════════

const REASON_DATA = 'IN-DATA-MISSING';
const REASON_PARAM = 'IN-PARAM-AMBIGUOUS';
const REASON_RULE = 'IN-RULE-NA';
const REASON_CONFLICT = 'IN-SOURCE-CONFLICT';

const INCONCLUSIVE = 'INCONCLUSIVE';
const PASS = 'PASS';
const FAIL = 'FAIL';

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/**
 * judge(ruleId, ruleVersion, params, inputs) -> { verdict, score, reasonCode }
 *
 * 规范 v0.3：INCONCLUSIVE 必须携带 reason_code（区分「0」与「不知道」）。
 * reasonCode 仅在 INCONCLUSIVE 时非 null，且参与 output_digest（buildOutput 负责）。
 */
function judge(ruleId, ruleVersion, params, inputs) {
  const p = params && typeof params === 'object' ? params : {};
  const src = inputs && typeof inputs === 'object' ? inputs : {};

  switch (ruleId) {
    case 'R-DRIFT-THRESHOLD': {
      if (!hasOwn(src, 'score')) return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_DATA };
      if (!hasOwn(p, 'threshold')) return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_PARAM };
      return { verdict: src.score > p.threshold ? FAIL : PASS, score: src.score, reasonCode: null };
    }
    case 'R-BOUNDARY-INCLUSIVE': {
      if (!hasOwn(src, 'score')) return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_DATA };
      if (!hasOwn(p, 'threshold')) return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_PARAM };
      return { verdict: src.score >= p.threshold ? FAIL : PASS, score: src.score, reasonCode: null };
    }
    case 'R-DENYLIST-MATCH': {
      if (!hasOwn(src, 'tools') || !Array.isArray(src.tools)) {
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_DATA };
      }
      if (!hasOwn(p, 'denylist') || !Array.isArray(p.denylist)) {
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_PARAM };
      }
      const deny = new Set(p.denylist);
      let hits = 0;
      for (const t of src.tools) if (deny.has(t)) hits++;
      return { verdict: hits > 0 ? FAIL : PASS, score: hits, reasonCode: null };
    }
    case 'R-RATE-LIMIT': {
      if (!hasOwn(src, 'count')) return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_DATA };
      if (!hasOwn(p, 'limit')) return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_PARAM };
      return { verdict: src.count > p.limit ? FAIL : PASS, score: src.count, reasonCode: null };
    }
    case 'R-REQUIRED-FIELD': {
      if (!hasOwn(p, 'required') || !Array.isArray(p.required)) {
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_PARAM };
      }
      const missing = p.required.filter((f) => !hasOwn(src, f));
      return missing.length
        ? { verdict: INCONCLUSIVE, score: missing.length, reasonCode: REASON_DATA }
        : { verdict: PASS, score: 0, reasonCode: null };
    }
    case 'R-SOURCE-AGREEMENT': {
      const sv = src.source_values;
      if (!sv || typeof sv !== 'object' || Object.keys(sv).length < 2) {
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_DATA };
      }
      if (!hasOwn(p, 'min_sources')) {
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_PARAM };
      }
      const keys = Object.keys(sv);
      if (keys.length < p.min_sources) {
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_DATA };
      }
      const vals = new Set(keys.map((k) => String(sv[k])));
      if (vals.size > 1) {
        // 两个真源给出不同结论 —— 这正是「不知道」，不得坍缩成任一二元结论
        return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_CONFLICT };
      }
      return { verdict: PASS, score: keys.length, reasonCode: null };
    }
    default:
      return { verdict: INCONCLUSIVE, score: 0, reasonCode: REASON_RULE };
  }
}

/** §7.1 输出对象（v0.3：INCONCLUSIVE 带 reason_code；PASS/FAIL 不得带该字段） */
function buildOutput(ruleId, ruleVersion, result, wantReason) {
  const out = {
    verdict: result.verdict,
    score: result.score,
    rule_id: ruleId,
    rule_version: ruleVersion,
  };
  if (wantReason && result.verdict === INCONCLUSIVE) out.reason_code = result.reasonCode;
  return out;
}

// ══════════════════════════════════════════════════════════════
// ④ Ed25519 验签（§8）
//    message = DOMAIN || 0x00 || SHA-256(canonical_json(payload)) 的原始字节
// ══════════════════════════════════════════════════════════════

// RFC 8410 / SPKI 固定前缀：30 2a 30 05 06 03 2b 65 70 03 21 00 + 32 字节原始公钥
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// PKCS#8 固定前缀：30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 + 32 字节种子
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** 32 字节原始公钥 -> KeyObject */
function publicKeyFromRaw(rawHex) {
  const raw = Buffer.from(rawHex, 'hex');
  if (raw.length !== 32) throw new Error(`Ed25519 公钥必须 32 字节，实际 ${raw.length}`);
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

/** 32 字节种子 -> 私钥 KeyObject */
function privateKeyFromSeed(seedHex) {
  const seed = Buffer.from(seedHex, 'hex');
  if (seed.length !== 32) throw new Error(`Ed25519 种子必须 32 字节，实际 ${seed.length}`);
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}

/** 从私钥导出 32 字节原始公钥 hex */
function rawPublicHexOf(privateKey) {
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32).toString('hex');
}

/**
 * 构造待签消息字节：DOMAIN(utf8) || 0x00 || SHA-256(canonical(payload))
 * 注意第三段是**摘要的原始 32 字节**，不是 hex 文本。
 */
function buildMessage(domain, payload) {
  return Buffer.concat([
    Buffer.from(domain, 'utf8'), // DOMAIN 按 UTF-8
    Buffer.from([0x00]), // 0x00 分隔符，不可省略
    Buffer.from(digestOf(payload), 'hex'),
  ]);
}

/** 验签：任何异常（长度、格式）都视为「验签不通过」，不抛出 */
function verifySignature(pubHex, payload, domain, sigHex) {
  try {
    const key = publicKeyFromRaw(pubHex);
    const msg = buildMessage(domain, payload);
    const sig = Buffer.from(sigHex, 'hex');
    if (sig.length !== 64) return false;
    // Ed25519 是纯签名算法，algorithm 传 null
    return cryptoVerify(null, msg, key, sig);
  } catch {
    return false;
  }
}

/**
 * 样本库 expected.message_sha256 的实际语义（经实测确认，规范 §8 未定义该字段）：
 *   message_digest = SHA-256( DOMAIN || 0x00 || SHA-256(canonical_json(payload)) )
 * 即对**整条 message** 再取一次摘要，而不是 §8 里那第三段「载荷摘要」。
 *
 * ⚠ 这是一个命名歧义（见 CROSS_LANG_REPORT.md 的 D-SPEC 清单）：字段名
 *   `message_digest` 极易被读成「SHA-256(canonical(payload))」。两种解释都自洽，
 *   但只有「整条 message 的摘要」能对上样本库的值。这里两个都算，以样本库语义为准，
 *   同时在结果里把两种值都暴露出来，便于第三方核对。
 */
function messageDigestOf(domain, payload) {
  return sha256Hex(buildMessage(domain, payload));
}

/** 载荷摘要（§8 第三段）：SHA-256(canonical_json(payload)) */
function payloadDigestOf(payload) {
  return digestOf(payload);
}

// ══════════════════════════════════════════════════════════════
// ⑤ 样本库执行
// ══════════════════════════════════════════════════════════════

const CATEGORIES = ['canonical', 'digest', 'verdict', 'signature', 'negative'];

/**
 * 单条样本复算。返回 { ok: boolean, why: string, extra?: object }
 */
function runVector(v, byId, opts = {}) {
  switch (v.category) {
    case 'canonical': {
      const got = canonicalJSON(v.input);
      const want = v.expected.canonical;
      return { ok: got === want, why: `got=${JSON.stringify(got)} want=${JSON.stringify(want)}` };
    }

    case 'digest': {
      const got = digestOf(v.input);
      const want = v.expected.digest;
      const gotUri = `sha256:${got}`;
      return {
        ok: got === want,
        why: `got=${got.slice(0, 16)}… want=${want.slice(0, 16)}… (uri=${gotUri.slice(0, 23)}…)`,
      };
    }

    case 'verdict': {
      const result = judge(v.rule_id, v.rule_version, v.params, v.input);
      const output = buildOutput(v.rule_id, v.rule_version, result, !!opts.wantReason);
      const gotDigest = digestOf(output);
      const verdictOk = result.verdict === v.expected.verdict;
      const scoreOk = result.score === v.expected.score;
      const digestOk = gotDigest === v.expected.output_digest;
      return {
        ok: verdictOk && scoreOk && digestOk,
        why:
          `verdict=${result.verdict}(want ${v.expected.verdict},${verdictOk ? 'ok' : 'MISMATCH'}) ` +
          `score=${result.score}(want ${v.expected.score},${scoreOk ? 'ok' : 'MISMATCH'}) ` +
          `digest_ok=${digestOk}` +
          (digestOk ? '' : ` got=${gotDigest.slice(0, 16)}… want=${v.expected.output_digest.slice(0, 16)}…`),
      };
    }

    case 'signature': {
      const expected = v.expected;
      const derivedPub = rawPublicHexOf(privateKeyFromSeed(v.seed_hex));
      const keyOk = derivedPub === expected.pubkey_hex;
      // sig_ok 本身即 CL0 强证据：验签成功意味着我校算出的 canonical(payload)
      // 与签名方逐字节一致，否则摘要不同、签名必失败。
      const sigOk = verifySignature(expected.pubkey_hex, v.payload, v.domain, expected.signature_hex);
      const wholeMsgDigest = messageDigestOf(v.domain, v.payload);
      const payloadDigest = payloadDigestOf(v.payload);
      // 以样本库实际语义（整条 message 的摘要）为准
      const msgDigestOk = wholeMsgDigest === expected.message_sha256;
      const payloadDigestIsTheField = payloadDigest === expected.message_sha256;
      return {
        ok: keyOk && sigOk && msgDigestOk,
        why:
          `key_ok=${keyOk} sig_ok=${sigOk} msg_digest_ok=${msgDigestOk}` +
          (msgDigestOk ? '' : ` got=${wholeMsgDigest.slice(0, 16)}… want=${expected.message_sha256.slice(0, 16)}…`),
        extra: { derivedPub, sigOk, keyOk, msgDigestOk, payloadDigestIsTheField },
      };
    }

    case 'negative': {
      const d = detectNegative(v, byId);
      return { ok: d.detected, why: `${d.reason}: detected=${d.detected}${d.detail ? ` (${d.detail})` : ''}` };
    }

    default:
      return { ok: false, why: `未知分类 "${v.category}"` };
  }
}

/**
 * 负样本：**按 mutation_spec 机械构造**（DVEF-001 v0.2 §10.1-1），由复算器解析 spec，
 * 被测实现不得自行用 replace() 拼接比对条件（v0.1 的自证缺陷）。
 * §10.4：负样本的期望是 valid=false —— 负样本"被检出"才算成功。
 */
function setPath(root, path, value) {
  const parts = String(path || '').split('/').filter((p) => p.length);
  let cur = root;
  for (let i = 0; i < parts.length - 1; i++) {
    const p = parts[i];
    if (Array.isArray(cur)) cur = cur[Number(p)];
    else {
      if (!hasOwn(cur, p) || typeof cur[p] !== 'object' || cur[p] === null) cur[p] = {};
      cur = cur[p];
    }
  }
  const last = parts[parts.length - 1];
  if (Array.isArray(cur)) cur[Number(last)] = value;
  else cur[last] = value;
  return root;
}

/** 已登记规则版本台账（§10.1-3：版本不在册必须可被真实检出，不得字符串硬匹配） */
const RULE_VERSIONS = {
  'R-DRIFT-THRESHOLD': ['1.0.0'],
  'R-BOUNDARY-INCLUSIVE': ['1.0.0'],
  'R-DENYLIST-MATCH': ['1.0.0'],
  'R-RATE-LIMIT': ['1.0.0'],
  'R-REQUIRED-FIELD': ['1.0.0'],
  'R-SOURCE-AGREEMENT': ['1.0.0'],
};

function detectNegative(v, byId) {
  const target = byId.get(v.target);
  const reason = v.expected.reason;
  if (!target) return { detected: false, reason, detail: `找不到 target=${v.target}` };

  const spec = v.mutation_spec || {};
  const op = spec.op;
  const path = spec.path || '';

  // ── 规范化结果被改：篡改串 ≠ 规范串，且独立实现输出 = 规范串 ──
  if (reason === 'canonical_mismatch') {
    const base = target.expected.canonical;
    let bad;
    if (op === 'insert') {
      bad = base.replace(',', `,${spec.value ?? ' '}`);
    } else {
      const find = spec.find ?? '';
      if (!base.includes(find)) {
        return { detected: false, reason, detail: `样本基准未包含 find=${JSON.stringify(find)}` };
      }
      bad = base.replace(find, spec.value ?? '');
    }
    const got = canonicalJSON(target.input);
    return {
      detected: bad !== base && got === base,
      reason,
      detail: `bad≠base=${bad !== base} impl==base=${got === base}`,
    };
  }

  // ── 篡改后摘要必须不再等于声明值 ──
  if (reason === 'digest_mismatch') {
    const declared = target.expected.digest || target.expected.output_digest;
    let mutated;
    if (path.startsWith('/output')) {
      mutated = {
        verdict: target.expected.verdict,
        score: target.expected.score,
        rule_id: target.rule_id,
        rule_version: target.rule_version,
      };
      setPath({ o: mutated }, path.replace('/output', '/o'), spec.value);
    } else {
      mutated = JSON.parse(JSON.stringify(target.input));
      setPath({ i: mutated }, path.replace('/input', '/i'), spec.value);
    }
    const got = digestOf(mutated);
    return {
      detected: got !== declared,
      reason,
      detail: `mutated_digest_differs=${got !== declared}`,
    };
  }

  // ── 签名必须失败：域错误 / 错误密钥 / 载荷改动 ──
  if (reason === 'signature_invalid') {
    if (path === '/domain') {
      const wrongOk = verifySignature(
        target.expected.pubkey_hex, target.payload, spec.value, target.expected.signature_hex,
      );
      const genuineOk = verifySignature(
        target.expected.pubkey_hex, target.payload, target.domain, target.expected.signature_hex,
      );
      return {
        detected: wrongOk === false && genuineOk === true,
        reason,
        detail: `wrong_domain_valid=${wrongOk} genuine_valid=${genuineOk}`,
      };
    }
    if (path === '/signer_seed_hex') {
      const other = rawPublicHexOf(privateKeyFromSeed(spec.value));
      const ok = verifySignature(other, target.payload, target.domain, target.expected.signature_hex);
      return { detected: ok === false, reason, detail: `wrong_key_rejected=${ok === false}` };
    }
    const payload = JSON.parse(JSON.stringify(target.payload));
    setPath({ p: payload }, path.replace('/payload', '/p'), spec.value);
    const ok = verifySignature(
      target.expected.pubkey_hex, payload, target.domain, target.expected.signature_hex,
    );
    return { detected: ok === false, reason, detail: `tampered_payload_rejected=${ok === false}` };
  }

  // ── 规则真值不允许等于被声称的结论 ──
  if (reason === 'verdict_violation') {
    const real = judge(target.rule_id, target.rule_version, target.params, target.input);
    const claimed = spec.value || 'PASS';
    return { detected: real.verdict !== claimed, reason, detail: `rule_says=${real.verdict} claimed=${claimed}` };
  }

  // ── 规则版本不在册 ──
  if (reason === 'version_mismatch') {
    const known = RULE_VERSIONS[target.rule_id] || [];
    const claimed = spec.value;
    return { detected: !known.includes(claimed), reason, detail: `claimed=${claimed} known=${known.join(',')}` };
  }

  return { detected: false, reason, detail: `未知 reason "${reason}"` };
}

/** 反向测试用：把 expected 改坏（深拷贝，不动样本库） */
function corruptExpected(v) {
  const v2 = JSON.parse(JSON.stringify(v));
  const e = v2.expected;
  const flip = (s) => (s[0] !== '0' ? '0' : '1') + s.slice(1);
  switch (v2.category) {
    case 'canonical': e.canonical = `${e.canonical} `; break;
    case 'digest': e.digest = flip(e.digest); break;
    case 'verdict': e.output_digest = flip(e.output_digest); break;
    case 'signature': {
      const last = e.signature_hex.slice(-1);
      e.signature_hex = e.signature_hex.slice(0, -1) + (last !== '0' ? '0' : '1');
      break;
    }
    case 'negative': e.reason = '__REVERSE_BUMP__'; break;
    default: break;
  }
  return v2;
}

/** §10.1-2：改坏 expected 后判据必须失败，否则复算器无判别力 */
function reverseTest(vectors, byId, wantReason) {
  const bad = [];
  for (const v of vectors) {
    let r;
    let crashed = null;
    try {
      r = runVector(corruptExpected(v), byId, { wantReason });
    } catch (e) {
      crashed = e;
      r = { ok: false, why: e.message };
    }
    // 崩溃不算「检出」：反向测试要的是判据优雅地判失败，不是抛异常
    if (crashed) bad.push({ id: v.id, category: v.category, why: `异常：${crashed.message}` });
    else if (r.ok) bad.push({ id: v.id, category: v.category, why: '改坏 expected 后仍判通过' });
  }
  return bad;
}


// ══════════════════════════════════════════════════════════════
// ⑥ 自检：规范化实现自身的断言（不依赖样本库）
// ══════════════════════════════════════════════════════════════

function selfTest() {
  const problems = [];
  const eq = (label, got, want) => {
    if (got !== want) problems.push(`${label}: got=${JSON.stringify(got)} want=${JSON.stringify(want)}`);
  };

  // RFC 8785 §3.2.3 = UTF-16 码元序：U+10000 的首码元 0xD800 < U+FFFD 0xFFFD，故补充平面在前。
  // （本文件旧版此处按码点序断言，与 RFC 相反 —— 2026-11-02 由跨语言交叉验证暴露并修正）
  eq('码元排序(补充平面 vs BMP)', canonicalJSON({ '\u{10000}': 1, '\uFFFD': 2 }), '{"\u{10000}":1,"\uFFFD":2}');
  // 数组保序
  eq('数组保序', canonicalJSON([3, 1, 2]), '[3,1,2]');
  // 负数与小数
  eq('负数', canonicalJSON(-1.5), '-1.5');
  eq('负零', canonicalJSON(-0), '0');
  // 控制字符转义
  eq('控制字符', canonicalJSON('\u0001'), '"\\u0001"');
  // 键含引号/反斜杠
  eq('键转义', canonicalJSON({ 'a"b': 1 }), '{"a\\"b":1}');
  // 孤立代理项必须拒绝
  try {
    canonicalJSON('\uD800');
    problems.push('孤立代理项未被拒绝');
  } catch {
    /* 预期抛错 */
  }

  return problems;
}

// ══════════════════════════════════════════════════════════════
// ⑦ 主流程
// ══════════════════════════════════════════════════════════════

function main(argv) {
  let vectorsPath = DEFAULT_VECTORS;
  let verbose = false;
  let reverse = false;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--vectors') vectorsPath = resolve(argv[++i]);
    else if (argv[i] === '--verbose') verbose = true;
    else if (argv[i] === '--reverse') reverse = true;
    else if (argv[i] === '--help' || argv[i] === '-h') {
      console.log('用法: node verify_vectors.mjs [--vectors <path>] [--verbose]');
      return 0;
    }
  }

  const startedAt = new Date();
  console.log('DVEF-001 v0.1 样本库独立复算（Node.js）');
  console.log('='.repeat(56));
  console.log(`运行时     node ${process.version} / ${process.platform}-${process.arch}`);
  console.log(`样本库     ${vectorsPath}`);
  console.log(`复算时间   ${startedAt.toISOString()}`);
  console.log('');

  // 自检先跑，防止「规范化本身有问题导致全盘误判」
  const stProblems = selfTest();
  if (stProblems.length) {
    console.log('规范化自检失败：');
    for (const p of stProblems) console.log(`  · ${p}`);
    console.log('');
  } else {
    console.log('规范化自检   OK（UTF-16 码元排序 / 保序 / 转义 / -0 / 孤立代理项）');
    console.log('');
  }

  let doc;
  try {
    doc = JSON.parse(readFileSync(vectorsPath, 'utf8'));
  } catch (e) {
    console.log(`❌ 无法读取/解析样本库：${e.message}`);
    return 1;
  }
  const vectors = doc.vectors || [];
  const byId = new Map(vectors.map((v) => [v.id, v]));

  // §14 版本协商：0.3 起 INCONCLUSIVE 必须带 reason_code；旧样本库按旧语义复算
  const svParts = String(doc.spec_version || '0.1').split('.').map((x) => parseInt(x, 10) || 0);
  const wantReason = svParts[0] > 0 || svParts[1] >= 3;

  const stat = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  const total = Object.fromEntries(CATEGORIES.map((c) => [c, 0]));
  const fails = [];

  for (const v of vectors) {
    const cat = v.category;
    if (!(cat in total)) {
      fails.push({ id: v.id, category: cat, why: `未知分类 "${cat}"` });
      continue;
    }
    total[cat] += 1;
    let r;
    try {
      r = runVector(v, byId, { wantReason });
    } catch (e) {
      r = { ok: false, why: `异常：${e.message}` };
    }
    if (r.ok) {
      stat[cat] += 1;
      if (verbose) console.log(`  ✓ ${v.id} ${cat} ${v.description || ''}\n      ${r.why}`);
    } else {
      fails.push({ id: v.id, category: cat, why: r.why });
      console.log(`  ✗ ${v.id} ${cat} ${v.description || ''}`);
      console.log(`      ${r.why}`);
    }
  }

  // 与样本库自声明的 counts 对齐（防止漏跑 / 解析问题）
  const declared = doc.counts || {};
  const countMismatch = [];
  for (const c of CATEGORIES) {
    if (declared[c] !== undefined && declared[c] !== total[c]) {
      countMismatch.push(`${c}: 实际 ${total[c]} 条，样本库声明 ${declared[c]} 条`);
    }
  }
  if (declared.total !== undefined && declared.total !== vectors.length) {
    countMismatch.push(`total: 实际 ${vectors.length} 条，样本库声明 ${declared.total} 条`);
  }

  const passed = Object.values(stat).reduce((a, b) => a + b, 0);
  const grand = Object.values(total).reduce((a, b) => a + b, 0);

  console.log('');
  for (const c of CATEGORIES) {
    console.log(`  ${c.padEnd(10)} ${String(stat[c]).padStart(3)}/${String(total[c]).padEnd(3)}`);
  }
  console.log(`  ${'合计'.padEnd(10)} ${String(passed).padStart(3)}/${String(grand).padEnd(3)}`);
  console.log(`  一致性等级  ${passed === grand ? 'CL3（CL0+CL1+CL2 全部逐字节/逐位一致，负样本全检出）' : '未达 CL2 门槛'}`);

  if (countMismatch.length) {
    console.log('');
    console.log('样本库计数与声明不符：');
    for (const m of countMismatch) console.log(`  · ${m}`);
  }

  if (fails.length) {
    console.log('');
    console.log('失败项：');
    for (const f of fails) {
      console.log(`  ${f.id.padEnd(6)} ${f.category.padEnd(10)} ${f.why}`);
    }
    console.log('');
    console.log(`❌ 未全部通过（${fails.length} 条失败）`);
    return 1;
  }

  if (reverse) {
    const bad = reverseTest(vectors, byId, wantReason);
    console.log('');
    console.log(
      `  反向测试   ${vectors.length - bad.length}/${vectors.length} 检出（改坏 expected 必须失败）`,
    );
    if (bad.length) {
      console.log('反向测试失败项（判据无判别力）：');
      for (const b of bad) console.log(`  ${b.id.padEnd(6)} ${b.category.padEnd(10)} ${b.why}`);
      return 1;
    }
  }

  console.log('');
  console.log('✅ 全部通过');
  return 0;
}

process.exitCode = main(process.argv.slice(2));
