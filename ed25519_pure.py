# -*- coding: utf-8 -*-
"""Ed25519 纯标准库实现（仅供 DVEF 外部复算包使用，零第三方依赖）。

实现范围：公钥派生 + 签名验证（RFC 8032 §5.1.7 验证方程）。
不实现签名（外部复算方不需要签名，只需要验签）。

正确性依据：与本仓库 cryptography 实现交叉验证（12 条签名样本 + 3 个种子派生公钥）。
"""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    k = D * x1 * x2 * y1 * y2 % P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k) % P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k) % P
    return (x3, y3)


def _scalarmult(p, e):
    if e == 0:
        return (0, 1)
    q = _scalarmult(p, e // 2)
    q = _edwards_add(q, q)
    if e & 1:
        q = _edwards_add(q, p)
    return q


BY = 4 * _inv(5) % P
BX = _xrecover(BY)
B = (BX, BY)


def _encodepoint(p):
    x, y = p
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _decodepoint(s):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("y out of range")
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = P - x
    p = (x, y)
    if not _isedwards(p):
        raise ValueError("point not on curve")
    return p


def _isedwards(p):
    x, y = p
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def H(m):
    return hashlib.sha512(m).digest()


def _clamp(h):
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def public_key_from_seed(seed: bytes) -> bytes:
    """RFC 8032 §5.1.5：seed(32B) -> public key(32B)"""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _clamp(H(seed))
    return _encodepoint(_scalarmult(B, a))


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7 验证方程：[S]B == R + [k]A，其中 k = SHA512(R||A||M) mod L"""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    r_bytes = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    try:
        a_point = _decodepoint(public_key)
        r_point = _decodepoint(r_bytes)
    except ValueError:
        return False
    k = int.from_bytes(H(r_bytes + public_key + message), "little") % L
    left = _scalarmult(B, s)
    right = _edwards_add(r_point, _scalarmult(a_point, k))
    return _encodepoint(left) == _encodepoint(right)
