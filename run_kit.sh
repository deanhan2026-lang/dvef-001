#!/bin/sh
set -e
echo "[0/3] 校验清单"
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c MANIFEST.sha256; else shasum -a 256 -c MANIFEST.sha256; fi
echo "[1/3] Python 复算 + 反向测试（样本库 v0.2）"
python3 verify_stdlib.py --vectors vectors_v0.2.json --reverse
echo "[2/3] Python 复算（样本库 v0.1，验证版本协商）"
python3 verify_stdlib.py --vectors vectors_v0.1.json --reverse
echo "[3/3] Node 交叉核对（可选）"
if command -v node >/dev/null 2>&1; then node verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse; else echo "  跳过：未检测到 node"; fi
