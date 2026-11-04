@echo off
echo [0/3] manifest check (see MANIFEST.sha256; use certutil per file if needed)
echo [1/3] Python verify + reverse (vectors v0.2)
python verify_stdlib.py --vectors vectors_v0.2.json --reverse || exit /b 1
echo [2/3] Python verify (vectors v0.1 -- version negotiation)
python verify_stdlib.py --vectors vectors_v0.1.json --reverse || exit /b 1
echo [3/3] Node cross-check (optional)
where node >nul 2>nul && (node verify_vectors_node.mjs --vectors vectors_v0.2.json --reverse) || echo   skipped: node not found
