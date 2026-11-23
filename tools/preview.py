#!/usr/bin/env python3
"""
One-off render test for the threatboard: build a throwaway HTML snapshot from a
curated items.json WITHOUT touching the real repo, so we can visually check the
dashboard renders before cron delivery.

    python3 tools/preview.py data/items/<date>.json <out.html>

Stages a full self-contained tree (index.html + tools/inject.py + validate.mjs)
in a temp dir so inject.py's ROOT resolves, injects the items there, then copies
the result out. Does not modify the real repo. SIGNALS are emptied (the repo's
GH Action refills them on the real repo).
"""
import shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
items = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
if not items.exists():
    sys.exit(f"FAIL: {items} not found")

tmp = Path(tempfile.mkdtemp(prefix="threatboard-preview-"))
try:
    # full tree: index.html + tools/ so inject.py's ROOT resolves
    tnode = tmp / "tools"
    tnode.mkdir()
    shutil.copy(ROOT / "index.html", tmp / "index.html")
    shutil.copy(ROOT / "tools" / "inject.py", tnode / "inject.py")
    shutil.copy(ROOT / "tools" / "validate.mjs", tnode / "validate.mjs")

    r = subprocess.run(["python3", "inject.py", str(items)], cwd=tnode,
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"FAIL: {r.stdout}\n{r.stderr}")
    shutil.copy(tmp / "index.html", out)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"OK: preview written to {out}")
print("Caveat: SIGNALS emptied (fetch.py refills on the real repo's GH Action).")
