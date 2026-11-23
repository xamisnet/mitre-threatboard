#!/usr/bin/env python3
"""
One-off render test for the threatboard: build a throwaway HTML snapshot from a
curated items.json WITHOUT touching the real repo, so we can visually check the
dashboard renders before cron delivery. 

    python3 tools/preview.py data/items/<date>.json <out.html>

Injects the items into a copy of index.html and renders nothing itself (open
the output in a browser or screenshot it). Does not modify index.html.
"""
import shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
items = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
if not items.exists():
    sys.exit(f"FAIL: {items} not found")

# Build a temp items copy keyed so inject.py reads it unchanged, then point a
# staged clone's injector at it. Simplest safe approach: copy index.html to a
# temp dir, copy inject.py+ref tables, run inject in isolation, then copy out.
tmp = ROOT / "tools" / ".preview"
if tmp.exists():
    shutil.rmtree(tmp)
tmp.mkdir()
shutil.copy(ROOT / "index.html", tmp / "index.html")
shutil.copy(ROOT / "tools" / "inject.py", tmp / "inject.py")

r = subprocess.run(["python3", "inject.py", str(items)], cwd=tmp,
                   capture_output=True, text=True)
if r.returncode != 0:
    sys.exit(f"FAIL: {r.stdout}\n{r.stderr}")
shutil.copy(tmp / "index.html", out)
shutil.rmtree(tmp)
print(f"OK: preview written to {out}")
print("Caveat: SIGNALS emptied (fetch.py refills on the real repo's GH Action).")
