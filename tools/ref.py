#!/usr/bin/env python3
"""
dict to build a compact reference the LLM gen uses to pick ONLY valid
technique + mitigation IDs for the threatboard ITEMS block.

    python3 tools/ref.py            # write tools/llm-reference.md (id -> name)
    python3 tools/ref.py --cat      # also emit the valid `cat` enum + sev enum
"""
import re, sys, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.html"
OUT = ROOT / "tools" / "llm-reference.md"

html = INDEX.read_text()
START = "/* ============================ TACTICS"
END = "/* ============================ HELPERS"
a, b = html.index(START), html.index(END)
block = html[a:b]

# Extract the TECHS map: {id: {n: name, t: tactic}}
tec_m = re.search(r"const TECHS=\{(.*?)\n\};", block, re.S).group(1)
tac_m = re.search(r"const TACTICS=\[(.*?)\n\];", block, re.S).group(1)
mit_m = re.search(r"const MIT=\{(.*?)\n\};", block, re.S).group(1)

tactics = dict(re.findall(r'\{id:"(\w+)",n:"([^"]+)"', tac_m))
techs = [(m.group(1), m.group(2), m.group(3)) for m in re.finditer(r'"?([A-Z0-9\.]+)"?:\{t:"([^"]+)",n:"([^"]+)"\}', tec_m)]
mits = [(m.group(1), m.group(2)) for m in re.finditer(r'((?:M|C)\d+):\{n:"([^"]+)"', mit_m)]

# categories + severities seen in existing curated ITEMS
items_m = re.search(r"const ITEMS=\[(.*?)\n\];", block, re.S).group(1)
cats = sorted(set(re.findall(r'\bcat:"([^"]+)"', items_m)))
sevs = sorted(set(re.findall(r'\bsev:"([^"]+)"', items_m)))

lines = []
lines.append("# Threatboard LLM reference — VALID ids only")
lines.append("")
lines.append("## Severity enum (`sev`)")
lines.append(", ".join(sevs))
lines.append("")
lines.append("## Category enum (`cat`)")
lines.append(", ".join(cats))
lines.append("")
lines.append("## Tactics")
for tid, tn in tactics.items():
    lines.append(f"- `{tid}` {tn}")
lines.append("")
lines.append("## Techniques (`tch` — pick ids from HERE only, id -> name -> tactic)")
tac_by_id = {tid: tn for tid, tn in tactics.items()}
for tid, tn, tac in techs:
    lines.append(f"- `{tid}` {tn}  [{tac_by_id.get(tac, tac)}]")
lines.append("")
lines.append("## Mitigations (`ctl` — cite M#### ids from HERE only)")
for mid, mn in mits:
    lines.append(f"- `{mid}` {mn}")

OUT.write_text("\n".join(lines) + "\n")
print(f"wrote {OUT} ({len(techs)} techniques, {len(mits)} mitigations, {len(tactics)} tactics)")
print(f"categories: {cats}")
print(f"severities: {sevs}")
