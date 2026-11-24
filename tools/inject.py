#!/usr/bin/env python3
"""
Deterministic injector for the threatboard ITEMS block.

Takes a JSON array of curated items (produced by an LLM gen that only used ids
from tools/llm-reference.md), validates every referenced id against the real
embedded TECHS/MIT tables, writes the `const ITEMS` block into index.html,
resets SIGNALS to {} (the repo's 06:00 GH Action refills it), then runs
`node tools/validate.mjs` as a hard gate.

    python3 tools/inject.py data/items/<date>.json

Exit 0 and prints the injected item count on success; exit 1 and a clear
message on any integrity failure. index.html is only modified after the data
is proven valid.
"""
import json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.html"

SEV = {"crit", "high", "med"}
CAT = {"breach", "ics", "nation", "patch", "ransom", "trend", "vuln"}


def load_tables():
    html = INDEX.read_text()
    a = html.index("/* ============================ TACTICS")
    b = html.index("/* ============================ HELPERS")
    block = html[a:b]
    tec = re.search(r"const TECHS=\{(.*?)\n\};", block, re.S).group(1)
    mit = re.search(r"const MIT=\{(.*?)\n\};", block, re.S).group(1)
    techs = set(re.findall(r"\"?([A-Z0-9\.]+)\"?:\{t:", tec))
    mits = set(re.findall(r"((?:M|C)\d+):\{n:", mit))
    return techs, mits


def as_js_str(s):
    return json.dumps(str(s), ensure_ascii=False)


def emit_block(items):
    lines = ["const ITEMS=["]
    for it in items:
        lines.append("{")
        lines.append(f' id:{as_js_str(it["id"])},d:{as_js_str(it["d"])},sev:{as_js_str(it["sev"])},'
                     f'cat:{as_js_str(it["cat"])},kev:{int(it.get("kev", 0))},wild:{int(it.get("wild", 0))},')
        lines.append(f' title:{as_js_str(it["title"])},')
        lines.append(f' src:{as_js_str(it["src"])},')
        lines.append(f' url:{as_js_str(it["url"])},')
        lines.append(f' tch:{json.dumps(it["tch"])},')
        lines.append(f' sum:{as_js_str(it["sum"])},')
        lines.append(f' act:{json.dumps(it.get("act", []))},')
        lines.append(' ctl:' + json.dumps(it.get("ctl", [])) + "},")
    lines.append("];")
    return "\n".join(lines) + "\n"


def main():
    path = Path(sys.argv[1]).resolve()
    items = json.loads(path.read_text())
    if not isinstance(items, list) or not items:
        sys.exit("FAIL: items file is not a non-empty JSON array")

    techs, mits = load_tables()
    errs = []
    ids = set()
    for i, it in enumerate(items):
        tag = f"item[{i}] ({it.get('id', '?')})"
        for f in ("id", "d", "sev", "cat", "title", "url", "sum"):
            if not it.get(f):
                errs.append(f"{tag}: missing '{f}'")
        if it["id"] in ids:
            errs.append(f"{tag}: duplicate id")
        ids.add(it["id"])
        if it.get("sev") not in SEV:
            errs.append(f"{tag}: bad sev {it.get('sev')!r}")
        if it.get("cat") not in CAT:
            errs.append(f"{tag}: bad cat {it.get('cat')!r}")
        for t in it.get("tch", []):
            if t not in techs:
                errs.append(f"{tag}: unknown technique {t}")
        if len(set(it.get("tch", []))) != len(it.get("tch", [])):
            errs.append(f"{tag}: duplicate technique ids")
        if len(it.get("tch", [])) < 3:
            errs.append(f"{tag}: fewer than 3 techniques")
        for c in it.get("ctl", []):
            for m in re.findall(r"M\d{4}", c):
                if m not in mits:
                    errs.append(f"{tag}: control cites unknown {m}")
        if not it.get("ctl"):
            errs.append(f"{tag}: no controls")

    if errs:
        print(f"FAIL: {len(errs)} problem(s) in {path.name}:\n  " + "\n  ".join(errs[:40]))
        sys.exit(1)

    new_block = emit_block(items)
    date = path.stem
    stamp = f"News scan: {date} 05:00 AEDT"
    html = INDEX.read_text()
    items_start = html.index("const ITEMS=[")
    begin_anchor = html.index("/* === SIGNALS:BEGIN")
    signals_decl = html.index("const SIGNALS=", begin_anchor)
    signals_end = html.index("/* === SIGNALS:END")

    # Rebuild: keep everything up to ITEMS, swap in the new items block, then
    # keep the SIGNALS markers but empty the declaration (fetch.py refills).
    prefix = html[:items_start]
    middle = new_block + "\n"
    sig_markers = html[begin_anchor:signals_decl]   # BEGIN comment + date line
    suffix = html[signals_end:]
    # Stamp the header ticker with the deterministic news-scan time (not a live
    # wall-clock) and remove the ticking interval so the page is byte-stable.
    suffix = suffix.replace('function tick(){document.getElementById("clock").textContent=new Date().toISOString().replace("T"," ").slice(0,19)+"Z";}\n',
                            "")
    suffix = suffix.replace("tick();setInterval(tick,1000);\n", "")

    final = prefix + middle + sig_markers + "const SIGNALS={};\n" + suffix
    final = final.replace('<span class="tag" id="clock">—</span>',
                          '                <span class="tag" id="clock">' + stamp + '</span>')
    # Only write after replacing both the block and the clock.
    INDEX.write_text(final)
    r = subprocess.run(["node", "tools/validate.mjs"], cwd=ROOT,
                       capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr)
        sys.exit("FAIL: validate.mjs rejected the injected block")
    print(f"OK: injected {len(items)} validated items into index.html")


if __name__ == "__main__":
    main()
