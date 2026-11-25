#!/usr/bin/env python3
"""
Deterministic brief injector for the THREATBOARD Brief tab.

Takes the day's curated items JSON plus an LLM-generated narrative brief in
markdown, renders the markdown to HTML, and writes it into the `BRIEF_HTML`
JS string constant that the Brief tab template renders via ${BRIEF_HTML}.
Also refreshes `const BRIEF_DATE` from the newest item date.

The tactic/technique/control *tables* in the Brief tab are NOT written here —
they are computed dynamically by the page from the live ITEMS array, so they
stay current on their own. This script only replaces the prose.

    python3 tools/briefify.py data/items/<date>.json data/briefs/<date>.md

Exit 0 on success. Runs node tools/validate.mjs as a hard gate before touching
index.html.
"""
import json, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.html"

BRIEF_DATE_RE = re.compile(r'(const BRIEF_DATE\s*=\s*)"[^"]*"')
BRIEF_HTML_RE = re.compile(r'(const BRIEF_HTML\s*=\s*)"(?:[^"\\]|\\.)*"')


def js_string(s: str) -> str:
    """Encode a string as a double-quoted JS string literal."""
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


INLINE = [
    (re.compile(r"\*\*(.+?)\*\*", re.S), "<strong>\\1</strong>"),
    (re.compile(r"(?<!\*)\*([^*\n]+?)\*(?!\*)"), "<em>\\1</em>"),
    (re.compile(r"`([^`\n]+?)`"), "<code>\\1</code>"),
]

# The daily cron authors a "bottom-line-up-front" block at the very top of the
# brief markdown, headed `## Bottom line`. briefify renders THAT into the styled
# bottom-line box (BRIEF_BL) and everything after it into the narrative
# BRIEF_HTML. `## Bottom line` is matched case-insensitively; nothing after it
# up to the next level-2 `## ` heading becomes part of the box.
BLUF_HEAD = re.compile(r"^##\s+Bottom line\s*:?\s*$", re.I)
LEVEL2 = re.compile(r"^##\s+")


def split_bluf(md: str) -> tuple[str, str]:
    """Return (bluf_chunk, main_md). If no `## Bottom line` head exists, returns
    ("", original_md) so the page falls back to the live-computed bottom line."""
    lines = md.split("\n")
    bluf, main = [], []
    in_bluf = False
    found = False
    for raw in lines:
        stripped = raw.strip()
        if not in_bluf:
            if BLUF_HEAD.match(stripped):
                in_bluf, found = True, True
                continue  # drop the heading itself; the box supplies its own <h4>
            main.append(raw)
            continue
        if LEVEL2.match(stripped):
            in_bluf = False
            main.append(raw)
            continue
        bluf.append(raw)
    if not found:
        return "", md.strip("\n")
    return "\n".join(bluf).strip("\n"), "\n".join(main).strip("\n")


def inline(s: str) -> str:
    for pat, rep in INLINE:
        s = pat.sub(rep, s)
    return s


def render(md: str) -> str:
    """Minimal, safe markdown -> HTML for the brief. Disallows raw HTML."""
    md = re.sub(r"<(/?)(script|style|iframe|object|embed|link|meta)(\s[^>]*)?>", "", md, flags=re.I)
    out = []
    para = []
    in_list = None  # "ul" | "ol"
    table_open = False

    def flush_para():
        if para:
            out.append(f"<p>{inline(' '.join(para))}</p>")
            para.clear()

    def flush_list():
        nonlocal in_list
        if in_list:
            out.append(f"</{in_list}>")
            in_list = None

    for raw in md.split("\n"):
        line = raw.rstrip()
        if not line.strip():
            flush_para(); flush_list()
            if table_open:
                out.append("</table>"); table_open = False
            continue
        h = re.match(r"^(#{1,6})\s+(.*)$", line)
        if h:
            flush_para(); flush_list()
            if table_open:
                out.append("</table>"); table_open = False
            lvl = len(h.group(1))
            tag = "h3" if lvl <= 3 else "h4"
            out.append(f"<{tag}>{inline(h.group(2))}</{tag}>")
            continue
        if re.match(r"^\s*(-|\d+\.)\s+", line):
            flush_para()
            if table_open:
                out.append("</table>"); table_open = False
            is_ol = bool(re.match(r"^\s*\d+\.\s+", line))
            want = "ol" if is_ol else "ul"
            if in_list != want:
                flush_list(); in_list = want; out.append(f"<{want}>")
            item = re.sub(r"^\s*(-|\d+\.)\s+", "", line)
            out.append(f"<li>{inline(item)}</li>")
            continue
        if "|" in line:
            flush_para(); flush_list()
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if set(cells) <= {"", "---", ":"} or not table_open and cells and all(c == "---" for c in cells):
                continue
            if not table_open:
                out.append("<table>"); table_open = True
            out.append("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in cells) + "</tr>")
            continue
        para.append(line)

    flush_para(); flush_list()
    if table_open:
        out.append("</table>")
    return "\n".join(out)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: briefify.py <items.json> <brief.md>")
    items_path = Path(sys.argv[1])
    items = json.loads(items_path.read_text())
    if not isinstance(items, list) or not items:
        sys.exit("FAIL: items file is not a non-empty JSON array")
    # as-at date = the collection date (from the filename), i.e. "this is
    # today's brief" — not the max item event date, which is "yesterday".
    m = re.search(r"(\d{4}-\d{2}-\d{2})", items_path.stem)
    brief_date = m.group(1) if m else (max(it.get("d", "") for it in items) if items else "unknown")
    if not brief_date or brief_date.startswith("unknown"):
        sys.exit("FAIL: could not determine brief date from items filename")

    md = Path(sys.argv[2]).read_text()
    bluf_md, narrative_md = split_bluf(md)
    bluf = render(bluf_md).strip()
    narrative = render(narrative_md).strip()
    if not narrative:
        sys.exit("FAIL: brief markdown rendered to empty HTML")

    bluf_js = js_string(bluf)
    injected = js_string(narrative)

    html = INDEX.read_text()
    start = "const BRIEF_DATE="
    start_bl = "const BRIEF_BL="
    end = "<h3>Where the activity concentrates"
    if end not in html or (start not in html and start_bl not in html):
        sys.exit("FAIL: index.html missing BRIEF block anchors - run the setup patch first")
    # Anchor the replacement at the EARLIEST of BRIEF_BL / BRIEF_DATE. Because a
    # prior run injects a BRIEF_BL line immediately before BRIEF_DATE, anchoring
    # only on BRIEF_DATE would strand that stale BRIEF_BL on every re-run. Taking
    # the min of both keeps repeated briefify calls idempotent (daily cron runs it).
    fi = min(html.index(m) for m in (start, start_bl) if m in html)
    i = html.rfind("\n", 0, fi) + 1
    j = html.index(end, i)
    block = (
        '  const BRIEF_BL=' + bluf_js + ';   // authored bottom-line-up-front, injected daily by tools/briefify.py\n'
        '  const BRIEF_DATE="' + brief_date + '";    // as-at date, refreshed daily by tools/briefify.py\n'
        '  const BRIEF_HTML=' + injected + ';   // narrative prose, injected daily by tools/briefify.py\n'
        '  document.getElementById("briefBody").innerHTML=`\n'
        '  <div class="dsec" style="border:1px solid var(--line2);border-left:3px solid var(--acc);padding:12px 14px;margin-bottom:14px;background:linear-gradient(180deg,rgba(34,211,238,.05),transparent)">\n'
        '    <h4 style="margin:0 0 6px;letter-spacing:.04em">Bottom line</h4>\n'
        '    ${BRIEF_BL || bottomLine}\n'
        '  </div>\n'
        '  ${BRIEF_HTML}\n'
    )
    html2 = html[:i] + block + html[j:]
    if html2 == html:
        # Already up to date (e.g. a re-run on the same date) — graceful no-op,
        # NOT an error. daily.sh's git diff check handles the real no-op case.
        print(f"OK: brief for {brief_date} already current (no change to index.html)")
        return

    INDEX.write_text(html2)
    r = subprocess.run(["node", "tools/validate.mjs"], cwd=ROOT,
                       capture_output=True, text=True)
    print(r.stdout)
    if r.returncode != 0:
        print(r.stderr)
        sys.exit("FAIL: validate.mjs rejected the injected brief")
    print(f"OK: brief for {brief_date} injected ({len(items)} items) into index.html")


if __name__ == "__main__":
    main()