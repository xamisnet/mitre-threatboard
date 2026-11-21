#!/usr/bin/env python3
"""
THREATBOARD fetcher — rebuilds the social-signal layer behind index.html.

Design note (important):
  Social posts are SIGNAL, not content. A Bluesky post saying "vCenter 0day
  being exploited!!" is a lead, not a verified item. So this script never
  invents dashboard items from a post. It:
    1. pulls structured data (CISA KEV, EPSS, NVD, RSS) for enrichment
    2. pulls social chatter (Bluesky, Mastodon, X-if-tokened)
    3. matches chatter to existing CVE IDs, and embeds it as SIGNALS
  Your curated ITEMS stay hand-written. The fetcher makes them live.

Usage:
    python3 tools/fetch.py                  # dry run, prints a report
    python3 tools/fetch.py --write          # rewrite the SIGNALS block
    python3 tools/fetch.py --verify        # only check watchlist handles
    python3 tools/fetch.py --days 7         # KEV lookback window

Exit codes: 0 ok, 1 something failed that you should know about.
"""

import argparse, json, os, re, sys, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timedelta, timezone
from html import unescape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.html"
WATCH = ROOT / "tools" / "watchlist.json"
OUT_NEW_KEV = ROOT / "data" / "new-kev.json"

UA = "threatboard-fetcher/1.0 (+https://github.com/xamisnet/mitre-threatboard)"
TIMEOUT = 25
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
RSS_FEEDS = [
    ("BleepingComputer", "BC", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "THN", "https://feeds.feedburner.com/TheHackersNews"),
]
RSS_SHORT = {n: s for n, s, _ in RSS_FEEDS}

failures = []


# ---------------------------------------------------------------- transport
def get(url, accept="application/json"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}") from e
    except Exception as e:
        raise RuntimeError(str(e)) from e


def get_json(url):
    return json.loads(get(url))


def note_fail(what, err):
    msg = f"{what}: {err}"
    failures.append(msg)
    print(f"    ! {msg}")


# ---------------------------------------------------------------- structured
def fetch_kev(days):
    """Recent KEV additions. Returns list of dicts."""
    print("  [1/4] CISA KEV …", end=" ", flush=True)
    try:
        d = get_json(KEV_URL)
    except Exception as e:
        note_fail("CISA KEV", e)
        return [], None
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [v for v in d.get("vulnerabilities", []) if v.get("dateAdded", "") >= cutoff]
    recent.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    print(f"{len(recent)} added since {cutoff} (catalogue {d.get('catalogVersion')})")
    return recent, d.get("catalogVersion")


def fetch_epss(cves):
    """EPSS scores, one request per CVE (API accepts batches but keep it gentle)."""
    print(f"  [2/4] EPSS for {len(cves)} CVEs …", end=" ", flush=True)
    out, ok = {}, 0
    for c in cves:
        try:
            d = get_json(EPSS_URL.format(c))
            for row in d.get("data", []):
                out[row["cve"]] = {"epss": float(row["epss"]), "pct": float(row["percentile"])}
                ok += 1
        except Exception:
            continue
    print(f"{ok} scored")
    if ok == 0:
        note_fail("EPSS", "no scores returned")
    return out


def fetch_rss():
    print("  [3/4] RSS headlines …", end=" ", flush=True)
    heads = []
    for name, short, url in RSS_FEEDS:
        try:
            raw = get(url, accept="application/rss+xml, application/xml")
            titles = re.findall(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", raw, re.S)
            for t in titles[1:16]:
                t = unescape(re.sub(r"<[^>]+>", "", t)).strip()
                if t:
                    heads.append({"src": name, "title": t})
            print(f"{short}={len(titles)-1}", end=" ", flush=True)
        except Exception as e:
            note_fail(f"RSS {name}", e)
    print()
    return heads


# -------------------------------------------------------------------- social
def norm_post(platform, author, url, iso, text, engagement=0):
    text = re.sub(r"<[^>]+>", " ", unescape(text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return {"p": platform, "a": author, "u": url, "t": (iso or "")[:19],
            "x": text[:300], "e": int(engagement or 0)}


def fetch_bluesky(accounts):
    """Public author feeds — no auth. (Keyword search is edge-blocked upstream.)

    Resolve handle -> DID first: some handles resolve but 400 on getAuthorFeed
    when queried by handle, and DID addressing is the more stable path.
    """
    out = []
    for acct in accounts:
        actor = acct
        try:
            actor = get_json("https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle"
                             f"?handle={acct}").get("did", acct)
        except Exception:
            pass  # may already be a DID
        try:
            d = get_json("https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed"
                         f"?actor={actor}&limit=25&filter=posts_no_replies")
        except Exception as e:
            note_fail(f"Bluesky @{acct}", e)
            continue
        for entry in d.get("feed", []):
            p = entry.get("post", {})
            rec = p.get("record", {})
            rkey = p.get("uri", "").rsplit("/", 1)[-1]
            handle = p.get("author", {}).get("handle", acct)
            out.append(norm_post(
                "bluesky", handle,
                f"https://bsky.app/profile/{handle}/post/{rkey}",
                rec.get("createdAt", ""),
                rec.get("text", ""),
                p.get("likeCount", 0) + p.get("repostCount", 0),
            ))
    return out


def fetch_mastodon(instances, tags, accounts):
    """Tag timelines are public on many instances; per-account statuses otherwise."""
    out = []
    for inst in instances:
        for tag in tags:
            try:
                d = get_json(f"https://{inst}/api/v1/timelines/tag/{tag}?limit=20")
            except Exception as e:
                # 422 == instance requires auth for this endpoint; not fatal
                if "422" not in str(e):
                    note_fail(f"Mastodon {inst} #{tag}", e)
                continue
            for s in d if isinstance(d, list) else []:
                acct = s.get("account", {}).get("acct", "?")
                dom = s.get("account", {}).get("url", "").split("/@")[-1]
                out.append(norm_post(
                    "mastodon", acct + ("" if "@" in acct else f"@{dom}"),
                    s.get("url", ""), s.get("created_at", ""),
                    s.get("content", ""),
                    s.get("reblogs_count", 0) + s.get("favourites_count", 0),
                ))
    for a in accounts:
        inst, acct = a.get("instance"), a.get("acct")
        try:
            who = get_json(f"https://{inst}/api/v1/accounts/lookup?acct={acct}")
            st = get_json(f"https://{inst}/api/v1/accounts/{who['id']}/statuses?limit=20")
        except Exception as e:
            note_fail(f"Mastodon {inst}/@{acct}", e)
            continue
        for s in st if isinstance(st, list) else []:
            out.append(norm_post(
                "mastodon", f"{acct}@{inst}", s.get("url", ""), s.get("created_at", ""),
                s.get("content", ""),
                s.get("reblogs_count", 0) + s.get("favourites_count", 0),
            ))
    return out


def fetch_x(accounts):
    """X requires a paid bearer token. Report unavailability honestly."""
    token = os.environ.get("X_BEARER_TOKEN")
    if not token:
        print("    (X: no X_BEARER_TOKEN — skipped, not silently failed)")
        return []
    out = []
    for acct in accounts:
        q = urllib.parse.quote(f"from:{acct} (CVE OR exploit OR 0day OR ransomware)")
        req = urllib.request.Request(
            f"https://api.twitter.com/2/tweets/search/recent?query={q}&max_results=25&tweet.fields=created_at,public_metrics",
            headers={"Authorization": f"Bearer {token}", "User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                d = json.loads(r.read())
        except Exception as e:
            note_fail(f"X @{acct}", e)
            continue
        for tw in d.get("data", []):
            m = tw.get("public_metrics", {})
            out.append(norm_post(
                "x", f"@{acct}", f"https://x.com/{acct}/status/{tw['id']}",
                tw.get("created_at", ""), tw.get("text", ""),
                m.get("like_count", 0) + m.get("retweet_count", 0)))
    return out


# ------------------------------------------------------------------ matching
def extract_cves(text):
    return {c.upper() for c in CVE_RE.findall(text or "")}


def keywords(title):
    stop = {"the", "and", "for", "with", "from", "into", "that", "this", "are", "its",
            "over", "after", "before", "critical", "vulnerability", "vulnerabilities"}
    return {w for w in re.findall(r"[a-z0-9]{5,}", (title or "").lower()) if w not in stop}


def dedupe(signals):
    """Same person posts the same thing on Bluesky and Mastodon. Collapse those.

    Keeps the highest-engagement copy of near-identical text.
    """
    best = {}
    for s in signals:
        key = re.sub(r"\W+", "", s["x"].lower())[:80]
        if key not in best or s["e"] > best[key]["e"]:
            best[key] = s
    return list(best.values())


def match_signals(signals, items):
    """Attach a signal to items by CVE first, then by title-keyword overlap."""
    signals = dedupe(signals)
    by_cve, by_kw = {}, {}
    for it in items:
        blob = f"{it.get('title','')} {it.get('sum','')}"
        for c in extract_cves(blob):
            by_cve.setdefault(c, set()).add(it["id"])
        by_kw[it["id"]] = keywords(it.get("title", ""))

    out, used = {}, 0
    reasons = {}
    for s in signals:
        cves = extract_cves(s["x"])
        hit, why = set(), ""
        for c in cves:
            if by_cve.get(c):
                hit |= by_cve[c]
                why = f"CVE {c}"
        if not hit:
            # Keyword fallback needs 3 distinct shared words, and attaches to the
            # single BEST-matching item only. Attaching to every item that clears
            # the bar let one generic "CISA KEV roundup" post spray across four
            # unrelated items.
            words = set(re.findall(r"[a-z0-9]{5,}", s["x"].lower()))
            best_iid, best_common = None, set()
            for iid, kw in by_kw.items():
                common = words & kw
                if len(common) > len(best_common):
                    best_iid, best_common = iid, common
            if best_iid and len(best_common) >= 3:
                hit.add(best_iid)
                why = "kw: " + ", ".join(sorted(best_common)[:4])
        if hit:
            used += 1
            for iid in hit:
                out.setdefault(iid, []).append(s)
                reasons[iid] = why
    for k in out:
        out[k].sort(key=lambda s: (s["e"], s["t"]), reverse=True)
        out[k] = out[k][:8]
    return out, used, reasons


# -------------------------------------------------------------------- output
BEGIN = "/* === SIGNALS:BEGIN"
END = "/* === SIGNALS:END === */"


def write_signals(sig_map):
    html = INDEX.read_text()
    a, b = html.find(BEGIN), html.find(END)
    if a < 0 or b < 0:
        raise SystemExit("FAIL: SIGNALS sentinels missing from index.html")
    block = (
        "/* === SIGNALS:BEGIN — regenerated by tools/fetch.py, do not hand-edit ===\n"
        f"   Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from Bluesky, Mastodon, X. */\n"
        f"const SIGNALS={json.dumps(sig_map, separators=(',', ':'), ensure_ascii=False)};\n"
        "/* === SIGNALS:END === */"
    )
    INDEX.write_text(html[:a] + block + html[b + len(END):])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="rewrite the SIGNALS block in index.html")
    ap.add_argument("--verify", action="store_true", help="only verify watchlist handles")
    ap.add_argument("--days", type=int, default=3, help="KEV lookback in days (default 3)")
    args = ap.parse_args()

    cfg = json.loads(WATCH.read_text())
    bs, md_acc, x_acc = cfg.get("bluesky_accounts", []), cfg.get("mastodon_accounts", []), cfg.get("x_accounts", [])
    md_inst, md_tags = cfg.get("mastodon_instances", []), cfg.get("mastodon_tags", [])

    if args.verify:
        print("Watchlist verification\n")
        for h in bs:
            try:
                get_json(f"https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={h}")
                print(f"  ok    bluesky  @{h}")
            except Exception as e:
                print(f"  FAIL  bluesky  @{h}  ({e})")
        for a in md_acc:
            try:
                get_json(f"https://{a['instance']}/api/v1/accounts/lookup?acct={a['acct']}")
                print(f"  ok    mastodon @{a['acct']}@{a['instance']}")
            except Exception as e:
                print(f"  FAIL  mastodon @{a['acct']}@{a['instance']}  ({e})")
        return

    print(f"THREATBOARD fetcher — {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC\n")

    recent_kev, catalog = fetch_kev(args.days)
    html = INDEX.read_text()
    existing_cves = extract_cves(html)
    new_kev = [v for v in recent_kev if v["cveID"].upper() not in existing_cves]
    epss = fetch_epss(sorted({v["cveID"] for v in recent_kev})[:40])
    heads = fetch_rss()

    print("  [4/4] social …", end=" ", flush=True)
    signals = []
    signals += fetch_bluesky(bs)
    signals += fetch_mastodon(md_inst, md_tags, md_acc)
    signals += fetch_x(x_acc)
    print(f"{len(signals)} posts from "
          f"{len({s['p'] for s in signals})} platform(s)")

    # items currently embedded in the dashboard
    html = INDEX.read_text()
    m = re.search(r"const ITEMS=\[(.*?)\n\];", html, re.S)
    items = []
    if m:
        items = [{"id": m2[0], "title": m2[1], "sum": ""}
                 for m2 in re.findall(r'\{id:"(\w+)",[^}]*?title:"(.*?)",\s*src:', html, re.S)]

    sig_map, used, reasons = match_signals(signals, items)
    print(f"\n  matched {used}/{len(signals)} posts to {len(sig_map)} item(s)")
    print(f"  {len(new_kev)} KEV entr(ies) not yet in the dashboard")

    if new_kev:
        print("\n  New KEV — candidates to add:")
        for v in new_kev[:10]:
            e = epss.get(v["cveID"])
            tag = f"  EPSS {e['epss']*100:.1f}%" if e else ""
            print(f"    {v['dateAdded']}  {v['cveID']:<18} {v['vendorProject']} {v['product']}{tag}")

    if heads:
        print(f"\n  Headlines ({len(heads)}):")
        for h in heads[:6]:
            print(f"    [{h['src'][:14]:14}] {h['title'][:88]}")

    if sig_map:
        print("\n  Sample matched signals:")
        for iid, ss in list(sig_map.items())[:4]:
            print(f"    {iid} [{reasons.get(iid,'?')}]: {ss[0]['p']} @{ss[0]['a']} — {ss[0]['x'][:70]}")

    if args.write:
        write_signals(sig_map)
        OUT_NEW_KEV.parent.mkdir(exist_ok=True)
        OUT_NEW_KEV.write_text(json.dumps(
            {"generated": datetime.now(timezone.utc).isoformat(),
             "catalog": catalog, "entries": new_kev}, indent=2))
        print(f"\n  wrote SIGNALS ({len(sig_map)} keys) into index.html")
        print(f"  wrote {OUT_NEW_KEV.relative_to(ROOT)}")
        print("  -> now run: node tools/validate.mjs")
    else:
        print("\n  (dry run — pass --write to update index.html)")

    if failures:
        print(f"\n  {len(failures)} source(s) failed:")
        for f in failures:
            print(f"    - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())