#!/usr/bin/env python3
"""
Verify candidate social handles before adding them to tools/watchlist.json.

A handle "resolving" is not enough — a squatter can own @briankrebs on any
instance. So this also pulls the profile (display name, follower count, bio)
so you can eyeball whether it is actually the person you meant.

Usage:
    python3 tools/verify-handles.py                     # check tools/candidates.json
    python3 tools/verify-handles.py --file my-list.json
    python3 tools/verify-handles.py --emit-watchlist    # print a paste-ready block

Candidate file format:
[
  {"name":"Brian Krebs","role":"Krebs on Security",
   "bluesky":["briankrebs.bsky.social"],
   "mastodon":[["infosec.exchange","briankrebs"]]}
]
"""

import argparse, json, re, sys, urllib.request, urllib.error
from html import unescape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UA = "threatboard-verify/1.0 (+https://github.com/xamisnet/mitre-threatboard)"
TIMEOUT = 20
BSKY = "https://public.api.bsky.app/xrpc"


def get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def strip_html(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unescape(s or ""))).strip()


# Phrase that reliably marks an account as not-the-person.
SUSPECT = ("parody", "unofficial", "placeholder", "automated feed", "fan account",
           "not the real", "i xpost only", "is on mastodon", "redirect")


def name_matches(cand_name, display):
    """Does the profile display name share a real word with the person's name?

    Catches the common failure where a handle resolves but belongs to someone
    else entirely (e.g. 'paganini.bsky.social' is a German artist, not
    Pierluigi Paganini).
    """
    a = {w.lower() for w in re.findall(r"[A-Za-z]{4,}", cand_name or "")}
    b = {w.lower() for w in re.findall(r"[A-Za-z]{4,}", display or "")}
    return bool(a & b)


def verdict(display, followers, bio, cand_name=""):
    """Grade an account. Resolving a handle proves nothing about who owns it."""
    blob = f"{display} {bio}".lower()
    if any(s in blob for s in SUSPECT):
        return "SUSPECT"
    if followers < 0:
        # Mastodon reports -1 when the count is hidden; fall back to identity.
        return "OK" if (display not in ("—", "") and name_matches(cand_name, display)) else "UNCONFIRMED"
    if followers < 5000 and not name_matches(cand_name, display):
        return "SUSPECT"          # right handle, wrong human
    if followers >= 1000 and display not in ("—", ""):
        return "OK"
    if followers >= 1000:
        return "NO-NAME"          # high reach but no display name to corroborate
    if followers < 100:
        return "WEAK"             # almost certainly a squatter or an empty shell
    return "UNCONFIRMED"


BSKY_URL_RE = re.compile(r"bsky\.app/profile/([A-Za-z0-9._:\-]+)")


def discover_bluesky(instance, acct):
    """Find a Bluesky handle a person lists on their Mastodon profile.

    Beats guessing: 'hacks4pancakes.bsky.social' does not exist, but her
    Mastodon profile metadata names 'hacks4pancakes.com'. Reading the profile
    finds real custom-domain handles that no naming convention would predict.
    """
    try:
        a = get_json(f"https://{instance}/api/v1/accounts/lookup?acct={acct}")
        a = get_json(f"https://{instance}/api/v1/accounts/{a['id']}") or a
    except Exception:
        return []
    blob = (a.get("note") or "") + " " + " ".join(
        f"{f.get('name','')} {f.get('value','')}" for f in (a.get("fields") or []))
    found = []
    for m in BSKY_URL_RE.findall(blob):
        h = m.strip().rstrip("/.,;")
        if h and h not in found:
            found.append(h)
    return found


def check_bluesky(handle):
    """Resolve handle -> DID, then fetch the profile for identity signals."""
    try:
        did = get_json(f"{BSKY}/com.atproto.identity.resolveHandle?handle={handle}")["did"]
    except Exception as e:
        return {"ok": False, "err": str(e).split(":")[0]}
    try:
        p = get_json(f"{BSKY}/app.bsky.actor.getProfile?actor={did}")
        return {
            "ok": True,
            "did": did,
            "handle": p.get("handle", handle),
            "display": p.get("displayName") or "—",
            "followers": p.get("followersCount", 0),
            "bio": strip_html(p.get("description", ""))[:70],
        }
    except Exception:
        return {"ok": True, "did": did, "handle": handle, "display": "—", "followers": 0, "bio": ""}


def check_mastodon(instance, acct):
    try:
        a = get_json(f"https://{instance}/api/v1/accounts/lookup?acct={acct}")
    except Exception as e:
        return {"ok": False, "err": str(e).split(":")[0]}
    return {
        "ok": True,
        "id": a.get("id"),
        "acct": f"@{a.get('acct','?')}@{instance}",
        "display": a.get("display_name") or "—",
        "followers": a.get("followers_count", 0),
        "bio": strip_html(a.get("note", ""))[:70],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=str(ROOT / "tools" / "candidates.json"))
    ap.add_argument("--emit-watchlist", action="store_true")
    args = ap.parse_args()

    cands = json.loads(Path(args.file).read_text())
    verified = {"bluesky": [], "mastodon": [], "x": []}
    unknown = []
    rejected = []

    print(f"Verifying {len(cands)} candidates\n")
    for c in cands:
        name, role = c.get("name", "?"), c.get("role", "")
        hits = []

        for h in c.get("bluesky", []) or []:
            r = check_bluesky(h)
            if r["ok"]:
                hits.append(("bluesky", r["handle"], r))
            else:
                unknown.append((name, "bluesky", h, r.get("err", "?")))

        for inst, acct in (c.get("mastodon", []) or []):
            r = check_mastodon(inst, acct)
            if r["ok"]:
                hits.append(("mastodon", r["acct"], r))
            else:
                unknown.append((name, "mastodon", f"@{acct}@{inst}", r.get("err", "?")))

        # Cross-platform discovery: read the Mastodon profile rather than guessing
        # the Bluesky handle (custom domains are unpredictable).
        seen_bs = {h[1] for h in hits if h[0] == "bluesky"}
        for inst, acct in (c.get("mastodon", []) or []):
            for hh in discover_bluesky(inst, acct):
                if hh in seen_bs:
                    continue
                rr = check_bluesky(hh)
                if rr["ok"]:
                    hits.append(("discovered", rr["handle"], rr))
                    seen_bs.add(rr["handle"])

        if hits:
            graded = sorted(hits, key=lambda h: -(h[2]["followers"] or 0))
            print(f"  ✓ {name}  ({role})")
            for plat, handle, r in graded:
                v = verdict(r["display"], r["followers"], r.get("bio", ""), name)
                mark = {"OK": "✅", "NO-NAME": "❔", "UNCONFIRMED": "⚠️", "SUSPECT": "🚫", "WEAK": "🚫"}[v]
                print(f"      {mark} {v:9} {plat:9} {handle}")
                print(f"                display=\"{r['display']}\"  followers={r['followers']:,}")
                if r.get("bio"):
                    print(f"                bio: {r['bio']}")
                if v == "OK":
                    if plat in ("bluesky", "discovered"):
                        verified["bluesky"].append(handle)
                    else:
                        verified["mastodon"].append({"instance": r["acct"].split("@")[-1],
                                                     "acct": r["acct"].lstrip("@").split("@")[0]})
                else:
                    rejected.append((name, plat, handle, v, r["display"], r["followers"]))
        else:
            print(f"  ✗ {name}  ({role}) — nothing resolved")

    if rejected:
        print(f"\n  ⚠ {len(rejected)} handle(s) RESOLVE but are the wrong account — do not add these:")
        for name, plat, h, v, disp, fol in rejected:
            print(f"    {v:9} {plat:9} {h:34} display=\"{disp}\" followers={fol:,}")

    if unknown:
        print(f"\n  {len(unknown)} handle(s) did not resolve (expected for guesses):")
        for name, plat, h, err in unknown[:40]:
            print(f"    {plat:9} {h:42} {err}")

    v_bs, v_md = len(verified["bluesky"]), len(verified["mastodon"])
    print(f"\n  RESULT: {v_bs} bluesky + {v_md} mastodon confirmed "
          f"of {sum(len(c.get('bluesky',[]) or [])+len(c.get('mastodon',[]) or []) for c in cands)} tried")

    if args.emit_watchlist:
        print("\n  --- paste into tools/watchlist.json ---")
        print('  "bluesky_accounts": ' + json.dumps(verified["bluesky"], indent=2))
        print('  "mastodon_accounts": ' + json.dumps(verified["mastodon"], indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())