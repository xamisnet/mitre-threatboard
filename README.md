# THREATBOARD

A single-file MITRE ATT&CK® cyber-news dashboard. It takes a day of security
reporting and turns it into a navigable **technique → tactic → mitigation**
map, so you can answer three questions in one place:

1. What actually happened in the last 24 hours?
2. Which ATT&CK techniques does that activity touch?
3. What controls would have blocked or reduced it?

No build step, no dependencies, no backend. One HTML file you can open
directly or serve from anything.

![Attack Matrix — severity colouring](shots/mode-sev.png)

---

## Quick start

```bash
git clone https://github.com/<owner>/mitre-threatboard.git
cd mitre-threatboard

./run.sh start          # http://127.0.0.1:8899/index.html
./run.sh status
./run.sh stop
```

Or skip the script entirely — it is a static page:

```bash
python3 -m http.server 8899
# or just open index.html in a browser
```

`PORT=9000 ./run.sh start` if 8899 is taken.

---

## What it does

**Five views, one dataset.**

| View | Purpose |
|---|---|
| **Attack Matrix** | All 14 tactics as columns; every technique reported in the window as a cell with an event count. |
| **News & Mapping** | One card per reported event: severity, type, technique IDs, primary source. |
| **Trends** | Where the activity concentrates — by tactic, activity type, and technique. |
| **Controls** | Every ATT&CK mitigation (M-code) that the mapped activity points at, ranked by coverage, with NIST SP 800-53 families. |
| **Brief** | A written executive brief generated from the same data. |

**Scoping.** Click any news card and the entire matrix narrows to that single
event — showing only the techniques it touches and marking untouched columns
*"not used by this event."* The side panel never opens on its own; use
**ⓘ details** on a card, or the map's own button, when you want the full
breakdown. Deep links are shareable:

```
#item=n01              scope the map to one event
#item=n01&tab=feed     ...and land on the news view
#cb=vol                start in volume colour mode
```

**Drill-down.** Click a technique cell for its mitigations, the events that
use it, and its kill-chain phase. Click a column header to filter the feed by
tactic.

---

## The colour scheme

Colour carries meaning, not decoration. Two independent axes, deliberately in
opposite temperature ranges so they never collide:

**Cool = kill-chain phase** (column headers and technique chips)

| Phase | Tactics | Colour |
|---|---|---|
| Pre-attack | Reconnaissance, Resource Development | violet |
| Intrusion / foothold | Initial Access → Credential Access | blue |
| Post-compromise | Discovery, Lateral Movement, Collection | cyan |
| Impact | C2, Exfiltration, Impact | magenta |

**Warm = severity** (matrix cell tint and badge) — red critical, orange high,
yellow medium. Tint intensity deepens with the number of events using that
technique, so severity and volume read in a single glance.

You can switch the cell axis with **Colour cells by → Severity / Volume /
Phase**:

| Mode | Encodes |
|---|---|
| **Severity** (default) | Worst severity of the events using the technique |
| **Volume** | How many events use it — a single-hue brightness ramp |
| **Phase** | The technique's kill-chain phase |

Elsewhere: activity-type chips are colour-coded (vulnerability, ransomware,
breach, nation-state, ICS, trend, patch); controls are tiered by coverage rank;
trend bars are coloured by phase and category.

![Volume colour mode](shots/mode-vol.png)

### Social signal

![News feed with social signal badges](shots/signals-feed.png)

---

## Data model

Everything is embedded in `index.html` in three tables, immediately after
`<script>`:

```js
const TACTICS = [{id:"TA0001", n:"Initial Access", s:"Initial Access"}, ...];
const TECHS   = { T1190:{t:"TA0001", n:"Exploit Public-Facing Application"}, ... };
const TECH_MIT= { T1190:["M1051","M1048","M1050","M1016","M1030"], ... };
const MIT     = { M1051:{n:"Update Software", nist:"SI-2, CM-6, RA-5"}, ... };
const ITEMS   = [{id:"n01", d:"2026-11-19", sev:"crit", cat:"vuln",
                  title:"...", src:"...", url:"...", tch:["T1190", ...],
                  sum:"...", act:["..."], ctl:["..."]}, ...];
```

To refresh the dashboard, replace `ITEMS` and keep `tch` referencing IDs that
exist in `TECHS`. The validator below enforces that.

Field notes:

- `sev` — `crit` | `high` | `med` | `info`
- `cat` — `vuln` | `breach` | `ransom` | `nation` | `ics` | `trend` | `patch`
- `tch` — ATT&CK technique IDs; drives every count, filter and colour
- `act` — attribution or actor notes
- `ctl` — plain-language, item-specific controls

---

## Example output

`docs/brief-2026-11-20.md` is a full brief produced from this dataset — the
kind of document the Brief tab renders, expanded with per-item citations. It
shows the intended end state: news → technique → control, with caveats stated
rather than buried.

---

## Refreshing — `tools/fetch.py`

Rebuilds the social-signal layer from live sources. Pure stdlib, no
dependencies.

```bash
python3 tools/fetch.py                # dry run — prints a report, writes nothing
python3 tools/fetch.py --write        # rewrite the SIGNALS block in index.html
python3 tools/fetch.py --verify       # only check that watchlist handles resolve
python3 tools/fetch.py --days 7       # widen the KEV lookback (default 3)
```

**The design principle: social posts are signal, not content.** A Bluesky post
saying "vCenter 0day being exploited!!" is a lead, not a verified item. So the
fetcher never invents dashboard items from a post. Instead it:

1. pulls structured data for enrichment — CISA KEV, EPSS, NVD, RSS
2. pulls social chatter — Bluesky, Mastodon, and X when a token is present
3. matches chatter to your existing items **by CVE first, then by headline
   keyword overlap**, and embeds it as `SIGNALS`

Your curated `ITEMS` stay hand-written. The fetcher makes them live, and tells
you which new KEV entries you haven't covered yet (`data/new-kev.json`).

Matched signals appear as a **social** badge on the card and a source list in
the detail panel, with platform, author, timestamp, engagement and a link.

### Sources, and what they actually allow

Verified against the live endpoints:

| Source | Access | Notes |
|---|---|---|
| **CISA KEV** | ✅ no auth | Full JSON catalogue of exploited vulns |
| **FIRST EPSS** | ✅ no auth | Exploitation probability per CVE |
| **NVD 2.0** | ✅ no auth | CVSS, CWE, descriptions (rate-limited) |
| **BleepingComputer RSS** | ✅ no auth | 15 items/feed |
| **The Hacker News RSS** | ✅ no auth | 50 items/feed |
| **SecurityWeek RSS** | ❌ 403 | Blocks default user-agents — needs a browser UA |
| **Bluesky** | ✅ author feeds | Per-account feeds work unauthenticated. **Keyword search is edge-blocked (403)** regardless of headers, so the fetcher follows accounts rather than searching. |
| **Mastodon** | ⚠️ instance-dependent | Tag timelines are public on many instances (mastodon.social, hachyderm.io, fosstodon.org, c.im). Some (infosec.exchange, mstdn.social) return 422 and require auth — handled gracefully, not fatal. |
| **X / Twitter** | 🔑 token required | Needs a paid API bearer token. Set `X_BEARER_TOKEN` to enable. Without it the adapter **reports itself unavailable rather than pretending** — you'll see `(X: no X_BEARER_TOKEN — skipped, not silently failed)` in the output. |

Scripts also fail loudly: any source error is collected and printed, and the
script exits `1` so CI surfaces it.

### The watchlist

`tools/watchlist.json` — edit freely:

```json
{
  "bluesky_accounts": ["bleepingcomputer.com", "briankrebs.bsky.social"],
  "mastodon_instances": ["mastodon.social", "hachyderm.io"],
  "mastodon_tags": ["cybersecurity", "infosec", "ransomware"],
  "mastodon_accounts": [{ "instance": "mastodon.social", "acct": "thehackernews" }],
  "x_accounts": []
}
```

Every handle is verified live on each run — unresolvable ones are reported and
skipped rather than silently dropped. Run `--verify` after editing.

**On seeding the list honestly:** I only ship handles I confirmed resolve
against the live APIs. I did not pad it with plausible-looking researcher
handles that might not exist. To grow it, watch which accounts actually post
about the tags you care about and add them.

### Running it on a schedule

`.github/workflows/refresh.yml` runs daily at 06:00 UTC (and on demand),
refreshes the signals, validates them, and **opens a pull request** if anything
changed. It never auto-merges — matched signals are heuristic, so a human
should eyeball the diff before it lands.

---

## Validating

```bash
node tools/validate.mjs
```

Checks referential integrity end to end:

- every technique referenced by an item exists in `TECHS`
- every technique maps to a valid tactic
- every technique has at least one mitigation, and every mitigation exists
- every `M####` mentioned in control prose actually exists
- no duplicate item IDs or duplicate techniques within an item
- each item cites at least three techniques and has controls

Exits non-zero on failure, so CI catches a broken data edit before it ships.
See `.github/workflows/validate.yml`.

---

## Scope and limitations

**This is a snapshot, not a feed.** The bundled dataset is a point-in-time
capture of public reporting from 20 November 2026, 05:00 UTC. It does not
update itself. Replacing `ITEMS` is a manual (or separately automated) step —
the app has no network access of its own.

**All content is third-party reporting.** Verify against the linked primary
source before acting on anything, especially breach counts and attribution.

**Severity reflects reported impact, not your exposure.** NGINX2Root only
matters if HTTP/2 is enabled on a reachable listener; an Apache Axis flaw only
matters if the legacy Axis surface is present. Version counts are not exposure.

**The control ranking is mechanical.** Coverage is computed from ATT&CK's
technique→mitigation mappings, which under-map cross-cutting controls —
`M1053 Data Backup` scores low despite being central to ransomware defence.
Treat the ranking as an input to judgement, not a verdict.

**Attribution is provisional** throughout, and the dashboard says so per item.

**Social signals are unverified leads.** They are matched to items by CVE ID or
headline keyword overlap — a heuristic that will occasionally attach a post to
the wrong item, or attach noise. Treat the `SIGNALS` layer as "who is talking
about this", never as corroboration of a fact. The dashboard labels it as such
in the UI.

**Bluesky keyword search does not work here.** It is edge-blocked (403) on the
public API regardless of headers, so the fetcher follows accounts instead of
searching. That is a real limitation, not a config problem.

**No secrets, no telemetry.** The app makes no outbound requests; source links
open in a new tab only when clicked. The fetcher runs locally and only ever
talks to the public endpoints listed above.

---

## Screenshots

| | |
|---|---|
| ![Severity mode](shots/mode-sev.png) | ![Phase mode](shots/mode-phase.png) |
| ![Scoped to one item](shots/head-n01.png) | ![News feed](shots/head-feed.png) |

---

## Licence

MIT — see [LICENSE](LICENSE).

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Technique
and mitigation identifiers are used here for defensive mapping only. This
project is not affiliated with or endorsed by MITRE.