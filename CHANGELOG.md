# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

## [0.7.25]

### Added
- **`hickok sql --ghost` — one flag for the safest footprint.** A max-opsec preset
  that routes through **Tor (verified, fail-closed)**, sends a **random real-browser
  User-Agent** and **paces requests** (delay) — the cautious setup for working an
  injection on a real target. Any piece is still overridable with its own flag. The
  same `--ghost` lands in [wraith](https://github.com/gusta-ve/wraith), so a stealth
  run is one word across the pair.

## [0.7.24]

### Added
- **One `dump` group with three clear targets, and dumping a *chosen* database.**
  The SQL console's dump commands are now `dump table <name>` (one table),
  `dump database [<name>]` (every table in a database — the current one if no name)
  and `dump all` (every reachable database). When the catalog shows more than one
  database, `dump database <name>` reaches into a specific one and `dump all` sweeps
  them all, skipping the engine's own system databases. Cross-database reads work
  where one injection point allows them (MySQL, MSSQL); on SQLite and Postgres, which
  expose a single database per connection, naming another is refused with a clear
  note instead of a wrong query. Each table still streams to the screen and a CSV,
  and Ctrl-C stops the sweep keeping everything pulled so far.

### Changed
- The SQL console's help is regrouped into a `walk` section and a `dump` section so
  the commands read as a short tutorial. `dump <table>` (no subcommand) still works
  as a shorthand for `dump table <table>`.

## [0.7.23]

### Added
- **`dump-all` — dump the whole database in one command.** The SQL console walks
  every table in turn, printing and saving a CSV for each, then tallies the rows
  across the database; `dump *` (also `dump all` / `dump database`) does the same.
  Ctrl-C stops the sweep but keeps and saves everything pulled up to that point —
  handy on a slow boolean-blind walk. The single-table `dump <table>` is unchanged.

## [0.7.22]

### Fixed
- **UNION column count no longer overshoots when the out-of-range `ORDER BY` error
  page looks like a normal page.** On an in-band target that leaks errors as one
  small line in a big page (a classic staff-directory lookup), the error page can be
  >95% similar to a normal one — the old fixed 0.95 cutoff read it as a valid column,
  so the count ran past the real width and every UNION probe then failed the
  column-count match. The engine wrongly concluded there was no UNION and fell back
  to slow boolean-blind. The count is now decided by *relative* similarity (each
  `ORDER BY n` against a deliberately-broken `ORDER BY 9999`), so it stops at the
  real width. `auto` and `--technique union` now take the fast in-band path on these
  targets instead of grinding bit-by-bit.
- The reflected-column probe now places a single string marker with `NULL` in the
  other columns (was a string in *every* column), so it survives strict UNION type
  checking on **Postgres/MSSQL** instead of erroring out.

## [0.7.21]

### Changed
- **Blind/boolean extraction is dramatically faster and more reliable.** The
  TRUE/FALSE comparison now runs on just the region of the page that reacts to the
  condition — the shared chrome is trimmed off — so the diff works on a handful of
  characters instead of the whole page. A walk that took minutes finishes in about
  a second, and bits stay reliable even when the tell is one line in a big page.
- Character extraction is **ASCII-first** (a short search for the common case),
  roughly halving the requests per character.
- A page that **reflects the injected payload** no longer adds per-request noise:
  the payload is stripped from the response before the comparison, so forms that
  echo your input can't flip bits.

### Fixed
- A blind catalog walk against a **WAF that blocks the catalog**
  (`information_schema` / `sqlite_master` / `pragma`) no longer runs the row/column
  count away into a near-infinite extraction — a filtered count yields nothing and
  the walk falls back to by-name guessing instead of hanging.

## [0.7.20]

### Fixed
- Boolean calibration's confirm step is now **quote-free**, so a target that
  strips single quotes from input no longer defeats it (it used to find no oracle
  and fall back to slow time-based extraction).
- By-name table/column probing (the fallback when the catalog is blocked) no
  longer **false-positives** on apps that return an error page for an unknown
  identifier: a probe whose response is anomalous (a third state, close to
  neither calibration page) is read as "doesn't exist" instead of tying to True —
  so a dump no longer selects columns that aren't there.

## [0.7.19]

### Fixed
- Boolean-blind **calibration now catches a small, consistent tell in a large
  page** — a one-line `Welcome` / `Invalid` in a full HTML response — instead of
  requiring the true/false pages to differ by ≥5%. It measures the page's own
  jitter (two identical TRUE requests) and accepts a context only when FALSE sits
  reliably beyond that jitter, confirmed with two textually-distinct true/false
  pairs so a merely reflected payload isn't mistaken for an oracle. Targets like
  this used to fall back to slow time-based extraction (or be missed entirely).

## [0.7.18]

### Changed
- The banner names **Wild Bill Hickok** (was `J.B. Hickok`), and the README
  closes in his name — leaning into the gunslinger the tool is named for.

## [0.7.17]

### Added
- **Session transcripts** — every reverse shell is logged to a file under
  `~/.local/share/hickok/sessions/`, announced when the shell lands, so the
  session survives as an engagement artifact.
- A dropped shell now **announces itself** (`session N died`) instead of going
  quiet — a lost foothold no longer passes unnoticed. A deliberate `kill` stays
  silent.
- More reverse-shell payloads: **socat** (and a fully-interactive `socat-pty`)
  and a **base64-wrapped bash** for contexts that choke on quotes or `/dev/tcp`.

### Changed
- `interact` / `upgrade` / `kill` **default to the only session** when no id is
  given — no more typing the id when there's just one shell.
- `upgrade` now spawns the PTY *and* sets its `TERM` and window size to match
  your terminal, so `clear` / `vi` / full-screen apps behave after `interact`.
- `guess_lhost` prefers a **VPN/tunnel interface** (`tun`/`tap`/`wg`/`utun`)
  when one is up — the engagement address — instead of the LAN/NAT route.
- `hickok call` lists findings **worst-severity first**, and recognises more
  code-execution titles (OS command, deserialization, file upload, struts,
  shellshock, log4, expression-language, …) as footholds.

## [0.7.16]

### Changed
- The quote-free encoding now covers the **whole** UNION path, not just the
  markers: catalog predicates baked into the queries (`type='table'`,
  `table_schema='public'`, …) are rewritten quote-free too, so `tables` /
  `columns` / `databases` over UNION also survive a single-quote-filtering WAF
  (previously only MySQL, which has no such literals, did).

### Fixed
- A dumped row whose cell value happened to contain the internal column
  separator could be shorter/longer than the header and crash the table
  printer with an index error; the printer is now length-safe.

## [0.7.15]

### Added
- `dump` now **saves the table to a CSV** and prints where (`N row(s) saved →
  …/hickok/sql/dumps/<host>_<param>_<table>.csv`) — the data outlives the session
  instead of only scrolling past. A re-dump overwrites in place; partial rows kept
  on Ctrl-C are saved too.
- `-o/--output DIR` to choose where dumps go (e.g. an engagement folder); the file
  there is a plain `<table>.csv`. Without it, dumps land in the standard data dir
  as before.

- Right under `DBMS:`, an **overview of the databases** — the current database
  always, and the full list when the catalog is reachable (the current one marked
  `*`) — so there's an immediate starting point for where to dig. New `databases`
  building block (blind and UNION) behind it.

### Changed
- Bigger, smarter name-guessing when the catalog is filtered: the common-table
  list is much longer, and with the database name known (read first) `tables`
  also tries `<db>_<name>` (shared-hosting / prefixed schemas) and common CMS/app
  prefixes (`wp_`, `phpbb_`, `tbl_`, …). Likeliest names first, de-duplicated, so
  a hit comes early.

## [0.7.14]

### Fixed
- **UNION on quote-filtering targets.** The union path built every payload with
  single-quoted literals (markers, separators, table names). A target that strips
  or filters single quotes reflected nothing back, so `hickok sql` wrongly
  concluded there was no UNION and fell back to the (here, also-filtered) blind
  walk — coming back empty. Markers and separators now go in as **quote-free
  literals** (a hex literal on MySQL, `char()`/`chr()` elsewhere); they decode to
  the same text the DBMS echoes, so reflection works through a quote filter while
  ordinary targets are unaffected.
- When UNION is in play but the catalog (`information_schema`) is blocked,
  `tables` / `columns` no longer skip the common-name fallback — so a known table
  can still be dumped (by-name probing needs no `information_schema`, quotes, or
  string functions), and the UNION reads the rows in a single request.

## [0.7.13]

### Added
- `hickok sql` now detects a **filtered / WAF response** — a page matching
  neither the calibrated TRUE nor FALSE page (a third state, e.g. a denylisted
  keyword like `information_schema`). Instead of silently reading it as a False
  bit (which made `tables` come back empty), it counts the anomaly and warns.
- **Common-name fallback** for enumeration: when the catalog
  (`information_schema`) is blocked or empty on a blind walk, `tables` /
  `columns` probe existence by name (`SELECT count(*) FROM <t>`) — no
  `information_schema` in the payload — so a filtered target can still be walked.

## [0.7.12]

### Fixed
- `hickok sql` no longer aborts a walk with `error: timed out`: the error-page
  read (the error-forcing oracle triggers 500s on purpose) is guarded, and a
  transient timeout retries once.
- A timed-out / empty response now reads as **False** instead of biasing the
  binary search to True — which used to run away into junk lengths and codes.
- Junk "runaway" values (the search hitting its ceiling) are no longer cached,
  so one flaky run can't poison later runs. `--fresh` clears a poisoned cache.

## [0.7.11]

### Changed
- A bare `hickok` now shows the banner and a short quickstart (a few example
  commands) instead of dumping the full help — `hickok -h` still has it all.

## [0.7.10]

### Changed
- The cards and captions now centre on the gunslinger's own column (measured
  from the art), so the whole spread lines up exactly under the figure.

## [0.7.9]

### Changed
- The dead man's hand captions now sit centred under the cards and the
  gunslinger, instead of left-indented.

## [0.7.8]

### Changed
- Repo/docs parity with wraith: README gains PyPI and Release badges, a table of
  contents and a Tests section; added `CONTRIBUTING.md`, `SECURITY.md` and a
  `Makefile`, and a `wraith-runs/` gitignore entry. No package code changed.

## [0.7.7]

### Changed
- Centred the banner art over the name and tagline (it was sitting too far right).

## [0.7.6]

### Changed
- Centred the banner art so the gunslinger sits in the middle, matching wraith.

## [0.7.5]

### Changed
- The banner dropped the block wordmark for the gunslinger's head — hat low,
  hard eyes — drawn in ASCII: the face of the tool, a preview of the full mascot
  that `hickok hand` reveals. The repo hero is the full mascot beside the name,
  set clean (no figlet anywhere).

## [0.7.4]

### Added
- `hickok sql` caches every value it extracts, per target. A boolean/time-blind
  walk costs many requests per value; with the cache, re-running returns anything
  pulled before **instantly (zero requests)**, and a walk interrupted with Ctrl-C
  resumes exactly where it stopped — each value is written the moment it's found
  (an append-only per-target log under `~/.local/share/hickok/sql/`). Use
  `--fresh` to ignore the cache and re-extract from scratch.

### Changed
- The wordmark is flatter — block letters without the heavy 3D drop shadow,
  matching wraith's.

## [0.7.3]

### Added
- **Showdown mode** — `hickok showdown` toggles a mode that sticks between runs.
  While on, the moment a reverse shell lands the listener plays the catch out: the
  gunslinger rises, lays down the dead man's hand, and calls it. The reward is for
  landing a shell; plain runs and a plain listener stay quiet.

- `hickok sql` now turns a live heartbeat — with the running request count —
  through every blocking step (calibration, fingerprint, UNION probe, and the
  blind walk). It ticks on its own timer, so even a slow remote keeps spinning
  instead of looking frozen between requests.

### Changed
- The dead man's hand in `hickok hand` is centred under the gunslinger.
- `hickok sql` extraction is incremental and interruptible: tables/columns print
  as they're pulled, and Ctrl-C mid-walk keeps what was gathered, prints what it
  has, and drops back to the console instead of throwing it all away.

### Fixed
- `hickok sql` no longer crashes with `chr() arg not in range` on a noisy/
  unreliable oracle (a flaky real-world target): out-of-range character codes
  are bounds-checked and become `?` instead of taking down the whole walk.
- While the spinner turns through a long walk, the terminal stops echoing
  keystrokes and drops buffered input — so typing or pasting mid-extraction can
  no longer get stuck on the spinner line or leak a stray command afterwards.

## [0.7.2]

### Added
- The gunslinger — line-art of J.B. Hickok holding the eights, drawn with a
  dark-amber → bright-gold glow. `hickok hand` now lays down the full reveal: the
  gunslinger rises, then the dead man's hand (aces, eights, and the unknown fifth
  card, face down). The same art sits beside the wordmark in the repo banner
  (`docs/hero.svg`, generated by `docs/make_hero.py`).

### Changed
- `hickok call` is the new name for acting on a wraith run (read the table, flag
  the footholds) — it was `hickok hand`. `hickok hand` is now purely the reveal.
- Banner wordmark is a lighter HICKOK (no heavy 3D block), and the cards no longer
  sit on top of every banner — they belong to the hand.
- Playing cards are taller and read like real cards (rank in the corners, suit
  pip centred).

## [0.7.1]

### Changed
- Wording: describe the SQL engine on its own terms (no comparisons to other
  tools).

## [0.7.0]

### Added
- `hickok sql` **time-based** technique — the universal fallback for a fully
  blind point (same page, no reflection, no error differential): it asks through
  a conditional sleep and times the response, then extracts exactly like the
  boolean path. Auto-selection is now union > boolean > time; force with
  `--technique time`. DBMS-aware sleeps (MySQL/PostgreSQL/MSSQL).

## [0.6.0]

### Added
- `hickok sql` now does **union-based** injection: when the page reflects query
  output it finds the column count and a reflected column, then reads whole
  values — and whole tables via `group_concat` — in *one* request instead of
  binary-searching each bit. A walk that took ~1000 blind requests is ~16.
  Technique auto-selects (union if reflected, else boolean-blind); force it with
  `--technique union|blind`.

## [0.5.0]

### Changed
- `--tor` / SOCKS is now **dependency-free** — hickok speaks SOCKS5 itself
  (stdlib), so no PySocks and no torsocks needed. It auto-detects the Tor port
  (9050 / 9150), resolves the target through Tor (no DNS leak), verifies the exit
  and fails closed. Just have Tor running. (The `hickok[tor]` extra is gone.)

## [0.4.1]

### Added
- `hickok sql --check-tor` — verify your Tor/proxy is actually anonymising you
  (and exit), to confirm the setup before a run. `--tor` already verifies
  inline; this is the standalone dry-run.

## [0.4.0]

### Added
- `hickok sql` evasion / OPSEC options: `--random-agent`, `-A/--user-agent`,
  `-H/--header`, `--cookie` (authenticated injection), `--proxy`, `--delay`,
  `--timeout`, and `-v` (prints every payload). Non-interactive one-shots
  `--banner`, `--tables`, `--dump <table>` (the `--batch` equivalent).
- `--tor` — route through Tor, done safely: **remote DNS** (`socks5h`, no leak)
  and **verified before any attack traffic, failing closed** if the exit can't be
  confirmed as Tor. SOCKS needs PySocks (`pip install hickok[tor]`); HTTP
  `--proxy` is dependency-free, and `torsocks hickok …` needs nothing.

## [0.3.1]

### Added
- `hickok sql` also calibrates an **error-forcing** oracle
  (`CASE WHEN (cond) THEN 1 ELSE 1/0 END`), so it works where a false condition
  barely changes the page — the injectable content is a small fraction of it
  (common on real apps). Verified extracting from a live MSSQL target.

## [0.3.0]

### Added
- `hickok sql` — a boolean-blind SQL injection engine. It
  calibrates a TRUE/FALSE oracle on an injectable parameter, fingerprints the
  DBMS (SQLite / MySQL / MSSQL / PostgreSQL), then reads data out by
  binary-searching each character: an interactive console with `banner`,
  `tables`, `columns <t>`, `dump <table>`, `query "<SELECT>"`, `user`, `db`.
  Target it with `-u`/`-p`, or run bare to read wraith's latest SQLi finding.

## [0.2.0]

### Changed
- `hickok hand` now finds wraith's runs by the shared standard location —
  `~/.local/share/wraith/runs/` (or wherever `WRAITH_RUNS` points), the same
  path wraith writes to — so it works from any directory, not just where the
  scan ran. Falls back to `./wraith-runs/` in the cwd.

## [0.1.3]

### Changed
- While waiting for the first reverse shell, hickok turns a spinner
  (`waiting for a shell on :9001 · 8s`) instead of leaving a blank screen — it
  clears the moment a shell connects (or press Enter to drop into the console).

## [0.1.2]

### Added
- `hickok hand` with no argument now picks up the latest run on its own — the
  most recent `findings.json` under `./wraith-runs/`. Run wraith, then just
  `hickok hand`. Pass a path to override.

## [0.1.1]

### Changed
- Banner footer is understated — `J.B. Hickok · Deadwood, 1876` instead of
  spelling out the dead man's hand. The eights on the banner already imply it.

## [0.1.0]

### Added
- Reverse-shell handler: multi-port listeners and an interactive console
  (`sessions`, `cmd`, `interact` with PTY raw-mode, `upgrade`, `kill`).
- `payloads` — reverse-shell one-liners (bash, sh-fifo, nc, python3, php, perl,
  PowerShell) for a given LHOST/LPORT, with LHOST auto-detection.
- `hickok hand findings.json` — reads a wraith run and flags the findings that
  mean code execution (a path to a shell); completes the dead man's hand.
- Themed console (ember / steel / bone / crimson), the eights, and the
  `eights` / dead-man's-hand reveals. Seeded from wraith's shell handler.
