# hickok

<p align="center">
  <img src="docs/hero.svg" alt="hickok — reverse-shell handler & post-exploitation" width="900">
</p>

A reverse-shell handler and post-exploitation console. Catch shells on multiple
listeners, run commands, upgrade to a full PTY, and generate reverse-shell
one-liners — from one dependency-free CLI.

It's the other half of a hand: [**wraith**](https://github.com/gusta-ve/wraith)
holds the aces — it does the recon and proves the way in; **hickok** brings the
eights — it acts on what wraith caught. Aces and eights, the *dead man's hand*.

[![CI](https://github.com/gusta-ve/hickok/actions/workflows/ci.yml/badge.svg)](https://github.com/gusta-ve/hickok/actions/workflows/ci.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![MIT](https://img.shields.io/badge/license-MIT-green)

## Install

```bash
pipx install hickok
```

Or from a clone: `pip install -e .` — or run it with no install at all:
`PYTHONPATH=src python3 -m hickok`.

## Usage

The listener is the default command, so a bare `hickok` starts catching shells:

```bash
hickok                                   # listen on :9001, drop into the console
hickok -l 9001,9002 --lhost 10.10.14.7   # multiple listeners, fixed LHOST
hickok payloads 10.10.14.7 9001          # print reverse-shell one-liners
hickok call                              # act on wraith's latest run (found on its own)
hickok call path/to/findings.json        # ...or a specific one
hickok sql -u 'http://host/p?id=1' -p id # walk a SQL-injectable parameter
hickok hand                              # lay down the dead man's hand (the reveal)
hickok showdown                          # toggle "showdown mode" — a landed shell plays out
```

Inside the console:

```
hickok>
  sessions          list connected shells
  payloads          reverse-shell one-liners for your LHOST
  cmd 1 id          run a command on session 1
  upgrade 1         turn a dumb shell into a PTY
  interact 1        attach (detach with Ctrl-])
  kill 1            drop a session
```

## SQL injection — `hickok sql`

Walk a database through SQL injection — find the way in and read it out. hickok
calibrates the injection, fingerprints the DBMS (SQLite / MySQL / MSSQL /
PostgreSQL) and picks the fastest technique automatically:

- **union** — when the page reflects query output, it reads whole values (and
  whole tables, via `group_concat`) in *one* request. A full walk that takes
  ~1000 blind requests is a handful here.
- **boolean-blind** — otherwise, it binary-searches each character through a
  TRUE/FALSE oracle (error-forcing when a false page barely changes).
- **time-based** — when *nothing* leaks (same page, no reflection), it asks
  through a conditional sleep and times the response. Slow, but universal.

Force one with `--technique union|blind|time` (default `auto`, fastest first).

```bash
hickok sql -u 'http://host/db?id=1' -p id   # or just `hickok sql` to read it
                                            # from wraith's latest SQLi finding
```

```
hickok(sql)>
  banner            DBMS version             user / db    current user / database
  tables            list tables              columns <t>  a table's columns
  dump <table>      dump its rows            query "<SELECT>"   extract one value
```

```
hickok(sql)> dump users
  id | username | password
  ---+----------+-----------
  1  | admin    | s3cr3t!
  2  | alice    | wonderland
```

Boolean-blind is slow by nature (each character is binary-searched over many
requests) — it turns a live heartbeat with the running count as it goes, and
**Ctrl-C keeps what it pulled** and drops back to the console.

Every value is **cached per target** as it's extracted, so you never pay for it
twice: re-run and anything pulled before comes back instantly (zero requests),
and a walk you interrupted resumes exactly where it stopped. `--fresh` ignores
the cache and re-extracts.

**Evasion / OPSEC:**

```bash
hickok sql -u '...' -p id \
  --random-agent \                 # a random real browser User-Agent
  --tor \                          # route via Tor, verified (see below)
  --cookie 'sid=…' -H 'X-Api: …' \ # authenticated injection
  --delay 0.3 -v 2 \               # throttle; print every payload
  --dump users                     # non-interactive: run one action and exit
```

`--tor` is **zero-dependency, leak-aware and fail-closed**: hickok speaks SOCKS5
itself (stdlib), auto-detects the Tor port (9050 / 9150), resolves the target
hostname **through Tor** (no DNS leak), and **verifies the exit is a Tor node
before sending any attack traffic** — if it can't confirm, it aborts rather than
deanonymising you. You only need Tor running (`sudo systemctl start tor`). Check
your setup first with `hickok sql --check-tor --tor`. `--proxy http://host:port`
and `--proxy socks5://host:port` work too.

## The bridge — `hickok call`

`hickok call` picks up wraith's latest run on its own — wraith writes to a fixed
per-user dir (`~/.local/share/wraith/runs/`, or wherever `WRAITH_RUNS` points)
that both tools agree on, so it works from any directory. It reads the table,
lists what wraith found, and flags every finding that means **code execution**
(command injection, SSTI, …) — those are the doors to a shell.

```bash
hickok call                          # wraith's latest run, wherever you are
hickok call path/to/findings.json    # ...or a specific one
```

```
  [Critical] Command Injection in 'host'   http://target/ping   ⮕ shell
  [High]     SSTI in 'name'                http://target/render ⮕ shell
  [High]     Reflected XSS in 'q'          http://target/search
```

`hickok hand` lays down the dead man's hand — the gunslinger, then the cards:

```
    ╭───────╮   ╭───────╮   ╭───────╮   ╭───────╮   ╭───────╮
    │ A     │   │ A     │   │ 8     │   │ 8     │   │╱╲╱╲╱╲╱│
    │   ♠   │   │   ♣   │   │   ♠   │   │   ♣   │   │╱╲╱╲╱╲╱│
    │     A │   │     A │   │     8 │   │     8 │   │╱╲╱╲╱╲╱│
    ╰───────╯   ╰───────╯   ╰───────╯   ╰───────╯   ╰───────╯

  aces and eights — the dead man's hand.
```

wraith deals the aces; hickok brings the eights. The hand is complete.

## Showdown mode — `hickok showdown`

`hickok showdown` toggles a mode that sticks between runs. While it's on, the
moment a reverse shell lands the listener plays the catch out: the gunslinger
rises, lays down the dead man's hand, and calls it — *the house folds.* The reward
is for actually getting in; plain runs and a plain listener stay quiet. Run
`hickok showdown` again to turn it off.

## Disclaimer

Built for authorized security testing and research — point it where you're meant
to. What anyone does with it from there is theirs alone; the author takes no
responsibility for misuse.

## License

MIT.

---

*in memory of J.B. Hickok — shot holding aces and eights, Deadwood, 1876.*
