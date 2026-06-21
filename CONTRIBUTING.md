# Contributing

Thanks for taking a look. hickok is a dependency-free reverse-shell handler and
post-exploitation console — the eights to [wraith](https://github.com/gusta-ve/wraith)'s
aces.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

It runs on the standard library alone — no third-party dependencies, including
for Tor/SOCKS.

## Ways to contribute

- **Reverse-shell payloads** — one-liners live in `src/hickok/payloads.py`.
- **SQL injection** — `src/hickok/sqli.py` holds the techniques (union / error /
  boolean / time) and the DBMS profiles; `src/hickok/sqlcache.py` owns the
  per-target folder layout (cache, log, dumps).
- **The bridge** — `src/hickok/findings.py` reads a wraith run and flags footholds.

## Ground rules

- Keep it dependency-free (standard library only).
- Run `pytest` before opening a PR — CI runs it on Python 3.10–3.12.
- Only test against systems you own or are authorized to test.
