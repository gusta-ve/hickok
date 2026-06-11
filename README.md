# hickok

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
hickok hand                              # act on wraith's latest run (found on its own)
hickok hand path/to/findings.json        # ...or a specific one
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

## The bridge — `hickok hand`

`hickok hand` picks up wraith's latest run on its own — wraith writes to a fixed
per-user dir (`~/.local/share/wraith/runs/`, or wherever `WRAITH_RUNS` points)
that both tools agree on, so it works from any directory. It reads the table,
lists what wraith found, and flags every finding that means **code execution**
(command injection, SSTI, …) — those are the doors to a shell.

```bash
hickok hand                          # wraith's latest run, wherever you are
hickok hand path/to/findings.json    # ...or a specific one
```

```
  [Critical] Command Injection in 'host'   http://target/ping   ⮕ shell
  [High]     SSTI in 'name'                http://target/render ⮕ shell
  [High]     Reflected XSS in 'q'          http://target/search

      ┌─────┐   ┌─────┐   ┌─────┐   ┌─────┐
      │ A♠  │   │ A♣  │   │ 8♠  │   │ 8♣  │
      └─────┘   └─────┘   └─────┘   └─────┘

  aces and eights — the dead man's hand.
```

wraith deals the aces; hickok brings the eights. The hand is complete.

## Disclaimer

Built for authorized security testing and research — point it where you're meant
to. What anyone does with it from there is theirs alone; the author takes no
responsibility for misuse.

## License

MIT.

---

*in memory of J.B. Hickok — shot holding aces and eights, Deadwood, 1876.*
