# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

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
