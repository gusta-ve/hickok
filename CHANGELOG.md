# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/).

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
