#!/usr/bin/env python3
"""Generate docs/hero.svg — the HICKOK wordmark beside the gunslinger line-art.

Reads the same art the CLI draws (src/hickok/art/hickok.txt), so the repo banner
and the terminal reveal never drift. Run after changing the art or wordmark:

    python3 docs/make_hero.py
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ART = (ROOT / "src/hickok/art/hickok.txt").read_text(encoding="utf-8").rstrip("\n").split("\n")

WORDMARK = [
    "██   ██ ██  ██████ ██   ██  ██████  ██   ██",
    "██   ██ ██ ██      ██  ██  ██    ██ ██  ██",
    "███████ ██ ██      █████   ██    ██ █████",
    "██   ██ ██ ██      ██  ██  ██    ██ ██  ██",
    "██   ██ ██  ██████ ██   ██  ██████  ██   ██",
]
TAGLINE = "reverse-shell handler & post-exploitation · gusta-ve"

# ---- layout -----------------------------------------------------------------
W, H = 994, 341                         # match wraith's hero proportions
RAMP = " .:-=+*#%@"

# wordmark: left column, vertically centred
WM_X, WM_FS, WM_LH = 40, 21, 26         # same weight as wraith
WM_Y0 = (H - len(WORDMARK) * WM_LH) // 2 + WM_FS

# art: right column — 41 rows squeezed into the same band as wraith's spectre
ART_FS, ART_LH = 7.0, 7.1
ART_X = 624
ART_Y0 = (H - len(ART) * ART_LH) / 2 + ART_FS


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main() -> None:
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" font-family="ui-monospace,Menlo,Consolas,monospace">',
        '<defs>'
        '<linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#ffcd5f"/><stop offset="1" stop-color="#8a3800"/>'
        '</linearGradient>'
        '<linearGradient id="a" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#ffe0a6"/><stop offset="1" stop-color="#9a6f38"/>'
        '</linearGradient>'
        '</defs>',
        f'<rect width="{W}" height="{H}" rx="12" fill="#0b0d10" stroke="#1c2128"/>',
    ]
    for i, line in enumerate(WORDMARK):
        y = WM_Y0 + i * WM_LH
        out.append(f'<text x="{WM_X}" y="{y}" font-size="{WM_FS}" font-weight="700" '
                   f'fill="url(#g)" xml:space="preserve">{esc(line)}</text>')
    for i, line in enumerate(ART):
        y = round(ART_Y0 + i * ART_LH, 1)
        out.append(f'<text x="{ART_X}" y="{y}" font-size="{ART_FS}" fill="url(#a)" '
                   f'xml:space="preserve">{esc(line)}</text>')
    out.append(f'<text x="{WM_X}" y="{H - 28}" font-size="13" fill="#8b949e" '
               f'xml:space="preserve">{esc(TAGLINE)}</text>')
    out.append('</svg>')
    dst = ROOT / "docs/hero.svg"
    dst.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"wrote {dst.relative_to(ROOT)}  ({len(ART)} art rows)")


if __name__ == "__main__":
    main()
