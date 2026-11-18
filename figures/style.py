"""The visual system the VSLA figures share: the Advanced AI Society palette (ink, lime, warm neutrals), the type
stacks, and the three actor glyphs. Every figure imports from here; nothing is hand-edited SVG.

`actor(x, y, scale, role)` returns a <g> in a 120x120 box: an ink tile with a lime glyph for the finder (a lens), the
intake (a shield) or the maintainer (a checked page)."""

from __future__ import annotations

# ----------------------------------------------------------------------------- palette (Advanced AI Society)
LIME, LIME_MID, LIME_DEEP, LIME_TINT = "#CFFF04", "#7A9900", "#566B00", "#F2FFB8"
INK = "#0A0A0A"
INK_SOFT = "#3A3833"
MUTED = "#6F6A62"
PAPER = "#FBFAF7"
PAPER_EDGE = "#E7E3DD"
LAVENDER = "#F0EDEA"          # the panel tint (name kept from the first palette)
TEAL, TEAL_D = LIME_MID, LIME_DEEP    # the "good / checked" accent
VIOLET_1, VIOLET_2 = INK_SOFT, INK    # the second accent
AMBER = "#D9A400"
CORAL = "#C97A1E"
ROSE = "#D43F45"
LEVEL = {0: "#8F8A82", 1: LIME, 2: LIME_DEEP, 3: INK}
LEVEL_FG = {0: "#FFFFFF", 1: INK, 2: "#FFFFFF", 3: LIME}
LEVEL_SOFT = {0: "#EEEBE6", 1: LIME_TINT, 2: "#E3EDC2", 3: "#DDD9D2"}
LEVEL_DEEP = {0: "#5F5A52", 1: LIME_DEEP, 2: "#3F5000", 3: INK}   # readable text on LEVEL_SOFT
LEVEL_PALE = {0: "#F7F5F1", 1: "#FAFFE0", 2: "#F1F6DF", 3: "#EFEDE9"}  # cell tints
STATUS = {"defeated": LIME_DEEP, "mitigated": AMBER, "recorded": INK, "out of scope": "#8F8A82"}
STATUS_SOFT = {"defeated": "#E3EDC2", "mitigated": "#FBF0CC", "recorded": "#DDD9D2", "out of scope": "#EEEBE6"}
KIND = {"external": LIME_DEEP, "structural": MUTED}
SHADOW = INK
OK, BAD = LIME_DEEP, ROSE

SANS = "Inter, -apple-system, 'Helvetica Neue', Helvetica, Arial, sans-serif"
SERIF = SANS                  # headings are sans in this series (name kept so call sites read the same)
MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

_S = f'fill="none" stroke="{LIME}" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"'
GLYPHS = {
    # a lens over a line of text: the finder looks
    "finder": f'<circle cx="54" cy="54" r="19" {_S}/><path d="M68 68L84 84" {_S}/>',
    # a shield with a check: the intake verifies
    "intake": f'<path d="M60 30l24 8v20c0 16-10 26-24 32c-14-6-24-16-24-32V38z" {_S}/><path d="M49 59l8 8l15-16" {_S}/>',
    # a page with a check: the maintainer accepts
    "maintainer": (f'<rect x="38" y="30" width="44" height="60" rx="7" {_S}/><path d="M48 46h24M48 58h14" {_S} opacity="0.45"/>'
                   f'<path d="M50 74l6 6l12-13" {_S}/>'),
}


def actor(x: float = 0, y: float = 0, scale: float = 1.0, role: str = "finder") -> str:
    return (f'<g transform="translate({x} {y}) scale({scale})"><rect x="12" y="12" width="96" height="96" rx="22" fill="{INK}"/>'
            f'{GLYPHS[role]}</g>')
