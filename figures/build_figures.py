"""Build every VSLA figure as SVG (and, when rsvg-convert is present, as PDF for the paper).

Run: python figures/build_figures.py
Every figure is a self-contained card with its own background, so it reads on light and dark GitHub alike. One visual
system (the Advanced AI Society palette): a paper card with a lime accent rule, sans headings and body, mono for digests
and ids, the four level colours as the semantic anchor, and three status glyphs (defeated / mitigated / recorded) that
are distinguished by shape as well as colour. Nothing here is hand-edited SVG; rsvg-convert renders it, so depth comes
from layered shapes and gradients, never from CSS filters."""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path

from style import (AMBER, BAD, CORAL, INK, INK_SOFT, KIND, LAVENDER, LEVEL, LEVEL_DEEP, LEVEL_FG, LEVEL_PALE, LEVEL_SOFT, LIME, MONO,
                   MUTED, OK, PAPER, PAPER_EDGE, ROSE, SANS, SERIF, SHADOW, STATUS, STATUS_SOFT, TEAL, TEAL_D, VIOLET_1, VIOLET_2, actor)

OUT = Path(__file__).parent
_markers: set[str] = set()

LEVEL_NAME = {0: "Unattested", 1: "Attested", 2: "Trusted", 3: "Hardened"}
LEVEL_TAG = {0: "no statement", 1: "the finder signed it", 2: "a platform re-checked it", 3: "a measured run signed it"}


# ----------------------------------------------------------------------------- primitives

def tw(s: str, size: float, family: str = SANS) -> float:
    """Rough text width for layout (Helvetica-ish metrics; mono is wider)."""
    k = 0.62 if family == MONO else 0.54
    return len(s) * size * k


def svg(w: int, h: int, body: str, *, title: str, label: str, accent: tuple[str, str] = (LIME, LIME)) -> str:
    defs = "".join(
        f'<marker id="arr{c.lstrip("#")}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M0 0L10 5L0 10z" fill="{c}"/></marker>' for c in sorted(_markers))
    defs += (f'<linearGradient id="gv" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{VIOLET_1}"/><stop offset="1" stop-color="{VIOLET_2}"/></linearGradient>'
             f'<linearGradient id="gt" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{TEAL}"/><stop offset="1" stop-color="{TEAL_D}"/></linearGradient>'
             f'<linearGradient id="gaccent" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{accent[0]}"/><stop offset="1" stop-color="{accent[1]}"/></linearGradient>'
             f'<linearGradient id="gpaper" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="{PAPER}"/></linearGradient>'
             f'<radialGradient id="gglow" cx="0.08" cy="0" r="0.9"><stop offset="0" stop-color="{LAVENDER}" stop-opacity="0.9"/><stop offset="0.45" stop-color="{LAVENDER}" stop-opacity="0"/></radialGradient>')
    for n in range(4):
        defs += (f'<linearGradient id="glvl{n}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="{LEVEL_SOFT[n]}"/></linearGradient>')
    _markers.clear()
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{esc(label)}" '
            f'font-family="{SANS}" font-size="14" fill="{INK}">'
            f'<title>{esc(title)}</title><defs>{defs}</defs>'
            f'<rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="22" fill="url(#gpaper)" stroke="{PAPER_EDGE}" stroke-width="2"/>'
            f'<rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="22" fill="url(#gglow)"/>'
            f'{body}</svg>\n')


def text(x: float, y: float, s: str, *, size: float = 14, fill: str = INK, weight: str | int = 400, anchor: str = "start",
         family: str = SANS, italic: bool = False, opacity: float = 1.0, ls: str | None = None) -> str:
    style = ' font-style="italic"' if italic else ""
    lsp = f' letter-spacing="{ls}"' if ls else ""
    op = f' opacity="{opacity}"' if opacity != 1.0 else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" font-weight="{weight}" text-anchor="{anchor}" '
            f'font-family="{family}"{style}{lsp}{op}>{esc(s)}</text>')


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def lines(x: float, y: float, s: str | list[str], *, width: int = 38, size: float = 13, lh: float | None = None, **kw) -> str:
    rows = s if isinstance(s, list) else textwrap.wrap(s, width)
    lh = lh or size * 1.38
    return "".join(text(x, y + i * lh, row, size=size, **kw) for i, row in enumerate(rows))


def rect(x: float, y: float, w: float, h: float, *, fill: str = "#fff", stroke: str = PAPER_EDGE, sw: float = 1.5, rx: float = 12,
         dash: str | None = None, opacity: float = 1.0) -> str:
    d = f' stroke-dasharray="{dash}"' if dash else ""
    op = f' opacity="{opacity}"' if opacity != 1.0 else ""
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}{op}/>'


def card(x: float, y: float, w: float, h: float, *, fill: str = "#fff", stroke: str = PAPER_EDGE, sw: float = 1.5, rx: float = 16,
         dash: str | None = None, lift: float = 4) -> str:
    """A panel with a soft layered shadow (no filters: two offset rects at low opacity)."""
    sh = (f'<rect x="{x:.1f}" y="{y + lift + 2:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{SHADOW}" opacity="0.045"/>'
          f'<rect x="{x:.1f}" y="{y + lift / 2:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{SHADOW}" opacity="0.05"/>') if lift else ""
    return sh + rect(x, y, w, h, fill=fill, stroke=stroke, sw=sw, rx=rx, dash=dash)


def line(x1: float, y1: float, x2: float, y2: float, *, color: str = PAPER_EDGE, sw: float = 1.5, dash: str | None = None, opacity: float = 1.0) -> str:
    d = f' stroke-dasharray="{dash}"' if dash else ""
    op = f' opacity="{opacity}"' if opacity != 1.0 else ""
    return f'<path d="M{x1:.1f} {y1:.1f}L{x2:.1f} {y2:.1f}" stroke="{color}" stroke-width="{sw}" stroke-linecap="round"{d}{op}/>'


def arrow(x1: float, y1: float, x2: float, y2: float, *, color: str = INK_SOFT, sw: float = 2.2, dash: str | None = None,
          curve: float = 0.0) -> str:
    _markers.add(color)
    d = f' stroke-dasharray="{dash}"' if dash else ""
    if curve:
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        nx, ny = -(y2 - y1), (x2 - x1)
        n = (nx * nx + ny * ny) ** 0.5 or 1
        cx, cy = mx + nx / n * curve, my + ny / n * curve
        path = f'M{x1:.1f} {y1:.1f}Q{cx:.1f} {cy:.1f} {x2:.1f} {y2:.1f}'
    else:
        path = f'M{x1:.1f} {y1:.1f}L{x2:.1f} {y2:.1f}'
    return f'<path d="{path}" stroke="{color}" stroke-width="{sw}" fill="none" stroke-linecap="round"{d} marker-end="url(#arr{color.lstrip("#")})"/>'


def pill(x: float, y: float, s: str, *, color: str, fg: str = "#fff", size: float = 12, pad: float = 10, stroke: str | None = None,
         weight: int = 600, family: str = SANS) -> str:
    w = tw(s, size, family) + pad * 2
    h = size + 10
    return (rect(x, y, w, h, fill=color, stroke=stroke or color, rx=h / 2, sw=1.2)
            + text(x + w / 2, y + size + 1.5, s, size=size, fill=fg, weight=weight, anchor="middle", family=family))


def pill_w(s: str, size: float = 12, pad: float = 10, family: str = SANS) -> float:
    return tw(s, size, family) + pad * 2


def level_tag(x: float, y: float, n: int, *, size: float = 12) -> str:
    return pill(x, y, f"L{n}", color=LEVEL[n], fg=LEVEL_FG[n], size=size, pad=8, weight=700)


def kind_tag(x: float, y: float, kind: str, *, size: float = 9.5) -> str:
    """external = compares against something the finder did not write; structural = self-consistency."""
    c = KIND[kind]
    lab = "EXT" if kind == "external" else "STR"
    return pill(x, y, lab, color="#fff", fg=c, size=size, pad=6, stroke=c, weight=700)


def status_glyph(x: float, y: float, status: str, *, r: float = 8.5) -> str:
    """Shape + colour per status: defeated = filled disc with a check; mitigated = half-filled disc; recorded = ring with a dot;
    out of scope = dashed ring."""
    c = STATUS[status]
    if status == "defeated":
        return (f'<circle cx="{x}" cy="{y}" r="{r}" fill="{c}"/>'
                f'<path d="M{x - 4} {y}l3 3l5.5-6" stroke="#fff" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>')
    if status == "mitigated":
        return (f'<circle cx="{x}" cy="{y}" r="{r}" fill="#fff" stroke="{c}" stroke-width="2"/>'
                f'<path d="M{x} {y - r}A{r} {r} 0 0 1 {x} {y + r}Z" fill="{c}"/>')
    if status == "recorded":
        return (f'<circle cx="{x}" cy="{y}" r="{r}" fill="#fff" stroke="{c}" stroke-width="2"/>'
                f'<circle cx="{x}" cy="{y}" r="{r * 0.42}" fill="{c}"/>')
    return f'<circle cx="{x}" cy="{y}" r="{r}" fill="none" stroke="{c}" stroke-width="2" stroke-dasharray="3 3"/>'


def ok_mark(x: float, y: float, ok: bool, *, r: float = 8) -> str:
    c = OK if ok else BAD
    if ok:
        return (f'<circle cx="{x}" cy="{y}" r="{r}" fill="{c}"/>'
                f'<path d="M{x - 3.8} {y}l2.8 2.8l5.2-5.6" stroke="#fff" stroke-width="2.1" fill="none" stroke-linecap="round" stroke-linejoin="round"/>')
    return (f'<circle cx="{x}" cy="{y}" r="{r}" fill="{c}"/>'
            f'<path d="M{x - 3.4} {y - 3.4}l6.8 6.8M{x + 3.4} {y - 3.4}l-6.8 6.8" stroke="#fff" stroke-width="2.1" stroke-linecap="round"/>')


def heading(x: float, y: float, s: str, *, size: float = 27) -> str:
    return text(x, y, s, size=size, family=SERIF, weight=600)


def sub(x: float, y: float, s: str, *, size: float = 14) -> str:
    return text(x, y, s, size=size, fill=MUTED, family=SERIF, italic=True)


def header(w: int, title: str, subtitle: str | list[str], *, x: int = 44) -> str:
    """Heading, accent rule and subtitle; returns the markup. Subtitles may wrap over two lines."""
    b = heading(x, 56, title)
    b += f'<rect x="{x}" y="66" width="64" height="3.5" rx="1.75" fill="url(#gaccent)"/>'
    rows = subtitle if isinstance(subtitle, list) else [subtitle]
    for i, r in enumerate(rows):
        b += sub(x, 92 + i * 18, r)
    return b


def eyebrow(x: float, y: float, s: str, *, color: str = MUTED, size: float = 10.5) -> str:
    return text(x, y, s.upper(), size=size, fill=color, weight=700, ls="1.6")


def footnote(w: int, h: int, s: str) -> str:
    return text(w / 2, h - 22, s, size=12.5, fill=MUTED, anchor="middle", italic=True, family=SERIF)


def legend_status(x: float, y: float) -> str:
    b = ""
    for i, (s, desc) in enumerate([("defeated", "detected; treated as L0"), ("mitigated", "costlier; still possible"),
                                   ("recorded", "succeeds; attributable after"), ("out of scope", "no lever")]):
        xx = x + [0, 250, 500, 760][i]
        b += status_glyph(xx + 8, y, s) + text(xx + 24, y + 4.5, s, size=12, weight=700, fill=STATUS[s] if s != "mitigated" else "#8A6800")
        b += text(xx + 24 + tw(s, 12) + 8, y + 4.5, desc, size=11, fill=MUTED, italic=True)
    return b


def write(name: str, content: str) -> None:
    (OUT / f"{name}.svg").write_text(content)
    if shutil.which("rsvg-convert"):
        pdf = OUT / "pdf"
        pdf.mkdir(exist_ok=True)
        subprocess.run(["rsvg-convert", "-f", "pdf", "-o", str(pdf / f"{name}.pdf"), str(OUT / f"{name}.svg")], check=True)
    print("built", name)


# ----------------------------------------------------------------------------- figures

def fig_ladder() -> None:
    W, H = 1040, 660
    b = header(W, "The VSLA ladder", "Each level is a floor: every requirement of the levels below it, plus its own. A verifier recomputes the level; it never takes the claim.")
    base_y, step = 556, 100
    reqs = {
        0: (["No statement: an email, an", "issue, a scanner dump, a", "human researcher's report.", "Trust is whoever sent it."], "buys nothing new"),
        1: (["Signed, complete account:", "subject bound to the commit,", "authorization basis, MBOM,", "Merkle-rooted transcript,", "a test executed by code that", "fails by assertion."], "reproducible, not yet real"),
        2: (["+ The platform re-ran the test", "at the subject revision with its", "own classifier and coverage check,", "signed a receipt; the finder's", "ledger verified against pinned", "countersigners, floors and age."], "somebody else reproduced it"),
        3: (["+ Weights, harness, policy and", "sandbox in an attested environment;", "the quote binds them and the", "signing key; the measurement is", "on the verifier's allowlist.", "Any api-served model caps it at L2."], "attributable to a measured run"),
    }
    for n in range(4):
        x = 44 + n * 240
        top = base_y - (n + 1) * step if n else base_y - 156
        b += card(x, top, 232, base_y - top + 44, fill=f"url(#glvl{n})", stroke=LEVEL[n], sw=2, rx=18, lift=5)
        b += f'<rect x="{x}" y="{top}" width="232" height="8" rx="4" fill="{LEVEL[n]}"/>'
        b += text(x + 18, top + 48, f"L{n}", size=32, family=SERIF, weight=700, fill=LEVEL_DEEP[n])
        b += text(x + 76, top + 48, LEVEL_NAME[n], size=21, family=SERIF, weight=600)
        b += eyebrow(x + 18, top + 72, LEVEL_TAG[n], color=LEVEL_DEEP[n], size=9.5)
        b += lines(x + 18, top + 96, reqs[n][0], size=12.2, fill=INK_SOFT, lh=16.5)
        b += text(x + 18, base_y + 24, reqs[n][1], size=11.5, fill=LEVEL_DEEP[n], italic=True, family=SERIF)
        if n < 3:
            nt = base_y - (n + 2) * step
            b += f'<circle cx="{x + 236}" cy="{nt + 30}" r="11" fill="#fff" stroke="{LEVEL[n + 1]}" stroke-width="2"/>'
            b += text(x + 236, nt + 34.5, "+", size=15, fill=LEVEL_DEEP[n + 1], weight=700, anchor="middle")
    b += footnote(W, H, "Three pillars are judged at every level and the weakest pillar sets the level; a claimed L3 with no ledger verifies at L1.")
    write("fig-ladder", svg(W, H, b, title="The VSLA ladder", label="Four VSLA levels drawn as a staircase from L0 Unattested to L3 Hardened, each step listing the requirements it adds"))


def fig_pillars() -> None:
    W, H = 1080, 700
    b = header(W, "Three pillars, three levels", "Every disclosure is asked three questions. A level is granted only when all three pillars meet it; the weakest pillar sets the level.")
    cols = [1, 2, 3]
    rows = [("Evidence", "Is the bug real, and would it be real for anyone who looked?",
             ["A test executed by code fails by assertion at the subject revision; Merkle-rooted transcript with measure and verify leaves; an MBOM naming every model. Proves reproducibility, not validity.",
              "The receiving platform re-executes in its own isolated sandbox at the subject revision, with its own classifier and a coverage check; on patches, its own review on a different model family and a source-only scope.",
              "Nothing new: the environment, not the evidence, is what L3 adds. The reproduction sandbox is bound into the quote."]),
            ("Identity", "Who says so, and what is their record?",
             ["A stable Ed25519 key per finder, an accountable operator, an authorization basis; keys have validity windows and can be revoked.",
              "Authoritative channel; a signed receipt from a pinned platform; the full ledger supplied, countersignatures verified against pinned keys, bound to this finder and track, consistent with the last root seen; score, breadth and age meet the floors.",
              "The enclave co-signature verifies under the key the verified quote binds; never a pinned key."]),
            ("Environment", "Could anyone, including the operator, have tampered with the finder?",
             ["Serving mode declared for every model (api, self-hosted, tee); weights carry a digest of the loaded bytes or say unmeasured. Trust equals declaration.",
              "Measured harness and sandbox digests in leaf 0 equal the receiver's own expectation for that version; provider weight attestations verify. External in form, copyable by a finder: it catches drift, not fraud.",
              "Weights, harness, policy and sandbox in a TEE or two-operator split; the quote binds them and the key; the (type, measurement, harness) triple is allowlisted. Any api-served model stops this pillar at L2."])]
    x0, y0 = 268, 126
    cw, rh = 262, 162
    for j, lvl in enumerate(cols):
        x = x0 + j * cw
        b += rect(x, y0, cw - 12, 36, fill=LEVEL[lvl], stroke="none", rx=10)
        b += text(x + (cw - 12) / 2, y0 + 24, f"L{lvl} · {LEVEL_NAME[lvl]}", size=15, fill=INK if lvl == 1 else "#fff", weight=700, anchor="middle")
    for i, (name, q, cells) in enumerate(rows):
        y = y0 + 48 + i * rh
        b += text(44, y + 40, name, size=19, family=SERIF, weight=600)
        b += lines(44, y + 62, q, width=24, size=11.5, fill=MUTED, italic=True, family=SERIF, lh=15)
        for j, lvl in enumerate(cols):
            x = x0 + j * cw
            b += rect(x, y, cw - 12, rh - 12, fill=LEVEL_PALE[lvl], stroke=LEVEL_SOFT[lvl], sw=1.5, rx=12)
            b += lines(x + 14, y + 22, cells[j], width=38, size=11.3, fill=INK_SOFT, lh=15)
    b += footnote(W, H, "The verified level is the minimum across the three pillars and the claim; each pillar reports the first check that failed.")
    write("fig-pillars", svg(W, H, b, title="Three pillars, three levels", label="A three-by-three matrix of VSLA pillars against levels"))


def fig_tracks() -> None:
    W, H = 1040, 500
    b = header(W, "Two tracks, one scale", "The Finding track attests that a bug is real; the Patch track that a fix is correct. A disclosure carries one of each, joined by the same subject.")
    tracks = [("Finding track", "the bug is real", TEAL,
               [(1, "a test fails by assertion at the subject revision, executed by code; MBOM; transcript with measure and verify leaves"),
                (2, "re-executed, classified and coverage-checked by the platform at the subject revision; receipt; the finder's Finding-track ledger verified against pinned countersigners"),
                (3, "reproduced inside the attested environment; the sandbox digest is bound into the quote")]),
              ("Patch track", "the fix is correct", VIOLET_2,
               [(1, "diff applies; the reproduction passes after it; the project suite passes; all executed by code in a clean checkout; files touched and scope in the statement"),
                (2, "the platform re-ran all three, reviewed the diff on a model family different from every patcher in the MBOM, and computed a source-only scope; its Patch-track ledger meets the floor"),
                (3, "patch produced and verified inside the attested environment; the reviewer model is in the MBOM and attested too")])]
    for i, (name, claim, col, items) in enumerate(tracks):
        x = 44 + i * 500
        b += card(x, 116, 476, 318, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=18)
        b += f'<rect x="{x}" y="116" width="476" height="7" rx="3.5" fill="{col}"/>'
        b += text(x + 22, 158, name, size=20, family=SERIF, weight=600)
        b += text(x + 22 + tw(name, 20, SERIF) + 12, 158, f"“{claim}”", size=13, fill=MUTED, italic=True, family=SERIF)
        for j, (lvl, t) in enumerate(items):
            y = 186 + j * 80
            b += level_tag(x + 22, y, lvl)
            b += lines(x + 70, y + 15, t, width=56, size=11.8, fill=INK_SOFT, lh=15)
    b += footnote(W, H, "Ledgers are scored per track and bound to the finder key: precision on findings buys no trust on patches, and no one else's history counts.")
    write("fig-tracks", svg(W, H, b, title="Two tracks", label="Finding and Patch tracks side by side, each with three level requirements"))


def fig_flow() -> None:
    W, H = 1120, 680
    b = header(W, "Machine-to-machine disclosure with VSLA", "The finder claims a level; the platform verifies one and signs a receipt; the maintainer's outcome is countersigned into the finder's ledger.")
    acts = [(120, "Finder agent", "finder", "qf", "scanner · hunter · researcher's agent"), (560, "Disclosure platform", "intake", "qi", "qudisclose intake + agent team"),
            (1000, "Maintainer", "maintainer", "qm", "or their operator agent")]
    for x, name, acc, p, sub_ in acts:
        b += card(x - 110, 118, 220, 196, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=18)
        b += actor(x - 54, 126, 0.9, acc)
        b += text(x, 272, name, size=17, family=SERIF, weight=600, anchor="middle")
        b += text(x, 292, sub_, size=11, fill=MUTED, anchor="middle", italic=True, family=SERIF)
    # finder -> platform
    b += arrow(232, 176, 448, 176, color=VIOLET_2, sw=3)
    b += rect(246, 128, 190, 40, fill=LEVEL_SOFT[1], stroke="none", rx=8)
    b += text(341, 145, "report + VSLA statement", size=12, weight=700, anchor="middle")
    b += text(341, 160, "claimed level · signed envelope · ledger", size=10.5, fill=MUTED, anchor="middle")
    # platform -> maintainer
    b += arrow(672, 176, 888, 176, color=TEAL, sw=3)
    b += rect(686, 128, 190, 40, fill=LEVEL_SOFT[2], stroke="none", rx=8)
    b += text(781, 145, "case + verified level", size=12, weight=700, anchor="middle")
    b += text(781, 160, "PR · advisory · statement · receipt", size=10.5, fill=MUTED, anchor="middle")
    # returns
    b += arrow(888, 232, 672, 232, color=INK_SOFT, sw=2, dash="6 5")
    b += text(781, 250, "outcome: accepted · duplicate · rejected · retracted", size=10.5, fill=INK_SOFT, anchor="middle")
    b += arrow(448, 232, 232, 232, color=INK_SOFT, sw=2, dash="6 5")
    b += text(341, 250, "DSSE receipt, then a countersigned ledger entry", size=10.5, fill=INK_SOFT, anchor="middle")
    # verification box
    vy = 346
    b += card(44, vy, 760, 250, fill=LAVENDER, stroke="none", rx=16, lift=0)
    b += text(64, vy + 32, "What the platform verifies before it believes a level", size=16, family=SERIF, weight=600)
    checks = [(1, "external", "signature, subject", "DSSE signature under a pinned finder key; subject[0] equals the report digest; revision bound"),
              (1, "structural", "transcript, reproduction", "root recomputed from the leaves; leaf 0 measures; the verify leaf agrees with the reproduction section"),
              (2, "external", "re-execution", "its own sandbox at the subject revision; its own classifier; the test imported the subject package"),
              (2, "external", "receipt, ledger", "its own platform key; full ledger, pinned countersigners, bound to finder and track, consistent"),
              (3, "external", "environment", "quote verifies under the pinned root; bindings match; measurement allowlisted; no api-served model")]
    for i, (lvl, kind, k, v) in enumerate(checks):
        y = vy + 56 + i * 36
        b += level_tag(64, y - 3, lvl, size=10.5)
        b += kind_tag(102, y - 1, kind)
        b += text(146, y + 11, k, size=12.5, weight=700)
        b += text(322, y + 11, v, size=10.8, fill=INK_SOFT)
    b += card(828, vy + 30, 248, 150, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=14)
    b += text(848, vy + 58, "claimed", size=12, fill=MUTED)
    b += level_tag(930, vy + 42, 3)
    b += arrow(960, vy + 70, 960, vy + 92, color=INK_SOFT, sw=1.8)
    b += text(848, vy + 118, "verified", size=12, fill=MUTED)
    b += level_tag(930, vy + 102, 1)
    b += text(848, vy + 142, "no ledger · no expectation → L1", size=10.5, fill=ROSE, weight=600)
    b += footnote(W, H, "Both parties keep a signed audit chain; a dispute about who knew what, when, rests on the receipt and on the log that includes it.")
    write("fig-flow", svg(W, H, b, title="Disclosure flow with VSLA", label="Finder, disclosure platform and maintainer with the statement, verification and countersignature arrows between them"))


def fig_cover() -> None:
    """The cover hero: the three parties and what passes between them, then claimed against verified. No heading, the
    title block above it is the heading; nothing here is repeated inside the paper."""
    W, H = 1120, 430
    b = ""
    acts = [(170, "Finder agent", "finder", "cf", "scanner · hunter · researcher's agent"), (560, "Disclosure platform", "intake", "ci", "intake · re-execution · receipt"),
            (950, "Maintainer", "maintainer", "cm", "or their operator agent")]
    for x, name, acc, p, sub_ in acts:
        b += card(x - 110, 24, 220, 190, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=18)
        b += actor(x - 54, 30, 0.9, acc)
        b += text(x, 174, name, size=17, family=SERIF, weight=600, anchor="middle")
        b += text(x, 194, sub_, size=11, fill=MUTED, anchor="middle", italic=True, family=SERIF)
    # forward: statement, then case
    b += arrow(284, 94, 446, 94, color=VIOLET_2, sw=3)
    b += rect(284, 44, 162, 40, fill=LEVEL_SOFT[1], stroke="none", rx=8)
    b += text(365, 61, "signed statement", size=12, weight=700, anchor="middle")
    b += text(365, 76, "level · transcript · ledger", size=10.4, fill=MUTED, anchor="middle")
    b += arrow(674, 94, 836, 94, color=TEAL, sw=3)
    b += rect(674, 44, 162, 40, fill=LEVEL_SOFT[2], stroke="none", rx=8)
    b += text(755, 61, "case + verified level", size=12, weight=700, anchor="middle")
    b += text(755, 76, "PR · advisory · receipt", size=10.4, fill=MUTED, anchor="middle")
    # back: outcome, then countersigned entry
    b += arrow(836, 140, 674, 140, color=INK_SOFT, sw=2, dash="6 5")
    b += text(755, 158, "outcome, countersigned", size=11.5, fill=INK_SOFT, anchor="middle")
    b += arrow(446, 140, 284, 140, color=INK_SOFT, sw=2, dash="6 5")
    b += text(365, 158, "receipt, then a ledger entry", size=11.5, fill=INK_SOFT, anchor="middle")
    # claimed vs verified strip
    sy = 250
    b += card(44, sy, W - 88, 138, fill=LAVENDER, stroke="none", rx=16, lift=0)
    b += eyebrow(64, sy + 28, "what the platform does with a claim", color=INK_SOFT)
    b += text(64, sy + 62, "claimed", size=12, fill=MUTED)
    b += level_tag(124, sy + 46, 3)
    b += arrow(172, sy + 56, 214, sy + 56, color=INK_SOFT, sw=1.8)
    px = 226
    for i, (name, kind, what) in enumerate([("Evidence", "external", "its own re-execution; transcript root recomputed"),
                                            ("Identity", "external", "pinned keys; ledger inclusion, not position"),
                                            ("Environment", "external", "quote under a pinned root; no api-served model")]):
        x = px + i * 236
        b += rect(x, sy + 40, 222, 60, fill="#fff", stroke=PAPER_EDGE, sw=1.2, rx=10)
        b += text(x + 12, sy + 60, name, size=12.5, weight=700)
        b += kind_tag(x + 12 + tw(name, 12.5) + 8, sy + 49, kind)
        b += lines(x + 12, sy + 76, what, width=38, size=10.4, fill=INK_SOFT, lh=12)
    b += arrow(px + 3 * 236 - 8, sy + 56, px + 3 * 236 + 30, sy + 56, color=INK_SOFT, sw=1.8)
    b += text(px + 3 * 236 + 40, sy + 62, "verified", size=12, fill=MUTED)
    b += level_tag(px + 3 * 236 + 100, sy + 46, 1)
    b += text(64, sy + 122, "The weakest pillar sets the level. A level is recomputed by whoever verifies, from pinned keys and its own re-execution; nothing self-reported counts.",
              size=12.5, fill=INK_SOFT, italic=True, family=SERIF)
    write("fig-cover", svg(W, H, b, title="VSLA on one page", label="Finder, disclosure platform and maintainer with the statement, receipt and ledger entry between them, and a claimed L3 that verifies as L1"))


def fig_attestation() -> None:
    W, H = 1100, 800
    b = header(W, "Anatomy of a VSLA statement", "An in-toto Statement v1 in a DSSE envelope over RFC 8785 canonical JSON. Digests go in; bodies stay out.")
    x0, y0, w = 44, 118, 640
    b += card(x0, y0, w, 640, fill="#fff", stroke=INK_SOFT, sw=1.6, rx=18)
    b += text(x0 + 20, y0 + 28, "_type: https://in-toto.io/Statement/v1", size=12, family=MONO, fill=MUTED)
    b += text(x0 + 20, y0 + 46, "predicateType: https://vsla.dev/provenance/v1", size=12, family=MONO, fill=MUTED)
    b += rect(x0 + 16, y0 + 60, w - 32, 68, fill=LAVENDER, stroke="none", rx=12)
    b += text(x0 + 30, y0 + 84, "subject", size=14, weight=700)
    b += text(x0 + 30, y0 + 104, "finding sha256:4c1f…  ·  git+…/example/vulnpkg @ 9b2e7c1d  ·  (patch: diff sha256:…)", size=11.5, family=MONO, fill=INK_SOFT)
    b += text(x0 + 30, y0 + 120, "the report that describes the bug, bound to the exact commit it is about; a Patch statement adds the diff", size=11, fill=MUTED, italic=True, family=SERIF)
    rows = [
        (1, "finder · authorization", "identity ed25519:7a9c…  ·  operator quome.com  ·  harness qudisclose 0.2.0 sha256:c41d…  ·  basis: program (SECURITY.md)"),
        (1, "mbom", "hunter qwen3.8:27b q8 self-hosted, weights sha256:9f3a… + provider attestation (DSSE)  ·  reproducer claude-opus-5-5 api (unmeasurable)"),
        (1, "transcript", "rfc6962-sha256 root 3e0b…  ·  7 leaves  ·  leaf 0 = measure(harness, sandbox)  ·  verify leaf = the test run  ·  bodies sealed (HPKE)"),
        (1, "reproduction", "test sha256:…  ·  command or commandDigest (embargoed)  ·  exit 1  ·  securityFailure per the classifier  ·  revision 9b2e…  ·  sandbox vm 5e1a…"),
        (2, "channel", "intake https://cvd.example.org/mcp  ·  intakeKey ed25519:…  ·  declaredIn SECURITY.md  (the platform's answer is the separate receipt)"),
        (2, "history", "ledger URL  ·  root 91d4…  ·  a summary only: the countersigned entries are what a verifier checks, never these numbers"),
        (3, "environment", "sev-snp | tdx | nitro | two-operator | signed-quote  ·  measurement on the allowlist  ·  quote binds enclaveKey ‖ harness ‖ weights ‖ sandbox"),
    ]
    y = y0 + 142
    for lvl, name, val in rows:
        b += rect(x0 + 16, y, w - 32, 62, fill=LEVEL_PALE[lvl], stroke=LEVEL_SOFT[lvl], sw=1.2, rx=10)
        b += level_tag(x0 + 26, y + 10, lvl)
        b += text(x0 + 70, y + 24, name, size=13.5, weight=700)
        b += lines(x0 + 70, y + 41, val, width=86, size=10.2, family=MONO, fill=INK_SOFT, lh=12.5)
        y += 68
    # profiles strip
    b += rect(x0 + 16, y + 2, w - 32, 46, fill="#fff", stroke=PAPER_EDGE, sw=1.2, rx=10, dash="4 3")
    b += text(x0 + 30, y + 21, "profile", size=12.5, weight=700)
    b += text(x0 + 92, y + 21, "published: test path, command and files touched in plaintext", size=10.8, fill=INK_SOFT)
    b += text(x0 + 92, y + 37, "embargoed: those fields are digests, so the statement can be published while the case is open", size=10.8, fill=INK_SOFT)
    # signatures
    rx = x0 + w + 36
    b += text(rx, y0 + 22, "Who signs what", size=17, family=SERIF, weight=600)
    sigs = [(1, "finder key", "signatures[0] on the envelope: Ed25519 over PAE(payloadType, payload). Pinned out of band; proves the statement was not altered after the finder made it."),
            (2, "platform receipt", "a separate DSSE object with its own payload type: {statement digest, channel, receivedAt, re-execution result, review, scope, anchor}. The finder's bytes are never touched; the platform signs what it saw when it ran the test itself."),
            (3, "enclave co-signature", "a second envelope signature under environment.enclaveKey. The verifier takes that key from the verified quote and nowhere else; if the quote fails, this signature counts for nothing.")]
    y = y0 + 40
    for lvl, name, desc in sigs:
        b += card(rx, y, 360, 150, fill="#fff", stroke=LEVEL[lvl], sw=2, rx=14)
        b += level_tag(rx + 14, y + 14, lvl)
        b += text(rx + 56, y + 30, name, size=14, weight=700)
        b += lines(rx + 14, y + 56, desc, width=50, size=11.6, fill=INK_SOFT, lh=15.5)
        y += 166
    b += lines(rx, y + 30, ["Every signed object (statement, receipt,", "ledger entry, weight attestation) is a DSSE", "envelope with its own payload type, so no", "signature can be replayed as another kind."], size=12, fill=MUTED, italic=True, family=SERIF, lh=16)
    write("fig-attestation", svg(W, H, b, title="Anatomy of a VSLA statement", label="A VSLA provenance statement with its subject, predicate sections tagged by level, the profile strip, and three signature bands"))


def fig_merkle() -> None:
    W, H = 1040, 700
    b = header(W, "A Merkle-rooted transcript", ["Every model turn and tool call is a leaf; leaf 0 measures the harness and a verify leaf records the test run.",
                                                 "One signed root makes the run tamper-evident after commitment; a dropped or edited leaf changes the root."])
    leaves = [("measure", "harness ‖ sandbox"), ("turn", "hunter"), ("tool", "read files.py"), ("tool", "write test"), ("tool", "run pytest"),
              ("turn", "reproducer"), ("verify", "exit 1 · assert"), ("turn", "patcher")]
    n = len(leaves)
    lx = [100 + i * 118 for i in range(n)]
    ly = 560
    tampered = 4

    def node(x: float, y: float, label: str, *, bad: bool = False, root: bool = False) -> str:
        col = ROSE if bad else (VIOLET_2 if root else TEAL)
        r = 21 if root else 15
        return (f'<circle cx="{x}" cy="{y + 2}" r="{r}" fill="{SHADOW}" opacity="0.08"/>'
                f'<circle cx="{x}" cy="{y}" r="{r}" fill="{col}" stroke="#fff" stroke-width="2.5"/>'
                + text(x, y + 4.5, label, size=11 if root else 10, fill="#fff", weight=700, anchor="middle", family=MONO))
    b_edges, b_nodes = "", ""
    xs, y, cur_bad, layer = lx, ly - 54, {tampered}, 1
    while len(xs) > 1:
        nxs = [(xs[i] + xs[i + 1]) / 2 for i in range(0, len(xs), 2)]
        ny = y - 90
        nbad: set[int] = set()
        for i in range(0, len(xs), 2):
            j = i // 2
            for k in (i, i + 1):
                bad = k in cur_bad
                if bad:
                    nbad.add(j)
                b_edges += f'<path d="M{xs[k]} {y}L{nxs[j]} {ny}" stroke="{ROSE if bad else "#D5D0C8"}" stroke-width="{3 if bad else 2}" fill="none"/>'
        for i, x in enumerate(xs):
            b_nodes += node(x, y, f"h{layer - 1}{i}" if layer > 1 else f"h{i}", bad=i in cur_bad)
        xs, y, cur_bad, layer = nxs, ny, nbad, layer + 1
    b_nodes += node(xs[0], y, "root", bad=bool(cur_bad), root=True)
    b += b_edges + b_nodes
    for i, (kind, lab) in enumerate(leaves):
        bad = i == tampered
        special = kind in ("measure", "verify")
        fill = "#FFE3E4" if bad else (LEVEL_SOFT[2] if special else LAVENDER)
        stroke = ROSE if bad else (TEAL if special else "none")
        b += rect(lx[i] - 52, ly - 10, 104, 58, fill=fill, stroke=stroke, sw=2, rx=10)
        b += text(lx[i], ly + 12, kind, size=11, fill=TEAL_D if special else MUTED, anchor="middle", family=MONO, weight=700 if special else 400)
        b += text(lx[i], ly + 31, lab, size=11.5, fill=INK, weight=600, anchor="middle")
        b += text(lx[i], ly + 64, f"leaf {i}", size=10, fill=MUTED, anchor="middle", family=MONO)
    b += text(lx[tampered], ly + 84, "edited after signing", size=11.5, fill=ROSE, weight=700, anchor="middle")
    b += text(lx[0], ly + 84, "must be leaf 0", size=11, fill=TEAL_D, weight=700, anchor="middle")
    b += text(lx[6], ly + 84, "must agree with reproduction", size=11, fill=TEAL_D, weight=700, anchor="middle")
    rx = xs[0] + 60
    b += arrow(xs[0] + 24, y, rx + 20, y, color=VIOLET_2)
    b += card(rx + 24, y - 34, 340, 84, fill="#fff", stroke=VIOLET_2, sw=2, rx=12)
    b += text(rx + 40, y - 11, "transcript.root is a field of the signed statement", size=11.5, family=MONO)
    b += text(rx + 40, y + 8, "signed once; anyone with the leaves recomputes it", size=11, fill=MUTED, italic=True, family=SERIF)
    b += text(rx + 40, y + 32, "root mismatch → E5 fails → statement rejected", size=11.5, fill=ROSE, weight=700)
    b += lines(44, 136, ["Leaves carry digests of each prompt, response and tool call, in order; bodies can be released later or sealed to one party",
                         "and checked against the root. Omission before signing is invisible to any root: completeness needs a recorder inside a measured harness (L3)."],
               size=12, fill=INK_SOFT, lh=16)
    write("fig-merkle", svg(W, H, b, title="Merkle-rooted transcript", label="A binary Merkle tree over eight transcript leaves, with the measure and verify leaves highlighted and one tampered leaf whose path to the root is red"))


def fig_threats() -> None:
    W = 1100
    groups = [
        ("The attacker is the finder or its operator", [
            ("T1", "Hallucinated finding", "a fluent report of a bug that does not exist", {1: "mitigated", 2: "mitigated"}),
            ("T2", "Edited transcript", "a turn changed after the root was signed", {1: "defeated"}),
            ("T2", "Omitted turns", "the finder commits three turns, not fifteen", {3: "mitigated"}),
            ("T3", "Forged or replayed statement", "an old finding resent, or sent under another name", {1: "defeated"}),
            ("T4", "Undisclosed model substitution", "the MBOM says a frontier model; a small one did the work", {1: "recorded", 3: "mitigated"}),
            ("T5", "Flooding", "a loud, low-precision finder; a new identity per flood", {1: "mitigated", 2: "recorded"}),
            ("T6", "Non-authoritative release", "a fix published outside the declared channel", {2: "recorded"}),
            ("T7", "Forged receipt time", "disclosed earlier than it did; one platform's clock", {2: "mitigated"}),
            ("T8", "Operator forges provenance", "a statement for a run that never happened", {3: "mitigated"}),
            ("T9", "Tampered or backdoored weights", "a fine-tune that plants or hides bugs", {3: "recorded"}),
            ("T12", "Over-claimed level", "L3 asserted with no quote", {1: "defeated"}),
            ("T16", "Trust laundering", "earn L2 for months, spend it on one harmful patch", {2: "mitigated"}),
            ("T20", "Sybil countersigners", "one operator, two keys, two platforms", {2: "mitigated"}),
            ("T21", "Duplicate farming", "replay public cases to collect duplicate outcomes", {2: "defeated"}),
            ("T24", "Hunter that never discloses", "the same stack against code it does not own", {}),
            ("T25", "Finder key compromise", "a stolen key inherits the score", {1: "mitigated", 3: "mitigated"}),
        ]),
        ("The attacker is the codebase or the environment", [
            ("T10", "Prompt injection steers the finder", "repo content or a PoC instructs the agent", {1: "mitigated"}),
            ("T11", "Malicious reproduction targets the platform", "the re-executed test reaches the key or other cases", {2: "mitigated"}),
            ("T17", "Re-execution resource exhaustion", "a flood of fresh identities, each costing a sandbox run", {1: "mitigated"}),
        ]),
        ("The attacker is the platform or the model provider", [
            ("T13", "Platform over-grants", "records L2 without re-executing", {2: "recorded"}),
            ("T14", "Platform leaks the embargoed finding", "logs, prompts or drafts reach a third party", {}),
            ("T15", "Provider's asymmetric knowledge", "its tooling finds a zero-day; it leaks first", {2: "recorded"}),
            ("T18", "Platform key compromise", "every receipt and countersignature it issued is forgeable", {2: "mitigated"}),
            ("T19", "Embargo inference from metadata", "paths, timing and ledger entries reveal what is being fixed", {2: "mitigated"}),
            ("T22", "Platform poisons or inflates a ledger", "false-positive for an enemy, accepted for a friend", {2: "recorded"}),
            ("T23", "Provider steers the pipeline", "one model triages, patches and reviews", {2: "mitigated"}),
        ]),
    ]
    rh, gh = 34, 44
    n_rows = sum(len(g[1]) for g in groups)
    H = 150 + n_rows * rh + len(groups) * gh + 70
    b = header(W, "Where each threat stops", ["Modelled on the SLSA threat table, with three words used precisely. The glyph at a level says what that level does;",
                                               "a second glyph to the right says what a higher level adds. Twenty-five threats; T2 is split into edits and omissions."])
    colx = {1: 760, 2: 850, 3: 940}
    y = 150
    for title, rows in groups:
        b += eyebrow(44, y + 14, title, color=INK_SOFT, size=10.5)
        b += line(44, y + 24, W - 44, y + 24, color=PAPER_EDGE, sw=1.2)
        y += gh
        for tid, name, desc, st in rows:
            b += rect(44, y - 2, W - 88, rh - 4, fill=("#fff" if (y // rh) % 2 else "#fcfbf7"), stroke="none", rx=8)
            b += text(56, y + 18, tid, size=10.5, family=MONO, fill=MUTED)
            b += text(100, y + 14, name, size=12.5, weight=700)
            b += text(100, y + 27, desc, size=10.2, fill=MUTED, italic=True, family=SERIF)
            lowest = min(st) if st else None
            for lvl, x in colx.items():
                if lowest is not None and lvl >= lowest:
                    b += f'<rect x="{x - 34}" y="{y + 2}" width="68" height="{rh - 10}" rx="8" fill="{LEVEL_SOFT[lvl]}"/>'
                if lvl in st:
                    b += status_glyph(x, y + 14, st[lvl])
                elif lowest is not None and lvl > lowest:
                    b += f'<circle cx="{x}" cy="{y + 14}" r="3" fill="{LEVEL[lvl]}" opacity="0.6"/>'
                else:
                    b += f'<circle cx="{x}" cy="{y + 14}" r="3.5" fill="none" stroke="#D5D0C8" stroke-width="1.5"/>'
            primary = st[lowest] if lowest is not None else "out of scope"
            c = STATUS[primary]
            b += rect(992, y + 3, 72, 22, fill=STATUS_SOFT[primary], stroke="none", rx=11)
            b += text(1028, y + 18, primary if primary != "out of scope" else "no lever", size=10.5, fill=(LEVEL_DEEP[1] if primary == "mitigated" else c), weight=700, anchor="middle")
            y += rh
    for lvl, x in colx.items():
        b += text(x, 142, f"L{lvl}", size=14, family=SERIF, weight=700, fill=LEVEL_DEEP[lvl], anchor="middle")
    b += text(1028, 142, "at lowest", size=11, family=SERIF, weight=600, fill=MUTED, anchor="middle")
    b += legend_status(60, H - 30)
    write("fig-threats", svg(W, H, b, title="Where each threat stops", label="Twenty-six threat rows grouped by attacker, each with the lowest VSLA level that acts on it and a glyph for defeated, mitigated, recorded or out of scope"))


def fig_tee() -> None:
    W, H = 1100, 786
    b = header(W, "Level 3: attribution to a measured run", ["Two environments satisfy the pillar. They are different trust statements, and the verifier records which one it accepted.",
                                                             "Neither proves the harness is honest, the inputs were honest, or the weights behave; the allowlist is where that judgement lives."])
    ax, ay = 44, 128
    b += card(ax, ay, 500, 426, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=18)
    b += text(ax + 20, ay + 32, "A · Hardware TEE", size=17, family=SERIF, weight=600)
    b += pill(ax + 20, ay + 44, "trust statement: not the operator", color=LEVEL_SOFT[3], fg=LEVEL_DEEP[3], size=10.5, pad=8)
    ay += 26
    b += rect(ax + 24, ay + 54, 330, 232, fill=LEVEL_PALE[3], stroke=VIOLET_2, sw=2, rx=14, dash="7 5")
    b += eyebrow(ax + 40, ay + 76, "inside the measured guest", color=VIOLET_2, size=9.5)
    for i, (k, v) in enumerate([("weights", "sha256 of the loaded bytes · provider-attested"), ("harness", "qudisclose 0.2.0 · c41d…"), ("policy", "disclosure policy · 77ab…"),
                                ("sandbox", "reproduction VM image · 5e1a…"), ("signing key", "generated inside; never exported")]):
        y = ay + 90 + i * 38
        b += rect(ax + 40, y, 298, 30, fill="#fff", stroke="none", rx=8)
        b += text(ax + 52, y + 20, k, size=12.5, weight=700)
        b += text(ax + 142, y + 20, v, size=10.2, family=MONO, fill=INK_SOFT)
    b += arrow(ax + 356, ay + 170, ax + 400, ay + 170, color=VIOLET_2, sw=2.5)
    b += rect(ax + 402, ay + 136, 80, 68, fill="url(#gv)", stroke="none", rx=12)
    b += text(ax + 442, ay + 164, "quote", size=13, fill="#fff", weight=700, anchor="middle")
    b += text(ax + 442, ay + 182, "vendor root", size=10, fill="#fff", anchor="middle", opacity=0.9)
    b += lines(ax + 24, ay + 312, ["measurement = launch digest of the guest image. The weights are not in it; the bindings",
                                   "travel in REPORT_DATA = SHA-256(enclaveKey ‖ harness ‖ weights ‖ sandbox) through a measured",
                                   "integrity root. The verifier allowlists (type, measurement, harness) and derives the enclave key",
                                   "from the verified quote; it never pins it."], size=11, fill=MUTED, italic=True, family=SERIF, lh=15)
    ay -= 26
    bx, by = 580, 128
    b += card(bx, by, 476, 426, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=18)
    b += text(bx + 20, by + 32, "B · Two operators", size=17, family=SERIF, weight=600)
    b += pill(bx + 20, by + 44, "trust statement: neither of two operators alone", color=LEVEL_SOFT[3], fg=LEVEL_DEEP[3], size=10.5, pad=8)
    for i, (name, who) in enumerate([("host 1", "cloud operator"), ("host 2", "the maintainer's machine")]):
        hx = bx + 24 + i * 230
        b += rect(hx, by + 80, 210, 150, fill=LEVEL_PALE[3], stroke=VIOLET_1, sw=2, rx=14)
        b += text(hx + 14, by + 102, name, size=13, weight=700)
        b += text(hx + 14, by + 118, who, size=11, fill=MUTED, italic=True, family=SERIF)
        for j, row in enumerate([f"share{i + 1}: weights ⊕ noise", "Merkle log · signed root", "2-of-2 co-signature"]):
            b += rect(hx + 14, by + 128 + j * 32, 182, 26, fill="#fff", stroke="none", rx=7)
            b += text(hx + 22, by + 146 + j * 32, row, size=11, family=MONO)
    b += arrow(bx + 234, by + 148, bx + 254, by + 148, color=INK_SOFT, sw=2)
    b += arrow(bx + 254, by + 168, bx + 234, by + 168, color=INK_SOFT, sw=2)
    b += text(bx + 238, by + 254, "both hosts sign the same manifest; the verifier requires two distinct pinned co-signers", size=11, fill=INK_SOFT, anchor="middle")
    b += lines(bx + 24, by + 282, ["No chip vendor in the trust base. The statement needs both parties; one host's tampering is",
                                   "named to a sequence number. This replaces “the operator cannot reach in” with “neither of",
                                   "two operators can reach in alone”, which is a weaker claim than it sounds when both",
                                   "hosts see the same plaintext."], size=11, fill=MUTED, italic=True, family=SERIF, lh=15)
    # bottom: api cap + chain
    cy = 584
    b += rect(44, cy, 1012, 48, fill="#FFE3E4", stroke="none", rx=12)
    b += text(64, cy + 22, "An api-served model cannot be measured by anyone but its provider.", size=12.5, weight=700, fill=ROSE)
    b += text(64, cy + 39, "Any serving: api model in the MBOM stops the Environment pillar at L2, including the patch agents this paper's own deployment runs.", size=11, fill=INK_SOFT)
    cy = 660
    chain = [("model provider", "signs {model, weights digest} as DSSE", TEAL), ("environment", "hashes the same bytes at load; binds them", VIOLET_2),
             ("statement", "carries quote + provider attestation", INK_SOFT), ("verifier", "chain closes under pinned keys, or no L3", TEAL_D)]
    for i, (k, v, c) in enumerate(chain):
        x = 44 + i * 262
        b += card(x, cy, 232, 64, fill="#fff", stroke=c, sw=2, rx=12, lift=3)
        b += text(x + 14, cy + 26, k, size=13, weight=700, fill=c)
        b += text(x + 14, cy + 46, v, size=10.8, fill=INK_SOFT)
        if i < 3:
            b += arrow(x + 236, cy + 32, x + 258, cy + 32, color=c, sw=2)
    b += footnote(W, H, "The reference verifier ships only the signed-quote adapter, a fixture that proves a pinned root key signed the bindings; hardware adapters are not claimed.")
    write("fig-tee", svg(W, H, b, title="Level 3 environments", label="Two Level 3 environment options, a hardware enclave and a two-host split, the api-served cap, and the weight attestation chain"))


def fig_history() -> None:
    W, H = 1040, 536
    b = header(W, "The trust ledger", "Countersigned DSSE entries are the leaves of a Merkle log; only entries under keys the reader has pinned count, and neutral outcomes are excluded.")
    y = 236
    b += line(80, y, 700, y, color="#D5D0C8", sw=3)
    # seq, outcome, signer, pinned, claimed>verified
    entries = [("a", "P", True, False), ("a", "M1", True, False), ("d", "P", True, False), ("a", "M2", True, False), ("a", "P", True, False), ("r", "M1", True, True),
               ("a", "P", True, False), ("a", "M2", True, False), ("a", "P", True, False), ("d", "M1", True, False), ("a", "P", True, False), ("a", "X", False, False), ("a", "M2", True, False)]
    col = {"a": TEAL, "d": "#C9C4BB", "r": ROSE}
    for i, (o, who, pinned, over) in enumerate(entries):
        x = 100 + i * 48
        if o == "d":
            b += f'<circle cx="{x}" cy="{y}" r="11" fill="#fff" stroke="{col[o]}" stroke-width="2.5" stroke-dasharray="3 2"/>'
        elif not pinned:
            b += f'<circle cx="{x}" cy="{y}" r="11" fill="#fff" stroke="{col[o]}" stroke-width="2.5"/>'
            b += f'<path d="M{x - 5} {y - 5}l10 10M{x + 5} {y - 5}l-10 10" stroke="{MUTED}" stroke-width="2" stroke-linecap="round"/>'
        else:
            b += f'<circle cx="{x}" cy="{y + 2}" r="11" fill="{SHADOW}" opacity="0.08"/><circle cx="{x}" cy="{y}" r="11" fill="{col[o]}" stroke="#fff" stroke-width="2.5"/>'
        sc = TEAL_D if pinned else MUTED
        b += f'<rect x="{x - 11}" y="{y - 36}" width="22" height="15" rx="4" fill="{"#fff" if pinned else "#eceef3"}" stroke="{sc}" stroke-width="1.2"/>'
        b += text(x, y - 25, who, size=8.5, fill=sc, anchor="middle", family=MONO, weight=700)
        b += text(x, y + 30, f"{i}", size=10, fill=MUTED, anchor="middle", family=MONO)
        if over:
            b += text(x, y + 44, "claimed>", size=8.5, fill=ROSE, anchor="middle", family=MONO)
            b += text(x, y + 54, "verified", size=8.5, fill=ROSE, anchor="middle", family=MONO)
    b += text(100, y - 52, "2026-06", size=11, fill=MUTED, family=MONO)
    b += text(100 + 12 * 48, y - 52, "2026-10", size=11, fill=MUTED, family=MONO, anchor="end")
    b += text(400, y - 52, "window: the last 50 by countersigned time", size=11, fill=MUTED, family=MONO, anchor="middle")
    ly = y + 82
    leg = [(TEAL, "accepted (counted)", "disc"), (ROSE, "rejected (counted; decays over 30 days)", "disc"), ("#C9C4BB", "duplicate / withdrawn (neutral: excluded)", "dash"), (MUTED, "unpinned countersigner (dropped)", "x")]
    for i, (c, lab, kind) in enumerate(leg):
        xx, yy = 80 + (i % 2) * 320, ly + (i // 2) * 24
        if kind == "disc":
            b += f'<circle cx="{xx + 7}" cy="{yy}" r="7" fill="{c}"/>'
        elif kind == "dash":
            b += f'<circle cx="{xx + 7}" cy="{yy}" r="7" fill="#fff" stroke="{c}" stroke-width="2" stroke-dasharray="3 2"/>'
        else:
            b += f'<circle cx="{xx + 7}" cy="{yy}" r="7" fill="#fff" stroke="{c}" stroke-width="2"/><path d="M{xx + 4} {yy - 3}l6 6M{xx + 10} {yy - 3}l-6 6" stroke="{c}" stroke-width="1.6"/>'
        b += text(xx + 20, yy + 4, lab, size=11.5, fill=INK_SOFT)
    b += text(80, ly + 60, "P = platform:cvd.example.org   M1, M2 = pinned maintainers   X = a key this reader did not pin", size=10.5, fill=MUTED, family=MONO)
    b += lines(80, ly + 82, ["Each entry is a DSSE envelope {kind, at, finder key, statement digest, platform, track, outcome, claimed, verified, reason?} whose",
                             "leaf bytes are the envelope itself, so the root commits to the countersignature. The finder's operator owns the order; no entry",
                             "carries an index. An outcome counts only if its finder is this key (or a predecessor named by a successor entry) and its track",
                             "is this statement's track. successor and revoke entries are lifecycle entries, not outcomes: they rotate a key or end it."],
               size=11.2, fill=MUTED, italic=True, family=SERIF, lh=15)
    # score card
    sx, sy = 740, 128
    b += card(sx, sy, 256, 358, fill=LAVENDER, stroke="none", rx=16, lift=0)
    b += eyebrow(sx + 18, sy + 26, "trust score · rubric v1.1", color=MUTED)
    b += text(sx + 18, sy + 74, "0.865", size=44, family=SERIF, weight=700, fill=TEAL_D)
    b += rect(sx + 18, sy + 90, 220, 10, fill="#fff", stroke="none", rx=5)
    b += rect(sx + 18, sy + 90, 220 * 0.865, 10, fill="url(#gt)", stroke="none", rx=5)
    b += line(sx + 18 + 220 * 0.6, sy + 84, sx + 18 + 220 * 0.6, sy + 106, color=ROSE, sw=2)
    b += text(sx + 18 + 220 * 0.6, sy + 120, "L2 floor 0.60", size=10.5, fill=ROSE, anchor="middle", weight=600)
    for i, (k, v) in enumerate([("P precision", "10 / 11"), ("B breadth", "3 pinned → 1.0"), ("S seasoning", "138 d, n=11 → 1.0"), ("C calibration", "1 over-claim → 0.82"), ("R recency", "1 rejection, 83 d → 0.97")]):
        b += text(sx + 18, sy + 150 + i * 20, k, size=11.5, fill=MUTED)
        b += text(sx + 238, sy + 150 + i * 20, v, size=11, weight=600, anchor="end", family=MONO)
    b += line(sx + 18, sy + 258, sx + 238, sy + 258, color="#D5D0C8", sw=1)
    b += eyebrow(sx + 18, sy + 280, "floors (hard gates)", color=MUTED, size=9.5)
    for i, (k, v) in enumerate([("score", "≥ 0.60"), ("counted entries", "≥ 5"), ("pinned countersigners", "≥ 2"), ("age of oldest", "≥ 30 d")]):
        b += text(sx + 18, sy + 300 + i * 16, k, size=10.8, fill=INK_SOFT)
        b += text(sx + 238, sy + 300 + i * 16, v, size=10.5, weight=700, anchor="end", family=MONO, fill=TEAL_D)
    write("fig-history", svg(W, H, b, title="Trust ledger", label="A timeline of thirteen countersigned ledger entries with pinned and unpinned countersigners, neutral entries excluded, and a score card reading 0.865 above the L2 floor"))


def fig_pilot() -> None:
    W, H = 1040, 560
    b = header(W, "Pilots: one hypothesis, paired metrics, three arms", "Does a verified Patch L2 statement get a machine patch accepted more often, and no less safely, than an identical unattested one?")
    arms = [("unattested", "the partner's existing stream of machine patches", LEVEL[0], LEVEL_SOFT[0]),
            ("attested", "the same pipeline, Patch L2 statement attached", TEAL, LEVEL_SOFT[2]),
            ("withheld", "the same pipeline, statement produced but not shown", VIOLET_2, LEVEL_SOFT[3])]
    for i, (name, desc, c, soft) in enumerate(arms):
        x = 44 + i * 324
        b += card(x, 122, 300, 86, fill=soft, stroke="none", rx=14, lift=0)
        b += eyebrow(x + 16, 146, f"arm {i + 1} · {name}", color=c if c != LEVEL[0] else LEVEL_DEEP[0])
        b += lines(x + 16, 170, desc, width=40, size=12, fill=INK_SOFT, lh=15)
    b += text(44, 240, "arm 3 separates the badge from the pipeline behind it", size=11.5, fill=MUTED, italic=True, family=SERIF)
    # metrics
    my = 262
    b += card(44, my, 480, 150, fill="#fff", stroke=TEAL, sw=2, rx=14)
    b += eyebrow(64, my + 26, "what we hope improves", color=TEAL_D)
    for i, m in enumerate(["acceptance rate vs. the partner's baseline", "time-to-merge", "maintainer minutes per case, per level"]):
        b += ok_mark(72, my + 54 + i * 26, True, r=6) + text(90, my + 58 + i * 26, m, size=12.5, fill=INK_SOFT)
    b += card(556, my, 440, 150, fill="#fff", stroke=ROSE, sw=2, rx=14)
    b += eyebrow(576, my + 26, "what must not get worse", color=ROSE)
    for i, m in enumerate(["post-merge revert and regression rate", "defects found in attested patches by later review", "false acceptance on a seeded adversarial set"]):
        b += f'<rect x="{578}" y="{my + 48 + i * 26}" width="12" height="12" rx="3" fill="{ROSE}"/>' + text(600, my + 58 + i * 26, m, size=12.5, fill=INK_SOFT)
    b += f'<circle cx="540" cy="{my + 75}" r="13" fill="#fff" stroke="{PAPER_EDGE}" stroke-width="1.5"/>' + text(540, my + 80, "&", size=14, fill=INK_SOFT, anchor="middle", weight=700, family=SERIF)
    # settings
    sy = 436
    b += rect(44, sy, 480, 84, fill=LAVENDER, stroke="none", rx=12)
    b += text(60, sy + 24, "Partner-hosted", size=14, family=SERIF, weight=600)
    b += lines(60, sy + 44, "an established project pins the intake as its authoritative channel and receives attested patches on already-triaged bugs", width=66, size=11, fill=INK_SOFT, lh=14)
    b += rect(556, sy, 440, 84, fill=LAVENDER, stroke="none", rx=12)
    b += text(572, sy + 24, "Staging (private fork)", size=14, family=SERIF, weight=600)
    b += lines(572, sy + 44, "the hunter runs on self-hosted weights against a private fork; each upstream is notified at discovery through its declared channel; no public hardened fork", width=60, size=11, fill=INK_SOFT, lh=14)
    b += footnote(W, H, "Guardrails: authorised targets only, the authorization basis in every statement, the whole pipeline on self-hosted weights, results published in aggregate.")
    write("fig-pilot", svg(W, H, b, title="Pilot design", label="Three pilot arms, paired improvement and safety metrics, and two settings with their guardrails"))


CHECKS = {
    "evidence": [("E1", 1, "structural", "envelope, types, schema; payload is canonical", "itself"),
                 ("E2", 1, "external", "finder signature over PAE", "pinned finder key"),
                 ("E3", 1, "external", "subject[0] = report digest; revision bound; times ordered, finishedAt ≤ now", "the report"),
                 ("E4", 1, "structural", "MBOM complete; weights digest or unmeasured", "itself"),
                 ("E5", 1, "structural", "root over the leaves; leaf 0 measures; verify leaf agrees", "itself (finder wrote both)"),
                 ("E6", 1, "structural", "executor code; exit 1; classifier flag; patch flags", "itself"),
                 ("E7", 2, "external", "re-executed at the subject revision, matched, own classifier, touched subject", "receiver's execution / verified receipt"),
                 ("E8", 2, "external", "patch: receiver's review, distinct family, source-only scope", "receiver's execution / verified receipt")],
    "identity": [("I1", 1, "external", "finder key valid at t_eval, not revoked; operator; basis", "pinned key, window, revoke entries"),
                 ("I2", 2, "external", "channel.intake is this platform; intakeKey is its pinned key", "pinned platform key"),
                 ("I3", 2, "external", "receipt under the platform: key intakeKey names; digest; channel; time chain; anchor form per policy", "pinned platform + log keys"),
                 ("I4", 2, "external", "ledger supplied; canonical; root; prefix extends what was shown; own entries included; finder chain + track; floors at t_eval", "pinned countersigners + last root"),
                 ("I5", 3, "external", "enclave co-signature under the quote-bound key", "the verified quote")],
    "environment": [("N1", 1, "structural", "every model declares a serving mode", "itself"),
                    ("N2", 2, "external", "measured harness = expectation; sandbox digest; attestations", "expectation (copyable)"),
                    ("N3", 3, "external", "quote ok; bindings exact; allowlisted; no api", "pinned root + allowlist")],
}


def fig_checks() -> None:
    W, H = 1100, 940
    b = header(W, "The verification matrix", ["Every check is external (compares against something the finder did not write) or structural (compares the statement with itself).",
                                              "Only external checks separate the levels; structural checks reject malformed statements."])
    x0, y0 = 44, 136
    colw = {1: 284, 2: 376, 3: 258}
    xs = {1: x0 + 138, 2: x0 + 138 + 284, 3: x0 + 138 + 660}
    for lvl in (1, 2, 3):
        b += rect(xs[lvl], y0, colw[lvl] - 10, 34, fill=LEVEL[lvl], stroke="none", rx=10)
        b += text(xs[lvl] + (colw[lvl] - 10) / 2, y0 + 23, f"L{lvl} · {LEVEL_NAME[lvl]}", size=14, fill=INK if lvl == 1 else "#fff", weight=700, anchor="middle")
    y = y0 + 48
    for pillar, checks in CHECKS.items():
        by_lvl = {1: [c for c in checks if c[1] == 1], 2: [c for c in checks if c[1] == 2], 3: [c for c in checks if c[1] == 3]}
        rows = max(len(v) for v in by_lvl.values())
        rh = 62
        h = rows * rh + 14
        b += text(x0, y + 28, pillar.capitalize(), size=16.5, family=SERIF, weight=600)
        for lvl in (1, 2, 3):
            b += rect(xs[lvl], y, colw[lvl] - 10, h, fill=LEVEL_PALE[lvl], stroke=LEVEL_SOFT[lvl], sw=1.2, rx=12)
            for i, (cid, _, kind, what, against) in enumerate(by_lvl[lvl]):
                yy = y + 10 + i * rh
                b += text(xs[lvl] + 12, yy + 17, cid, size=12.5, family=MONO, weight=700, fill=KIND[kind])
                b += kind_tag(xs[lvl] + 42, yy + 5, kind)
                b += lines(xs[lvl] + 86, yy + 15, what, width=int((colw[lvl] - 104) / 5.7), size=10.2, fill=INK_SOFT, lh=11.5)
                b += text(xs[lvl] + 12, yy + 54, f"vs {against}", size=9.5, fill=KIND[kind], italic=True, family=SERIF)
        y += h + 14
    b += kind_tag(x0, H - 52, "external") + text(x0 + 44, H - 42, "external: a pinned key, an expectation the receiver obtained independently, or the receiver's own execution", size=11.5, fill=INK_SOFT)
    b += kind_tag(x0, H - 30, "structural") + text(x0 + 44, H - 20, "structural: self-consistency; a finder that writes both sides can always satisfy it", size=11.5, fill=INK_SOFT)
    write("fig-checks", svg(W, H, b, title="The verification matrix", label="Sixteen verification checks laid out by pillar and level, each tagged external or structural with what it compares against"))


def fig_receipt() -> None:
    W, H = 1040, 760
    b = header(W, "The platform receipt", "A separate DSSE object with its own payload type, signed by the platform key, issued once per case. The finder's envelope is never modified.")
    x0, y0, w = 44, 124, 560
    b += card(x0, y0, w, 562, fill="#fff", stroke=TEAL, sw=2, rx=18)
    b += text(x0 + 20, y0 + 28, "payloadType: application/vnd.vsla.receipt+json", size=12, family=MONO, fill=MUTED)
    b += text(x0 + 20, y0 + 46, "signatures[0].keyid: platform:cvd.example.org", size=12, family=MONO, fill=MUTED)
    fields = [("statementDigest", "sha256 of the finder's payload bytes: this receipt is about exactly that statement", TEAL),
              ("channel · receivedAt", "the intake URL the statement named, and the platform's clock: startedAt ≤ finishedAt ≤ receivedAt ≤ integratedTime ≤ now", TEAL),
              ("reexecution.status", "matched · mismatched · environment-error · timeout · not-attempted (admission control deferred it)", VIOLET_2),
              ("reexecution.revision", "the subject commit the platform checked out; a revision it cannot resolve is environment-error", VIOLET_2),
              ("reexecution.classifier", "securityFailure by the platform's own rule (assertion in a collected test, no collection / import / timeout error)", VIOLET_2),
              ("reexecution.touchedSubject", "the re-executed test imported or covered the subject package the platform's own config names", VIOLET_2),
              ("reexecution.sandbox", "backend, isolation class (vm · container · process) and image digest; a production intake says vm", VIOLET_2),
              ("patch: review · scope", "the platform's own review: approved, reviewerFamily, distinctFamily; scope computed from the diff (source-only · mixed)", VIOLET_2),
              ("anchor · log-inclusion", "a signed checkpoint {log, treeSize, rootHash, integratedTime} and an RFC 6962 inclusion proof for this receipt body: append-only, auditable; what require_anchor accepts", AMBER),
              ("anchor · signed-timestamp", "a pinned log key's signature over the receipt digest and a time: proves the receipt existed by then on that key's word, nothing about append-only-ness; accepted only if the policy opts in", AMBER)]
    y = y0 + 64
    for k, v, c in fields:
        b += f'<rect x="{x0 + 16}" y="{y}" width="4" height="34" rx="2" fill="{c}"/>'
        b += text(x0 + 30, y + 13, k, size=11.5, family=MONO, weight=700)
        b += lines(x0 + 30, y + 27, v, width=92, size=9.8, fill=INK_SOFT, lh=11.5)
        y += 47
    rx = x0 + w + 36
    b += text(rx, y0 + 22, "Why a separate object", size=17, family=SERIF, weight=600)
    notes = [(TEAL, "The finder's payload is signed once and never touched; a third signature on the envelope would mean re-serialising it."),
             (VIOLET_2, "E7 and E8 read the re-execution block only after I3 has verified the receipt under the pinned platform key named in channel.intakeKey, and not at all when the policy requires an anchor and none verifies."),
             (AMBER, "One evaluation instant, t_eval: the anchor's integratedTime, else receivedAt, else the verifier's clock. Every key window, every revoke entry and the rubric's decay are evaluated there, so the result does not depend on when it is verified."),
             (INK_SOFT, "A negative receipt (mismatched, not-attempted) is what a finder disputes; silence is not an outcome. A verifier elsewhere needs only the statement, the receipt and its pinned keys.")]
    y = y0 + 40
    for c, t in notes:
        b += f'<circle cx="{rx + 6}" cy="{y + 6}" r="5" fill="{c}"/>'
        b += lines(rx + 22, y + 10, t, width=44, size=11.6, fill=INK_SOFT, lh=15.5)
        y += 118
    b += footnote(W, H, "A timestamp bounds receivedAt from above on one key's word; only log inclusion is append-only and lets another platform find the receipt.")
    write("fig-receipt", svg(W, H, b, title="The platform receipt", label="Anatomy of the VSLA receipt as a separate DSSE object, listing its fields, next to four notes on why it is separate"))


def fig_consistency() -> None:
    W, H = 1040, 790
    b = header(W, "Ledger consistency", ["The finder's operator owns the ledger and its order. A platform stores the root and count of what it was shown and checks two things next time:",
                                         "the prefix still has that root, and every entry the platform itself wrote is included somewhere. Position is the finder's business."])

    def chain(x: float, y: float, outcomes: list[tuple[str, str]], *, label: str, bad: set[int] | None = None, mark: set[int] | None = None) -> str:
        s = text(x, y - 18, label, size=11.5, fill=MUTED, family=SERIF, italic=True)
        bad = bad or set(); mark = mark or set()
        for i, (o, who) in enumerate(outcomes):
            xx = x + i * 56
            c = {"a": TEAL, "r": ROSE, "f": ROSE, "n": "#C9C4BB"}[o]
            is_bad = i in bad
            s += rect(xx, y, 46, 34, fill=("#FFE3E4" if is_bad else ("#eefaf8" if i in mark else "#fff")), stroke=(ROSE if is_bad else c), sw=2, rx=8)
            s += text(xx + 23, y + 15, f"#{i}", size=9.5, fill=MUTED, anchor="middle", family=MONO)
            s += text(xx + 23, y + 28, who, size=9.5, fill=c, anchor="middle", family=MONO, weight=700)
            if i < len(outcomes) - 1:
                s += line(xx + 46, y + 17, xx + 56, y + 17, color="#C9C4BB", sw=2)
        return s

    base = [("a", "M1"), ("a", "P2"), ("a", "M1"), ("a", "P2"), ("a", "M1")]
    px, py = 44, 150
    b += card(px, py, 470, 196, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=16)
    b += eyebrow(px + 18, py + 26, "1 · first submission", color=TEAL_D)
    b += chain(px + 18, py + 60, base, label="presented ledger (5 entries, all pinned)")
    b += text(px + 18, py + 126, "platform stores  last_seen = (root₅, 5)  over what it was shown", size=11.5, family=MONO, fill=INK_SOFT)
    b += text(px + 18, py + 148, "case closes: platform countersigns  P = rejected  (reason signed)", size=11.5, family=MONO, fill=INK_SOFT)
    b += text(px + 18, py + 170, "and expects: prefix₅ = root₅, and P included somewhere", size=11.5, family=MONO, fill=TEAL_D, weight=700)
    px2 = 536
    b += card(px2, py, 460, 196, fill="#fff", stroke=TEAL, sw=2, rx=16)
    b += eyebrow(px2 + 18, py + 26, "2a · honest next submission", color=TEAL_D)
    b += chain(px2 + 18, py + 60, base + [("r", "P"), ("a", "M2")], label="presented ledger: the finder appended P, then a maintainer's entry", mark={5})
    b += ok_mark(px2 + 26, py + 134, True) + text(px2 + 44, py + 138, "prefix of 5 is still root₅; P is included → I4 continues to the rubric", size=11.5, fill=INK_SOFT)
    b += text(px2 + 44, py + 158, "the platform's own rejection counts against the score, as it should", size=11, fill=MUTED, italic=True, family=SERIF)
    py2 = 370
    b += card(px, py2, 952, 190, fill="#fff", stroke=TEAL, sw=2, rx=16)
    b += eyebrow(px + 18, py2 + 26, "2b · two platforms, or two cases in flight: honest concurrency", color=TEAL_D)
    b += chain(px + 18, py2 + 60, base + [("a", "A"), ("a", "B")], label="A and B each closed a case on the same 5-entry ledger; the finder appends both as they arrive", mark={5, 6})
    b += chain(px + 18 + 480, py2 + 60, base + [("a", "B"), ("a", "A")], label="… or in the other order", mark={5, 6})
    b += ok_mark(px + 26, py2 + 134, True) + text(px + 44, py2 + 138, "at A: prefix₅ = root₅ and A's entry is included; at B: prefix₅ = root₅ and B's entry is included. Neither platform assigned an index, so nothing collides.", size=11.3, fill=INK_SOFT)
    b += text(px + 44, py2 + 158, "the rubric window is the last 50 entries by countersigned time, so the order the finder chose cannot move the score", size=11, fill=MUTED, italic=True, family=SERIF)
    py3 = 584
    b += card(px, py3, 470, 150, fill="#fff", stroke=ROSE, sw=2, rx=16)
    b += eyebrow(px + 18, py3 + 26, "2c · the platform's entry omitted", color=ROSE)
    b += chain(px + 18, py3 + 60, base + [("a", "M2")], label="presented ledger: 6 entries, P is not among them", bad={5})
    b += ok_mark(px + 26, py3 + 128, False) + text(px + 44, py3 + 132, "prefix intact, but P is absent → ledger-fork, disqualifying", size=11.5, fill=ROSE, weight=600)
    b += card(px2, py3, 460, 150, fill="#fff", stroke=ROSE, sw=2, rx=16)
    b += eyebrow(px2 + 18, py3 + 26, "2d · prefix rewritten or trimmed", color=ROSE)
    b += chain(px2 + 18, py3 + 60, [base[1], base[0], base[2], base[3]], label="the first five are no longer the five that were shown", bad={0, 1, 2, 3})
    b += ok_mark(px2 + 26, py3 + 128, False) + text(px2 + 44, py3 + 132, "prefix root ≠ root₅ → ledger-fork, disqualifying", size=11.5, fill=ROSE, weight=600)
    b += footnote(W, H, "A split view between platforms that never compare notes is still invisible here; a shared log is the remedy. The window is by countersigned time, never by presented order.")
    write("fig-consistency", svg(W, H, b, title="Ledger consistency", label="Five panels: a first submission, an honest extension including the platform's entry, honest two-platform concurrency in either order, an omission and a rewritten prefix, the last two marked ledger-fork"))


def fig_evidence() -> None:
    W, H = 1040, 600
    b = header(W, "What the Evidence pillar checks on the Finding track", "L1 is the finder's own account, executed by code. L2 is someone else's execution. Neither is a proof that the bug is real.")
    # L1 column
    for i, (lvl, title, items) in enumerate([
            (1, "the finder's account", [("code executed it", "a test runner produced the exit code; a model's claim that it ran does not count"),
                                         ("fails by assertion", "classifier: at least one collected test failed by assertion; no collection, import, fixture or timeout error"),
                                         ("at the subject revision", "reproduction.revision equals subject[1]; the verify leaf in the transcript agrees"),
                                         ("bound and signed", "test digest, command (or its digest), output digest, start and end; finder signature under a pinned key")]),
            (2, "the receiver's execution", [("re-executed", "the platform checks out the subject commit in its own isolated sandbox and runs the same command"),
                                            ("its own classifier", "the platform's rule over the runner's structured result; the finder's flag is never copied"),
                                            ("touched the subject", "the test imported or covered the package the platform's own repo config names, not a string the finder wrote"),
                                            ("signed into a receipt", "status, revision, classifier result, coverage, isolation class; a third party verifies the receipt before trusting any of it")])]):
        x = 44 + i * 500
        b += card(x, 128, 476, 300, fill=f"url(#glvl{lvl})", stroke=LEVEL[lvl], sw=2, rx=18)
        b += level_tag(x + 20, 146, lvl, size=13)
        b += text(x + 70, 163, title, size=17, family=SERIF, weight=600)
        for j, (k, v) in enumerate(items):
            y = 192 + j * 58
            b += ok_mark(x + 30, y + 4, True, r=7)
            b += text(x + 48, y + 8, k, size=12.5, weight=700)
            b += lines(x + 48, y + 24, v, width=66, size=10.5, fill=INK_SOFT, lh=13)
    b += arrow(522, 278, 542, 278, color=INK_SOFT, sw=2)
    # does not prove strip
    sy = 452
    b += rect(44, sy, 952, 92, fill="#FFE3E4", stroke="none", rx=14)
    b += eyebrow(64, sy + 24, "what it does not prove", color=ROSE)
    b += lines(64, sy + 46, ["A finder can write a test that fails on demand, and `import subject; assert False` clears both the classifier and the coverage check. The classifier",
                             "filters honest non-security failures; it is not sound against a hostile test, which can forge the runner's own report. The semantic judgement",
                             "(is this exploitable, is it the bug the report describes) is the receiver's, and a level is an input to triage ordering, never to review depth."],
               size=11, fill=INK_SOFT, lh=14.5)
    b += footnote(W, H, "Differential reproduction (fails at the subject revision, passes at a reference) is the check that would speak to validity; v1.0 specifies it as optional.")
    write("fig-evidence", svg(W, H, b, title="Evidence at L1 and L2", label="Two columns comparing the finder's own executed test at L1 with the receiver's re-execution at L2, over a strip listing what neither proves"))


def fig_attacks() -> None:
    W = 1100
    rows = [
        ("round 1", "self-reported ledger summary granted Identity L2", "I4 fails without the entries; a summary is not evidence", "V-3"),
        ("round 1", "countersignatures never verified; garbage signatures scored 0.88", "every entry verified under a pinned platform: or maintainer: key; others dropped", "V-5"),
        ("round 1", "weight digest compared with the finder's own copy of an attestation", "attestation is a provider-signed DSSE object under a pinned provider key", "F-17"),
        ("round 1", "enclave key pinned in the keyring", "the enclave key comes from the verified quote and nowhere else", "F-16"),
        ("round 1", "two colluding keys reached the floor on day zero", "pinned countersigner allowlist; age gate of 30 days", "V-5"),
        ("round 1", "duplicates counted as positives; withdrawing penalised", "neutral outcomes are excluded from the window", "rubric"),
        ("round 1", "three canonicalisations, three ledger signing bodies", "RFC 8785 everywhere; one DSSE payload type per object; one leaf definition", "F-1"),
        ("round 2", "a receipt signed by the finder's own pinned key reached L2", "I3 needs the platform: key named by intakeKey; E7 reads a receipt only after I3", "I3"),
        ("round 2", "another finder's published ledger counted as one's own", "entries whose finder field is not this key are dropped", "I4"),
        ("round 2", "a Finding-track ledger granted Patch L2", "entries are counted per track", "I4"),
        ("round 2", "entry order chosen by the finder swung the score 0.37 ↔ 0.93", "the window is the last 50 by countersigned time; order cannot move the score", "I4"),
        ("round 2", "the platform's own appended entry was not enforced next time", "the platform's own entry must be included; omission is a ledger-fork", "P-14"),
        ("round 2", "two-operator accepted one root listed twice as 2-of-2", "co-signers must be distinct pinned roots", "N3"),
        ("round 2", "duplicate JSON keys in a signed payload; ints beyond 2⁵³", "payload must equal its own canonical form; duplicate keys rejected", "E1"),
        ("round 2", "“anchored in a log” claimed, never checked", "require_anchor for third parties; the anchor verifies under a pinned log key", "P-16"),
        ("round 3", "seq assigned by the platform forked honest finders (two cases, two platforms)", "the finder owns the index; the platform checks inclusion, not position", "P-14"),
        ("round 3", "key windows evaluated at times the checked party wrote; anchor time unused", "one evaluation instant t_eval: anchor time, else receipt time, else now", "V-7"),
        ("round 3", "successor and revoke cited as mitigations, implemented nowhere", "successor chains history to the new key; an operator revoke fails I1 at t_eval", "F-20"),
        ("round 3", "a pinned-key timestamp read as “anchored in a transparency log”", "two named forms; require_anchor accepts inclusion, timestamps by opt-in", "P-16"),
        ("round 3", "qudisclose keyed the ledger by reporter name; the spec by key and track", "mirror, last_seen and own entries keyed by (finder key, track)", "P-14"),
        ("round 3", "a deferred (not-attempted) submission was recorded as an over-claim", "claimed and verified are written only when the platform re-executed", "P-6"),
        ("round 3", "I4 passed or failed depending on the verifier's wall clock", "the rubric is evaluated at t_eval; the verdict is a function of the inputs", "V-7"),
        ("round 3", "audit trail, postmortem and advisory readable on embargoed cases", "every read surface gated by the reporter-or-admin rule", "P-13"),
        ("round 3", "one free duplicate entry made a fresh identity “known” to admission", "only non-neutral verified entries count toward admission", "P-12"),
        ("round 3", "a junk signature beside a valid one vetoed it; a 100 000-deep payload crashed verify()", "any verifying signature under the keyid counts; payload size and depth are capped", "E1"),
    ]
    rh = 36
    H = 150 + len(rows) * rh + 60
    b = header(W, "Attacks the reviews demonstrated, and what closes them", "Every row was a probe that made a verifier, the rubric or the platform do something it should not have. Each is now a failing test.")
    y = 140
    b += text(60, y, "found", size=10.5, fill=MUTED, weight=700, ls="1.2")
    b += text(140, y, "ATTACK", size=10.5, fill=MUTED, weight=700, ls="1.2")
    b += text(600, y, "CLOSED BY", size=10.5, fill=MUTED, weight=700, ls="1.2")
    b += text(1030, y, "WHERE", size=10.5, fill=MUTED, weight=700, ls="1.2", anchor="end")
    y += 12
    for i, (rnd, attack, fix, where) in enumerate(rows):
        b += rect(44, y, W - 88, rh - 4, fill=("#fff" if i % 2 else "#fcfbf7"), stroke="none", rx=8)
        soft = {"round 1": STATUS_SOFT["mitigated"], "round 2": STATUS_SOFT["recorded"], "round 3": STATUS_SOFT["defeated"]}[rnd]
        deep = {"round 1": LEVEL_DEEP[1], "round 2": LEVEL_DEEP[3], "round 3": LEVEL_DEEP[2]}[rnd]
        b += rect(56, y + 8, 70, 16, fill=soft, stroke="none", rx=8)
        b += text(91, y + 19.5, rnd, size=9.5, fill=deep, weight=700, anchor="middle")
        b += text(140, y + 20, attack, size=11.3, fill=INK)
        b += ok_mark(588, y + 16, True, r=6)
        b += text(602, y + 20, fix, size=11, fill=INK_SOFT)
        b += text(1030, y + 20, where, size=10.5, fill=MUTED, family=MONO, anchor="end")
        y += rh
    b += footnote(W, H, "Rounds 1 and 2 found checks that compared against what the finder controls; round 3 found design questions the spec had not decided: who owns the index, which clock governs.")
    write("fig-attacks", svg(W, H, b, title="Attacks and their fixes", label="Twenty-five rows of demonstrated attacks on the verifier, rubric and platform across three review rounds, each paired with the rule that now closes it"))


def fig_qudisclose() -> None:
    W, H = 1100, 860
    b = header(W, "qudisclose: one deployment, two roles", ["A finder for every case it verifies (amber hooks) and a platform for every statement a reporter submits (teal hooks),",
                                                            "on one intake, one case pipeline, two sandbox backends and two keys."])
    F, FS, FD = LEVEL[1], LEVEL_SOFT[1], LEVEL_DEEP[1]
    P, PS, PD = LEVEL[2], LEVEL_SOFT[2], LEVEL_DEEP[2]
    # ---- left: the intake
    ix, iy, iw, ih = 44, 136, 236, 430
    b += card(ix, iy, iw, ih, fill="#fff", stroke=PAPER_EDGE, sw=1.5, rx=16)
    b += eyebrow(ix + 16, iy + 26, "MCP intake", color=INK_SOFT)
    b += text(ix + 16, iy + 50, "GuardMiddleware, per tool call", size=12, family=SERIF, italic=True, fill=MUTED)
    items = [("bearer token", "EdDSA JWT; one required scope per tool"), ("signed envelope", "per-message Ed25519 envelope with nonce and expiry; replay rejected"),
             ("rate limit", "per identity, before any tool runs"), ("strict inputs", "pydantic models; attestation bundle size-capped"),
             ("audit log", "hash-chained, signed; inputs and outputs of every call"), ("embargo gate", "every read surface shows an open case only to its reporter or an admin")]
    y = iy + 74
    for k, v in items:
        b += f'<rect x="{ix + 16}" y="{y}" width="4" height="40" rx="2" fill="{INK_SOFT}"/>'
        b += text(ix + 28, y + 12, k, size=11.5, weight=700)
        b += lines(ix + 28, y + 26, v, width=34, size=9.8, fill=INK_SOFT, lh=11)
        y += 58
    # ---- centre: the timeline
    ty = 380
    xs = [336 + i * 101 for i in range(8)]
    stages = [("intake", "dedup · scan · ack"), ("triage ‖ reproducer", "speculative, parallel"), ("own re-run", "normative classifier"), ("patcher", "edits in sandbox"),
              ("clean verify", "apply · repro · suite"), ("reviewer", "distinct model family"), ("release", "PR · advisory"), ("postmortem", "every case")]
    b += line(xs[0], ty, xs[-1], ty, color="#C9C4BB", sw=3)
    for i, (x, (name, sub_)) in enumerate(zip(xs, stages)):
        b += f'<circle cx="{x}" cy="{ty}" r="11" fill="#fff" stroke="{INK_SOFT}" stroke-width="2.2"/>'
        b += text(x, ty + 4, str(i + 1), size=10, fill=INK_SOFT, weight=700, anchor="middle", family=MONO)
        b += text(x, ty + 30, name, size=10.8, weight=700, anchor="middle")
        b += text(x, ty + 43, sub_, size=9.2, fill=MUTED, anchor="middle", italic=True, family=SERIF)
    b += text(xs[0] - 6, ty - 22, "one case", size=11, fill=MUTED, family=SERIF, italic=True)

    def hook(x: float, y: float, w: float, h: float, title: str, body: str, *, role: str, to: list[float], above: bool, width: int = 30) -> str:
        c, cs, cd = (F, FS, FD) if role == "finder" else (P, PS, PD)
        g = card(x, y, w, h, fill=cs, stroke=c, sw=1.6, rx=12)
        g += text(x + 12, y + 18, title, size=10.6, weight=700, fill=cd)
        g += lines(x + 12, y + 32, body, width=width, size=9.4, fill=INK_SOFT, lh=10.8)
        for tx in to:
            y1, y2 = (y + h, ty - 14) if above else (y, ty + 52)
            g += line(tx, y1, tx, y2, color=c, sw=1.6, dash="4 3")
        return g

    fy = 150
    b += hook(xs[0] - 42, fy + 70, 150, 88, "leaf 0: measurement", "harness digest (hashed at load) and sandbox digest, before any model turn lands on the transcript", role="finder", to=[xs[0]], above=True, width=28)
    b += hook(xs[1] - 10, fy, 480, 54, "a transcript leaf per model turn and tool call", "the recording provider wraps every model call with the case id; sandbox tool calls are leaves too; bodies never enter a leaf, only digests", role="finder", to=[xs[1]], above=True, width=92)
    b += hook(xs[2] - 40, fy + 70, 108, 96, "verify leaf", "own re-run: command, exit, class, output digest; E5 checks it against the reproduction", role="finder", to=[xs[2]], above=True, width=19)
    b += hook(xs[2] + 76, fy + 70, 204, 96, "Finding statement", "after the re-run fails by assertion: embargoed + published profiles, MBOM with family and serving mode, signed by the attestation key", role="finder", to=[xs[2] + 88], above=True, width=40)
    b += hook(xs[5] - 10, fy + 70, 204, 96, "Patch statement", "after review: diff digest, files touched (or digest), computed scope, attempts; the finder's own review is informational", role="finder", to=[xs[6]], above=True, width=40)
    py = 470
    pw, pg = 142, 10
    px = [xs[0] - 24 + i * (pw + pg) for i in range(5)]
    b += hook(px[0], py, pw, 112, "intake: verify", "everything but re-execution: signature, schema, subject, leaves, ledger; claimed and preliminary level recorded", role="platform", to=[xs[0]], above=False, width=27)
    b += hook(px[1], py, pw, 112, "admission", "no non-neutral countersigned outcome under a pinned key → unknown: slow lane, not-attempted receipt, no sandbox", role="platform", to=[xs[1]], above=False, width=27)
    b += hook(px[2], py, pw, 112, "re-execute", "sandbox at the subject revision; own classifier; coverage vs the repo-config package; Patch: apply · repro · suite · scope · review", role="platform", to=[xs[2], xs[4]], above=False, width=27)
    b += hook(px[3], py, pw, 112, "receipt + record", "DSSE receipt under the platform key, issued once; verification record with every check and its kind, on the case and in the audit chain", role="platform", to=[xs[5]], above=False, width=27)
    b += hook(px[4], py, pw, 112, "close: ledger", "countersigned entry per track, no index; claimed/verified only if re-executed; state per (finder key, track): root shown + own entries to be included", role="platform", to=[xs[7]], above=False, width=27)
    by = 622
    b += card(44, by, 520, 170, fill=LAVENDER, stroke="none", rx=14, lift=0)
    b += eyebrow(60, by + 26, "sandbox backends (VSLA-P-11)", color=MUTED)
    b += text(60, by + 52, "local · process", size=12.5, weight=700)
    b += pill(200, by + 40, "development", color="#fff", fg=MUTED, size=9.5, pad=7, stroke=PAPER_EDGE)
    b += lines(60, by + 70, "git worktree per case; scrubbed env; rlimits (CPU, memory, files, processes); wall clock; egress cut by unshare -n on Linux, sandbox-exec (deny network*) on macOS; host filesystem still readable", width=70, size=9.8, fill=INK_SOFT, lh=11.5)
    b += text(60, by + 128, "quome · vm", size=12.5, weight=700)
    b += pill(168, by + 116, "production", color=TEAL, fg="#fff", size=9.5, pad=7)
    b += lines(60, by + 146, "an isolated sandbox VM per case: egress killswitch, east-west and metadata guards; the receipt names the class", width=70, size=9.8, fill=INK_SOFT, lh=11.5)
    b += card(584, by, 472, 170, fill=LAVENDER, stroke="none", rx=14, lift=0)
    b += eyebrow(600, by + 26, "keys", color=MUTED)
    for i, (k, v) in enumerate([("platform key", "signs receipts and ledger countersignatures; an ephemeral key is refused unless declared a demo"),
                                ("attestation key", "signs qudisclose's own Finding and Patch statements (finder role)"),
                                ("pinned keyring", "finders, platform and maintainer countersigners, providers, roots, logs; validity windows; never an enclave key")]):
        yy = by + 50 + i * 42
        b += text(600, yy, k, size=11.5, weight=700)
        b += lines(600, yy + 14, v, width=74, size=9.8, fill=INK_SOFT, lh=11)
    b += rect(820, 136, 236, 44, fill="#fff", stroke=PAPER_EDGE, sw=1.2, rx=10)
    b += rect(832, 148, 18, 10, fill=FS, stroke=F, sw=1.4, rx=3) + text(856, 157, "finder role: qudisclose attests its own case", size=9.6, fill=INK_SOFT)
    b += rect(832, 164, 18, 10, fill=PS, stroke=P, sw=1.4, rx=3) + text(856, 173, "platform role: a reporter's statement", size=9.6, fill=INK_SOFT)
    b += footnote(W, H, "Nothing in the pipeline waits for a human unless policy says so; the verified level is recorded and routes the case, it never opens a pull request by itself.")
    write("fig-qudisclose", svg(W, H, b, title="qudisclose architecture", label="The qudisclose intake, the one-case pipeline as a timeline with finder-role VSLA hooks above and platform-role hooks below, the two sandbox backends and the three keys"))


def fig_verified() -> None:
    W, H = 1000, 470
    b = header(W, "Claimed is not verified", "The level in a statement is a claim. The level on a case is what the receiver could check, pillar by pillar, with the kind of every check.")
    pillars = [("Evidence", "evidence", 2), ("Identity", "identity", 1), ("Environment", "environment", 1)]
    fails = {"I4": "ledger not supplied", "N2": "no expectation", "I5": "", "N3": ""}
    y = 148
    b += level_tag(44, y + 40, 3, size=16)
    b += text(44, y + 96, "claimed", size=12, fill=MUTED)
    b += arrow(110, y + 52, 150, y + 52, color=INK_SOFT)
    for i, (name, key, lvl) in enumerate(pillars):
        yy = y + i * 74
        b += text(166, yy + 20, name, size=13, family=SERIF, weight=600)
        b += level_tag(166, yy + 30, lvl, size=10.5)
        x = 268
        for cid, clvl, kind, _, _ in CHECKS[key]:
            ok = cid not in fails
            w = 60
            b += rect(x, yy, w, 56, fill=("#fff" if ok else "#FFE3E4"), stroke=(LEVEL[clvl] if ok else ROSE), sw=1.6, rx=10)
            b += text(x + w / 2, yy + 18, cid, size=11.5, weight=700, anchor="middle", family=MONO, fill=(INK if ok else ROSE))
            b += kind_tag(x + 13, yy + 24, kind, size=8.5)
            b += ok_mark(x + w / 2, yy + 47, ok, r=6) if cid not in ("I5", "N3") else text(x + w / 2, yy + 50, "skip", size=9, fill=MUTED, anchor="middle", family=MONO)
            x += w + 8
        if any(c[0] in fails and fails[c[0]] for c in CHECKS[key]):
            cid = next(c[0] for c in CHECKS[key] if c[0] in fails and fails[c[0]])
            b += text(x + 6, yy + 34, f"{cid}: {fails[cid]}", size=11, fill=ROSE, weight=600)
    b += arrow(880, y + 52, 918, y + 52, color=INK_SOFT)
    b += level_tag(924, y + 40, 1, size=16)
    b += text(924, y + 96, "verified", size=12, fill=MUTED)
    b += lines(44, 390, ["Evidence reaches L2 (the receiver re-executed); Identity stops at L1 (the ledger was not supplied, and a summary is not evidence);",
                         "Environment stops at L1 (no expectation for this harness version). The verified level is the minimum, L1, recorded with every check",
                         "and its kind in the audit log and in the ledger entry; I5 and N3 are not reached once N2 has failed."], size=11.6, fill=INK_SOFT, lh=15.5)
    write("fig-verified", svg(W, H, b, title="Claimed versus verified", label="Sixteen verification checks across three pillars reducing a claimed Level 3 to a verified Level 1, each check tagged external or structural"))


FIGURES = (fig_ladder, fig_pillars, fig_tracks, fig_flow, fig_attestation, fig_merkle, fig_threats, fig_tee, fig_history, fig_pilot,
           fig_verified, fig_checks, fig_receipt, fig_consistency, fig_evidence, fig_attacks, fig_qudisclose, fig_cover)

if __name__ == "__main__":
    for fn in FIGURES:
        fn()
