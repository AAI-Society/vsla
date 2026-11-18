"""Build paper/vsla.docx from paper/vsla.tex, for commenting in Google Docs or Word.

Run: python paper/build_docx.py     (needs tectonic, rsvg-convert, python-docx, and pandoc on PATH or pypandoc_binary)

The PDF stays the paper of record. pandoc converts the text, formulas, table and figures; this script then lays the
result out to match the PDF: the cover band, the summary boxes, the abstract page, serif justified body, run-in
paragraph headings, booktabs-style table and figure widths. Section, figure, table and citation numbers are written in
as text, taken from the same LaTeX run that builds the PDF, so the two agree."""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

HERE = Path(__file__).parent
FIGS = HERE.parent / "figures"
TEXT_W = 8.5 - 2 * 1.05                       # inches, as in the PDF
SERIF, SANS, MONO = "Times New Roman", "Arial", "Courier New"
INK, LIME, DARKLIME, PAPER, MUTED, NEUTRAL = "0A0A0A", "CFFF04", "7A9900", "F0EDEA", "8F8A82", "E7E3DD"
TITLE = "VSLA: Supply-chain Levels for Machine-to-Machine Vulnerability Disclosure"
TAGLINE = "A graded, verifiable trust framework for disclosures made by agents, modelled on SLSA."
MARK_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 100"><g fill="#CFFF04"><rect x="0" y="0" width="16" height="100"/>'
            '<rect x="16" y="0" width="26" height="24"/><rect x="16" y="76" width="26" height="24"/><rect x="104" y="0" width="16" height="100"/>'
            '<rect x="78" y="0" width="26" height="24"/><rect x="78" y="76" width="26" height="24"/></g></svg>')


# ----------------------------------------------------------------------------- LaTeX side

def pandoc() -> str:
    if shutil.which("pandoc"):
        return "pandoc"
    import pypandoc
    return pypandoc.get_pandoc_path()


def labels(tex: Path, work: Path) -> dict[str, str]:
    """Label -> printed number, from the .aux of a real LaTeX run."""
    subprocess.run(["tectonic", "--keep-intermediates", "--outdir", str(work), str(tex)], check=True, capture_output=True)
    aux = (work / (tex.stem + ".aux")).read_text()
    return {m.group(1): m.group(2) for m in re.finditer(r"\\newlabel\{([^}]+)\}\{\{([^}]*)\}", aux)}


def braced(s: str, i: int) -> tuple[str, int]:
    """The contents of the brace group opening at s[i], and the index after it."""
    depth, j = 0, i
    while True:
        depth += s[j] == "{"
        depth -= s[j] == "}"
        j += 1
        if depth == 0:
            return s[i + 1:j - 1], j


def prepare(src: str, num: dict[str, str]) -> tuple[str, dict]:
    """The LaTeX pandoc reads, and what the layout step needs to know about the front matter."""
    _, body = src.split(r"\begin{document}", 1)
    front, body = body.split("\\newpage\n\\setcounter{page}{1}", 1)

    def grab(start: str, end: str) -> str:
        a = front.index(start) + len(start)
        return front[a:front.index(end, a)].strip()

    epigraph = "On what basis " + grab(r"\noindent{\itshape On what basis", r"\par}")
    abstract = grab("{\\linespread{1.06}\\selectfont\n", "\\par}")
    idea = grab(r"{\footnotesize\itshape ", "}\n")
    glance_titles, glance_texts = [], []
    for m in re.finditer(r"\\glance\{\w+\}", front):
        title, j = braced(front, m.end())
        text, _ = braced(front, j)
        glance_titles.append(title)
        glance_texts.append(text)
    guide = [rf"\textbf{{{lead.replace(chr(92) + ',', ' ')}}} {text.strip()}"
             for lead, text in re.findall(r"\\item\[(.+?)\]\s*(.+)", front)]
    info = {"revision": re.search(r"Draft v[\d.]+, revision \d+ \$\\cdot\$ \w+ \d+", front).group(0).replace(r"$\cdot$", "·"),
            "glance_titles": glance_titles, "n_guide": len(guide),
            "widths": [float(w or 1) for w in re.findall(r"\\includegraphics\[width=([\d.]*)\\linewidth\]", src)]}

    parts = ["QQEPI", epigraph, "QQFIG", r"\includegraphics{fig-cover.png}", "QQGLANCE", *glance_texts, "QQABS", abstract,
             "QQGUIDE", *guide, "QQIDEA", idea, "QQBODY"]
    tex = (r"\documentclass{article}\usepackage{graphicx}\usepackage{hyperref}\begin{document}" + "\n\n"
           + "\n\n".join(parts) + "\n\n" + body)

    keys = re.findall(r"\\bibitem\{([^}]+)\}", tex)
    cite = {k: str(i + 1) for i, k in enumerate(keys)}
    tex = re.sub(r"~?\\cite\{([^}]+)\}", lambda m: " [" + ", ".join(cite[k.strip()] for k in m.group(1).split(",")) + "]", tex)
    tex = re.sub(r"\\ref\{([^}]+)\}", lambda m: num[m.group(1)], tex)

    def caption(m: re.Match) -> str:
        lab = re.search(r"\\label\{([^}]+)\}", m.group(0))
        kind = "Figure" if m.group(1) == "figure" else "Table"
        n = num.get(lab.group(1), "") if lab else ""
        return re.sub(r"\\caption\{", lambda _: rf"\caption{{{kind} {n}: ", m.group(0), count=1)
    tex = re.sub(r"\\begin\{(figure|table)\}.*?\\end\{\1\}", caption, tex, flags=re.S)

    out, sec, subs = [], 0, 0
    for line in tex.split("\n"):
        if line.startswith(r"\section{"):
            sec, subs = sec + 1, 0
            line = line.replace(r"\section{", rf"\section{{{sec}~~~", 1)
        elif line.startswith(r"\subsection{"):
            subs += 1
            line = line.replace(r"\subsection{", rf"\subsection{{{sec}.{subs}~~~", 1)
        out.append(line)
    tex = "\n".join(out)
    # run-in paragraph headings, as LaTeX sets them
    tex = re.sub(r"\\paragraph\{", r"\\textbf{", tex)

    a, b = tex.index(r"\begin{thebibliography}"), tex.index(r"\end{thebibliography}")
    items = [re.sub(r"^\{[^}]+\}\s*", "", x).strip() for x in tex[a:b].split(r"\bibitem")[1:]]
    refs = r"\section*{References}" + "\n\n" + "\n\n".join(rf"[{i + 1}] {x}" for i, x in enumerate(items))
    tex = tex[:a] + refs + tex[b + len(r"\end{thebibliography}"):]

    tex = tex.replace(r"\vsla{}", "VSLA").replace(r"\vsla", "VSLA").replace(r"\slsa{}", "SLSA").replace(r"\slsa", "SLSA")
    tex = re.sub(r"\\lvl\{(\d)\}", r"\\textbf{L\1}", tex)
    tex = re.sub(r"\\includegraphics(\[[^\]]*\])?\{\.\./figures/pdf/(fig-[\w-]+)\.pdf\}", r"\\includegraphics{\2.png}", tex)
    return tex, info


# ----------------------------------------------------------------------------- Word side

def shade(cell, fill: str) -> None:
    pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), fill)
    pr.append(shd)


def borders(el, tag: str, **edges: tuple[str, int] | None) -> None:
    """Set borders on a table (w:tblBorders), cell (w:tcBorders) or paragraph (w:pBdr): edge=(colour, eighths of a point) or None."""
    box = OxmlElement(tag)
    for edge, spec in edges.items():
        e = OxmlElement(f"w:{edge}")
        if spec is None:
            e.set(qn("w:val"), "nil")
        else:
            e.set(qn("w:val"), "single"); e.set(qn("w:sz"), str(spec[1])); e.set(qn("w:space"), "0"); e.set(qn("w:color"), spec[0])
        box.append(e)
    el.append(box)


def fix_widths(table, widths: list[float]) -> None:
    """Pin a table's width and its columns (inches): table width, fixed layout, the grid and every cell."""
    table.autofit = False
    pr = table._tbl.tblPr
    for tag in ("w:tblW", "w:tblLayout"):
        for old in pr.findall(qn(tag)):
            pr.remove(old)
    w = OxmlElement("w:tblW"); w.set(qn("w:w"), str(int(sum(widths) * 1440))); w.set(qn("w:type"), "dxa"); pr.append(w)
    lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); pr.append(lay)
    for col, width in zip(table._tbl.tblGrid.findall(qn("w:gridCol")), widths):
        col.set(qn("w:w"), str(int(width * 1440)))
    for row in table.rows:
        for cell, width in zip(row.cells, widths):
            cell.width = Inches(width)


def cell_margins(cell, top: float, left: float, bottom: float, right: float) -> None:
    mar = OxmlElement("w:tcMar")
    for side, v in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:w"), str(int(v * 1440))); e.set(qn("w:type"), "dxa")
        mar.append(e)
    cell._tc.get_or_add_tcPr().append(mar)


def row_height(row, inches: float) -> None:
    pr = row._tr.get_or_add_trPr()
    h = OxmlElement("w:trHeight")
    h.set(qn("w:val"), str(int(inches * 1440))); h.set(qn("w:hRule"), "exact")
    pr.append(h)


def font(run, name: str, size: float, *, bold: bool | None = None, italic: bool | None = None, color: str | None = None) -> None:
    run.font.name = name
    rpr = run._r.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rf.set(qn(a), name)
    run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if italic is not None:
        run.font.italic = italic
    if color:
        run.font.color.rgb = RGBColor.from_string(color)


def para(doc, text: str = "", *, name: str = SERIF, size: float = 11, before: float = 0, after: float = 0, align=None, **kw):
    p = doc.add_paragraph()
    p.style = doc.styles["Normal"]
    p.paragraph_format.space_before, p.paragraph_format.space_after = Pt(before), Pt(after)
    if align is not None:
        p.alignment = align
    if text:
        font(p.add_run(text), name, size, **kw)
    return p


def restyle(p, *, name: str = SERIF, size: float = 11, italic: bool | None = None, align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            before: float = 0, after: float = 0, style=None) -> None:
    if style is not None:
        p.style = style
    p.alignment = align
    f = p.paragraph_format
    f.space_before, f.space_after, f.first_line_indent = Pt(before), Pt(after), Inches(0)
    for r in p.runs:
        font(r, MONO if (r.style is not None and "Verbatim" in r.style.name) else name, size, italic=italic)


def bar(doc, width: float, fill: str = LIME, height: float = 0.045):
    t = doc.add_table(rows=1, cols=1)
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    t.autofit = False
    c = t.rows[0].cells[0]
    fix_widths(t, [width])
    shade(c, fill)
    row_height(t.rows[0], height)
    font(c.paragraphs[0].add_run(" "), SANS, 1)
    c.paragraphs[0].paragraph_format.space_after = Pt(0)
    return t


def set_style(doc, name: str, *, face: str, size: float, bold: bool = False, italic: bool = False, color: str = "000000",
              before: float = 0, after: float = 0, align=None, indent: float | None = None, line: float | None = None, keep: bool = False) -> None:
    if name not in [s.name for s in doc.styles]:
        return
    st = doc.styles[name]
    rpr = st.element.get_or_add_rPr()
    for child in list(rpr):
        if child.tag in (qn("w:rFonts"), qn("w:color"), qn("w:sz"), qn("w:szCs"), qn("w:b"), qn("w:bCs"), qn("w:i"), qn("w:iCs")):
            rpr.remove(child)
    st.font.name = face
    rf = rpr.find(qn("w:rFonts"))
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rf.set(qn(a), face)
    st.font.size, st.font.bold, st.font.italic = Pt(size), bold, italic
    st.font.color.rgb = RGBColor.from_string(color)
    if st.type == 1:    # paragraph style
        f = st.paragraph_format
        f.space_before, f.space_after = Pt(before), Pt(after)
        if align is not None:
            f.alignment = align
        if indent is not None:
            f.first_line_indent = Inches(indent)
        if line is not None:
            f.line_spacing = line
        f.keep_with_next = keep


def layout(path: Path, info: dict, mark_png: Path) -> None:
    doc = Document(str(path))
    J, L, C = WD_ALIGN_PARAGRAPH.JUSTIFY, WD_ALIGN_PARAGRAPH.LEFT, WD_ALIGN_PARAGRAPH.CENTER

    sec = doc.sections[0]
    sec.left_margin = sec.right_margin = sec.top_margin = sec.bottom_margin = Inches(1.05)

    # ---- styles: an 11pt serif article, as the PDF is
    set_style(doc, "Normal", face=SERIF, size=11, line=1.06)
    set_style(doc, "Body Text", face=SERIF, size=11, align=J, indent=0.2, line=1.06)
    set_style(doc, "First Paragraph", face=SERIF, size=11, align=J, indent=0, line=1.06)
    set_style(doc, "Compact", face=SERIF, size=11, align=J, line=1.06)
    set_style(doc, "Heading 1", face=SERIF, size=14.4, bold=True, before=18, after=9, keep=True)
    set_style(doc, "Heading 2", face=SERIF, size=12, bold=True, before=13, after=6, keep=True)
    set_style(doc, "Image Caption", face=SERIF, size=9, before=4, after=12, align=L)
    set_style(doc, "Table Caption", face=SERIF, size=9, before=4, after=12, align=C)
    set_style(doc, "Captioned Figure", face=SERIF, size=11, before=10, after=0, align=C)
    set_style(doc, "Verbatim Char", face=MONO, size=10)
    set_style(doc, "Hyperlink", face=SERIF, size=11)
    set_style(doc, "Footnote Text", face=SERIF, size=9)

    body = doc.element.body
    paras = {p.text.strip(): p for p in doc.paragraphs if p.text.strip().startswith("QQ")}

    def between(a: str, b: str) -> list:
        out, el = [], paras[a]._p.getnext()
        while el is not paras[b]._p:
            out.append(el)
            el = el.getnext()
        return out

    by_el = {p._p: p for p in doc.paragraphs}
    anchor = paras["QQEPI"]._p

    def place(el) -> None:          # move an element built at the end of the document to just before the anchor
        anchor.addprevious(el)

    # ---- the cover band
    band = doc.add_table(rows=2, cols=1)
    band.autofit = False
    top, rule = band.rows[0].cells[0], band.rows[1].cells[0]
    fix_widths(band, [TEXT_W])
    shade(top, INK); shade(rule, LIME)
    cell_margins(top, 0.26, 0.28, 0.24, 0.28)
    row_height(band.rows[1], 0.07)
    font(rule.paragraphs[0].add_run(" "), SANS, 1)
    p = top.paragraphs[0]
    p.paragraph_format.space_after = Pt(2)
    p.add_run().add_picture(str(mark_png), height=Inches(0.2))
    font(p.add_run("   ADVANCED AI SOCIETY"), SANS, 8, bold=True, color=LIME)
    p = top.add_paragraph(); p.paragraph_format.space_after = Pt(20)
    font(p.add_run("        " + info["revision"]), SANS, 8, color=MUTED)
    p = top.add_paragraph(); p.paragraph_format.space_after = Pt(34); p.paragraph_format.line_spacing = 1.0
    font(p.add_run(TITLE), SANS, 21.5, bold=True, color=PAPER)
    p = top.add_paragraph(); p.paragraph_format.space_after = Pt(0)
    font(p.add_run("\u2501\u2501  "), SANS, 9, bold=True, color=LIME)
    font(p.add_run(TAGLINE), SANS, 9, color=PAPER)
    place(band._tbl)

    # ---- authors
    p = para(doc, before=16, after=3)
    p.paragraph_format.tab_stops.add_tab_stop(Inches(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
    font(p.add_run("Jim Schwoebel"), SERIF, 10, bold=True)
    r = p.add_run("1,2"); font(r, SERIF, 10); r.font.superscript = True
    font(p.add_run("\tgithub.com/AAI-Society/vsla"), MONO, 9)
    place(p._p)
    p = para(doc, after=6)
    p.paragraph_format.tab_stops.add_tab_stop(Inches(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
    for sup, text in (("1", " Quome, Inc.    "), ("2", " Advanced AI Society, ")):
        r = p.add_run(sup); font(r, SERIF, 8); r.font.superscript = True
        font(p.add_run(text), SERIF, 8)
    font(p.add_run("https://advancedaisociety.org"), MONO, 8)
    font(p.add_run("\tjim@quome.com"), MONO, 8)
    place(p._p)
    p = para(doc, after=8)
    borders(p._p.get_or_add_pPr(), "w:pBdr", bottom=(LIME, 13))
    place(p._p)

    # ---- epigraph and cover figure
    for el in between("QQEPI", "QQFIG"):
        restyle(by_el[el], italic=True, after=8, style=doc.styles["Normal"])
    for el in between("QQFIG", "QQGLANCE"):
        by_el[el].alignment = C
        by_el[el].paragraph_format.space_after = Pt(8)

    # ---- the three summary boxes
    texts = between("QQGLANCE", "QQABS")
    anchor = paras["QQABS"]._p
    box = doc.add_table(rows=1, cols=5)
    box.autofit = False
    gap, w = 0.14, (TEXT_W - 2 * 0.14) / 3
    colours = [DARKLIME, INK, INK]
    fills = ["F8FAF2", "F3F3F3", "F3F3F3"]
    fix_widths(box, [w, gap, w, gap, w])
    for i, c in enumerate(box.rows[0].cells):
        if i % 2:
            continue
        k = i // 2
        shade(c, fills[k])
        borders(c._tc.get_or_add_tcPr(), "w:tcBorders", **{e: (colours[k], 8) for e in ("top", "left", "bottom", "right")})
        cell_margins(c, 0.1, 0.12, 0.1, 0.12)
        t = c.paragraphs[0]
        t.paragraph_format.space_after = Pt(4)
        font(t.add_run(info["glance_titles"][k].upper()), SANS, 7, bold=True, color=colours[k])
        c._tc.append(texts[k])
        restyle(by_el[texts[k]], size=9, align=L, style=doc.styles["Normal"])
    place(box._tbl)
    brk = para(doc)
    brk.add_run().add_break(WD_BREAK.PAGE)
    place(brk._p)

    # ---- abstract page
    def label(text: str, colour: str) -> None:
        q = para(doc, text, name=SANS, size=8, bold=True, color=colour, after=3)
        place(q._p)
        place(bar(doc, 0.87)._tbl)
        place(para(doc, after=6)._p)

    label("ABSTRACT", DARKLIME)
    for el in between("QQABS", "QQGUIDE"):
        restyle(by_el[el], after=12, style=doc.styles["Normal"])
    anchor = paras["QQGUIDE"]._p
    label("A READER'S GUIDE", INK)
    items = between("QQGUIDE", "QQIDEA")
    half = (len(items) + 1) // 2
    guide = doc.add_table(rows=1, cols=2)
    guide.autofit = False
    fix_widths(guide, [TEXT_W / 2, TEXT_W / 2])
    for k, c in enumerate(guide.rows[0].cells):
        cell_margins(c, 0, 0 if k == 0 else 0.12, 0, 0.12 if k == 0 else 0)
        for el in items[k * half:(k + 1) * half]:
            c._tc.append(el)
            restyle(by_el[el], size=9, align=L, after=4, style=doc.styles["Normal"])
        c._tc.remove(c.paragraphs[0]._p)
    place(guide._tbl)
    p = para(doc, before=10, after=4)
    borders(p._p.get_or_add_pPr(), "w:pBdr", bottom=(NEUTRAL, 5))
    place(p._p)
    for el in between("QQIDEA", "QQBODY"):
        restyle(by_el[el], size=9, italic=True, align=L, style=doc.styles["Normal"])
    brk = para(doc)
    brk.add_run().add_break(WD_BREAK.PAGE)
    paras["QQBODY"]._p.addprevious(brk._p)
    for p in paras.values():
        body.remove(p._p)

    # ---- body: figure widths, captions, run-in headings, the table, references
    widths = iter(info["widths"])
    for shape in doc.inline_shapes:
        if shape._inline.getparent().getparent().getparent().getparent().tag != qn("w:body"):
            continue                 # the bracket mark sits in a table cell
        ratio = shape.height / shape.width
        shape.width = Inches(TEXT_W * next(widths))
        shape.height = int(shape.width * ratio)
        for ext in shape._inline.iter(qn("a:ext")):      # the picture's own frame, or it is clipped to the old size
            ext.set("cx", str(shape.width)); ext.set("cy", str(shape.height))

    in_refs = False
    for p in doc.paragraphs:
        name = p.style.name
        if name == "Heading 1":
            in_refs = p.text.strip() == "References"
        if name in ("Image Caption", "Table Caption") and p.runs:
            m = re.match(r"((?:Figure|Table) \d+:)(.*)", p.runs[0].text, flags=re.S)
            if m:
                p.runs[0].text = m.group(2)
                lead = copy.deepcopy(p.runs[0]._r)
                p.runs[0]._r.addprevious(lead)
                p.runs[0].text = m.group(1)
                p.runs[0].font.bold = True
            for r in p.runs:
                r.font.italic = False
        elif name in ("Body Text", "First Paragraph") and p.runs and p.runs[0].bold and not in_refs:
            p.paragraph_format.first_line_indent = Inches(0)     # a run-in heading
            p.paragraph_format.space_before = Pt(9)
            p.runs[0].text = p.runs[0].text.rstrip() + "  "
        elif in_refs and name in ("Body Text", "First Paragraph"):
            restyle(p, size=9, align=L, after=2)
            p.paragraph_format.left_indent, p.paragraph_format.first_line_indent = Inches(0.3), Inches(-0.3)

    for t in doc.tables:
        if t._tbl.getparent().tag != qn("w:body") or t in (band, box, guide) or len(t.columns) != 3:
            continue
        pr = t._tbl.tblPr
        for old in pr.findall(qn("w:tblBorders")):
            pr.remove(old)
        borders(pr, "w:tblBorders", top=(INK, 8), bottom=(INK, 8), left=None, right=None, insideH=None, insideV=None)
        for c in t.rows[0].cells:
            borders(c._tc.get_or_add_tcPr(), "w:tcBorders", bottom=(INK, 5))
        for row in t.rows:
            for c in row.cells:
                for q in c.paragraphs:
                    restyle(q, size=9, align=L, after=2)

    # ---- page number in the footer, as the PDF has
    f = sec.footer.paragraphs[0]
    f.alignment = C
    for kind, text in (("begin", None), (None, "PAGE"), ("end", None)):
        r = f.add_run()
        font(r, SERIF, 10)
        if kind:
            ch = OxmlElement("w:fldChar"); ch.set(qn("w:fldCharType"), kind); r._r.append(ch)
        else:
            it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = text; r._r.append(it)

    doc.save(str(path))


def main() -> None:
    src = (HERE / "vsla.tex").read_text()
    out = HERE / "vsla.docx"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        tex, info = prepare(src, labels(HERE / "vsla.tex", work))
        for name in set(re.findall(r"\{(fig-[\w-]+)\.png\}", tex)):
            subprocess.run(["rsvg-convert", "-w", "1500", "-b", "white", "-o", str(work / f"{name}.png"), str(FIGS / f"{name}.svg")], check=True)
        (work / "mark.svg").write_text(MARK_SVG)
        subprocess.run(["rsvg-convert", "-w", "240", "-o", str(work / "mark.png"), str(work / "mark.svg")], check=True)
        (work / "vsla-docx.tex").write_text(tex)
        subprocess.run([pandoc(), "vsla-docx.tex", "-f", "latex", "-t", "docx", "--resource-path", ".", "-o", str(out)], check=True, cwd=work)
        layout(out, info, work / "mark.png")
    print("built", out)


if __name__ == "__main__":
    main()
