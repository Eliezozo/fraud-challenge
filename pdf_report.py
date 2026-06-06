"""
Génération de rapport PDF sans dépendance externe.

Implémente un sous-ensemble minimal de la spécification PDF 1.4 (texte,
polices standard Helvetica/Helvetica-Bold, filets) afin de produire un
rapport d'analyse anti-fraude téléchargeable, sans aucune librairie tierce.
"""

from __future__ import annotations

import textwrap
from datetime import datetime

A4_WIDTH = 595.28
A4_HEIGHT = 841.89
MARGIN_X = 50.0
MARGIN_TOP = 800.0
MARGIN_BOTTOM = 50.0
CONTENT_WIDTH = A4_WIDTH - 2 * MARGIN_X

GREEN = (0.11, 0.62, 0.46)
RED = (0.91, 0.30, 0.24)
GREY = (0.4, 0.4, 0.4)


def _escape(text: str) -> str:
    return (
        text.replace("\\", r"\\")
        .replace("(", r"\(")
        .replace(")", r"\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _char_width(size: float) -> float:
    """Largeur moyenne approximative d'un caractère Helvetica."""
    return size * 0.5


def _fit(text: str, width: float, size: float) -> str:
    max_chars = max(1, int(width / _char_width(size)))
    if len(text) <= max_chars:
        return text
    if max_chars <= 1:
        return text[:max_chars]
    return text[: max_chars - 1] + "\u2026"


def _wrap(text: str, width: float, size: float) -> list[str]:
    max_chars = max(1, int(width / _char_width(size)))
    lines: list[str] = []
    for paragraph in text.split("\n"):
        wrapped = textwrap.wrap(paragraph, width=max_chars) or [""]
        lines.extend(wrapped)
    return lines


class SimplePDF:
    """Constructeur PDF minimaliste avec pagination automatique."""

    def __init__(self) -> None:
        self._pages: list[list[str]] = []
        self._ops: list[str] = []
        self.y = MARGIN_TOP
        self._start_page()

    def _start_page(self) -> None:
        self._ops = []
        self._pages.append(self._ops)
        self.y = MARGIN_TOP

    def _ensure(self, needed: float) -> None:
        if self.y - needed < MARGIN_BOTTOM:
            self._start_page()

    def _emit_text(
        self,
        x: float,
        y: float,
        text: str,
        size: float,
        bold: bool,
        color: tuple[float, float, float] | None,
    ) -> None:
        font = "F2" if bold else "F1"
        seg: list[str] = []
        if color is not None:
            seg.append(f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg")
        seg.append("BT")
        seg.append(f"/{font} {size:.1f} Tf")
        seg.append(f"{x:.2f} {y:.2f} Td")
        seg.append(f"({_escape(text)}) Tj")
        seg.append("ET")
        if color is not None:
            seg.append("0 0 0 rg")
        self._ops.append("\n".join(seg))

    def heading(self, text: str, size: float = 15.0) -> None:
        self.spacer(6)
        self._ensure(size + 6)
        self.y -= size
        self._emit_text(MARGIN_X, self.y, text, size, bold=True, color=None)
        self.y -= 4
        self.rule()

    def subheading(self, text: str, size: float = 11.0) -> None:
        self._ensure(size + 4)
        self.y -= size
        self._emit_text(MARGIN_X, self.y, text, size, bold=True, color=None)
        self.y -= 3

    def line(
        self,
        text: str,
        size: float = 9.5,
        bold: bool = False,
        color: tuple[float, float, float] | None = None,
        indent: float = 0.0,
    ) -> None:
        for ln in _wrap(text, CONTENT_WIDTH - indent, size):
            self._ensure(size + 3)
            self.y -= size
            self._emit_text(MARGIN_X + indent, self.y, ln, size, bold, color)
            self.y -= 3

    def key_value(self, key: str, value: str, size: float = 10.0) -> None:
        self._ensure(size + 3)
        self.y -= size
        self._emit_text(MARGIN_X, self.y, key, size, bold=True, color=None)
        self._emit_text(MARGIN_X + 160, self.y, value, size, bold=False, color=None)
        self.y -= 3

    def spacer(self, height: float = 6.0) -> None:
        self.y -= height

    def rule(self) -> None:
        self._ensure(6)
        self.y -= 3
        self._ops.append(
            f"{GREY[0]} {GREY[1]} {GREY[2]} RG 0.5 w "
            f"{MARGIN_X:.2f} {self.y:.2f} m {A4_WIDTH - MARGIN_X:.2f} {self.y:.2f} l S"
        )
        self.y -= 6

    def table(
        self,
        headers: list[str],
        rows: list[list[str]],
        widths: list[float],
        size: float = 8.5,
        row_colors: list[tuple[float, float, float] | None] | None = None,
    ) -> None:
        row_h = size + 5

        def draw_header() -> None:
            self._ensure(row_h)
            self.y -= size
            x = MARGIN_X
            for head, w in zip(headers, widths):
                self._emit_text(x + 2, self.y, _fit(head, w - 4, size), size, bold=True, color=None)
                x += w
            self.y -= 4
            self.rule()

        draw_header()
        for idx, row in enumerate(rows):
            if self.y - row_h < MARGIN_BOTTOM:
                draw_header()
            self.y -= size
            x = MARGIN_X
            color = row_colors[idx] if row_colors else None
            for cell, w in zip(row, widths):
                self._emit_text(x + 2, self.y, _fit(str(cell), w - 4, size), size, bold=False, color=color)
                x += w
            self.y -= 5

    def build(self) -> bytes:
        objects: dict[int, bytes] = {}
        catalog_id, pages_id, f1_id, f2_id = 1, 2, 3, 4

        objects[catalog_id] = b"<< /Type /Catalog /Pages 2 0 R >>"
        objects[f1_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        objects[f2_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"

        next_id = 5
        page_ids: list[int] = []
        for ops in self._pages:
            page_id = next_id
            content_id = next_id + 1
            next_id += 2
            page_ids.append(page_id)

            stream = "\n".join(ops).encode("cp1252", errors="replace")
            objects[content_id] = (
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
            )
            page_dict = (
                f"<< /Type /Page /Parent 2 0 R "
                f"/MediaBox [0 0 {A4_WIDTH:.2f} {A4_HEIGHT:.2f}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                f"/Contents {content_id} 0 R >>"
            ).encode()
            objects[page_id] = page_dict

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[pages_id] = (
            f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
        )

        out = bytearray(b"%PDF-1.4\n")
        offsets: dict[int, int] = {}
        for obj_id in sorted(objects):
            offsets[obj_id] = len(out)
            out += f"{obj_id} 0 obj\n".encode() + objects[obj_id] + b"\nendobj\n"

        xref_pos = len(out)
        total = max(objects) + 1
        out += f"xref\n0 {total}\n".encode()
        out += b"0000000000 65535 f \n"
        for obj_id in range(1, total):
            out += f"{offsets[obj_id]:010d} 00000 n \n".encode()
        out += (
            f"trailer\n<< /Size {total} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
        )
        return bytes(out)


def build_analysis_pdf(rows: list[dict], summary: dict) -> bytes:
    """Construit le rapport PDF d'analyse anti-fraude à partir des lignes
    déjà formatées (`ID`, `Client`, `Date`, `Montant`, `Pays`, `Commerçant`,
    `Score`, `Verdict`, `Niveau`, `Raison`, `is_suspicious`)."""
    pdf = SimplePDF()

    pdf.line("Rapport d'analyse anti-fraude", size=20, bold=True)
    pdf.line(
        "Genere le " + datetime.now().strftime("%d/%m/%Y a %H:%M"),
        size=9,
        color=GREY,
    )
    pdf.rule()

    pdf.heading("Synthese")
    pdf.key_value("Transactions analysees", str(summary.get("total", 0)))
    pdf.key_value("Alertes (suspectes)", str(summary.get("alerts", 0)))
    pdf.key_value("Transactions conformes", str(summary.get("conformes", 0)))
    pdf.key_value("Score de risque moyen", f"{summary.get('avg_score', 0.0):.2f} / 1.00")
    pdf.key_value("Taux d'alerte", f"{summary.get('alert_rate', 0.0):.1f} %")

    levels = summary.get("level_counts", {})
    pdf.spacer(4)
    pdf.subheading("Repartition par niveau de risque")
    pdf.key_value("Faible (< 0,40)", str(levels.get("Faible", 0)))
    pdf.key_value("Modere (0,40 - 0,69)", str(levels.get("Modéré", 0)))
    pdf.key_value("Eleve (>= 0,70)", str(levels.get("Élevé", 0)))

    alerts = [r for r in rows if r.get("is_suspicious")]
    pdf.heading("Alertes detectees")
    if not alerts:
        pdf.line("Aucune transaction suspecte dans ce lot.", color=GREEN)
    else:
        for r in alerts:
            header = (
                f"{r['ID']}  -  {r['Client']}  -  {r['Montant']}  -  "
                f"{r['Pays']}  (score {float(r['Score']):.2f})"
            )
            pdf.line(header, size=10, bold=True, color=RED)
            pdf.line(f"Motif : {r.get('Raison', '')}", size=9, indent=10)
            pdf.spacer(2)

    pdf.heading("Detail de toutes les transactions")
    widths = [60, 50, 95, 80, 55, 45, 70]
    headers = ["ID", "Client", "Date", "Montant", "Pays", "Score", "Verdict"]
    table_rows: list[list[str]] = []
    colors: list[tuple[float, float, float] | None] = []
    for r in rows:
        table_rows.append([
            str(r["ID"]),
            str(r["Client"]),
            str(r["Date"]),
            str(r["Montant"]),
            str(r["Pays"]),
            f"{float(r['Score']):.2f}",
            str(r["Verdict"]),
        ])
        colors.append(RED if r.get("is_suspicious") else None)
    pdf.table(headers, table_rows, widths, row_colors=colors)

    return pdf.build()
