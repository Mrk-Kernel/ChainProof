"""Custody report export in JSON and PDF."""

import hashlib
import json
from pathlib import Path

from fpdf import FPDF

REPORT_FIELDS = ("index", "timestamp", "action", "actor", "evidence", "prev_hash", "entry_hash")


class ReportExporter:
    def __init__(self, case_dir, audit_log, public_key_fingerprint=None,
                 head_hash=None, anchor_result=None):
        self.case_dir = Path(case_dir)
        self.audit_log = audit_log
        self.public_key_fingerprint = public_key_fingerprint
        self.head_hash = head_hash
        self.anchor_result = anchor_result

    def _report_data(self):
        ok, message = self.audit_log.verify()
        return {
            "case_dir": str(self.case_dir),
            "public_key_fingerprint_sha256": self.public_key_fingerprint,
            "head_hash": self.head_hash,
            "head_anchor": self.anchor_result,
            "chain_verification": {"passed": ok, "message": message},
            "entries": self.audit_log.entries,
        }

    def export_json(self, out_path):
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        report = self._report_data()
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return out_path

    def export_pdf(self, out_path):
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        data = self._report_data()
        cv = data["chain_verification"]

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "ChainProof - Chain of Custody Report", new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 7, f"Case directory: {self.case_dir}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Public key fingerprint (SHA-256): {self.public_key_fingerprint}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Log entries: {len(self.audit_log.entries)}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Head hash (SHA-256): {self.head_hash[:32]}...", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Chain verification: {'PASSED' if cv['passed'] else 'FAILED'} - {cv['message']}", new_x="LMARGIN", new_y="NEXT")
        if self.anchor_result:
            pdf.cell(0, 7, f"Head anchor: {self.anchor_result.get('status_string')}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

        pdf.set_font("helvetica", "B", 11)
        pdf.cell(0, 7, "Audit Log Entries", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        headers = ["#", "Time (UTC)", "Action", "Actor", "Entry Hash (SHA-256)", "Prev Hash"]
        widths = [8, 30, 28, 22, 60, 60]

        pdf.set_font("helvetica", "B", 8)
        for header, width in zip(headers, widths):
            pdf.cell(width, 7, header, border=1)
        pdf.ln()

        pdf.set_font("helvetica", "", 8)
        for entry in self.audit_log.entries:
            evidence = entry.get("evidence") or {}
            ev_label = ""
            if evidence:
                ev_label = f"{evidence.get('name','')} ({evidence.get('sha256','')[:12]}...)"
            row = [
                str(entry["index"]),
                entry["timestamp"][:16],
                entry["action"],
                entry["actor"],
                entry["entry_hash"][:16] + "...",
                entry["prev_hash"][:12] + "...",
            ]
            if ev_label:
                row[1] = row[1] + "\n" + ev_label[:40]
            for cell_text, width in zip(row, widths):
                pdf.multi_cell(width, 5, cell_text, border=1)
            pdf.ln(-2)

        pdf.ln(6)
        pdf.set_font("helvetica", "I", 9)
        pdf.multi_cell(0, 5, "This report documents a hash-chained, signed audit log. Any modification "
                           "to a log entry breaks the chain and invalidates signatures. The signing "
                           "key must be stored outside the case directory and protected separately; "
                           "anyone with the key can re-sign the entire chain.")
        pdf.output(str(out_path))
        return out_path
