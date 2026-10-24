"""Personal-data inventory: one row per finding, for a DPDP / GDPR record of what is held, where, and how it is protected."""
from __future__ import annotations

import csv
import io
import json

from .masks import RULES

CATEGORY = {
    "aadhaar": "identity", "pan": "identity", "passport_in": "identity", "dob": "identity",
    "person_name": "identity", "email": "contact", "phone_in": "contact", "address": "contact",
    "card": "financial", "upi": "financial", "ifsc": "financial", "gstin": "business",
    "ip": "online", "free_text": "unstructured",
}
CONTROL = {
    "keep_last4": "mask: keep last 4 digits", "email": "mask: keep first letter and domain",
    "full": "mask: fully", "redact": "redact identifiers inside text", "none": "tag only",
}
FIELDS = ["table", "column", "path", "pii_type", "description", "category", "sensitivity", "confidence", "evidence",
          "recommended_control", "owner", "lawful_purpose", "retention"]


def rows(findings, scanned_at: str) -> list[dict]:
    out = []
    for f in findings:
        out.append({
            "table": f.table, "column": f.column, "path": f.path or "", "pii_type": f.pii, "description": f.label,
            "category": CATEGORY.get(f.pii, "other"), "sensitivity": f.sensitivity, "confidence": f.confidence,
            "evidence": f.evidence, "recommended_control": CONTROL[RULES.get(f.pii, "full")],
            # Business fields a scanner cannot know; left for the data owner to fill in.
            "owner": "", "lawful_purpose": "", "retention": "", "_scanned_at": scanned_at,
        })
    return out


def to_csv(findings, scanned_at: str) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS + ["scanned_at"], lineterminator="\n")
    w.writeheader()
    for r in rows(findings, scanned_at):
        r["scanned_at"] = r.pop("_scanned_at")
        w.writerow(r)
    return buf.getvalue()


def to_json(findings, scanned_at: str) -> str:
    data = rows(findings, scanned_at)
    for r in data:
        r.pop("_scanned_at")
    return json.dumps({"scanned_at": scanned_at, "items": data}, indent=2)
