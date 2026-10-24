"""Sample each column and classify it. Works over any DB-API 2.0 connection."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .detectors import DETECTORS, NAME_ONLY, Detector

MATCH_THRESHOLD = 0.6        # share of sampled values that must match
HINTED_THRESHOLD = 0.3       # lower bar when the column name also suggests the type
NAME_ONLY_CONFIDENCE = 0.5


@dataclass
class ColumnFinding:
    table: str
    column: str
    pii: str
    label: str
    sensitivity: str
    confidence: float
    match_rate: float
    sampled: int
    evidence: str            # "values" | "values+name" | "name"
    examples: list[str] = field(default_factory=list)  # masked previews, never raw values
    path: str | None = None  # location inside a JSON / STRUCT / ARRAY column, e.g. customer.phone or items[].upi

    @property
    def location(self) -> str:
        return f"{self.column}.{self.path}" if self.path else self.column


def _hinted(column: str, hints: tuple[str, ...]) -> bool:
    c = column.lower()
    return any(c == h or c.startswith(h + "_") or c.endswith("_" + h) or h in c.split("_") or (len(h) > 4 and h in c)
               for h in hints)


def classify(column: str, values: list[str]) -> tuple[Detector | None, float, float, str]:
    """Best detector for a column, its confidence, match rate and evidence kind."""
    best: tuple[Detector | None, float, float, str] = (None, 0.0, 0.0, "")
    n = len(values)
    for det in DETECTORS:
        rate = sum(1 for v in values if det.match(v)) / n if n else 0.0
        hinted = _hinted(column, det.name_hints)
        if rate >= MATCH_THRESHOLD or (hinted and rate >= HINTED_THRESHOLD):
            conf = min(1.0, rate + (0.15 if hinted else 0.0))
            if conf > best[1]:
                best = (det, conf, rate, "values+name" if hinted else "values")
    return best


MAX_DEPTH = 12


def _as_nested(v):
    """A dict / list as-is, a JSON object or array string parsed; anything else None."""
    if isinstance(v, (dict, list)):
        return v
    if isinstance(v, str) and v[:1] in "{[":
        try:
            parsed = json.loads(v)
        except ValueError:
            return None
        return parsed if isinstance(parsed, (dict, list)) else None
    return None


def flatten(value, prefix: str = "", out: dict[str, list[str]] | None = None, depth: int = 0) -> dict[str, list[str]]:
    """Leaf values by path: {"customer.phone": [...], "items[].upi": [...]}."""
    out = {} if out is None else out
    if depth > MAX_DEPTH:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(value, list):
        for v in value:
            flatten(v, f"{prefix}[]", out, depth + 1)
    elif value is not None and prefix:
        out.setdefault(prefix, []).append(str(value).strip())
    return out


def _classify_values(table: str, col: str, values: list[str], hint_name: str, path: str | None) -> ColumnFinding | None:
    from .masks import preview

    det, conf, rate, evidence = classify(hint_name, values) if values else (None, 0.0, 0.0, "")
    if det is not None:
        return ColumnFinding(table, col, det.name, det.label, det.sensitivity, round(conf, 3), round(rate, 3),
                             len(values), evidence, [preview(det.name, v) for v in values[:2]], path)
    for name, label, sensitivity, hints in NAME_ONLY:
        if _hinted(hint_name, hints):
            return ColumnFinding(table, col, name, label, sensitivity, NAME_ONLY_CONFIDENCE, 0.0, len(values),
                                 "name", [preview(name, v) for v in values[:2]], path)
    return None


def scan_table(conn, table: str, sample: int = 1000, quote: str = '"') -> list[ColumnFinding]:
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table} WHERE 1 = 0")
    columns = [d[0] for d in cur.description]
    cur.close()
    findings = []
    for col in columns:
        cur = conn.cursor()
        q = f"{quote}{col}{quote}"
        cur.execute(f"SELECT {q} FROM {table} WHERE {q} IS NOT NULL LIMIT {int(sample)}")
        raw = [r[0] for r in cur.fetchall()]
        cur.close()
        nested = [n for n in (_as_nested(v) for v in raw) if n is not None]
        if raw and len(nested) >= len(raw) / 2:
            # Semi-structured column: classify every leaf path; the last key plays the role of a column name.
            paths: dict[str, list[str]] = {}
            for doc in nested:
                flatten(doc, out=paths)
            for path, values in sorted(paths.items()):
                key = path.replace("[]", "").rsplit(".", 1)[-1]
                f = _classify_values(table, col, values, key, path)
                if f is not None:
                    findings.append(f)
            continue
        f = _classify_values(table, col, [str(v).strip() for v in raw], col, None)
        if f is not None:
            findings.append(f)
    return findings


def list_tables(conn) -> list[str]:
    cur = conn.cursor()
    cur.execute("SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('information_schema', 'pg_catalog') ORDER BY 1, 2")
    out = [f"{s}.{t}" for s, t in cur.fetchall()]
    cur.close()
    return out
