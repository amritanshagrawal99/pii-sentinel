"""Sample each column and classify it. Works over any DB-API 2.0 connection."""
from __future__ import annotations

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


def scan_table(conn, table: str, sample: int = 1000, quote: str = '"') -> list[ColumnFinding]:
    from .masks import preview

    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table} WHERE 1 = 0")
    columns = [d[0] for d in cur.description]
    cur.close()
    findings = []
    for col in columns:
        cur = conn.cursor()
        q = f"{quote}{col}{quote}"
        cur.execute(f"SELECT {q} FROM {table} WHERE {q} IS NOT NULL LIMIT {int(sample)}")
        values = [str(r[0]).strip() for r in cur.fetchall()]
        cur.close()
        det, conf, rate, evidence = classify(col, values) if values else (None, 0.0, 0.0, "")
        if det is not None:
            findings.append(ColumnFinding(table, col, det.name, det.label, det.sensitivity, round(conf, 3), round(rate, 3),
                                          len(values), evidence, [preview(det.name, v) for v in values[:2]]))
            continue
        for name, label, sensitivity, hints in NAME_ONLY:
            if _hinted(col, hints):
                findings.append(ColumnFinding(table, col, name, label, sensitivity, NAME_ONLY_CONFIDENCE, 0.0, len(values),
                                              "name", [preview(name, v) for v in values[:2]]))
                break
    return findings


def list_tables(conn) -> list[str]:
    cur = conn.cursor()
    cur.execute("SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_schema NOT IN ('information_schema', 'pg_catalog') ORDER BY 1, 2")
    out = [f"{s}.{t}" for s, t in cur.fetchall()]
    cur.close()
    return out
