"""Sample each column and classify it. Works over any DB-API 2.0 connection."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .detectors import DETECTORS, NAME_ONLY, SPANS, Detector

MATCH_THRESHOLD = 0.6        # share of sampled values that must match
HINTED_THRESHOLD = 0.3       # lower bar when the column name also suggests the type
NAME_ONLY_CONFIDENCE = 0.5
FREE_TEXT_THRESHOLD = 0.05   # share of rows containing at least one validated identifier


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
    return _free_text(table, col, values, path)


def find_spans(text: str) -> list[tuple[str, int, int]]:
    """(pii type, start, end) for every validated identifier inside `text`, non-overlapping."""
    by_name = {d.name: d for d in DETECTORS}
    hits: list[tuple[str, int, int]] = []
    for name, pattern in SPANS.items():
        for m in pattern.finditer(text):
            if any(m.start() < e and s < m.end() for _, s, e in hits):
                continue
            if by_name[name].match(m.group(0)):
                hits.append((name, m.start(), m.end()))
    return sorted(hits, key=lambda h: h[1])


def _free_text(table: str, col: str, values: list[str], path: str | None) -> ColumnFinding | None:
    from .detectors import HIGH, LOW, MEDIUM

    if not values or not any(" " in v for v in values[:50]):
        return None  # only prose-like columns
    rows_with, kinds = 0, {}
    examples = []
    for v in values:
        spans = find_spans(v)
        if spans:
            rows_with += 1
            for name, *_ in spans:
                kinds[name] = kinds.get(name, 0) + 1
            if len(examples) < 2:
                examples.append(redact_text(v, spans))
    rate = rows_with / len(values)
    if rate < FREE_TEXT_THRESHOLD or rows_with < 3:
        return None
    sens = {d.name: d.sensitivity for d in DETECTORS}
    rank = {LOW: 0, MEDIUM: 1, HIGH: 2}
    worst = max((sens[k] for k in kinds), key=rank.get)
    label = "PII in free text (" + ", ".join(sorted(kinds)) + ")"
    return ColumnFinding(table, col, "free_text", label, worst, round(min(1.0, 0.5 + rate), 3), round(rate, 3), len(values),
                         "spans", examples, path)


def redact_text(text: str, spans: list[tuple[str, int, int]]) -> str:
    out, last = [], 0
    for name, s, e in spans:
        out += [text[last:s], f"[{name.upper()}]"]
        last = e
    return "".join(out + [text[last:]])


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
