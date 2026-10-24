import subprocess
import sys
from pathlib import Path

import duckdb
import pytest
import sqlglot

from pii_sentinel.cli import main
from pii_sentinel.masks import _sql_expr, databricks_masks, preview, snowflake_policies
from pii_sentinel.scanner import classify, scan_table

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    path = tmp_path_factory.mktemp("db") / "customers.duckdb"
    subprocess.run([sys.executable, str(ROOT / "examples" / "make_customer_db.py"), str(path)], check=True, capture_output=True)
    return path


@pytest.fixture(scope="module")
def findings(db):
    con = duckdb.connect(str(db), read_only=True)
    out = scan_table(con, "customers") + scan_table(con, "vendors")
    con.close()
    return {f.column: f for f in out}


def test_every_pii_column_found(findings):
    assert {c: f.pii for c, f in findings.items()} == {
        "full_name": "person_name", "email": "email", "mobile": "phone_in", "aadhaar_no": "aadhaar", "pan": "pan",
        "upi_handle": "upi", "card_number": "card", "address": "address", "last_login_ip": "ip",
        "gstin": "gstin", "ifsc": "ifsc"}


def test_decoys_not_flagged(findings):
    for decoy in ("customer_id", "segment", "order_ref", "notes", "vendor_id", "legal_name", "sku"):
        assert decoy not in findings  # order_ref is 12 random digits: ~10% pass Verhoeff, far below the threshold


def test_report_never_contains_raw_values(findings):
    f = findings["aadhaar_no"]
    assert all(e.startswith("XXXXXXXX") for e in f.examples)
    assert findings["pan"].examples == ["*****", "*****"]


def test_value_evidence_beats_misleading_name():
    det, conf, rate, evidence = classify("notes", ["call me at 9845012345"] * 10)
    assert det is None  # partial matches in free text are not a phone column
    det, *_ = classify("contact", ["9845012345"] * 4 + ["n/a"] * 6)
    assert det is not None and det.name == "phone_in"  # 40% match is enough when the name agrees


@pytest.mark.parametrize("dialect", ["snowflake", "databricks"])
@pytest.mark.parametrize("pii,value", [("aadhaar", "2345 6789 0124"), ("card", "4111-1111-1111-1111"),
                                       ("phone_in", "+91 98450 12345"), ("email", "amrit@example.com"), ("pan", "ABCPE1234F")])
def test_masking_sql_matches_preview(dialect, pii, value):
    """Execute each policy expression (transpiled to DuckDB) and compare with the Python preview."""
    sql = sqlglot.transpile(f"SELECT {_sql_expr(pii, dialect)} FROM (SELECT ? AS val)", read=dialect, write="duckdb")[0]
    assert duckdb.connect().execute(sql, [value]).fetchone()[0] == preview(pii, value)


def test_policy_sql_parses(findings):
    for sql, dialect in ((snowflake_policies(findings.values()), "snowflake"), (databricks_masks(findings.values()), "databricks")):
        for stmt in [s for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]:
            if "MASKING POLICY" in stmt and "CREATE" in stmt or "SET MASK" in stmt or "SET TAG" in stmt or "CREATE TAG" in stmt:
                continue  # sqlglot has no grammar for these governance statements
            sqlglot.parse_one(stmt, read=dialect)
        assert "pii_mask_aadhaar" in sql or "mask_aadhaar" in sql


def test_cli_fail_on_and_policies(db, tmp_path, capsys):
    out = tmp_path / "p.sql"
    rc = main(["scan", "--url", f"duckdb:///{db}", "--all", "--policies", "databricks", "-o", str(out), "--fail-on", "high"])
    assert rc == 1 and "SET MASK governance.mask_aadhaar" in out.read_text()
    assert "# PII scan: 11 column(s) flagged" in capsys.readouterr().out
    assert main(["scan", "--url", f"duckdb:///{db}", "--table", "vendors", "--fail-on", "high"]) == 0
