"""Build a DuckDB file with realistic synthetic customer data, PII mixed with look-alike decoys.

    python examples/make_customer_db.py customers.duckdb
    pii-sentinel scan --url duckdb:///customers.duckdb --all --policies snowflake

Every identifier is generated with a valid checksum (Verhoeff for Aadhaar, Luhn for cards, mod-36 for GSTIN), and
every value is fake. Decoy columns (12-digit order numbers, product codes, free text) must NOT be flagged.
"""
import json
import random
import string
import sys

import duckdb

from pii_sentinel.detectors import gstin_check_char, luhn_valid, verhoeff_check_digit

rng = random.Random(7)
FIRST = ["Asha", "Vikram", "Meera", "Rohan", "Priya", "Arjun", "Kavya", "Nikhil"]
LAST = ["Rao", "Iyer", "Nair", "Sharma", "Reddy", "Gupta", "Menon", "Das"]
BANKS = ["okhdfcbank", "okaxis", "oksbi", "ybl", "paytm"]


def aadhaar():
    base = str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(10))
    d = base + verhoeff_check_digit(base)
    return f"{d[:4]} {d[4:8]} {d[8:]}" if rng.random() < 0.5 else d


def pan(kind="P"):
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(3)) + kind + rng.choice(string.ascii_uppercase) + \
        f"{rng.randint(0, 9999):04d}" + rng.choice(string.ascii_uppercase)


def gstin():
    first = f"{rng.randint(1, 37):02d}" + pan("C") + str(rng.randint(1, 9)) + "Z"
    return first + gstin_check_char(first)


def card():
    while True:
        d = "4" + "".join(rng.choice(string.digits) for _ in range(15))
        if luhn_valid(d):
            return " ".join(d[i:i + 4] for i in range(0, 16, 4))


def phone():
    n = str(rng.choice("6789")) + "".join(rng.choice(string.digits) for _ in range(9))
    return rng.choice([n, "+91 " + n[:5] + " " + n[5:], "0" + n])


def main(path: str) -> None:
    con = duckdb.connect(path)
    con.execute("""CREATE OR REPLACE TABLE customers (customer_id INTEGER, full_name VARCHAR, email VARCHAR, mobile VARCHAR,
                   aadhaar_no VARCHAR, pan VARCHAR, upi_handle VARCHAR, card_number VARCHAR, address VARCHAR,
                   segment VARCHAR, order_ref VARCHAR, notes VARCHAR, last_login_ip VARCHAR)""")
    rows = []
    for i in range(500):
        name = f"{rng.choice(FIRST)} {rng.choice(LAST)}"
        handle = name.lower().replace(" ", ".") + str(rng.randint(1, 99))
        rows.append((i, name, handle + "@example.com", phone(), aadhaar(), pan(), handle + "@" + rng.choice(BANKS), card(),
                     f"{rng.randint(1, 300)}, MG Road, Bengaluru 5600{rng.randint(10, 99)}",
                     rng.choice(["retail", "sme", "premium"]),
                     "".join(rng.choice(string.digits) for _ in range(12)),  # decoy: 12-digit order number
                     rng.choice(["call back later", "prefers email", "", "VIP"]),
                     f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"))
    con.executemany("INSERT INTO customers VALUES (" + ", ".join("?" * 13) + ")", rows)
    con.execute("CREATE OR REPLACE TABLE vendors (vendor_id INTEGER, legal_name VARCHAR, gstin VARCHAR, ifsc VARCHAR, sku VARCHAR)")
    con.executemany("INSERT INTO vendors VALUES (?, ?, ?, ?, ?)", [
        (i, f"Vendor {i} Pvt Ltd", gstin(), "HDFC0" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(6)),
         "SKU-" + "".join(rng.choice(string.ascii_uppercase) for _ in range(3)) + str(rng.randint(100, 999))) for i in range(100)])
    # Semi-structured: PII nested at different depths inside JSON and STRUCT values, next to nested decoys.
    con.execute("CREATE OR REPLACE TABLE events (event_id INTEGER, payload JSON, device STRUCT(os VARCHAR, ip VARCHAR))")
    events = []
    for i in range(300):
        doc = {"type": rng.choice(["checkout", "refund"]), "order": {"ref": "".join(rng.choice(string.digits) for _ in range(12)),
               "total": round(rng.random() * 5000, 2)},
               "customer": {"phone": phone(), "contact": {"email": f"user{i}@example.com"}},
               "payments": [{"upi": f"user{i}@{rng.choice(BANKS)}", "amount": 100} for _ in range(rng.randint(1, 2))]}
        events.append((i, json.dumps(doc), {"os": rng.choice(["android", "ios"]),
                                             "ip": f"49.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"}))
    con.executemany("INSERT INTO events VALUES (?, ?, ?)", events)
    con.close()
    print(f"wrote {path}: customers (500 rows), vendors (100 rows), events (300 rows, JSON + STRUCT)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "customers.duckdb")
