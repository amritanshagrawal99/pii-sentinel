# pii-sentinel

[![CI](https://github.com/amritanshagrawal99/pii-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/amritanshagrawal99/pii-sentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Find the personal data in your warehouse tables, and generate the masking policies for it.** It understands Indian
identifiers: **Aadhaar** (Verhoeff checksum), **PAN**, **GSTIN** (mod-36 check character), **UPI IDs**, **IFSC** and Indian
mobile numbers, alongside emails, payment cards (Luhn), passports, IPs, names, addresses and dates of birth.

With India's DPDP Act in force, "where is our PII and is it masked?" is a question every data team gets asked. Regex-only
scanners drown you in false positives: any 12-digit order number "looks like" an Aadhaar. pii-sentinel samples the values,
**validates checksums**, and requires most of a column to match before flagging it.

```bash
pip install "pii-sentinel[duckdb] @ git+https://github.com/amritanshagrawal99/pii-sentinel.git"
python examples/make_customer_db.py customers.duckdb        # synthetic data: real-looking, valid checksums, all fake
pii-sentinel scan --url duckdb:///customers.duckdb --all --policies snowflake -o masking.sql
```

> # PII scan: 11 column(s) flagged
>
> | Table | Column | Type | Sensitivity | Confidence | Evidence | Masked sample |
> |---|---|---|---|---|---|---|
> | `main.customers` | `aadhaar_no` | Aadhaar number | high | 100% | values+name (100% of 500) | `XXXXXXXX9131`, `XXXXXXXX4125` |
> | `main.customers` | `card_number` | Payment card number | high | 100% | values+name (100% of 500) | `XXXXXXXXXXXX0588`, ... |
> | `main.customers` | `pan` | PAN | high | 100% | values+name (100% of 500) | `*****`, `*****` |
> | `main.customers` | `email` | Email address | medium | 100% | values+name (100% of 500) | `a***@example.com`, ... |
> | `main.customers` | `upi_handle` | UPI ID | medium | 100% | values+name (100% of 500) | `a***@okaxis`, `p***@ybl` |
> | `main.customers` | `mobile` | Indian mobile number | medium | 100% | values+name (100% of 500) | `XXXXXX0830`, ... |
> | `main.vendors` | `gstin` | GSTIN | low | 100% | values+name (100% of 100) | `*****`, `*****` |
> | ... | | | | | | |

The same table has decoy columns that are **not** flagged: `order_ref` (12 random digits), free-text `notes`, `segment`,
`sku`. The report never prints raw values, only masked previews.

### Inside JSON, STRUCT and ARRAY values

Event payloads and API logs hide PII deep inside documents. When most values of a column are JSON objects or arrays (or
`STRUCT` / `LIST` values), every leaf path is classified separately, and the last key acts as the column-name hint:

> | Table | Column | Type | Sensitivity | Confidence | Evidence |
> |---|---|---|---|---|---|
> | `events` | `payload.customer.contact.email` | Email address | medium | 100% | values+name (100% of 300) |
> | `events` | `payload.customer.phone` | Indian mobile number | medium | 100% | values+name (100% of 300) |
> | `events` | `payload.payments[].upi` | UPI ID | medium | 100% | values+name (100% of 448) |
> | `events` | `device.ip` | IP address | low | 100% | values+name (100% of 300) |

`payload.order.ref` (12 random digits) is not flagged. Masking policies apply to whole columns, so nested findings come
with a commented block in the policy SQL listing the paths, instead of a policy that would silently hide the whole document.

### Inside free text

Support notes and comments leak identifiers that aren't a column of their own. Text columns are searched for identifiers
*inside* the prose. Every candidate span is validated with the same checks as above, and the column is flagged when at
least 5% of rows contain one:

> | `customers` | `notes` | PII in free text (email, phone_in) | medium | 75% | spans (25% of 500) | `send invoice to [EMAIL]` |

`order 2345 6789 0123 delayed` in the same column is not counted, because the number fails the Verhoeff check. The policy
for a free-text column is a redaction, not a full mask, so the rest of the note stays readable:

```sql
REGEXP_REPLACE(REGEXP_REPLACE(... REGEXP_REPLACE(val, '<email>', '[EMAIL]') ..., '<phone>', '[PHONE_IN]')
```

The SQL regexes use no backslashes or lookarounds, so the same text works in Snowflake's POSIX regex and Databricks' Java
regex. They're tested to produce the same output as the Python redaction on real identifiers. SQL can't run checksums, so
it also redacts look-alikes such as that order number. For redaction, that's the safe direction.

## Generated policies

```sql
CREATE MASKING POLICY IF NOT EXISTS pii_mask_aadhaar AS (val STRING) RETURNS STRING ->
  CASE WHEN IS_ROLE_IN_SESSION('PII_READER') THEN val
       ELSE CONCAT(REPEAT('X', GREATEST(LENGTH(REGEXP_REPLACE(val, '[^0-9]', '')) - 4, 0)),
                   RIGHT(REGEXP_REPLACE(val, '[^0-9]', ''), 4)) END;

ALTER TABLE main.customers MODIFY COLUMN aadhaar_no SET TAG pii_type = 'aadhaar';
ALTER TABLE main.customers MODIFY COLUMN aadhaar_no SET MASKING POLICY pii_mask_aadhaar;
```

`--policies databricks` produces the Unity Catalog equivalent:
`CREATE FUNCTION governance.mask_aadhaar(val STRING) RETURN CASE WHEN is_account_group_member('pii_readers') ...`, plus
`ALTER TABLE ... ALTER COLUMN ... SET MASK` and column tags.

Masking keeps the **last 4 digits** for Aadhaar, cards and phones (what people use to confirm identity), **first letter and
domain** for emails and UPI IDs, and masks everything else fully. The Snowflake and Databricks expressions are tested by
transpiling them to DuckDB with sqlglot, executing them, and comparing with the Python previews in the report.

## How a column is classified

1. Sample up to `--sample` (1000) non-null values.
2. Run every detector. Checksummed types (Aadhaar, GSTIN, cards) must validate, not just look right.
3. Flag the column if **60%** of values match, or **30%** if the column name agrees (`mobile`, `aadhaar_no`, `pan`, ...).
   A matching name adds 15 points of confidence.
4. Columns whose values have no checkable shape (names, addresses, dates of birth) are flagged from the column name alone,
   at 50% confidence, for review.

Why the thresholds matter: about **1 in 10** random 12-digit numbers passes the Verhoeff check by chance. A column of order
numbers therefore matches about 10% of the time, far below 60%. The tests assert both the rejection rate and that the decoy
column isn't flagged.

## In CI

```bash
pii-sentinel scan --url duckdb:///staging.duckdb --all --fail-on high    # fail when a high-sensitivity column appears
```

Any DB-API 2.0 connection works from Python: `pii_sentinel.scanner.scan_table(conn, "schema.table")`, for example with
Snowflake or Databricks SQL connectors. The CLI opens DuckDB and SQLite files read-only.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest && ruff check src tests examples
```

## License

[MIT](LICENSE). Synthetic example data only; no real identifiers are included or generated from real people.
