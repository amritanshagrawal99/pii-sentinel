"""Value-level PII detectors. Identifiers with a checksum are validated, not just pattern-matched, so that
order numbers and other look-alike codes are not flagged."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass

HIGH, MEDIUM, LOW = "high", "medium", "low"

# ------------------------------------------------------------------ checksums

_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


_GST_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_char(first14: str) -> str:
    total = 0
    for i, ch in enumerate(first14):
        v = _GST_CHARS.index(ch) * (2 if i % 2 else 1)
        total += v // 36 + v % 36
    return _GST_CHARS[(36 - total % 36) % 36]


# ------------------------------------------------------------------ detectors

@dataclass(frozen=True)
class Detector:
    name: str
    label: str
    sensitivity: str
    match: Callable[[str], bool]
    name_hints: tuple[str, ...] = ()


def _digits(v: str) -> str:
    return re.sub(r"[\s\-]", "", v)


_AADHAAR = re.compile(r"^[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}$")
_PAN = re.compile(r"^[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]$")
_GSTIN = re.compile(r"^(0[1-9]|[1-3]\d)[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")
_IFSC = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
_UPI = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z][A-Za-z0-9]{1,63}$")  # handle@bank: no dot in the PSP part
_IN_MOBILE = re.compile(r"^(?:\+?91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5}$")
_CARD = re.compile(r"^\d{4}([\s\-]?\d{4}){2,3}(\d{1,3})?$")
_PASSPORT_IN = re.compile(r"^[A-PR-WY][1-9]\d\s?\d{4}[1-9]$")


def _aadhaar(v: str) -> bool:
    return bool(_AADHAAR.match(v)) and verhoeff_valid(_digits(v))


def _gstin(v: str) -> bool:
    return bool(_GSTIN.match(v)) and gstin_check_char(v[:14]) == v[14]


def _card(v: str) -> bool:
    d = _digits(v)
    return bool(_CARD.match(v)) and 13 <= len(d) <= 19 and d[0] in "3456" and luhn_valid(d)


def _ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return "." in v or ":" in v


DETECTORS: tuple[Detector, ...] = (
    Detector("aadhaar", "Aadhaar number", HIGH, _aadhaar, ("aadhaar", "aadhar", "uid", "uidai")),
    Detector("pan", "PAN", HIGH, lambda v: bool(_PAN.match(v)), ("pan",)),
    Detector("card", "Payment card number", HIGH, _card, ("card", "cc_", "ccnum", "pan_number")),
    Detector("passport_in", "Indian passport number", HIGH, lambda v: bool(_PASSPORT_IN.match(v)), ("passport",)),
    Detector("gstin", "GSTIN", LOW, _gstin, ("gst", "gstin")),
    Detector("email", "Email address", MEDIUM, lambda v: bool(_EMAIL.match(v)), ("email", "e_mail", "mail")),
    Detector("upi", "UPI ID", MEDIUM, lambda v: bool(_UPI.match(v)) and not _EMAIL.match(v), ("upi", "vpa")),
    Detector("phone_in", "Indian mobile number", MEDIUM, lambda v: bool(_IN_MOBILE.match(v)), ("phone", "mobile", "msisdn", "contact")),
    Detector("ip", "IP address", LOW, _ip, ("ip", "ip_address", "client_ip")),
    Detector("ifsc", "IFSC code", LOW, lambda v: bool(_IFSC.match(v)), ("ifsc",)),
)

# Columns that are personal by name even when values have no checkable pattern.
NAME_ONLY = (
    ("person_name", "Person name", MEDIUM, ("first_name", "last_name", "full_name", "customer_name", "given_name", "surname")),
    ("address", "Postal address", MEDIUM, ("address", "addr_line", "street", "pincode", "pin_code", "zipcode")),
    ("dob", "Date of birth", HIGH, ("dob", "date_of_birth", "birth_date", "birthdate")),
)
