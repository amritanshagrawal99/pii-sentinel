import random
import string

import pytest

from pii_sentinel.detectors import DETECTORS, gstin_check_char, luhn_valid, verhoeff_check_digit, verhoeff_valid

D = {d.name: d for d in DETECTORS}


def test_verhoeff_round_trip_and_rejection_rate():
    rng = random.Random(1)
    for _ in range(200):
        base = "".join(rng.choice(string.digits) for _ in range(11))
        assert verhoeff_valid(base + verhoeff_check_digit(base))
    rnd = ["".join(rng.choice(string.digits) for _ in range(12)) for _ in range(5000)]
    assert 0.07 < sum(map(verhoeff_valid, rnd)) / len(rnd) < 0.13  # ~1 in 10 random numbers pass by chance


def test_gstin_published_example():
    assert gstin_check_char("27AAPFU0939F1Z") == "V"
    assert D["gstin"].match("27AAPFU0939F1ZV") and not D["gstin"].match("27AAPFU0939F1ZW")


def test_luhn():
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")


@pytest.mark.parametrize("name,value,ok", [
    ("aadhaar", "234567890124", True), ("aadhaar", "2345 6789 0124", True), ("aadhaar", "2345 6789 0123", False),
    ("aadhaar", "134567890124", False),           # Aadhaar never starts with 0 or 1
    ("pan", "ABCPE1234F", True), ("pan", "ABCXE1234F", False),  # 4th char must be a valid holder type
    ("card", "4111 1111 1111 1111", True), ("card", "1234 5678 9012 3456", False),
    ("email", "a.b@example.co.in", True), ("email", "not an email", False),
    ("upi", "amrit@okhdfcbank", True), ("upi", "a@b.com", False),  # an email is not a UPI handle
    ("phone_in", "+91 98450 12345", True), ("phone_in", "09845012345", True), ("phone_in", "5845012345", False),
    ("ip", "10.0.0.1", True), ("ip", "::1", True), ("ip", "999.1.1.1", False), ("ip", "12345", False),
    ("ifsc", "HDFC0001234", True), ("ifsc", "HDFC1001234", False),
    ("passport_in", "K1234567", True), ("passport_in", "Q1234567", False),
])
def test_detectors(name, value, ok):
    assert D[name].match(value) is ok
