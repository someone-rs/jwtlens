"""Tests for jwtlens — decode, encode, verify, RSA, and the CLI."""

import json
import time

import pytest

from jwtlens.core import (
    JwtError, b64url_decode, b64url_encode, decode, encode,
    parse_rsa_public_key, time_warnings, verify,
)
from jwtlens.cli import main

# The RFC 7519 §3.1 example token, signed with "your-256-bit-secret".
RFC_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
RFC_SECRET = b"your-256-bit-secret"

# RS256 token signed with the test key below (openssl dgst -sha256 -sign).
RS256_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkYSBMb3ZlbGFjZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9"
    ".IPvBitaJRubNqtGQ-ONP-Q1hIiu6XmwCn7w_zSW90_z9kb85vsYLs-FJOplZnOfHUFblIcRnMMFdstYOUQYy9daLJO6kKCis0Uly4H7Jzul9pUHxQTYHyc8Y6uVydMhpYjTnvgwWVUqC1afc3GEgHZJWb_xM3S-TORNzulmRhde1nmi2ccZH5JdGev6dNA4_QJXuX050tvWSM-Zb-MN8zHPmg9VhmDraabfpclGG7GtA6ridC_kogMMfmtvyYmHGpZcFhcJW0sUXk3ueNd3s49DPCsiTyeZoeLlVx8WWEx3XI7EX45DA18SmfogyxlXvRlbU6FnjePg3Bc1RBS9_DA"
)
RS256_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjkhW8XTEbg3kxFeVKbBI
AUxDL8sKRDIMHZUY48tYbx6M9yvaosLTcjVKer2cvM2WQH1EIP7UySOiGBbcnvqy
IpGKyCHhciz1desSU7sOCtcic+89bhUQ7VkCylGm8g0fGbjIDZiP1NTFkyjAlV60
UdV3w6YjdbpmawG0JWwVdItQOdavz8Qlif4ZdekWd/lxFID6r662prqO34BulS4v
cOqJnb26jiymAfJ8F/pNZq3DF7dTD3UfZDproUKAy44l1/J4ymSgxg+1tadYUZCe
LyKhK6f2BDwgNec0tROVTu6zKeruNgP3ckh6chEM57dTC1pn7Jsxl/6U3k5G0uJv
QwIDAQAB
-----END PUBLIC KEY-----"""


# ---------------------------------------------------------------------------
# base64url
# ---------------------------------------------------------------------------


def test_b64url_roundtrip():
    for raw in (b"", b"a", b"hello world", bytes(range(256))):
        assert b64url_decode(b64url_encode(raw)) == raw
    assert b64url_encode(b"hello") == "aGVsbG8"  # no padding


def test_b64url_rejects_bad_chars():
    with pytest.raises(JwtError):
        b64url_decode("ab+c/")
    with pytest.raises(JwtError):
        b64url_decode("ab=c")


# ---------------------------------------------------------------------------
# decode
# ---------------------------------------------------------------------------


def test_decode_rfc_example():
    token = decode(RFC_TOKEN)
    assert token.header == {"alg": "HS256", "typ": "JWT"}
    assert token.payload["sub"] == "1234567890"
    assert token.payload["name"] == "John Doe"
    assert token.payload["iat"] == 1516239022
    assert token.alg == "HS256"
    assert token.signature  # non-empty


def test_decode_rejects_wrong_segment_count():
    for bad in ("abc", "a.b", "a.b.c.d", "", "  "):
        with pytest.raises(JwtError):
            decode(bad)


def test_decode_rejects_non_json_payload():
    bad_payload = b64url_encode(b"not json")
    with pytest.raises(JwtError):
        decode(f"e30.{bad_payload}.abc")


def test_decode_rejects_non_object():
    arr = b64url_encode(b"[1,2,3]")
    with pytest.raises(JwtError):
        decode(f"e30.{arr}.abc")


# ---------------------------------------------------------------------------
# encode / verify (HMAC)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
def test_hmac_roundtrip(alg):
    token = encode({"sub": "42", "role": "admin"}, key=b"s3cr3t", alg=alg,
                   add_iat=False)
    parsed = decode(token)
    assert parsed.payload["sub"] == "42"
    assert verify(parsed, key=b"s3cr3t") == []
    assert verify(parsed, key=b"wrong") == ["signature mismatch"]


def test_encode_matches_rfc_vector():
    token = encode({"sub": "1234567890", "name": "John Doe",
                    "iat": 1516239022}, key=RFC_SECRET, alg="HS256",
                   add_iat=False)
    assert token == RFC_TOKEN


def test_encode_adds_iat_by_default():
    token = encode({"sub": "1"}, key=b"k", add_iat=True)
    assert abs(decode(token).payload["iat"] - int(time.time())) <= 2


def test_encode_none_produces_empty_signature():
    token = encode({"sub": "1"}, alg="none", add_iat=False)
    assert token.endswith(".")
    assert decode(token).signature == b""


def test_encode_rejects_rs_signing():
    with pytest.raises(JwtError, match="cannot sign"):
        encode({"sub": "1"}, alg="RS256")


def test_encode_rejects_non_object_payload():
    with pytest.raises(JwtError):
        encode(["not", "a", "dict"])  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# verify: claims
# ---------------------------------------------------------------------------


def _token_with(payload, key=b"s3cr3t", alg="HS256"):
    return decode(encode(payload, key=key, alg=alg, add_iat=False))


def test_verify_expired_token_fails():
    token = _token_with({"sub": "1", "exp": int(time.time()) - 10})
    failures = verify(token, key=b"s3cr3t")
    assert any("expired" in f for f in failures)


def test_verify_expired_token_passes_with_ignore():
    token = _token_with({"sub": "1", "exp": int(time.time()) - 10})
    assert verify(token, key=b"s3cr3t", check_exp=False) == []


def test_verify_leeway_covers_small_skew():
    token = _token_with({"sub": "1", "exp": int(time.time()) - 30})
    assert verify(token, key=b"s3cr3t", leeway=60) == []
    assert verify(token, key=b"s3cr3t", leeway=10) != []


def test_verify_nbf_in_future_fails():
    token = _token_with({"sub": "1", "nbf": int(time.time()) + 600})
    failures = verify(token, key=b"s3cr3t")
    assert any("not valid before" in f for f in failures)


def test_verify_audience_and_issuer():
    token = _token_with({"sub": "1", "aud": "api", "iss": "auth.example"})
    assert verify(token, key=b"s3cr3t", audience="api",
                  issuer="auth.example") == []
    assert any("audience" in f for f in
               verify(token, key=b"s3cr3t", audience="other"))
    assert any("issuer" in f for f in
               verify(token, key=b"s3cr3t", issuer="other"))
    # aud as a list also works
    token2 = _token_with({"sub": "1", "aud": ["web", "api"]})
    assert verify(token2, key=b"s3cr3t", audience="api") == []


def test_verify_none_rejected_by_default():
    token = decode(encode({"sub": "1"}, alg="none", add_iat=False))
    failures = verify(token)
    assert any("alg=none" in f for f in failures)
    assert verify(token, allow_none=True) == []


def test_verify_none_with_signature_rejected_even_when_allowed():
    token = decode(encode({"sub": "1"}, alg="none", add_iat=False))
    token.signature = b"forged"
    failures = verify(token, allow_none=True)
    assert any("empty signature" in f for f in failures)


def test_verify_requires_key_for_hmac():
    with pytest.raises(JwtError, match="needs an HMAC secret"):
        verify(decode(RFC_TOKEN))


def test_verify_rejects_unknown_alg():
    token = decode(encode({"sub": "1"}, key=b"k", add_iat=False))
    token.header["alg"] = "ES256"
    with pytest.raises(JwtError, match="unsupported alg"):
        verify(token, key=b"k")


def test_time_warnings():
    now = int(time.time())
    expired = _token_with({"exp": now - 3600})
    assert any("expired" in w for w in time_warnings(expired))
    future = _token_with({"nbf": now + 3600})
    assert any("not valid before" in w for w in time_warnings(future))
    healthy = _token_with({"exp": now + 3600})
    assert time_warnings(healthy) == []


# ---------------------------------------------------------------------------
# RSA (pure-python verify)
# ---------------------------------------------------------------------------


def test_parse_rsa_public_key():
    n, e = parse_rsa_public_key(RS256_PUBLIC_KEY)
    assert e == 65537
    assert n.bit_length() == 2048


def test_parse_rsa_public_key_rejects_garbage():
    with pytest.raises(JwtError):
        parse_rsa_public_key("not a key at all")
    with pytest.raises(JwtError):
        parse_rsa_public_key("-----BEGIN PUBLIC KEY-----\n@@@\n-----END PUBLIC KEY-----")


def test_rs256_verify_ok():
    token = decode(RS256_TOKEN)
    assert token.header["alg"] == "RS256"
    assert verify(token, public_key_pem=RS256_PUBLIC_KEY) == []


def test_rs256_tampered_payload_fails():
    token = decode(RS256_TOKEN)
    # Change a claim and re-encode the payload without re-signing.
    claims = dict(token.payload)
    claims["name"] = "Eve Attacker"
    header_b64, _payload_b64, sig_b64 = token.raw.split(".")
    tampered = (f"{header_b64}."
                f"{b64url_encode(json.dumps(claims, separators=(',', ':')).encode())}."
                f"{sig_b64}")
    assert verify(decode(tampered), public_key_pem=RS256_PUBLIC_KEY) == [
        "signature mismatch"]


def test_rs256_needs_public_key():
    with pytest.raises(JwtError, match="needs an RSA public key"):
        verify(decode(RS256_TOKEN))


def test_rs256_wrong_key_type_rejected():
    with pytest.raises(JwtError, match="needs an HMAC secret"):
        verify(decode(RFC_TOKEN), public_key_pem=RS256_PUBLIC_KEY)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_decode_rfc(capsys):
    assert main(["decode", RFC_TOKEN]) == 0
    out = capsys.readouterr().out
    assert "John Doe" in out
    assert "1234567890" in out
    assert "2018-01-18" in out  # human-readable iat


def test_cli_decode_json(capsys):
    assert main(["decode", "--json", RFC_TOKEN]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["payload"]["name"] == "John Doe"


def test_cli_decode_malformed(capsys):
    assert main(["decode", "not.a.token"]) == 2


def test_cli_verify_ok(capsys):
    assert main(["verify", RFC_TOKEN, "--secret", "your-256-bit-secret"]) == 0
    assert "VALID" in capsys.readouterr().out


def test_cli_verify_bad_secret(capsys):
    assert main(["verify", RFC_TOKEN, "--secret", "nope"]) == 1
    assert "INVALID" in capsys.readouterr().out


def test_cli_verify_expired(capsys):
    token = encode({"sub": "1", "exp": int(time.time()) - 5},
                   key=b"k", add_iat=False)
    assert main(["verify", token, "--secret", "k"]) == 1
    assert main(["verify", token, "--secret", "k", "--ignore-exp"]) == 0


def test_cli_verify_json(capsys):
    assert main(["verify", "--json", RFC_TOKEN,
                 "--secret", "your-256-bit-secret"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {"valid": True, "failures": []}


def test_cli_verify_rs256(capsys):
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".pem",
                                     delete=False) as fh:
        fh.write(RS256_PUBLIC_KEY)
        path = fh.name
    try:
        assert main(["verify", RS256_TOKEN, "--public-key", path]) == 0
        assert "VALID" in capsys.readouterr().out
    finally:
        os.unlink(path)


def test_cli_encode_roundtrip(capsys):
    assert main(["encode", "--payload", '{"sub":"7"}',
                 "--secret", "k", "--no-iat"]) == 0
    token = capsys.readouterr().out.strip()
    assert main(["verify", token, "--secret", "k"]) == 0


def test_cli_encode_needs_secret(capsys):
    assert main(["encode", "--payload", '{"sub":"7"}']) == 2


def test_cli_encode_none(capsys):
    assert main(["encode", "--payload", '{"sub":"7"}', "--alg", "none",
                 "--no-iat"]) == 0
    token = capsys.readouterr().out.strip()
    assert token.endswith(".")
    assert main(["verify", token]) == 1  # none rejected by default
    assert main(["verify", token, "--allow-none"]) == 0


def test_cli_token_from_stdin(capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(RFC_TOKEN + "\n"))
    assert main(["decode", "-"]) == 0
    assert "John Doe" in capsys.readouterr().out
