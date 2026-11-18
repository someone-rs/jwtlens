"""Core JWT logic for jwtlens — stdlib only.

Decode, encode and verify JSON Web Tokens (RFC 7519).

Supported algorithms:
  - HS256 / HS384 / HS512  (HMAC, sign + verify)
  - RS256 / RS384 / RS512  (RSA PKCS#1 v1.5, verify only — pure Python,
    no third-party crypto needed)
  - none                   (decode + explicit opt-in verify only)

No dependencies beyond the Python standard library.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from typing import Any, Optional

__all__ = [
    "JwtError",
    "Token",
    "b64url_encode",
    "b64url_decode",
    "decode",
    "encode",
    "verify",
    "human_time",
]

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class JwtError(ValueError):
    """Raised when a token is malformed or a verification step fails."""


# ---------------------------------------------------------------------------
# Base64url helpers
# ---------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    """Encode bytes to unpadded base64url (as used inside JWTs)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """Decode unpadded base64url, raising JwtError on bad input."""
    if not isinstance(data, str):
        raise JwtError("base64url segment must be a string")
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
           for c in data):
        raise JwtError("invalid character in base64url segment")
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise JwtError(f"invalid base64url segment: {exc}") from exc


# ---------------------------------------------------------------------------
# Token model
# ---------------------------------------------------------------------------


class Token:
    """A parsed JWT: header, payload, raw signature and signing input."""

    def __init__(self, header: dict, payload: dict, signature: bytes,
                 signing_input: str, raw: str):
        self.header = header
        self.payload = payload
        self.signature = signature
        self.signing_input = signing_input
        self.raw = raw

    @property
    def alg(self) -> str:
        return str(self.header.get("alg", ""))

    @property
    def kid(self) -> Optional[str]:
        kid = self.header.get("kid")
        return str(kid) if kid is not None else None


def _parse_json_segment(raw: bytes, what: str) -> dict:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtError(f"{what} is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise JwtError(f"{what} must be a JSON object, got {type(obj).__name__}")
    return obj


def decode(raw: str) -> Token:
    """Parse a compact-serialization JWT without verifying its signature.

    Raises JwtError for anything that is not a well-formed token.
    """
    raw = raw.strip()
    parts = raw.split(".")
    if len(parts) != 3:
        raise JwtError(
            f"expected 3 dot-separated segments, got {len(parts)} — "
            "is this a compact JWT?"
        )
    header_b64, payload_b64, signature_b64 = parts
    if not header_b64 or not payload_b64:
        raise JwtError("header and payload segments must not be empty")
    header = _parse_json_segment(b64url_decode(header_b64), "header")
    payload = _parse_json_segment(b64url_decode(payload_b64), "payload")
    signature = b64url_decode(signature_b64) if signature_b64 else b""
    return Token(header, payload, signature, f"{header_b64}.{payload_b64}", raw)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def human_time(ts: Any) -> str:
    """Render a numeric date claim as ISO-8601 UTC plus a relative hint."""
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return str(ts)
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    iso = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    delta = int(ts) - int(time.time())
    if delta < 0:
        rel = _rel(-delta) + " ago"
    else:
        rel = "in " + _rel(delta)
    return f"{iso} ({rel})"


def _rel(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def time_warnings(token: Token, now: Optional[int] = None) -> list[str]:
    """Human-readable warnings about the token's time claims."""
    now = int(time.time()) if now is None else now
    warnings: list[str] = []
    exp = token.payload.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
        if exp <= now:
            warnings.append(f"expired {human_time(exp)}")
        elif exp - now < 300:
            warnings.append(f"expires very soon ({human_time(exp)})")
    nbf = token.payload.get("nbf")
    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and nbf > now:
        warnings.append(f"not valid before {human_time(nbf)}")
    return warnings


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_RSA_ALGS = {
    "RS256": hashlib.sha256,
    "RS384": hashlib.sha384,
    "RS512": hashlib.sha512,
}

# DigestInfo prefixes for EMSA-PKCS1-v1_5 (RFC 8017 §9.2).
_DIGEST_INFO_PREFIX = {
    "RS256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "RS384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "RS512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def encode(payload: dict, key: bytes = b"", alg: str = "HS256",
           header: Optional[dict] = None, add_iat: bool = True) -> str:
    """Create a compact JWT.

    ``key`` is the HMAC secret (ignored for ``alg="none"``).
    Raises JwtError for unsupported algorithms or non-JSON payloads.
    """
    if alg not in _HMAC_ALGS and alg != "none":
        raise JwtError(
            f"cannot sign with alg={alg!r}: jwtlens signs HS256/HS384/HS512 "
            "and none only (RS* is verify-only)"
        )
    if not isinstance(payload, dict):
        raise JwtError("--payload must be a JSON object")
    hdr = {"alg": alg, "typ": "JWT"}
    if header:
        hdr.update(header)
    claims = dict(payload)
    if add_iat and "iat" not in claims:
        claims["iat"] = int(time.time())
    header_b64 = b64url_encode(json.dumps(hdr, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    if alg == "none":
        return signing_input + "."
    digest = _HMAC_ALGS[alg]
    sig = hmac.new(key, signing_input.encode("ascii"), digest).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Read one DER TLV at ``offset``; return (tag, value_start, value_end)."""
    if offset + 2 > len(data):
        raise JwtError("truncated DER data in public key")
    tag = data[offset]
    length = data[offset + 1]
    pos = offset + 2
    if length & 0x80:  # long form
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4 or pos + nbytes > len(data):
            raise JwtError("unsupported DER length in public key")
        length = int.from_bytes(data[pos:pos + nbytes], "big")
        pos += nbytes
    end = pos + length
    if end > len(data):
        raise JwtError("DER length overruns public key data")
    return tag, pos, end


def parse_rsa_public_key(pem: str) -> tuple[int, int]:
    """Extract (modulus, exponent) from a PEM SubjectPublicKeyInfo key.

    Raises JwtError on anything that is not a PEM RSA public key.
    """
    lines = [ln.strip() for ln in pem.strip().splitlines()
             if ln.strip() and not ln.startswith("-----")]
    if not lines:
        raise JwtError("no key data found — expected a PEM public key")
    try:
        der = base64.b64decode("".join(lines))
    except binascii.Error as exc:
        raise JwtError(f"PEM body is not valid base64: {exc}") from exc
    try:
        tag, spki_start, spki_end = _read_tlv(der, 0)
        if tag != 0x30:
            raise JwtError("public key is not a DER SEQUENCE")
        # Skip the AlgorithmIdentifier SEQUENCE.
        _tag, _s, alg_end = _read_tlv(der, spki_start)
        # BIT STRING holding the RSAPublicKey SEQUENCE.
        tag, bit_start, _bit_end = _read_tlv(der, alg_end)
        if tag != 0x03:
            raise JwtError("expected BIT STRING in public key")
        if der[bit_start] != 0x00:
            raise JwtError("unexpected BIT STRING padding in public key")
        tag, rsa_start, _rsa_end = _read_tlv(der, bit_start + 1)
        if tag != 0x30:
            raise JwtError("expected RSAPublicKey SEQUENCE in public key")
        _tag, n_start, n_end = _read_tlv(der, rsa_start)
        modulus = int.from_bytes(der[n_start:n_end], "big")
        _tag, e_start, e_end = _read_tlv(der, n_end)
        exponent = int.from_bytes(der[e_start:e_end], "big")
    except JwtError:
        raise
    except Exception as exc:  # malformed DER of any shape
        raise JwtError(f"could not parse RSA public key: {exc}") from exc
    if modulus <= 0 or exponent <= 0:
        raise JwtError("public key has non-positive modulus or exponent")
    return modulus, exponent


def _rsa_verify(token: Token, modulus: int, exponent: int) -> bool:
    """Verify an RS* signature with pure-Python RSA (PKCS#1 v1.5)."""
    prefix = _DIGEST_INFO_PREFIX.get(token.alg)
    if prefix is None:
        raise JwtError(f"unsupported RSA alg {token.alg!r}")
    k = (modulus.bit_length() + 7) // 8
    if len(token.signature) != k:
        return False
    em_int = pow(int.from_bytes(token.signature, "big"), exponent, modulus)
    em = em_int.to_bytes(k, "big")
    digest = _RSA_ALGS[token.alg](
        token.signing_input.encode("ascii")).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(prefix) - len(digest) - 3) \
        + b"\x00" + prefix + digest
    return hmac.compare_digest(em, expected)


def verify(token: Token, key: Optional[bytes] = None,
           public_key_pem: Optional[str] = None,
           allow_none: bool = False,
           audience: Optional[str] = None,
           issuer: Optional[str] = None,
           leeway: int = 0,
           check_exp: bool = True,
           now: Optional[int] = None) -> list[str]:
    """Verify a token's signature and claims.

    Returns a list of failure reasons; an empty list means the token is
    valid. Raises JwtError for structural problems (unknown alg, key/alg
    mismatch, unparseable key).
    """
    now = int(time.time()) if now is None else now
    failures: list[str] = []
    alg = token.alg

    # ---- signature ----
    if alg == "none":
        if not allow_none:
            failures.append(
                "alg=none: unsigned token rejected (pass --allow-none "
                "to accept it)")
        elif token.signature:
            failures.append("alg=none token must have an empty signature")
    elif alg in _HMAC_ALGS:
        if key is None:
            raise JwtError(
                f"alg={alg} needs an HMAC secret — pass --secret or "
                "--secret-file")
        if public_key_pem is not None:
            raise JwtError(
                f"alg={alg} is HMAC but a public key was given — "
                "use --secret instead")
        expected = hmac.new(key, token.signing_input.encode("ascii"),
                            _HMAC_ALGS[alg]).digest()
        if not token.signature or not hmac.compare_digest(
                expected, token.signature):
            failures.append("signature mismatch")
    elif alg in _RSA_ALGS:
        if public_key_pem is None:
            raise JwtError(
                f"alg={alg} needs an RSA public key — pass --public-key")
        modulus, exponent = parse_rsa_public_key(public_key_pem)
        if not _rsa_verify(token, modulus, exponent):
            failures.append("signature mismatch")
    else:
        raise JwtError(
            f"unsupported alg {alg!r} — jwtlens verifies "
            "HS256/HS384/HS512, RS256/RS384/RS512 and none")

    # ---- time claims ----
    if check_exp:
        exp = token.payload.get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool):
            if exp + leeway <= now:
                failures.append(f"token expired at {human_time(exp)}")
    nbf = token.payload.get("nbf")
    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool):
        if nbf - leeway > now:
            failures.append(f"token not valid before {human_time(nbf)}")

    # ---- audience / issuer ----
    if audience is not None:
        aud = token.payload.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if audience not in auds:
            failures.append(
                f"audience mismatch: expected {audience!r}, got {aud!r}")
    if issuer is not None:
        if token.payload.get("iss") != issuer:
            failures.append(
                f"issuer mismatch: expected {issuer!r}, "
                f"got {token.payload.get('iss')!r}")

    return failures
