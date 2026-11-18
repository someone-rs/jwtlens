# jwtlens 🔍

[![PyPI](https://img.shields.io/pypi/v/jwtlens)](https://pypi.org/project/jwtlens/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-42%20passing-brightgreen)](#testing)

**Decode, verify and mint JSON Web Tokens from your terminal — offline, stdlib-only.**

No dependencies. No network calls. No telemetry. Paste a token, see exactly
what's inside it — including when it expires, in plain language.

```console
$ jwtlens decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Header
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload
  sub: "1234567890"
  name: "John Doe"
  iat: 1516239022  →  2018-01-18 01:30:22 UTC (3226d 2h ago)

Signature (HS256): 49f94ac7044948c78a285d904f87f0a4c7897f7e8f3a4eb2255fda750b2cc397
```

## Install

```console
pip install jwtlens
```

Requires Python 3.9+. Zero dependencies — the whole tool is the standard
library.

## Why jwtlens?

- **Decode** any token and read its claims as human dates (`exp` becomes
  `2026-11-18 05:09:22 UTC (in 1h 0m)`), with warnings when a token is
  already expired, not yet valid, or unsigned.
- **Verify** HMAC (`HS256/384/512`) and RSA (`RS256/384/512`) signatures.
  The RSA check is implemented in pure Python (PKCS#1 v1.5, `pow()` and
  `hashlib`) — that's why there are no dependencies at all.
- **Mint** tokens for testing, with `--exp-in 3600` so you never hand-compute
  an expiry timestamp again.
- **Script-friendly**: exit codes `0` valid / `1` invalid / `2` usage error,
  plus `--json` output for every subcommand. Tokens can come from an
  argument, stdin (`-`), or `@file`.

## Usage

### Decode — see what's inside a token

```console
$ jwtlens decode <token>
$ echo <token> | jwtlens decode -
$ jwtlens decode @token.txt --json
```

`decode` never verifies anything — it just shows you the claims, with
warnings for expired tokens, tokens that aren't valid yet, and `alg=none`
(unsigned) tokens.

### Verify — is this token real, and is it still good?

```console
$ jwtlens verify <token> --secret your-256-bit-secret
✓ VALID
  alg: HS256
  sub: "1234567890"
  name: "John Doe"
  iat: 1516239022  →  2018-01-18 01:30:22 UTC (3226d 2h ago)
```

```console
$ jwtlens verify <token> --secret wrong-secret
✗ INVALID
  - signature mismatch
```

RSA tokens verify against a PEM public key (see `demo/test-public-key.pem`
and `demo/rs256-token.txt` for a working pair):

```console
$ jwtlens verify <token> --public-key public.pem
✓ VALID
  alg: RS256
  ...
```

Useful flags:

| Flag | What it does |
| --- | --- |
| `--secret` / `--secret-file` | HMAC secret (or a file holding it — keeps secrets out of shell history) |
| `--public-key FILE` | PEM RSA public key for RS\* tokens |
| `--aud EXPECTED` | require a matching `aud` claim |
| `--iss EXPECTED` | require a matching `iss` claim |
| `--leeway SECONDS` | tolerate clock skew on `exp`/`nbf` |
| `--ignore-exp` | skip the expiry check |
| `--allow-none` | accept unsigned (`alg=none`) tokens — off by default, for a reason |
| `--json` | emit `{"valid": true, "failures": []}` |

### Encode — mint a token for testing

```console
$ jwtlens encode --payload '{"sub":"42","role":"admin"}' --secret hunter2 --exp-in 3600
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc5NDk3ODU2MiwiaWF0IjoxNzk0OTc0OTYyfQ.V_aI2rQmDnp66zH_E68wOUo0TA_HPWlq1-lA62xKruU
```

`--exp-in SECONDS` sets `exp` to now + that many seconds, and `iat` is added
automatically unless you pass `--no-iat`. `--alg` accepts `HS256` (default),
`HS384`, `HS512`, or `none`. RSA signing is intentionally not supported —
private keys should stay in your key manager, not in a CLI.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | success / token valid |
| `1` | token invalid (bad signature, expired, wrong audience, …) |
| `2` | usage error (malformed token, missing secret, bad JSON, …) |

## Security notes

- **Never paste a production token into an online decoder.** jwtlens runs
  entirely on your machine for exactly this reason.
- `alg=none` tokens are rejected by `verify` unless you pass `--allow-none`.
  An unsigned token proves nothing about who made it.
- Secrets passed with `--secret` stay in your shell history — prefer
  `--secret-file` in scripts.
- jwtlens is a debugging tool, not an auth library. For verifying tokens
  inside your application, use a maintained JWT library for your stack.

## Library use

```python
from jwtlens.core import decode, verify

token = decode("eyJhbGciOiJIUzI1NiIs...")
print(token.payload["sub"])
failures = verify(token, key=b"your-256-bit-secret")
assert failures == []  # empty list == valid
```

## Testing

```console
pip install pytest
pytest -q
# 42 passed
```

The suite covers the RFC 7519 example token byte-for-byte, HMAC round-trips
for all three algorithms, expiry/`nbf`/audience/issuer checks, `alg=none`
handling, and a real RS256 token verified against its public key — all
offline.

## License

MIT — see [LICENSE](LICENSE).
