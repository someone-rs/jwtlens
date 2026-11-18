"""Command-line interface for jwtlens.

Subcommands:
  jwtlens decode <token>   pretty-print header + payload, flag time issues
  jwtlens verify <token>   check signature and claims, exit 0/1/2
  jwtlens encode ...       mint a token (HS256/HS384/HS512 or none)
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import __version__
from .core import JwtError, decode, encode, human_time, time_warnings, verify

# ---------------------------------------------------------------------------
# Terminal colours (plain ANSI, no dependencies)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _color(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def red(text: str) -> str:
    return _color("31", text)


def green(text: str) -> str:
    return _color("32", text)


def yellow(text: str) -> str:
    return _color("33", text)


def cyan(text: str) -> str:
    return _color("36", text)


def bold(text: str) -> str:
    return _color("1", text)


# ---------------------------------------------------------------------------
# Token input
# ---------------------------------------------------------------------------


def read_token(arg: str) -> str:
    """A token argument may be the token itself, ``-`` (stdin), or @file."""
    if arg == "-":
        return sys.stdin.read().strip()
    if arg.startswith("@"):
        try:
            with open(arg[1:], "r", encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise JwtError(f"cannot read token file {arg[1:]!r}: {exc}") from exc
    return arg


def read_secret(args: argparse.Namespace) -> bytes | None:
    """Resolve --secret / --secret-file into bytes (or None if neither)."""
    if getattr(args, "secret", None) is not None:
        return args.secret.encode("utf-8")
    if getattr(args, "secret_file", None) is not None:
        try:
            with open(args.secret_file, "rb") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise JwtError(
                f"cannot read secret file {args.secret_file!r}: {exc}") from exc
    return None


def read_public_key(args: argparse.Namespace) -> str | None:
    if getattr(args, "public_key", None) is None:
        return None
    try:
        with open(args.public_key, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise JwtError(
            f"cannot read public key file {args.public_key!r}: {exc}") from exc


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_TIME_CLAIMS = ("exp", "iat", "nbf", "auth_time")


def _render_claims(payload: dict) -> list[str]:
    lines: list[str] = []
    for key, value in payload.items():
        if key in _TIME_CLAIMS and isinstance(value, (int, float)) \
                and not isinstance(value, bool):
            lines.append(f"  {cyan(key)}: {value}  →  {human_time(value)}")
        else:
            rendered = json.dumps(value, ensure_ascii=False)
            lines.append(f"  {cyan(key)}: {rendered}")
    return lines


def render_token(token, *, show_signature: bool = True) -> str:
    out: list[str] = []
    out.append(bold("Header"))
    out.append(json.dumps(token.header, indent=2, ensure_ascii=False))
    out.append("")
    out.append(bold("Payload"))
    out.extend(_render_claims(token.payload))
    if show_signature:
        out.append("")
        sig = token.signature.hex() if token.signature else "(empty)"
        out.append(f"{bold('Signature')} ({token.alg or 'none'}): {sig}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_decode(args: argparse.Namespace) -> int:
    try:
        token = decode(read_token(args.token))
    except JwtError as exc:
        print(red(f"error: {exc}"), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"header": token.header, "payload": token.payload},
                         indent=2, ensure_ascii=False))
        return 0

    print(render_token(token))

    warnings = list(time_warnings(token))
    if token.alg == "none":
        warnings.append("alg=none: this token is UNSIGNED — anyone could "
                        "have made it")
    if token.alg not in ("HS256", "HS384", "HS512",
                         "RS256", "RS384", "RS512", "none"):
        warnings.append(f"unknown alg {token.alg!r}")
    if warnings:
        print()
        for warning in warnings:
            print(yellow(f"! {warning}"))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        token = decode(read_token(args.token))
        secret = read_secret(args)
        pubkey = read_public_key(args)
        failures = verify(
            token,
            key=secret,
            public_key_pem=pubkey,
            allow_none=args.allow_none,
            audience=args.aud,
            issuer=args.iss,
            leeway=args.leeway,
            check_exp=not args.ignore_exp,
        )
    except JwtError as exc:
        print(red(f"error: {exc}"), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"valid": not failures, "failures": failures},
                         indent=2))
        return 0 if not failures else 1

    if failures:
        print(red("✗ INVALID"))
        for failure in failures:
            print(red(f"  - {failure}"))
        return 1

    print(green("✓ VALID"))
    print(f"  alg: {token.alg or 'none'}"
          + (f"  kid: {token.kid}" if token.kid else ""))
    for line in _render_claims(token.payload):
        print(line)
    warnings = time_warnings(token)
    for warning in warnings:
        print(yellow(f"! {warning}"))
    return 0


def _parse_payload(text: str) -> dict:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JwtError(f"--payload is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise JwtError("--payload must be a JSON object")
    return obj


def cmd_encode(args: argparse.Namespace) -> int:
    try:
        payload = _parse_payload(args.payload)
        if args.exp_in is not None:
            payload["exp"] = int(time.time()) + args.exp_in
        header = None
        if args.header:
            header = _parse_payload(args.header)
        secret = read_secret(args) or b""
        if args.alg != "none" and not secret and not args.secret_file:
            print(red("error: --secret is required for HS* algorithms"),
                  file=sys.stderr)
            return 2
        token = encode(payload, key=secret, alg=args.alg, header=header,
                       add_iat=not args.no_iat)
    except JwtError as exc:
        print(red(f"error: {exc}"), file=sys.stderr)
        return 2
    print(token)
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jwtlens",
        description="Decode, verify and mint JSON Web Tokens — "
                    "offline, stdlib-only.",
    )
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("--no-color", action="store_true",
                        help="disable coloured output")

    sub = parser.add_subparsers(dest="command", required=True)

    p_decode = sub.add_parser(
        "decode", help="pretty-print a token's header and payload")
    p_decode.add_argument("token",
                          help="the JWT, '-' to read stdin, or @file")
    p_decode.add_argument("--json", action="store_true",
                          help="emit header+payload as JSON")
    p_decode.set_defaults(func=cmd_decode)

    p_verify = sub.add_parser(
        "verify", help="check a token's signature and claims")
    p_verify.add_argument("token",
                          help="the JWT, '-' to read stdin, or @file")
    p_verify.add_argument("--secret", help="HMAC secret (HS*)")
    p_verify.add_argument("--secret-file",
                          help="file holding the HMAC secret (HS*)")
    p_verify.add_argument("--public-key",
                          help="PEM RSA public key file (RS*)")
    p_verify.add_argument("--allow-none", action="store_true",
                          help="accept unsigned (alg=none) tokens")
    p_verify.add_argument("--aud", help="expected audience claim")
    p_verify.add_argument("--iss", help="expected issuer claim")
    p_verify.add_argument("--leeway", type=int, default=0,
                          help="seconds of clock-skew tolerance (default 0)")
    p_verify.add_argument("--ignore-exp", action="store_true",
                          help="skip the expiry check")
    p_verify.add_argument("--json", action="store_true",
                          help="emit {valid, failures} as JSON")
    p_verify.set_defaults(func=cmd_verify)

    p_encode = sub.add_parser("encode", help="mint a token")
    p_encode.add_argument("--payload", required=True,
                          help='claims as JSON, e.g. \'{"sub":"42"}\'')
    p_encode.add_argument("--header",
                          help='extra header fields as JSON, e.g. \'{"kid":"k1"}\'')
    p_encode.add_argument("--secret", help="HMAC secret (HS*)")
    p_encode.add_argument("--secret-file",
                          help="file holding the HMAC secret (HS*)")
    p_encode.add_argument("--alg", default="HS256",
                          choices=["HS256", "HS384", "HS512", "none"],
                          help="signing algorithm (default HS256)")
    p_encode.add_argument("--exp-in", type=int, metavar="SECONDS",
                          help="set exp to now + SECONDS")
    p_encode.add_argument("--no-iat", action="store_true",
                          help="do not add an iat claim automatically")
    p_encode.set_defaults(func=cmd_encode)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    global _USE_COLOR
    if args.no_color:
        _USE_COLOR = False
    try:
        return args.func(args)
    except JwtError as exc:
        print(red(f"error: {exc}"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
