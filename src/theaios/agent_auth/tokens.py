"""Short-lived, audience-bound tokens for a resolved agent.

A tool server (an MCP server, an internal API) receives a call from an agent and must know
who it acts for and what it may do. The agent's runtime issues a token for that audience; the
tool server verifies it with the same key and gets back the current resolution.

Format: ``base64url(json claims) "." base64url(HMAC-SHA256(key, claims))``. Claims: version,
agent, identity, user, roles, delegation chain, audience, issued-at, expiry, and the
fingerprint of the resolution. Verification refuses a bad signature, another audience, an
expired token, and a token whose resolution no longer matches the current policy (the policy
or the user's roles changed since it was issued).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass

from theaios.agent_auth.resolution import ResolvedAgent

TOKEN_VERSION = 1
MAX_TTL = 3600
MAX_LEEWAY = 300
MIN_KEY_BYTES = 32


class TokenError(Exception):
    """The token cannot be trusted; the message says why."""


@dataclass(frozen=True)
class TokenClaims:
    agent: str
    identity: str
    user: str
    roles: tuple[str, ...]
    chain: tuple[str, ...]
    audience: str
    issued_at: int
    expires_at: int
    fingerprint: str


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    """Strict: only the exact unpadded url-safe spelling decodes, so a token has one form."""
    if not text or any(c not in _B64 for c in text):
        raise ValueError("not url-safe base64")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if _b64(data) != text:
        raise ValueError("non-canonical base64")
    return data


_B64 = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def check_keys(key: bytes | Sequence[bytes] | None) -> list[bytes]:
    """One key, or several for rotation: the first signs, every one verifies."""
    if key is None:
        raise TokenError(
            "tokens need a secret key (AuthEngine(..., token_key=...)); generate one with "
            "secrets.token_bytes(32)"
        )
    keys = [key] if isinstance(key, (bytes, str)) else list(key)
    if not keys:
        raise TokenError("token_key is an empty list")
    for k in keys:
        if not isinstance(k, bytes):
            raise TokenError(
                f"token keys must be bytes, not {type(k).__name__} (use key.encode() or "
                "secrets.token_bytes(32))"
            )
        if len(k) < MIN_KEY_BYTES:
            raise TokenError(f"a token key must be at least {MIN_KEY_BYTES} bytes, got {len(k)}")
    return keys


def check_key(key: bytes | Sequence[bytes] | None) -> bytes:
    """The signing key (the first one)."""
    return check_keys(key)[0]


def issue(resolved: ResolvedAgent, audience: str, ttl: int, key: bytes) -> str:
    if not audience:
        raise TokenError("a token needs an audience (the service that will verify it)")
    if not 0 < ttl <= MAX_TTL:
        raise TokenError(f"ttl must be between 1 and {MAX_TTL} seconds")
    if not resolved.access:
        raise TokenError(f"no token for an agent without access: {resolved.access_reason}")
    now = int(time.time())
    claims = {
        "v": TOKEN_VERSION,
        "agent": resolved.agent,
        "identity": resolved.principal.identity,
        "user": resolved.principal.user,
        "roles": sorted(resolved.principal.roles),
        "chain": list(resolved.chain),
        "aud": audience,
        "iat": now,
        "exp": now + ttl,
        "fp": resolved.fingerprint,
    }
    body = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(check_key(key), body, hashlib.sha256).digest()
    return f"{_b64(body)}.{_b64(sig)}"


def decode(
    token: str, audience: str, key: bytes | Sequence[bytes], *, leeway: int = 0
) -> TokenClaims:
    """Check signature, audience, issue time and expiry; return the claims (the fingerprint
    is checked by the engine against a fresh resolution)."""
    if not 0 <= leeway <= MAX_LEEWAY:
        raise TokenError(f"leeway must be between 0 and {MAX_LEEWAY} seconds")
    try:
        body_b64, sig_b64 = token.split(".")
        body, sig = _unb64(body_b64), _unb64(sig_b64)
    except (ValueError, TypeError, AttributeError):
        raise TokenError("malformed token") from None
    if not any(
        hmac.compare_digest(sig, hmac.new(k, body, hashlib.sha256).digest())
        for k in check_keys(key)
    ):
        raise TokenError("bad signature: the token was altered or signed with another key")
    try:
        c = json.loads(body)
        claims = TokenClaims(
            agent=str(c["agent"]),
            identity=str(c["identity"]),
            user=str(c["user"]),
            roles=tuple(str(r) for r in c["roles"]),
            chain=tuple(str(a) for a in c["chain"]),
            audience=str(c["aud"]),
            issued_at=int(c["iat"]),
            expires_at=int(c["exp"]),
            fingerprint=str(c["fp"]),
        )
        version = int(c["v"])
    except (ValueError, KeyError, TypeError):
        raise TokenError("malformed token claims") from None
    if version != TOKEN_VERSION:
        raise TokenError(f"unsupported token version {version}")
    if claims.audience != audience:
        raise TokenError(f"token is for '{claims.audience}', not '{audience}'")
    now = time.time()
    if claims.issued_at > now + leeway:
        raise TokenError("token issued in the future: the issuer's clock is ahead")
    if not 0 < claims.expires_at - claims.issued_at <= MAX_TTL:
        raise TokenError(f"token lifetime is not between 1 and {MAX_TTL} seconds")
    if now > claims.expires_at + leeway:
        raise TokenError("token expired")
    return claims
