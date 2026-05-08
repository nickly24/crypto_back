from __future__ import annotations

import base64
import hashlib
import os
from urllib.parse import urlencode

import jwt
import requests

from config import Config

GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
TELEGRAM_ISSUER = "https://oauth.telegram.org"
TELEGRAM_AUTH_URL = "https://oauth.telegram.org/auth"
TELEGRAM_TOKEN_URL = "https://oauth.telegram.org/token"
TELEGRAM_JWKS_URL = "https://oauth.telegram.org/.well-known/jwks.json"

_google_jwks_client = jwt.PyJWKClient(GOOGLE_JWKS_URL)
_telegram_jwks_client = jwt.PyJWKClient(TELEGRAM_JWKS_URL)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_nonce(size: int = 32) -> str:
    return _b64url(os.urandom(size))


def generate_state(size: int = 24) -> str:
    return _b64url(os.urandom(size))


def generate_pkce_pair() -> tuple[str, str]:
    verifier = _b64url(os.urandom(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def verify_google_id_token(id_token: str) -> dict:
    if not Config.GOOGLE_CLIENT_ID:
        raise ValueError("Google auth is not configured")

    signing_key = _google_jwks_client.get_signing_key_from_jwt(id_token)
    payload = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=Config.GOOGLE_CLIENT_ID,
        issuer=list(GOOGLE_ISSUERS),
    )
    if not payload.get("sub"):
        raise ValueError("Google token is missing sub")
    return payload


def get_telegram_redirect_uri() -> str:
    if Config.TELEGRAM_REDIRECT_URI:
        return Config.TELEGRAM_REDIRECT_URI
    if not Config.BACKEND_PUBLIC_URL:
        raise ValueError("Telegram redirect URI is not configured")
    return Config.BACKEND_PUBLIC_URL.rstrip("/") + "/api/auth/telegram/callback"


def build_telegram_authorize_url(state: str, nonce: str, code_challenge: str) -> str:
    if not Config.TELEGRAM_CLIENT_ID:
        raise ValueError("Telegram auth is not configured")

    params = {
        "client_id": Config.TELEGRAM_CLIENT_ID,
        "redirect_uri": get_telegram_redirect_uri(),
        "response_type": "code",
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{TELEGRAM_AUTH_URL}?{urlencode(params)}"


def exchange_telegram_code(code: str, code_verifier: str) -> dict:
    if not Config.TELEGRAM_CLIENT_ID or not Config.TELEGRAM_CLIENT_SECRET:
        raise ValueError("Telegram auth is not configured")

    creds = f"{Config.TELEGRAM_CLIENT_ID}:{Config.TELEGRAM_CLIENT_SECRET}"
    headers = {
        "Authorization": "Basic " + base64.b64encode(creds.encode("utf-8")).decode("ascii"),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": get_telegram_redirect_uri(),
        "client_id": Config.TELEGRAM_CLIENT_ID,
        "code_verifier": code_verifier,
    }
    resp = requests.post(TELEGRAM_TOKEN_URL, data=body, headers=headers, timeout=15)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.status_code != 200:
        message = data.get("error_description") or data.get("error") or "Telegram token exchange failed"
        raise ValueError(message)
    return data


def verify_telegram_id_token(id_token: str, nonce: str | None = None) -> dict:
    if not Config.TELEGRAM_CLIENT_ID:
        raise ValueError("Telegram auth is not configured")

    signing_key = _telegram_jwks_client.get_signing_key_from_jwt(id_token)
    payload = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=str(Config.TELEGRAM_CLIENT_ID),
        issuer=TELEGRAM_ISSUER,
    )
    if nonce and payload.get("nonce") not in (None, nonce):
        raise ValueError("Telegram nonce mismatch")
    if not payload.get("sub"):
        raise ValueError("Telegram token is missing sub")
    return payload
