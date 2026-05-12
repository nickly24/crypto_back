from __future__ import annotations

import base64
import datetime as dt
import json
import secrets
import time
import uuid
from urllib.parse import urlencode
from typing import Any, Dict

import bcrypt
import jwt
import requests
from flask import Flask, jsonify, redirect, request
from flask_cors import CORS

from bot_gateway import build_bot_gateway
from config import Config
from db import execute, insert_id, query_all, query_one
from social_auth import (
    build_telegram_authorize_url,
    exchange_telegram_code,
    generate_nonce,
    generate_pkce_pair,
    generate_state,
    verify_google_id_token,
    verify_telegram_id_token,
)


def _poll_db(sql: str, params: tuple, check_fn, timeout: float = 15.0, interval: float = 1.0):
    """Poll DB until check_fn(row) returns True or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = query_one(sql, params)
        if row and check_fn(row):
            return row
        time.sleep(interval)
    return query_one(sql, params)


def _make_token(user: dict) -> str:
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "exp": dt.datetime.utcnow() + dt.timedelta(seconds=Config.JWT_TTL_SECONDS),
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALG)


def _parse_auth() -> dict | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(
            token,
            Config.SECRET_KEY,
            algorithms=[Config.JWT_ALG],
        )
        return payload
    except jwt.PyJWTError:
        return None


def _ok(data: Dict[str, Any], code: int = 200):
    return jsonify({"ok": True, "data": data}), code


def _err(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code


def _format_subscription(user: dict) -> Dict[str, Any]:
    """Извлекает plan и subscription_ends_at из строки users, формат для API."""
    plan = user.get("plan") or "FREE"
    if plan == "PRO_PLUS":
        plan = "PRO+"
    ends = user.get("subscription_ends_at")
    return {
        "plan": plan,
        "subscription_ends_at": ends.isoformat() if ends else None,
    }


DEFAULT_BASKET_PAIRS: list[tuple[str, str]] = [
    ("BTC-USDT-SWAP", "ETH-USDT-SWAP"),
    ("BNB-USDT-SWAP", "XRP-USDT-SWAP"),
    ("LINK-USDT-SWAP", "DOGE-USDT-SWAP"),
    ("LTC-USDT-SWAP", "XTZ-USDT-SWAP"),
    ("TRX-USDT-SWAP", "ETC-USDT-SWAP"),
]


def _build_auth_payload(user: dict) -> Dict[str, Any]:
    token = _make_token(user)
    sub = _format_subscription(user)
    return {
        "access_token": token,
        "refresh_token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"],
            **sub,
        },
    }


def _normalize_email(email: str | None) -> str | None:
    if not email:
        return None
    value = email.strip().lower()
    return value or None


def _get_user_by_id(user_id: int) -> dict | None:
    return query_one(
        "SELECT id, email, role, is_blocked, plan, subscription_ends_at FROM users WHERE id = %s",
        (user_id,),
    )


def _get_identity(provider: str, provider_user_id: str) -> dict | None:
    return query_one(
        "SELECT user_id FROM user_identities WHERE provider = %s AND provider_user_id = %s",
        (provider, provider_user_id),
    )


def _make_placeholder_email(provider: str, provider_user_id: str) -> str:
    return f"{provider}-{provider_user_id}@social.local"


def _seed_default_bot_config(user_id: int) -> None:
    cfg = query_one("SELECT id FROM bot_configs WHERE user_id = %s", (user_id,))
    if cfg:
        config_id = int(cfg["id"])
    else:
        config_id = insert_id(
            """
            INSERT INTO bot_configs (
                user_id, position_size_pct, orders_per_trade, entry_spread_pct,
                take_profit_pct, dca_count, dca_step_pct, stop_loss_pct,
                stop_loss_enabled, leverage, no_new_position, simulation_mode,
                error_filter_enabled, error_filter_pattern, error_retry_count, desired_state
            ) VALUES (%s, 200.00, 1, 2.00, 0.80, 3, 3.00, 4.00, 0, 20, 0, 1, 1, 'Please try again', 3, 'stopped')
            """,
            (user_id,),
        )

    existing_pairs = query_one("SELECT id FROM basket_pairs WHERE bot_config_id = %s LIMIT 1", (config_id,))
    if not existing_pairs:
        for idx, (basket1, basket2) in enumerate(DEFAULT_BASKET_PAIRS, start=1):
            execute(
                """
                INSERT INTO basket_pairs (bot_config_id, pair_index, symbol_basket1, symbol_basket2)
                VALUES (%s, %s, %s, %s)
                """,
                (config_id, idx, basket1, basket2),
            )

    execute(
        """
        INSERT INTO bot_state (user_id, actual_state, updated_at)
        VALUES (%s, 'stopped', NOW())
        ON DUPLICATE KEY UPDATE actual_state = actual_state
        """,
        (user_id,),
    )


def _create_user(email: str, password_hash: str, role: str = "user") -> int:
    return insert_id(
        "INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)",
        (email, password_hash, role),
    )


def _create_social_user(email: str) -> dict:
    synthetic_password = bcrypt.hashpw(secrets.token_urlsafe(32).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_id = _create_user(email, synthetic_password, "user")
    _seed_default_bot_config(user_id)
    user = _get_user_by_id(user_id)
    if not user:
        raise RuntimeError("Failed to create user")
    return user


def _link_identity(
    *,
    user_id: int,
    provider: str,
    provider_user_id: str,
    email: str | None,
    display_name: str | None,
    avatar_url: str | None,
) -> None:
    execute(
        """
        INSERT INTO user_identities (user_id, provider, provider_user_id, email, display_name, avatar_url)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            email = VALUES(email),
            display_name = VALUES(display_name),
            avatar_url = VALUES(avatar_url),
            updated_at = NOW()
        """,
        (user_id, provider, provider_user_id, email, display_name, avatar_url),
    )


def _resolve_or_create_social_user(
    *,
    provider: str,
    provider_user_id: str,
    email: str | None,
    display_name: str | None,
    avatar_url: str | None,
) -> tuple[dict | None, str | None]:
    identity = _get_identity(provider, provider_user_id)
    if identity:
        user = _get_user_by_id(int(identity["user_id"]))
        if not user:
            return None, "Linked user not found"
        if user.get("is_blocked"):
            return None, "User is blocked"
        _link_identity(
            user_id=user["id"],
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
            display_name=display_name,
            avatar_url=avatar_url,
        )
        return user, None

    normalized_email = _normalize_email(email)
    if normalized_email:
        existing_user = query_one(
            "SELECT id FROM users WHERE email = %s",
            (normalized_email,),
        )
        if existing_user:
            return None, (
                "An account with this email already exists. "
                "Sign in with your password first, then connect this provider safely."
            )

    user = _create_social_user(normalized_email or _make_placeholder_email(provider, provider_user_id))
    _link_identity(
        user_id=user["id"],
        provider=provider,
        provider_user_id=provider_user_id,
        email=normalized_email,
        display_name=display_name,
        avatar_url=avatar_url,
    )
    return user, None


def _create_oauth_state(provider: str, next_path: str | None = None) -> dict:
    state = generate_state()
    nonce = generate_nonce()
    code_verifier, code_challenge = generate_pkce_pair()
    expires_at = dt.datetime.utcnow() + dt.timedelta(minutes=10)
    execute(
        """
        INSERT INTO oauth_states (provider, state, code_verifier, nonce, next_path, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (provider, state, code_verifier, nonce, next_path, expires_at),
    )
    return {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier,
        "code_challenge": code_challenge,
    }


def _consume_oauth_state(provider: str, state: str) -> dict | None:
    row = query_one(
        """
        SELECT state, code_verifier, nonce, next_path, expires_at
        FROM oauth_states
        WHERE provider = %s AND state = %s
        """,
        (provider, state),
    )
    if not row:
        return None
    execute("DELETE FROM oauth_states WHERE provider = %s AND state = %s", (provider, state))
    expires_at = row.get("expires_at")
    if not expires_at or expires_at < dt.datetime.utcnow():
        return None
    return row


def _build_frontend_callback_url(*, token: str | None = None, error: str | None = None, next_path: str | None = None) -> str:
    base = (Config.FRONTEND_ORIGIN or "http://localhost:3000").rstrip("/")
    callback = base + "/auth/callback"
    params: dict[str, str] = {}
    if token:
        params["token"] = token
    if error:
        params["error"] = error
    if next_path:
        params["next"] = next_path
    return callback + (f"#{urlencode(params)}" if params else "")


app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
bot_gateway = build_bot_gateway()

_BASE_CORS_ORIGINS = frozenset(
    {
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://nickly24-crypto-front-a2d6.twc1.net",
    }
)


def _resolved_cors_origins() -> frozenset[str]:
    s = set(_BASE_CORS_ORIGINS)
    fo = (Config.FRONTEND_ORIGIN or "").strip()
    if fo:
        s.add(fo)
    return frozenset(s)


if Config.CORS_ALLOW_ALL_ORIGINS:
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=True,
    )
    ALLOWED_CORS_ORIGINS: frozenset[str] | None = None
else:
    ALLOWED_CORS_ORIGINS = _resolved_cors_origins()
    CORS(
        app,
        resources={r"/api/*": {"origins": list(ALLOWED_CORS_ORIGINS)}},
        supports_credentials=True,
    )


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if Config.CORS_ALLOW_ALL_ORIGINS:
        allow_origin = origin or "*"
    elif origin and ALLOWED_CORS_ORIGINS is not None and origin in ALLOWED_CORS_ORIGINS:
        allow_origin = origin
    else:
        allow_origin = (Config.FRONTEND_ORIGIN or "").strip() or "*"
    response.headers.setdefault("Access-Control-Allow-Origin", allow_origin)
    response.headers.setdefault("Vary", "Origin")
    response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
    if allow_origin != "*":
        response.headers.setdefault("Access-Control-Allow-Credentials", "true")
    return response


@app.get("/api/health")
def health():
    return _ok({"status": "ok"})


@app.post("/api/auth/login")
def auth_login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return _err("Email и пароль обязательны", 422)

    user = query_one(
        "SELECT id, email, password_hash, role, is_blocked, plan, subscription_ends_at "
        "FROM users WHERE email = %s",
        (email,),
    )
    if not user:
        return _err("Неверный логин или пароль", 401)
    if user["is_blocked"]:
        return _err("Пользователь заблокирован", 403)

    stored = user["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored):
        return _err("Неверный логин или пароль", 401)

    return _ok(_build_auth_payload(user))


@app.get("/api/auth/me")
def auth_me():
    payload = _parse_auth()
    if not payload:
        return _err("Unauthorized", 401)
    user = query_one(
        "SELECT id, email, role, plan, subscription_ends_at FROM users WHERE id = %s",
        (int(payload["sub"]),),
    )
    if not user:
        return _err("User not found", 404)
    sub = _format_subscription(user)
    return _ok(
        {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"],
            **sub,
        }
    )


@app.post("/api/admin/login")
def admin_login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return _err("Email и пароль обязательны", 422)

    user = query_one(
        "SELECT id, email, password_hash, role, is_blocked, plan, subscription_ends_at "
        "FROM users WHERE email = %s",
        (email,),
    )
    if not user:
        return _err("Неверный логин или пароль", 401)
    if user["is_blocked"]:
        return _err("Пользователь заблокирован", 403)
    if user["role"] != "admin":
        return _err("Нет прав администратора", 403)

    stored = user["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored):
        return _err("Неверный логин или пароль", 401)

    return _ok(_build_auth_payload(user))


@app.post("/api/auth/google")
def auth_google():
    body = request.get_json(silent=True) or {}
    credential = (body.get("credential") or "").strip()
    if not credential:
        return _err("Google credential is required", 422)

    try:
        payload = verify_google_id_token(credential)
    except Exception as exc:
        return _err(f"Google sign-in failed: {exc}", 401)

    user, conflict = _resolve_or_create_social_user(
        provider="google",
        provider_user_id=str(payload["sub"]),
        email=_normalize_email(payload.get("email")),
        display_name=payload.get("name"),
        avatar_url=payload.get("picture"),
    )
    if conflict:
        return _err(conflict, 409)
    if not user:
        return _err("Unable to sign in with Google", 500)
    return _ok(_build_auth_payload(user))


@app.get("/api/auth/telegram/start")
def auth_telegram_start():
    next_path = (request.args.get("next") or "/dashboard").strip() or "/dashboard"
    try:
        oauth_state = _create_oauth_state("telegram", next_path=next_path)
        auth_url = build_telegram_authorize_url(
            oauth_state["state"],
            oauth_state["nonce"],
            oauth_state["code_challenge"],
        )
    except Exception as exc:
        return _err(f"Telegram auth is unavailable: {exc}", 503)
    return _ok({"auth_url": auth_url})


@app.get("/api/auth/telegram/callback")
def auth_telegram_callback():
    code = (request.args.get("code") or "").strip()
    state = (request.args.get("state") or "").strip()
    error = (request.args.get("error") or "").strip()
    error_description = (request.args.get("error_description") or "").strip()

    if error:
        return redirect(_build_frontend_callback_url(error=error_description or error))
    if not code or not state:
        return redirect(_build_frontend_callback_url(error="Telegram callback is missing code or state"))

    saved_state = _consume_oauth_state("telegram", state)
    if not saved_state:
        return redirect(_build_frontend_callback_url(error="Telegram sign-in state expired. Please try again."))

    try:
        token_payload = exchange_telegram_code(code, saved_state["code_verifier"])
        id_token = token_payload.get("id_token") or ""
        if not id_token:
            raise ValueError("Telegram did not return an ID token")
        claims = verify_telegram_id_token(id_token, nonce=saved_state.get("nonce"))
    except Exception as exc:
        return redirect(_build_frontend_callback_url(error=f"Telegram sign-in failed: {exc}"))

    telegram_id = str(claims.get("sub") or claims.get("id") or "")
    if not telegram_id:
        return redirect(_build_frontend_callback_url(error="Telegram token is missing user id"))

    preferred_username = claims.get("preferred_username")
    display_name = claims.get("name") or preferred_username or "Telegram user"
    placeholder_email = _make_placeholder_email("telegram", telegram_id)

    user, conflict = _resolve_or_create_social_user(
        provider="telegram",
        provider_user_id=telegram_id,
        email=placeholder_email,
        display_name=display_name,
        avatar_url=claims.get("picture"),
    )
    if conflict:
        return redirect(_build_frontend_callback_url(error=conflict))
    if not user:
        return redirect(_build_frontend_callback_url(error="Unable to sign in with Telegram"))

    token = _make_token(user)
    return redirect(
        _build_frontend_callback_url(
            token=token,
            next_path=saved_state.get("next_path") or "/dashboard",
        )
    )


@app.get("/api/admin/me")
def admin_me():
    payload = _parse_auth()
    if not payload or payload.get("role") != "admin":
        return _err("Unauthorized", 401)
    user = query_one(
        "SELECT id, email, role, plan, subscription_ends_at FROM users WHERE id = %s",
        (int(payload["sub"]),),
    )
    if not user:
        return _err("User not found", 404)
    sub = _format_subscription(user)
    return _ok(
        {
            "id": user["id"],
            "email": user["email"],
            "role": user["role"],
            **sub,
        }
    )


@app.get("/api/subscription")
def get_subscription():
    """Возвращает план и дату окончания подписки текущего пользователя."""
    payload = _parse_auth()
    if not payload:
        return _err("Unauthorized", 401)
    user = query_one(
        "SELECT plan, subscription_ends_at FROM users WHERE id = %s",
        (int(payload["sub"]),),
    )
    if not user:
        return _err("User not found", 404)
    return _ok(_format_subscription(user))


@app.post("/api/subscription/purchase")
def purchase_subscription():
    """Покупка/продление подписки. Body: { plan: "PRO" | "PRO+" }. Пока без реальной оплаты — сразу продлевает на 30 дней."""
    payload = _parse_auth()
    if not payload:
        return _err("Unauthorized", 401)
    user_id = int(payload["sub"])
    body = request.get_json(silent=True) or {}
    plan_raw = (body.get("plan") or "").strip().upper().replace(" ", "")
    if plan_raw in ("PRO", "PRO+"):
        db_plan = "PRO_PLUS" if plan_raw == "PRO+" else "PRO"
    else:
        return _err("Invalid plan. Use PRO or PRO+", 422)

    user = query_one(
        "SELECT plan, subscription_ends_at FROM users WHERE id = %s",
        (user_id,),
    )
    if not user:
        return _err("User not found", 404)

    now = dt.datetime.utcnow()
    ends_at = user.get("subscription_ends_at")
    if ends_at and ends_at > now:
        new_ends = ends_at + dt.timedelta(days=30)
    else:
        new_ends = now + dt.timedelta(days=30)

    execute(
        "UPDATE users SET plan = %s, subscription_ends_at = %s WHERE id = %s",
        (db_plan, new_ends, user_id),
    )
    return _ok({
        "plan": "PRO+" if db_plan == "PRO_PLUS" else "PRO",
        "subscription_ends_at": new_ends.isoformat(),
    })


def _yookassa_auth_header() -> str:
    raw = f"{Config.YOOKASSA_SHOP_ID}:{Config.YOOKASSA_SECRET_KEY}"
    return "Basic " + base64.b64encode(raw.encode()).decode()


@app.get("/api/subscription/prices")
def get_subscription_prices():
    """Цены тарифов в рублях из БД."""
    rows = query_all("SELECT plan, amount_rub FROM tariff_prices ORDER BY amount_rub")
    prices = {}
    for r in rows:
        plan = "PRO+" if r["plan"] == "PRO_PLUS" else r["plan"]
        prices[plan] = float(r["amount_rub"])
    return _ok({"prices": prices})


@app.post("/api/subscription/create-payment")
def create_subscription_payment():
    """Создаёт платёж в ЮKassa, возвращает confirmation_url для редиректа."""
    payload = _parse_auth()
    if not payload:
        return _err("Unauthorized", 401)
    user_id = int(payload["sub"])
    if not Config.YOOKASSA_SHOP_ID or not Config.YOOKASSA_SECRET_KEY:
        return _err("Payments not configured", 503)

    body = request.get_json(silent=True) or {}
    plan_raw = (body.get("plan") or "").strip().upper().replace(" ", "")
    if plan_raw not in ("PRO", "PRO+"):
        return _err("Invalid plan. Use PRO or PRO+", 422)
    db_plan = "PRO_PLUS" if plan_raw == "PRO+" else "PRO"

    row = query_one("SELECT amount_rub FROM tariff_prices WHERE plan = %s", (db_plan,))
    if not row:
        return _err("Tariff not found", 404)
    amount_rub = float(row["amount_rub"])
    if amount_rub <= 0:
        return _err("Invalid tariff price", 400)

    return_url = (Config.FRONTEND_ORIGIN or "").rstrip("/") + "/dashboard?payment=success"
    if not return_url.startswith("http"):
        return_url = "http://localhost:3000/dashboard?payment=success"

    yookassa_body = {
        "amount": {"value": f"{amount_rub:.2f}", "currency": "RUB"},
        "capture": True,
        "confirmation": {"type": "redirect", "return_url": return_url},
        "description": f"Подписка {plan_raw} на 30 дней",
    }
    idem_key = str(uuid.uuid4())
    try:
        resp = requests.post(
            f"{Config.YOOKASSA_API_URL}/payments",
            headers={
                "Authorization": _yookassa_auth_header(),
                "Idempotence-Key": idem_key,
                "Content-Type": "application/json",
            },
            json=yookassa_body,
            timeout=10,
        )
    except Exception as e:
        return _err(f"Payment service error: {e}", 502)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.status_code != 200:
        return _err(data.get("description", data.get("message", "YooKassa error")), 400)

    yookassa_id = data.get("id")
    confirmation = data.get("confirmation", {})
    confirmation_url = confirmation.get("confirmation_url") or ""
    if not yookassa_id or not confirmation_url:
        return _err("Invalid YooKassa response", 502)

    execute(
        "INSERT INTO subscription_payments (user_id, plan, amount_rub, yookassa_payment_id, status) VALUES (%s, %s, %s, %s, 'pending')",
        (user_id, db_plan, amount_rub, yookassa_id),
    )
    return _ok({
        "payment_id": yookassa_id,
        "confirmation_url": confirmation_url,
        "amount_rub": amount_rub,
        "plan": "PRO+" if db_plan == "PRO_PLUS" else "PRO",
    })


def _apply_payment_succeeded(yookassa_id: str) -> bool:
    """Продлевает подписку по успешному платежу ЮKassa. Возвращает True, если обновление выполнено."""
    row = query_one("SELECT id, user_id, plan, status FROM subscription_payments WHERE yookassa_payment_id = %s", (yookassa_id,))
    if not row or row.get("status") == "succeeded":
        return False
    user_id = row["user_id"]
    db_plan = row["plan"]
    now = dt.datetime.utcnow()
    user = query_one("SELECT subscription_ends_at FROM users WHERE id = %s", (user_id,))
    if not user:
        return False
    ends_at = user.get("subscription_ends_at")
    if ends_at and ends_at > now:
        new_ends = ends_at + dt.timedelta(days=30)
    else:
        new_ends = now + dt.timedelta(days=30)
    execute("UPDATE users SET plan = %s, subscription_ends_at = %s WHERE id = %s", (db_plan, new_ends, user_id))
    execute("UPDATE subscription_payments SET status = 'succeeded' WHERE yookassa_payment_id = %s", (yookassa_id,))
    return True


@app.post("/api/webhooks/yookassa")
def webhook_yookassa():
    """Входящие уведомления ЮKassa. При payment.succeeded продлеваем подписку."""
    raw = request.get_data(as_text=True)
    app.logger.info("YooKassa webhook received, body length=%s", len(raw or ""))
    try:
        payload = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        app.logger.warning("YooKassa webhook invalid JSON: %s", e)
        return "", 400
    event = payload.get("event")
    obj = payload.get("object", {})
    yookassa_id = obj.get("id")
    app.logger.info("YooKassa webhook event=%s payment_id=%s status=%s", event, yookassa_id, obj.get("status"))
    if event != "payment.succeeded":
        return "", 200
    status = obj.get("status")
    if not yookassa_id or status != "succeeded":
        return "", 200
    applied = _apply_payment_succeeded(yookassa_id)
    app.logger.info("YooKassa payment %s applied=%s", yookassa_id, applied)
    return "", 200


@app.post("/api/subscription/sync-after-payment")
def sync_after_payment():
    """После возврата с ЮKassa: проверяем последний pending-платёж через API и при успехе продлеваем подписку."""
    payload = _parse_auth()
    if not payload:
        return _err("Unauthorized", 401)
    user_id = int(payload["sub"])
    if not Config.YOOKASSA_SHOP_ID or not Config.YOOKASSA_SECRET_KEY:
        return _err("Payments not configured", 503)

    row = query_one(
        "SELECT yookassa_payment_id, plan, status FROM subscription_payments WHERE user_id = %s AND status = 'pending' ORDER BY created_at DESC LIMIT 1",
        (user_id,),
    )
    if not row:
        return _ok({"synced": False, "reason": "no_pending_payment"})

    yookassa_id = row["yookassa_payment_id"]
    try:
        resp = requests.get(
            f"{Config.YOOKASSA_API_URL}/payments/{yookassa_id}",
            headers={"Authorization": _yookassa_auth_header()},
            timeout=10,
        )
    except Exception as e:
        app.logger.warning("YooKassa GET payment error: %s", e)
        return _err("Payment service error", 502)
    data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    if resp.status_code != 200:
        return _ok({"synced": False, "reason": "payment_fetch_failed"})
    if data.get("status") != "succeeded":
        return _ok({"synced": False, "reason": "payment_not_succeeded", "status": data.get("status")})

    applied = _apply_payment_succeeded(yookassa_id)
    app.logger.info("sync-after-payment user_id=%s yookassa_id=%s applied=%s", user_id, yookassa_id, applied)
    return _ok({"synced": applied})


# ---------------------------------------------------------------------------
# Bot Manager proxy routes (будем вызывать Flask-сервер менеджера)
# Пока без реального теста — только каркас.
# ---------------------------------------------------------------------------


def _require_auth_user() -> dict | None:
    payload = _parse_auth()
    if not payload:
        return None
    return payload


def _require_auth_user_or_401():
    user = _require_auth_user()
    if not user:
        return None, _err("Unauthorized", 401)
    return user, None


@app.get("/api/bot/status")
def bot_status():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    try:
        payload, status = bot_gateway.status(user_id)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)

    response = jsonify(payload), status
    response[0].headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response[0].headers["Pragma"] = "no-cache"
    return response


@app.post("/api/bot/start")
def bot_start():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    try:
        payload, status = bot_gateway.start(user_id)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)
    if status != 200:
        return jsonify(payload), status

    row = _poll_db(
        "SELECT actual_state FROM bot_state WHERE user_id = %s",
        (user_id,),
        lambda r: r.get("actual_state") == "running",
        timeout=15.0,
        interval=1.0,
    )
    started = row and row.get("actual_state") == "running"
    return _ok({"status": "started" if started else "timeout", "alive": started})


@app.post("/api/bot/stop")
def bot_stop():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    try:
        payload, status = bot_gateway.stop(user_id)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)
    if status != 200:
        return jsonify(payload), status

    deadline = time.time() + 5
    stopped = False
    while time.time() < deadline:
        try:
            data, status = bot_gateway.status(user_id)
            if status != 200:
                stopped = True
                break
            if not data.get("data", {}).get("alive", True):
                stopped = True
                break
        except Exception:
            stopped = True
            break
        time.sleep(1.0)

    return _ok({"status": "stopped" if stopped else "timeout", "alive": not stopped})


@app.post("/api/bot/close-position")
def bot_close_position():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    before = query_one("SELECT position_open FROM bot_state WHERE user_id = %s", (user_id,))
    was_open = before and before.get("position_open") == 1

    try:
        payload, status = bot_gateway.close_position(user_id)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)
    if status != 200:
        return jsonify(payload), status

    if was_open:
        row = _poll_db(
            "SELECT position_open FROM bot_state WHERE user_id = %s",
            (user_id,),
            lambda r: r.get("position_open") == 0,
            timeout=25.0,
            interval=0.5,
        )
        closed = row and row.get("position_open") == 0
        # Не удаляем chart_spread_points при закрытии — история спреда остаётся
        trade = query_one(
            "SELECT id, pnl_pct, close_reason FROM trades WHERE user_id = %s ORDER BY id DESC LIMIT 1",
            (user_id,),
        )
        return _ok({
            "status": "closed" if closed else "timeout",
            "position_closed": closed,
            "trade": {
                "id": trade["id"],
                "pnl_pct": float(trade["pnl_pct"]),
                "reason": trade["close_reason"],
            } if trade else None,
        })

    return _ok({"status": "no_position", "position_closed": True})


@app.post("/api/bot/spread/reset")
def bot_spread_reset():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    execute(
        """
        UPDATE bot_state
        SET current_spread_pct = 0.0000,
            reference_prices = NULL,
            quotes_snapshot = NULL,
            buy_basket = NULL,
            sell_basket = NULL,
            updated_at = NOW()
        WHERE user_id = %s
        """,
        (user_id,),
    )
    return _ok({"status": "spread_reset", "current_spread_pct": 0.0})


@app.get("/api/bot/logs")
def bot_logs():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    limit = request.args.get("limit", 50)
    try:
        payload, status = bot_gateway.logs(user_id, int(limit))
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)
    return jsonify(payload), status


# ---------------------------------------------------------------------------
# Instruments (OKX public API — ключ не нужен)
# ---------------------------------------------------------------------------


@app.get("/api/instruments")
def get_instruments():
    user, error = _require_auth_user_or_401()
    if error:
        return error

    try:
        resp = requests.get(
            "https://www.okx.com/api/v5/public/instruments",
            params={"instType": "SWAP"},
            timeout=10,
        )
        data = resp.json()
    except Exception as e:
        return _err(f"OKX API error: {e}", 502)

    if data.get("code") != "0":
        return _err(data.get("msg", "OKX error"), 502)

    instruments = [
        inst["instId"]
        for inst in data.get("data", [])
        if inst.get("settleCcy") == "USDT"
    ]
    return _ok({"instruments": instruments})


# ---------------------------------------------------------------------------
# Chart data (spread, instrument prices)
# ---------------------------------------------------------------------------


@app.get("/api/chart/spread")
def get_chart_spread():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])
    minutes_arg = request.args.get("minutes", type=int)
    if minutes_arg is not None:
        minutes = min(1440, max(1, minutes_arg))  # 1..1440 min (24h)
        interval_sql = "DATE_SUB(NOW(), INTERVAL %s MINUTE)"
        interval_val = minutes
    else:
        hours = min(24, max(1, int(request.args.get("hours", 10))))
        interval_sql = "DATE_SUB(NOW(), INTERVAL %s HOUR)"
        interval_val = hours

    rows = query_all(
        f"""
        SELECT ts, spread_pct, r_basket1_pct, r_basket2_pct
        FROM chart_spread_points
        WHERE user_id = %s AND ts >= {interval_sql}
        ORDER BY ts ASC
        """,
        (user_id, interval_val),
    )
    if not rows:
        # Compatibility fallback for environments where spread is written only to spread_log.
        rows = query_all(
            f"""
            SELECT recorded_at AS ts, spread_pct, r_basket1_pct, r_basket2_pct
            FROM spread_log
            WHERE user_id = %s AND recorded_at >= {interval_sql}
            ORDER BY recorded_at ASC
            """,
            (user_id, interval_val),
        )
    points = [
        {
            "ts": r["ts"].isoformat() if hasattr(r["ts"], "isoformat") else str(r["ts"]),
            "spread_pct": float(r["spread_pct"]),
            "r_basket1_pct": float(r["r_basket1_pct"]),
            "r_basket2_pct": float(r["r_basket2_pct"]),
        }
        for r in rows
    ]
    return _ok({"points": points})


@app.get("/api/chart/instruments")
def get_chart_instruments():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])
    hours = min(24, max(1, int(request.args.get("hours", 10))))

    cfg = query_one("SELECT id FROM bot_configs WHERE user_id = %s", (user_id,))
    if not cfg:
        return _ok({"points": []})

    inst_rows = query_all(
        """
        SELECT DISTINCT symbol_basket1 AS inst_id FROM basket_pairs WHERE bot_config_id = %s
        UNION
        SELECT DISTINCT symbol_basket2 FROM basket_pairs WHERE bot_config_id = %s
        """,
        (cfg["id"], cfg["id"]),
    )
    inst_ids = [r["inst_id"] for r in inst_rows if r["inst_id"]]

    rows = query_all(
        """
        SELECT ts, inst_id, price
        FROM chart_instrument_points
        WHERE user_id = %s AND ts >= DATE_SUB(NOW(), INTERVAL %s HOUR)
        ORDER BY ts ASC
        """,
        (user_id, hours),
    )
    points = [
        {
            "ts": r["ts"].isoformat() if hasattr(r["ts"], "isoformat") else str(r["ts"]),
            "inst_id": r["inst_id"],
            "price": float(r["price"]),
        }
        for r in rows
    ]
    return _ok({"points": points, "instruments": inst_ids})


@app.post("/api/chart/spread/reset")
def reset_chart_spread():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])
    execute("DELETE FROM chart_spread_points WHERE user_id = %s", (user_id,))
    return _ok({"ok": True})


@app.post("/api/chart/instruments/reset")
def reset_chart_instruments():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])
    execute("DELETE FROM chart_instrument_points WHERE user_id = %s", (user_id,))
    return _ok({"ok": True})


@app.get("/api/chart/candles")
def get_chart_candles():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    inst_id = request.args.get("instId", "").strip()
    bar = request.args.get("bar", "1m")
    limit = min(300, max(60, int(request.args.get("limit", 300))))
    if not inst_id:
        return _err("instId required", 400)
    try:
        resp = requests.get(
            "https://www.okx.com/api/v5/market/candles",
            params={"instId": inst_id, "bar": bar, "limit": str(limit)},
            timeout=10,
        )
        data = resp.json()
    except Exception as e:
        return _err(f"OKX API error: {e}", 502)
    if data.get("code") != "0":
        return _err(data.get("msg", "OKX error"), 502)
    candles = []
    for row in data.get("data", []):
        candles.append({
            "ts": int(row[0]),
            "o": float(row[1]),
            "h": float(row[2]),
            "l": float(row[3]),
            "c": float(row[4]),
            "v": float(row[5]),
        })
    return _ok({"candles": candles})


# ---------------------------------------------------------------------------
# Live OKX positions (per-user keys from DB)
# ---------------------------------------------------------------------------


def _get_okx_keys_for_user(user_id: int) -> dict | None:
    row = query_one(
        "SELECT okx_api_key, okx_secret_key, okx_passphrase "
        "FROM user_settings WHERE user_id = %s",
        (user_id,),
    )
    if not row or not row.get("okx_api_key"):
        return None
    from crypto.encryption import decrypt

    return {
        "api_key": decrypt(row["okx_api_key"]) or "",
        "secret_key": decrypt(row["okx_secret_key"]) or "",
        "passphrase": decrypt(row["okx_passphrase"]) or "",
    }


def _okx_sdk_get_positions(api_key: str, secret_key: str, passphrase: str) -> dict:
    """
    Получаем позиции через тот же OKXClient, что использует bot_manager,
    чтобы результат точно совпадал с тем, что видит бот.
    """
    import socket

    import okx.Account as OkxAccount  # type: ignore
    from config import Config

    # Используем тот же флаг demo/real, что и у бэкенда.
    demo = getattr(Config, "OKX_DEMO", "0") == "1"
    flag = "1" if demo else "0"

    # Минимальное использование python-okx SDK, чтобы не зависеть от bot_manager.trading.
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(Config.OKX_HTTP_TIMEOUT)
    try:
        client = OkxAccount.AccountAPI(api_key, secret_key, passphrase, False, flag)
        r = client.get_positions(instType="SWAP")
    finally:
        socket.setdefaulttimeout(previous_timeout)
    # SDK возвращает dict с ключами code/data и т.п. — интерфейс совместим с тем,
    # как ожидает остальной код (см. bot_manager.okx_client).
    return r


@app.get("/api/bot/positions-live")
def bot_positions_live():
    """Текущие позиции с биржи OKX: цена, ликвидация, плечо, upl."""
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    keys = _get_okx_keys_for_user(user_id)
    if not keys:
        app.logger.warning("positions-live: no OKX keys for user_id=%s", user_id)
        return _err("OKX keys not configured", 400)

    try:
        raw_resp = _okx_sdk_get_positions(
            keys["api_key"], keys["secret_key"], keys["passphrase"]
        )
    except Exception as e:
        app.logger.exception("positions-live: OKX API error for user_id=%s: %s", user_id, e)
        return _err(f"OKX API error: {e}", 502)

    import json as _json

    try:
        app.logger.info(
            "positions-live: OKX get_positions raw response for user_id=%s: %s",
            user_id,
            _json.dumps(raw_resp, ensure_ascii=False)[:2000],
        )
    except Exception:
        app.logger.info(
            "positions-live: OKX get_positions raw response for user_id=%s (non-serializable type %s)",
            user_id,
            type(raw_resp),
        )

    raw_positions = raw_resp.get("data", []) if isinstance(raw_resp, dict) else []

    app.logger.info(
        "positions-live: fetched %d raw positions from OKX for user_id=%s",
        len(raw_positions or []),
        user_id,
    )

    out: list[dict] = []
    for p in raw_positions:
        if p.get("instType") not in (None, "", "SWAP"):
            continue
        settle_ccy = p.get("settleCcy") or p.get("ccy")
        if settle_ccy != "USDT":
            continue
        pos_str = p.get("pos") or "0"
        try:
            pos = float(pos_str)
        except (TypeError, ValueError):
            continue
        if pos == 0:
            continue
        try:
            avg_px = float(p.get("avgPx") or 0)
            mark_px = float(p.get("markPx") or 0)
            liq_px = float(p.get("liqPx") or 0)
            lever = float(p.get("lever") or 0)
            upl = float(p.get("upl") or 0)
        except (TypeError, ValueError):
            continue

        side = "long" if pos > 0 else "short"
        distance_pct: float | None = None
        if liq_px > 0 and mark_px > 0:
            if side == "long":
                distance_pct = (mark_px - liq_px) / mark_px * 100.0
            else:
                distance_pct = (liq_px - mark_px) / mark_px * 100.0

        out.append(
            {
                "instId": p.get("instId"),
                "side": side,
                "qty": abs(pos),
                "avgPx": avg_px,
                "markPx": mark_px,
                "liqPx": liq_px,
                "lever": lever,
                "upl": upl,
                "distance_to_liq_pct": distance_pct,
            }
        )

    if not out:
        app.logger.warning(
            "positions-live: no non-zero USDT-SWAP positions after filtering (raw=%d) for user_id=%s",
            len(raw_positions or []),
            user_id,
        )

    return _ok({"positions": out})


# ---------------------------------------------------------------------------
# Profile: OKX keys
# ---------------------------------------------------------------------------


@app.get("/api/profile/okx-keys")
def get_okx_keys():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    row = query_one(
        "SELECT okx_api_key, okx_secret_key, okx_passphrase "
        "FROM user_settings WHERE user_id = %s",
        (user_id,),
    )
    if not row:
        return _ok(
            {
                "masked_api_key": None,
                "has_secret": False,
                "has_passphrase": False,
            }
        )

    masked_api = None
    if row["okx_api_key"]:
        # Ключ зашифрован, поэтому просто маскируем длину
        masked_api = "********"

    data = {
        "masked_api_key": masked_api,
        "has_secret": bool(row["okx_secret_key"]),
        "has_passphrase": bool(row["okx_passphrase"]),
    }
    return _ok(data)


@app.put("/api/profile/okx-keys")
def save_okx_keys():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    body = request.get_json(silent=True) or {}
    api_key = (body.get("api_key") or "").strip()
    secret_key = (body.get("secret_key") or "").strip()
    passphrase = (body.get("passphrase") or "").strip()

    # Для простоты: если поле пустое — оставляем текущее значение.
    current = query_one(
        "SELECT okx_api_key, okx_secret_key, okx_passphrase "
        "FROM user_settings WHERE user_id = %s",
        (user_id,),
    ) or {}

    from crypto.encryption import encrypt

    enc_api = current.get("okx_api_key")
    enc_secret = current.get("okx_secret_key")
    enc_pass = current.get("okx_passphrase")

    if api_key:
        enc_api = encrypt(api_key)
    if secret_key:
        enc_secret = encrypt(secret_key)
    if passphrase:
        enc_pass = encrypt(passphrase)

    execute(
        """
        INSERT INTO user_settings (user_id, okx_api_key, okx_secret_key, okx_passphrase)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
          okx_api_key = VALUES(okx_api_key),
          okx_secret_key = VALUES(okx_secret_key),
          okx_passphrase = VALUES(okx_passphrase)
        """,
        (user_id, enc_api, enc_secret, enc_pass),
    )

    return _ok({"ok": True})


# ---------------------------------------------------------------------------
# Bot config: GET / PUT / reset
# ---------------------------------------------------------------------------


@app.get("/api/bot/config")
def get_bot_config():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    cfg = query_one(
        "SELECT * FROM bot_configs WHERE user_id = %s",
        (user_id,),
    )
    if not cfg:
        return _err("Bot config not found", 404)

    pairs = query_all(
        "SELECT pair_index, symbol_basket1, symbol_basket2 "
        "FROM basket_pairs WHERE bot_config_id = %s "
        "ORDER BY pair_index",
        (cfg["id"],),
    )

    baskets = [
        {"basket1": p["symbol_basket1"], "basket2": p["symbol_basket2"]}
        for p in pairs
    ]

    params = {
        "position_size_pct": float(cfg["position_size_pct"]),
        "orders_per_trade": int(cfg["orders_per_trade"]),
        "entry_spread_pct": float(cfg["entry_spread_pct"]),
        "take_profit_pct": float(cfg["take_profit_pct"]),
        "dca_count": int(cfg["dca_count"]),
        "dca_step_pct": float(cfg["dca_step_pct"]),
        "stop_loss_pct": float(cfg["stop_loss_pct"]),
        "stop_loss_enabled": bool(cfg["stop_loss_enabled"]),
        "leverage": int(cfg["leverage"]),
    }

    modes = {
        "no_new_position": bool(cfg["no_new_position"]),
        "simulation_mode": bool(cfg["simulation_mode"]),
    }

    error_handling = {
        "error_filter_enabled": bool(cfg.get("error_filter_enabled", 0)),
        "error_filter_pattern": cfg.get("error_filter_pattern", ""),
        "error_retry_count": int(cfg.get("error_retry_count", 0)),
    }

    return _ok(
        {
            "baskets": baskets,
            "params": params,
            "modes": modes,
            "error_handling": error_handling,
        }
    )


DEVELOPER_CONFIG_USER_ID = 1


@app.get("/api/developer/config")
def get_developer_config():
    """Read-only bot config for user_id=1. Only available for PRO+ subscribers."""
    user, error = _require_auth_user_or_401()
    if error:
        return error
    current_user_id = int(user["sub"])
    row = query_one("SELECT plan FROM users WHERE id = %s", (current_user_id,))
    if not row or row.get("plan") != "PRO_PLUS":
        return _err("Developer config is available on PRO+ plan only", 403)

    cfg = query_one(
        "SELECT * FROM bot_configs WHERE user_id = %s",
        (DEVELOPER_CONFIG_USER_ID,),
    )
    if not cfg:
        return _err("Developer config not found", 404)

    pairs = query_all(
        "SELECT pair_index, symbol_basket1, symbol_basket2 "
        "FROM basket_pairs WHERE bot_config_id = %s "
        "ORDER BY pair_index",
        (cfg["id"],),
    )
    baskets = [
        {"basket1": p["symbol_basket1"], "basket2": p["symbol_basket2"]}
        for p in pairs
    ]
    params = {
        "position_size_pct": float(cfg["position_size_pct"]),
        "orders_per_trade": int(cfg["orders_per_trade"]),
        "entry_spread_pct": float(cfg["entry_spread_pct"]),
        "take_profit_pct": float(cfg["take_profit_pct"]),
        "dca_count": int(cfg["dca_count"]),
        "dca_step_pct": float(cfg["dca_step_pct"]),
        "stop_loss_pct": float(cfg["stop_loss_pct"]),
        "stop_loss_enabled": bool(cfg["stop_loss_enabled"]),
        "leverage": int(cfg["leverage"]),
    }
    modes = {
        "no_new_position": bool(cfg["no_new_position"]),
        "simulation_mode": bool(cfg["simulation_mode"]),
    }
    error_handling = {
        "error_filter_enabled": bool(cfg.get("error_filter_enabled", 0)),
        "error_filter_pattern": cfg.get("error_filter_pattern", ""),
        "error_retry_count": int(cfg.get("error_retry_count", 0)),
    }
    return _ok({
        "baskets": baskets,
        "params": params,
        "modes": modes,
        "error_handling": error_handling,
    })


@app.put("/api/bot/config")
def update_bot_config():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    body = request.get_json(silent=True) or {}
    baskets = body.get("baskets") or []
    params = body.get("params") or {}
    modes = body.get("modes") or {}
    error_handling = body.get("error_handling") or {}

    cfg = query_one(
        "SELECT * FROM bot_configs WHERE user_id = %s",
        (user_id,),
    )
    if not cfg:
        return _err("Bot config not found", 404)

    execute(
        """
        UPDATE bot_configs
        SET position_size_pct=%s,
            orders_per_trade=%s,
            entry_spread_pct=%s,
            take_profit_pct=%s,
            dca_count=%s,
            dca_step_pct=%s,
            stop_loss_pct=%s,
            stop_loss_enabled=%s,
            leverage=%s,
            no_new_position=%s,
            simulation_mode=%s,
            error_filter_enabled=%s,
            error_filter_pattern=%s,
            error_retry_count=%s,
            updated_at=NOW()
        WHERE id=%s AND user_id=%s
        """,
        (
            params.get("position_size_pct", cfg["position_size_pct"]),
            params.get("orders_per_trade", cfg["orders_per_trade"]),
            params.get("entry_spread_pct", cfg["entry_spread_pct"]),
            params.get("take_profit_pct", cfg["take_profit_pct"]),
            params.get("dca_count", cfg["dca_count"]),
            params.get("dca_step_pct", cfg["dca_step_pct"]),
            params.get("stop_loss_pct", cfg["stop_loss_pct"]),
            int(params.get("stop_loss_enabled", cfg["stop_loss_enabled"])),
            params.get("leverage", cfg["leverage"]),
            int(modes.get("no_new_position", cfg["no_new_position"])),
            int(modes.get("simulation_mode", cfg["simulation_mode"])),
            int(error_handling.get("error_filter_enabled", cfg.get("error_filter_enabled", 0))),
            error_handling.get("error_filter_pattern", cfg.get("error_filter_pattern", "")),
            error_handling.get("error_retry_count", cfg.get("error_retry_count", 0)),
            cfg["id"],
            user_id,
        ),
    )

    # Перезаписываем корзины
    execute("DELETE FROM basket_pairs WHERE bot_config_id = %s", (cfg["id"],))
    for idx, b in enumerate(baskets, start=1):
        execute(
            """
            INSERT INTO basket_pairs (bot_config_id, pair_index, symbol_basket1, symbol_basket2)
            VALUES (%s, %s, %s, %s)
            """,
            (cfg["id"], idx, b.get("basket1"), b.get("basket2")),
        )
    execute("DELETE FROM chart_instrument_points WHERE user_id = %s", (user_id,))

    return _ok({"ok": True})


@app.post("/api/bot/config/reset")
def reset_bot_config():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    cfg = query_one(
        "SELECT * FROM bot_configs WHERE user_id = %s",
        (user_id,),
    )
    if not cfg:
        return _err("Bot config not found", 404)

    execute(
        """
        UPDATE bot_configs
        SET position_size_pct=200.00,
            orders_per_trade=1,
            entry_spread_pct=2.00,
            take_profit_pct=0.80,
            dca_count=3,
            dca_step_pct=3.00,
            stop_loss_pct=4.00,
            stop_loss_enabled=0,
            leverage=20,
            no_new_position=0,
            simulation_mode=1,
            error_filter_enabled=1,
            error_filter_pattern='Please try again',
            error_retry_count=3,
            updated_at=NOW()
        WHERE id=%s AND user_id=%s
        """,
        (cfg["id"], user_id),
    )

    # Дефолтные пары (с DOGE вместо EOS)
    default_pairs = [
        ("BTC-USDT-SWAP", "ETH-USDT-SWAP"),
        ("BNB-USDT-SWAP", "XRP-USDT-SWAP"),
        ("LINK-USDT-SWAP", "DOGE-USDT-SWAP"),
        ("LTC-USDT-SWAP", "XTZ-USDT-SWAP"),
        ("TRX-USDT-SWAP", "ETC-USDT-SWAP"),
    ]

    execute("DELETE FROM basket_pairs WHERE bot_config_id = %s", (cfg["id"],))
    for idx, (b1, b2) in enumerate(default_pairs, start=1):
        execute(
            """
            INSERT INTO basket_pairs (bot_config_id, pair_index, symbol_basket1, symbol_basket2)
            VALUES (%s, %s, %s, %s)
            """,
            (cfg["id"], idx, b1, b2),
        )

    return get_bot_config()


# ---------------------------------------------------------------------------
# Analytics: summary + trades list
# ---------------------------------------------------------------------------


@app.get("/api/analytics/summary")
def analytics_summary():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    stats = query_one(
        """
        SELECT
          COUNT(*) AS trades_count,
          COALESCE(SUM(CASE WHEN pnl_pct > 0 THEN 1 ELSE 0 END), 0) AS wins,
          COALESCE(SUM(pnl_pct), 0) AS pnl_total_pct,
          COALESCE(SUM(pnl_usdt), 0) AS pnl_total_usdt,
          COALESCE(AVG(pnl_pct), 0) AS avg_trade_pct
        FROM trades
        WHERE user_id = %s
        """,
        (user_id,),
    ) or {
        "trades_count": 0,
        "wins": 0,
        "pnl_total_pct": 0,
        "pnl_total_usdt": 0,
        "avg_trade_pct": 0,
    }

    winrate = 0.0
    if stats["trades_count"] > 0:
        winrate = float(stats["wins"]) / float(stats["trades_count"]) * 100.0

    return _ok(
        {
            "trades_count": int(stats["trades_count"]),
            "winrate_pct": round(winrate, 2),
            "pnl_total_pct": float(stats["pnl_total_pct"]),
            "pnl_total_usdt": float(stats["pnl_total_usdt"]),
            "avg_trade_pct": float(stats["avg_trade_pct"]),
        }
    )


@app.get("/api/analytics/trades")
def analytics_trades():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    limit = int(request.args.get("limit", 50))
    rows = query_all(
        """
        SELECT
          id,
          opened_at,
          closed_at,
          duration_seconds,
          entry_spread_pct,
          exit_spread_pct,
          pnl_pct,
          pnl_usdt,
          long_basket,
          short_basket,
          close_reason
        FROM trades
        WHERE user_id = %s
        ORDER BY id DESC
        LIMIT %s
        """,
        (user_id, limit),
    )

    def _serialize(r: dict) -> dict:
        return {
            "id": r["id"],
            "opened_at": r["opened_at"].isoformat() if r.get("opened_at") else None,
            "closed_at": r["closed_at"].isoformat() if r.get("closed_at") else None,
            "duration_sec": r.get("duration_seconds"),
            "entry_spread_pct": float(r.get("entry_spread_pct", 0)),
            "exit_spread_pct": float(r.get("exit_spread_pct", 0)),
            "pnl_pct": float(r.get("pnl_pct", 0)),
            "pnl_usdt": float(r.get("pnl_usdt", 0)),
            "long_basket": r.get("long_basket"),
            "short_basket": r.get("short_basket"),
            "reason": r.get("close_reason"),
        }

    return _ok({"trades": [_serialize(r) for r in rows]})


@app.get("/api/analytics/trades/detailed")
def analytics_trades_detailed():
    """Сделки с pairs_detail (корзины/позиции) для детализации в аналитике."""
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    limit = int(request.args.get("limit", 50))
    rows = query_all(
        """
        SELECT
          id,
          opened_at,
          closed_at,
          duration_seconds,
          entry_spread_pct,
          exit_spread_pct,
          pnl_pct,
          pnl_usdt,
          total_volume_usdt,
          long_basket,
          short_basket,
          close_reason,
          pairs_detail
        FROM trades
        WHERE user_id = %s
        ORDER BY id DESC
        LIMIT %s
        """,
        (user_id, limit),
    )

    def _serialize(r: dict) -> dict:
        pairs_detail = r.get("pairs_detail")
        if isinstance(pairs_detail, str) and pairs_detail:
            try:
                pairs_detail = json.loads(pairs_detail)
            except (ValueError, TypeError):
                pairs_detail = None
        return {
            "id": r["id"],
            "opened_at": r["opened_at"].isoformat() if r.get("opened_at") else None,
            "closed_at": r["closed_at"].isoformat() if r.get("closed_at") else None,
            "duration_sec": r.get("duration_seconds"),
            "entry_spread_pct": float(r.get("entry_spread_pct", 0)),
            "exit_spread_pct": float(r.get("exit_spread_pct", 0)),
            "pnl_pct": float(r.get("pnl_pct", 0)),
            "pnl_usdt": float(r.get("pnl_usdt", 0)),
            "total_volume_usdt": float(r.get("total_volume_usdt", 0)),
            "long_basket": r.get("long_basket"),
            "short_basket": r.get("short_basket"),
            "reason": r.get("close_reason"),
            "pairs_detail": pairs_detail or {},
        }

    return _ok({"trades": [_serialize(r) for r in rows]})


if __name__ == "__main__":
    # Disable reloader in monolith mode: duplicated Flask processes break in-memory worker manager.
    app.run(host="127.0.0.1", port=Config.PORT, debug=False, use_reloader=False, threaded=True)
