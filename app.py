from __future__ import annotations

import datetime as dt
import time
from typing import Any, Dict

import bcrypt
import jwt
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from config import Config
from db import execute, query_all, query_one


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


app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY

CORS(
    app,
    resources={r"/api/*": {"origins": Config.FRONTEND_ORIGIN}},
    supports_credentials=True,
)


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
        "SELECT id, email, password_hash, role, is_blocked "
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

    token = _make_token(user)
    return _ok(
        {
            "access_token": token,
            "refresh_token": token,  # упрощение для dev
            "user": {
                "id": user["id"],
                "email": user["email"],
                "role": user["role"],
            },
        }
    )


@app.get("/api/auth/me")
def auth_me():
    payload = _parse_auth()
    if not payload:
        return _err("Unauthorized", 401)
    return _ok(
        {
            "id": int(payload["sub"]),
            "email": payload["email"],
            "role": payload["role"],
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
        "SELECT id, email, password_hash, role, is_blocked "
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

    token = _make_token(user)
    return _ok(
        {
            "access_token": token,
            "refresh_token": token,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "role": user["role"],
            },
        }
    )


@app.get("/api/admin/me")
def admin_me():
    payload = _parse_auth()
    if not payload or payload.get("role") != "admin":
        return _err("Unauthorized", 401)
    return _ok(
        {
            "id": int(payload["sub"]),
            "email": payload["email"],
            "role": payload["role"],
        }
    )


# ---------------------------------------------------------------------------
# Bot Manager proxy routes (будем вызывать Flask-сервер менеджера)
# Пока без реального теста — только каркас.
# ---------------------------------------------------------------------------


def _manager_headers() -> Dict[str, str]:
    return {
        "X-Manager-Key": Config.MANAGER_API_KEY,
        "Content-Type": "application/json",
    }


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

    url = f"{Config.MANAGER_URL}/api/workers/{user_id}"
    try:
        resp = requests.get(url, headers=_manager_headers(), timeout=3)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)

    return jsonify(resp.json()), resp.status_code


@app.post("/api/bot/start")
def bot_start():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    url = f"{Config.MANAGER_URL}/api/workers/{user_id}/start"
    try:
        resp = requests.post(url, headers=_manager_headers(), timeout=5)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)

    if resp.status_code != 200:
        return jsonify(resp.json()), resp.status_code

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

    url = f"{Config.MANAGER_URL}/api/workers/{user_id}/stop"
    try:
        resp = requests.post(url, headers=_manager_headers(), timeout=5)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)

    if resp.status_code != 200:
        return jsonify(resp.json()), resp.status_code

    deadline = time.time() + 5
    stopped = False
    while time.time() < deadline:
        try:
            check = requests.get(
                f"{Config.MANAGER_URL}/api/workers/{user_id}",
                headers=_manager_headers(), timeout=3,
            )
            data = check.json()
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

    url = f"{Config.MANAGER_URL}/api/workers/{user_id}/close-positions"
    try:
        resp = requests.post(url, headers=_manager_headers(), timeout=10)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)

    if resp.status_code != 200:
        return jsonify(resp.json()), resp.status_code

    if was_open:
        row = _poll_db(
            "SELECT position_open FROM bot_state WHERE user_id = %s",
            (user_id,),
            lambda r: r.get("position_open") == 0,
            timeout=20.0,
            interval=1.0,
        )
        closed = row and row.get("position_open") == 0
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


@app.get("/api/bot/logs")
def bot_logs():
    user, error = _require_auth_user_or_401()
    if error:
        return error
    user_id = int(user["sub"])

    limit = request.args.get("limit", 50)
    url = f"{Config.MANAGER_URL}/api/logs/{user_id}?limit={limit}"
    try:
        resp = requests.get(url, headers=_manager_headers(), timeout=3)
    except Exception as e:
        return _err(f"Manager unavailable: {e}", 503)

    return jsonify(resp.json()), resp.status_code


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

    from bot_manager.crypto.encryption import encrypt  # type: ignore[import]

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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)
