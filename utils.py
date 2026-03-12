from __future__ import annotations

import datetime as dt
from functools import wraps
from typing import Any, Callable, Dict

import jwt
from flask import jsonify, request

from back.config import Config


def make_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "email": user["email"],
        "role": user["role"],
        "exp": dt.datetime.utcnow() + dt.timedelta(seconds=Config.JWT_TTL_SECONDS),
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm=Config.JWT_ALG)


def parse_auth() -> dict | None:
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


def require_admin(fn: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        payload = parse_auth()
        if not payload:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        if payload.get("role") != "admin":
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        request.user = payload  # type: ignore[attr-defined]
        return fn(*args, **kwargs)

    return wrapper


def ok(data: Dict[str, Any], code: int = 200):
    return jsonify({"ok": True, "data": data}), code


def err(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code

