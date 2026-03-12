from __future__ import annotations

import bcrypt
from flask import Blueprint, request

from db import query_one
from utils import err, make_token, ok, parse_auth, require_admin


auth_bp = Blueprint("auth", __name__)


@auth_bp.get("/api/health")
def health():
    return ok({"status": "ok"})


@auth_bp.post("/api/auth/login")
def auth_login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return err("Email и пароль обязательны", 422)

    user = query_one(
        "SELECT id, email, password_hash, role, is_blocked "
        "FROM users WHERE email = %s",
        (email,),
    )
    if not user:
        return err("Неверный логин или пароль", 401)
    if user["is_blocked"]:
        return err("Пользователь заблокирован", 403)

    stored = user["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored):
        return err("Неверный логин или пароль", 401)

    token = make_token(user)
    return ok(
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


@auth_bp.get("/api/auth/me")
def auth_me():
    payload = parse_auth()
    if not payload:
        return err("Unauthorized", 401)
    return ok(
        {
            "id": payload["sub"],
            "email": payload["email"],
            "role": payload["role"],
        }
    )


@auth_bp.post("/api/admin/login")
def admin_login():
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return err("Email и пароль обязательны", 422)

    user = query_one(
        "SELECT id, email, password_hash, role, is_blocked "
        "FROM users WHERE email = %s",
        (email,),
    )
    if not user:
        return err("Неверный логин или пароль", 401)
    if user["is_blocked"]:
        return err("Пользователь заблокирован", 403)
    if user["role"] != "admin":
        return err("Нет прав администратора", 403)

    stored = user["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored):
        return err("Неверный логин или пароль", 401)

    token = make_token(user)
    return ok(
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


@auth_bp.get("/api/admin/me")
@require_admin
def admin_me():
    from flask import request as flask_request  # для type hints

    payload = flask_request.user  # type: ignore[attr-defined]
    return ok(
        {
            "id": payload["sub"],
            "email": payload["email"],
            "role": payload["role"],
        }
    )

