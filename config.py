from __future__ import annotations

import os
from dotenv import load_dotenv


# Загружаем .env именно из папки back,
# чтобы конфиги бэкенда были независимы от bot_manager.
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


class Config:
    # MySQL
    DB_HOST: str = os.getenv("DB_HOST", "147.45.138.77")
    DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
    DB_USER: str = os.getenv("DB_USER", "cryptobot")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "cryptobot")
    DB_NAME: str = os.getenv("DB_NAME", "crypto")

    # Flask
    SECRET_KEY: str = os.getenv(
        "BACKEND_SECRET_KEY",
        "dev-backend-secret-change-me",  # для dev; в проде переопределить
    )
    BACKEND_PUBLIC_URL: str = os.getenv("BACKEND_PUBLIC_URL", "").strip()

    # CORS: FRONTEND_ORIGIN — базовый URL фронта (редиректы YooKassa и т.п.)
    FRONTEND_ORIGIN: str = os.getenv("FRONTEND_ORIGIN", "https://nickly24-crypto-front-a2d6.twc1.net/")
    # true: любой Origin в CORS (отражается в Access-Control-Allow-Origin). В проде при желании задать false.
    CORS_ALLOW_ALL_ORIGINS: bool = os.getenv("CORS_ALLOW_ALL_ORIGINS", "true").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    # JWT
    JWT_ALG: str = "HS256"
    JWT_TTL_SECONDS: int = int(os.getenv("JWT_TTL_SECONDS", "86400"))  # 1 день

    # Server
    PORT: int = int(os.getenv("PORT", "8000"))

    # Bot Gateway mode: "local" (in-process manager) or "http" (legacy bot_manager service)
    BOT_GATEWAY_MODE: str = os.getenv("BOT_GATEWAY_MODE", "local").lower()

    # Legacy Bot Manager HTTP API (used when BOT_GATEWAY_MODE=http)
    MANAGER_URL: str = os.getenv("MANAGER_URL", "http://127.0.0.1:6800")
    MANAGER_API_KEY: str = os.getenv("MANAGER_API_KEY", os.getenv("MANAGER_SECRET", "your-secret-key-here"))
    MANAGER_SECRET: str = os.getenv("MANAGER_SECRET", MANAGER_API_KEY)

    # Encryption (Fernet) — тот же ключ, что и в bot_manager (общая БД user_settings)
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "dvKM1FbZzPZ--aLlGtqckBYuHVgwNaDGiILZNeP_lKY=")

    # OKX: demo / real flag
    OKX_DEMO: str = os.getenv("OKX_DEMO", "0")

    # Bot runtime settings (used by in-process manager + workers)
    DB_POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", "10"))
    MANAGER_HOST: str = os.getenv("MANAGER_HOST", "0.0.0.0")
    MANAGER_PORT: int = int(os.getenv("MANAGER_PORT", "6800"))
    HEALTH_CHECK_INTERVAL: int = int(os.getenv("HEALTH_CHECK_INTERVAL", "10"))
    WORKER_HANG_TIMEOUT: int = int(os.getenv("WORKER_HANG_TIMEOUT", "60"))
    WORKER_STOP_TIMEOUT: int = int(os.getenv("WORKER_STOP_TIMEOUT", "15"))
    WS_STALE_TIMEOUT: int = int(os.getenv("WS_STALE_TIMEOUT", "90"))
    MAX_RESTARTS_PER_WINDOW: int = int(os.getenv("MAX_RESTARTS_PER_WINDOW", "3"))
    RESTART_WINDOW_SECONDS: int = int(os.getenv("RESTART_WINDOW_SECONDS", "300"))
    PYTHON_BIN: str = os.getenv("PYTHON_BIN", "python3")

    # YooKassa (самозанятый / магазин)
    YOOKASSA_SHOP_ID: str = os.getenv("YOOKASSA_SHOP_ID", "")
    YOOKASSA_SECRET_KEY: str = os.getenv("YOOKASSA_SECRET_KEY", "")
    YOOKASSA_API_URL: str = "https://api.yookassa.ru/v3"

    # Social auth
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    TELEGRAM_CLIENT_ID: str = os.getenv("TELEGRAM_CLIENT_ID", "").strip()
    TELEGRAM_CLIENT_SECRET: str = os.getenv("TELEGRAM_CLIENT_SECRET", "").strip()
    TELEGRAM_REDIRECT_URI: str = os.getenv("TELEGRAM_REDIRECT_URI", "").strip()
