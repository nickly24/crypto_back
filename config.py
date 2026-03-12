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

    # CORS
    FRONTEND_ORIGIN: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")

    # JWT
    JWT_ALG: str = "HS256"
    JWT_TTL_SECONDS: int = int(os.getenv("JWT_TTL_SECONDS", "86400"))  # 1 день

    # Bot Manager HTTP API
    MANAGER_URL: str = os.getenv("MANAGER_URL", "http://127.0.0.1:6800")
    MANAGER_API_KEY: str = os.getenv("MANAGER_API_KEY", "your-secret-key-here")

