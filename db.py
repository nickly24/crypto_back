from __future__ import annotations

import pymysql

from config import Config


def get_connection() -> pymysql.connections.Connection:
    return pymysql.connect(
        host=Config.DB_HOST,
        port=Config.DB_PORT,
        user=Config.DB_USER,
        password=Config.DB_PASSWORD,
        database=Config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def query_one(sql: str, params: tuple | None = None) -> dict | None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            row = cur.fetchone()
        return row
    finally:
        conn.close()


def query_all(sql: str, params: tuple | None = None) -> list[dict]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            rows = cur.fetchall()
        return list(rows)
    finally:
        conn.close()


def execute(sql: str, params: tuple | None = None) -> int:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.rowcount
    finally:
        conn.close()

