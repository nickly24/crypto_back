from __future__ import annotations

import pymysql
from dbutils.pooled_db import PooledDB

from config import Config

_pool: PooledDB | None = None


def _get_pool() -> PooledDB:
    global _pool
    if _pool is None:
        _pool = PooledDB(
            creator=pymysql,
            maxconnections=Config.DB_POOL_SIZE,
            mincached=0,
            maxcached=Config.DB_POOL_SIZE,
            blocking=True,
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=Config.DB_CONNECT_TIMEOUT,
            read_timeout=Config.DB_READ_TIMEOUT,
            write_timeout=Config.DB_WRITE_TIMEOUT,
        )
    return _pool


def get_connection() -> pymysql.connections.Connection:
    return _get_pool().connection()


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


def insert_id(sql: str, params: tuple | None = None) -> int:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return int(cur.lastrowid)
    finally:
        conn.close()
