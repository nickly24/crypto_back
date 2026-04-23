from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from config import Config

from .db.connection import Database
from .db import queries as Q
from .models import WorkerInfo

log = logging.getLogger("manager")

WORKER_LOGS_DIR = Path(__file__).resolve().parent / "logs"
WORKER_LOGS_DIR.mkdir(exist_ok=True)
BACK_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = BACK_ROOT.parent
LEGACY_BOT_MANAGER_ROOT = REPO_ROOT / "bot_manager"
LEGACY_WORKER_SCRIPT = LEGACY_BOT_MANAGER_ROOT / "bot_worker.py"
LEGACY_PYTHON_BIN = LEGACY_BOT_MANAGER_ROOT / "env" / "bin" / "python"


class BotManager:
    def __init__(self) -> None:
        self.db = Database()
        self.workers: dict[int, WorkerInfo] = {}
        self._running = True
        self._lock = threading.Lock()
        self._bg_thread: threading.Thread | None = None

    def start_background(self) -> None:
        self._running = True
        self._bg_thread = threading.Thread(target=self._loop, daemon=True, name="manager-loop")
        self._bg_thread.start()

    def stop_background(self) -> None:
        self._running = False
        if self._bg_thread and self._bg_thread.is_alive():
            self._bg_thread.join(timeout=5)

    def _loop(self) -> None:
        while self._running:
            try:
                self._health_check()
                self._update_heartbeat()
            except Exception:
                log.exception("Error in manager loop")
            time.sleep(Config.HEALTH_CHECK_INTERVAL)

    def recover(self) -> list[int]:
        rows = self.db.execute(Q.SELECT_RUNNING_BOTS)
        recovered: list[int] = []
        for row in rows:
            uid = row["user_id"]
            try:
                self._start_worker(uid)
                self._log_event(uid, "info", "Бот восстановлен после перезапуска менеджера")
                recovered.append(uid)
            except Exception:
                log.exception("Failed to recover bot for user %s", uid)
        return recovered

    def start_bot(self, user_id: int) -> dict:
        with self._lock:
            self._validate_user(user_id)
            if user_id in self.workers and self.workers[user_id].alive:
                return {"status": "already_running", "pid": self.workers[user_id].pid}
            cmd_id = self._audit("start", user_id)
            try:
                self._start_worker(user_id)
                self.db.execute(Q.FINISH_COMMAND, (cmd_id,))
                return {"status": "started", "pid": self.workers[user_id].pid}
            except Exception as exc:
                self.db.execute(Q.FAIL_COMMAND, (str(exc), cmd_id))
                raise

    def stop_bot(self, user_id: int) -> dict:
        with self._lock:
            cmd_id = self._audit("stop", user_id)
            try:
                result = self._stop_worker(user_id)
                self.db.execute(Q.FINISH_COMMAND, (cmd_id,))
                return result
            except Exception as exc:
                self.db.execute(Q.FAIL_COMMAND, (str(exc), cmd_id))
                raise

    def restart_bot(self, user_id: int) -> dict:
        with self._lock:
            self._stop_worker(user_id)
            time.sleep(1)
            self._start_worker(user_id)
            return {"status": "restarted", "pid": self.workers[user_id].pid}

    def close_positions(self, user_id: int) -> dict:
        with self._lock:
            if user_id not in self.workers or not self.workers[user_id].alive:
                raise RuntimeError("Бот не запущен")
            os.kill(self.workers[user_id].pid, signal.SIGUSR1)
            return {"status": "signal_sent", "signal": "SIGUSR1"}

    def get_worker_status(self, user_id: int) -> dict | None:
        w = self.workers.get(user_id)
        if not w:
            return None
        info = w.to_dict()
        rows = self.db.execute(Q.SELECT_STATE, (user_id,))
        if rows and rows[0].get("worker_pid") == w.pid:
            info["db_state"] = rows[0]
        else:
            info["db_state"] = None
        return info

    def list_workers(self) -> list[dict]:
        return [w.to_dict() for w in self.workers.values()]

    def get_logs(self, user_id: int, limit: int = 50) -> list[dict]:
        return self.db.execute(Q.SELECT_EVENTS, (user_id, limit))

    def shutdown(self) -> None:
        self._running = False
        with self._lock:
            for uid, w in list(self.workers.items()):
                if w.alive:
                    os.kill(w.pid, signal.SIGTERM)
            for uid, w in list(self.workers.items()):
                try:
                    w.process.wait(timeout=Config.WORKER_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    os.kill(w.pid, signal.SIGKILL)
                    w.process.wait(timeout=5)
                if w.log_file:
                    w.log_file.close()
            self.workers.clear()

    def _start_worker(self, user_id: int) -> None:
        keys = self.db.execute(Q.SELECT_USER_KEYS, (user_id,))
        if not keys or not keys[0].get("okx_api_key"):
            raise ValueError(f"API-ключи OKX не настроены для user_id={user_id}")
        cfg = self.db.execute(Q.SELECT_CONFIG, (user_id,))
        if not cfg:
            raise ValueError(f"Конфиг бота не найден для user_id={user_id}")
        log_path = WORKER_LOGS_DIR / f"worker_{user_id}.log"
        log_file = open(log_path, "a", buffering=1)
        # Use the production-proven trading worker to keep live spread/stop behavior stable.
        if LEGACY_WORKER_SCRIPT.exists():
            python_bin = str(LEGACY_PYTHON_BIN) if LEGACY_PYTHON_BIN.exists() else Config.PYTHON_BIN
            cmd = [python_bin, str(LEGACY_WORKER_SCRIPT), "--user-id", str(user_id)]
            cwd = str(LEGACY_BOT_MANAGER_ROOT)
        else:
            cmd = [sys.executable, "-m", "bot_runtime.bot_worker", "--user-id", str(user_id)]
            cwd = str(BACK_ROOT)

        process = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=log_file,
            cwd=cwd,
        )
        self.workers[user_id] = WorkerInfo(process=process, user_id=user_id, log_file=log_file)
        self.db.execute(Q.SET_DESIRED_STATE, ("running", user_id))
        self.db.execute(Q.UPSERT_STATE_RUNNING, (user_id, process.pid, process.pid))
        self._log_event(user_id, "info", f"Worker запущен (pid={process.pid})")

    def _stop_worker(self, user_id: int) -> dict:
        w = self.workers.get(user_id)
        if not w:
            return {"status": "not_running"}
        if w.alive:
            os.kill(w.pid, signal.SIGTERM)
            try:
                w.process.wait(timeout=Config.WORKER_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                os.kill(w.pid, signal.SIGKILL)
                w.process.wait(timeout=5)
        if w.log_file:
            w.log_file.close()
        self.workers.pop(user_id, None)
        self.db.execute(Q.SET_DESIRED_STATE, ("stopped", user_id))
        self.db.execute(Q.SET_STATE_STOPPED, (user_id,))
        return {"status": "stopped"}

    def _health_check(self) -> None:
        now = datetime.utcnow()
        with self._lock:
            for uid, w in list(self.workers.items()):
                if not w.alive:
                    self._try_restart(uid, w)
                    continue
                rows = self.db.execute(Q.SELECT_STATE, (uid,))
                if rows:
                    last_update = rows[0].get("updated_at")
                    if last_update and (now - last_update).total_seconds() > Config.WORKER_HANG_TIMEOUT:
                        os.kill(w.pid, signal.SIGKILL)
                        w.process.wait(timeout=5)
                        self._try_restart(uid, w)

    def _try_restart(self, user_id: int, w: WorkerInfo) -> None:
        now = datetime.utcnow()
        window = timedelta(seconds=Config.RESTART_WINDOW_SECONDS)
        if now - w.last_restart_window_start > window:
            w.restart_count = 0
            w.last_restart_window_start = now
        if w.restart_count >= Config.MAX_RESTARTS_PER_WINDOW:
            self.db.execute(Q.SET_STATE_ERROR, (user_id,))
            self.db.execute(Q.SET_DESIRED_STATE, ("stopped", user_id))
            self.workers.pop(user_id, None)
            return
        w.restart_count += 1
        self.workers.pop(user_id, None)
        self._start_worker(user_id)

    def _update_heartbeat(self) -> None:
        alive = sum(1 for w in self.workers.values() if w.alive)
        pid = os.getpid()
        self.db.execute(Q.UPSERT_HEARTBEAT, (pid, alive, pid, alive))

    def _validate_user(self, user_id: int) -> None:
        rows = self.db.execute(Q.SELECT_USER, (user_id,))
        if not rows:
            raise ValueError(f"Пользователь user_id={user_id} не найден")
        if rows[0].get("is_blocked"):
            raise PermissionError(f"Пользователь user_id={user_id} заблокирован")

    def _audit(self, command: str, user_id: int) -> int:
        return self.db.insert_id(Q.INSERT_COMMAND, (user_id, command))

    def _log_event(self, user_id: int, level: str, message: str, details: dict | None = None) -> None:
        self.db.execute(Q.INSERT_EVENT, (user_id, level, message, json.dumps(details) if details else None))

