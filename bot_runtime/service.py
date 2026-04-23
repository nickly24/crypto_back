from __future__ import annotations

import atexit
import threading
from datetime import datetime

from .manager import BotManager
from .db import queries as Q

_manager: BotManager | None = None
_lock = threading.Lock()


def get_manager() -> BotManager:
    global _manager
    with _lock:
        if _manager is None:
            _manager = BotManager()
            _manager.recover()
            _manager.start_background()
            atexit.register(_manager.shutdown)
    return _manager


class LocalManagerService:
    def __init__(self) -> None:
        self.manager = get_manager()

    def status(self, user_id: int) -> tuple[dict, int]:
        info = self.manager.get_worker_status(user_id)
        if info is not None:
            return {"ok": True, "data": info}, 200

        rows = self.manager.db.execute(Q.SELECT_STATE, (user_id,))
        db_state = rows[0] if rows else None
        if db_state:
            return {
                "ok": True,
                "data": {
                    "user_id": user_id,
                    "pid": None,
                    "alive": False,
                    "started_at": None,
                    "restart_count": 0,
                    "uptime_seconds": 0,
                    "db_state": db_state,
                },
            }, 200
        return {"ok": False, "error": f"Worker для user_id={user_id} не найден"}, 404

    def start(self, user_id: int) -> tuple[dict, int]:
        try:
            return {"ok": True, "data": self.manager.start_bot(user_id)}, 200
        except (ValueError, PermissionError) as exc:
            return {"ok": False, "error": str(exc)}, 422
        except Exception as exc:
            return {"ok": False, "error": str(exc)}, 500

    def stop(self, user_id: int) -> tuple[dict, int]:
        try:
            return {"ok": True, "data": self.manager.stop_bot(user_id)}, 200
        except Exception as exc:
            return {"ok": False, "error": str(exc)}, 500

    def close_positions(self, user_id: int) -> tuple[dict, int]:
        try:
            return {"ok": True, "data": self.manager.close_positions(user_id)}, 200
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc)}, 422
        except Exception as exc:
            return {"ok": False, "error": str(exc)}, 500

    def logs(self, user_id: int, limit: int) -> tuple[dict, int]:
        rows = self.manager.get_logs(user_id, limit)
        for row in rows:
            for key, value in row.items():
                if isinstance(value, datetime):
                    row[key] = value.isoformat()
        return {"ok": True, "data": rows}, 200

