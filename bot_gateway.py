from __future__ import annotations

from typing import Protocol

import requests

from config import Config
from bot_runtime.service import LocalManagerService


class BotGateway(Protocol):
    def status(self, user_id: int) -> tuple[dict, int]: ...
    def start(self, user_id: int) -> tuple[dict, int]: ...
    def stop(self, user_id: int) -> tuple[dict, int]: ...
    def close_position(self, user_id: int) -> tuple[dict, int]: ...
    def logs(self, user_id: int, limit: int) -> tuple[dict, int]: ...


class HttpBotGateway:
    def _headers(self) -> dict[str, str]:
        return {
            "X-Manager-Key": Config.MANAGER_API_KEY,
            "Content-Type": "application/json",
        }

    def status(self, user_id: int) -> tuple[dict, int]:
        r = requests.get(f"{Config.MANAGER_URL}/api/workers/{user_id}", headers=self._headers(), timeout=3)
        return r.json(), r.status_code

    def start(self, user_id: int) -> tuple[dict, int]:
        r = requests.post(f"{Config.MANAGER_URL}/api/workers/{user_id}/start", headers=self._headers(), timeout=5)
        return r.json(), r.status_code

    def stop(self, user_id: int) -> tuple[dict, int]:
        r = requests.post(f"{Config.MANAGER_URL}/api/workers/{user_id}/stop", headers=self._headers(), timeout=5)
        return r.json(), r.status_code

    def close_position(self, user_id: int) -> tuple[dict, int]:
        r = requests.post(f"{Config.MANAGER_URL}/api/workers/{user_id}/close-positions", headers=self._headers(), timeout=10)
        return r.json(), r.status_code

    def logs(self, user_id: int, limit: int) -> tuple[dict, int]:
        r = requests.get(f"{Config.MANAGER_URL}/api/logs/{user_id}?limit={limit}", headers=self._headers(), timeout=3)
        return r.json(), r.status_code


class LocalBotGateway:
    def __init__(self) -> None:
        self._service: LocalManagerService | None = None

    @property
    def service(self) -> LocalManagerService:
        if self._service is None:
            self._service = LocalManagerService()
        return self._service

    def status(self, user_id: int) -> tuple[dict, int]:
        return self.service.status(user_id)

    def start(self, user_id: int) -> tuple[dict, int]:
        return self.service.start(user_id)

    def stop(self, user_id: int) -> tuple[dict, int]:
        return self.service.stop(user_id)

    def close_position(self, user_id: int) -> tuple[dict, int]:
        return self.service.close_positions(user_id)

    def logs(self, user_id: int, limit: int) -> tuple[dict, int]:
        return self.service.logs(user_id, limit)


def build_bot_gateway() -> BotGateway:
    return LocalBotGateway() if Config.BOT_GATEWAY_MODE == "local" else HttpBotGateway()

