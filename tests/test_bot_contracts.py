from __future__ import annotations

import unittest
from unittest.mock import patch

import jwt

from app import app
from config import Config


class StubGateway:
    def status(self, user_id: int):
        return {"ok": True, "data": {"alive": True, "pid": 123}}, 200

    def start(self, user_id: int):
        return {"ok": True, "data": {"status": "started", "pid": 123}}, 200

    def stop(self, user_id: int):
        return {"ok": True, "data": {"status": "stopped"}}, 200

    def close_position(self, user_id: int):
        return {"ok": True, "data": {"status": "signal_sent"}}, 200

    def logs(self, user_id: int, limit: int):
        return {"ok": True, "data": [{"id": 1, "message": "log"}]}, 200


class BotContractsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app.test_client()
        self.token = jwt.encode({"sub": "1", "role": "user"}, Config.SECRET_KEY, algorithm=Config.JWT_ALG)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    @patch("app.bot_gateway", new=StubGateway())
    def test_status_contract(self):
        resp = self.client.get("/api/bot/status", headers=self.headers)
        body = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertIn("ok", body)
        self.assertIn("data", body)
        self.assertIn("alive", body["data"])

    @patch("app.bot_gateway", new=StubGateway())
    @patch("app._poll_db", return_value={"actual_state": "running"})
    def test_start_contract(self, _poll):
        resp = self.client.post("/api/bot/start", headers=self.headers)
        body = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertIn(body["data"]["status"], ("started", "timeout"))
        self.assertIn("alive", body["data"])

    @patch("app.bot_gateway", new=StubGateway())
    def test_stop_contract(self):
        resp = self.client.post("/api/bot/stop", headers=self.headers)
        body = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertIn("status", body["data"])

    @patch("app.bot_gateway", new=StubGateway())
    @patch("app.query_one", side_effect=[{"position_open": 1}, {"position_open": 0}, {"id": 9, "pnl_pct": 1.1, "close_reason": "manual"}])
    def test_close_position_contract(self, _query):
        resp = self.client.post("/api/bot/close-position", headers=self.headers)
        body = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertIn("position_closed", body["data"])

    @patch("app.bot_gateway", new=StubGateway())
    def test_logs_contract(self):
        resp = self.client.get("/api/bot/logs?limit=10", headers=self.headers)
        body = resp.get_json()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(body["ok"])
        self.assertIsInstance(body["data"], list)


if __name__ == "__main__":
    unittest.main()

