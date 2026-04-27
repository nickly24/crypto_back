from __future__ import annotations

import unittest
from unittest.mock import patch

from bot_runtime.trading.engine import TradingEngine


class WebSocketStaleTests(unittest.TestCase):
    def _engine(self) -> TradingEngine:
        engine = TradingEngine.__new__(TradingEngine)
        engine._ws_started_at = 100.0
        engine._last_tick_at = 0.0
        engine._logged_events = []
        engine._state_updates = []
        engine._log_event = lambda level, message, details=None: engine._logged_events.append((level, message))
        engine._update_db_state = (
            lambda actual_state, connection_status="connected": engine._state_updates.append(
                (actual_state, connection_status)
            )
        )
        return engine

    def test_ws_stale_uses_subscription_time_before_first_tick(self) -> None:
        engine = self._engine()

        with patch("bot_runtime.trading.engine.Config.WS_STALE_TIMEOUT", 30):
            with self.assertRaisesRegex(RuntimeError, "OKX WebSocket stale"):
                engine._raise_if_ws_stale(now=131.0)

        self.assertEqual(engine._logged_events[0][0], "error")
        self.assertEqual(engine._state_updates, [("error", "stale")])

    def test_ws_recent_tick_is_not_stale(self) -> None:
        engine = self._engine()
        engine._last_tick_at = 120.0

        with patch("bot_runtime.trading.engine.Config.WS_STALE_TIMEOUT", 30):
            engine._raise_if_ws_stale(now=149.0)

        self.assertEqual(engine._logged_events, [])
        self.assertEqual(engine._state_updates, [])


if __name__ == "__main__":
    unittest.main()
