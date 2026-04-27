from __future__ import annotations

import unittest
from unittest.mock import patch

from bot_runtime.trading.position import PositionManager


class FakeOKX:
    def __init__(self, first_positions: list[dict] | None = None) -> None:
        self.orders: list[dict] = []
        self._positions_calls = 0
        self.first_positions = first_positions

    def get_positions(self) -> list[dict]:
        self._positions_calls += 1
        if self.first_positions is not None:
            return self.first_positions
        if self._positions_calls == 1:
            return [
                {"instId": "ADA-USDT-SWAP", "pos": "-2", "avgPx": "0.25", "upl": "0"},
                {"instId": "BNB-USDT-SWAP", "pos": "0.37", "avgPx": "630", "upl": "0"},
            ]
        return []

    def place_batch_orders(self, orders: list[dict]) -> list[dict]:
        self.orders.extend(orders)
        return [{"sCode": "0", "instId": o["instId"], "ordId": "ok"} for o in orders]


class FakeSpreadCalculator:
    all_symbols = ["ADA-USDT-SWAP", "BNB-USDT-SWAP"]
    current_prices = {}
    reference_prices = {}


class PositionCloseTest(unittest.TestCase):
    @patch("bot_runtime.trading.position.time.sleep", return_value=None)
    def test_close_uses_positive_sz_for_short_positions(self, _sleep):
        okx = FakeOKX()
        pm = PositionManager(okx, FakeSpreadCalculator(), {})

        pm._execute_close()

        ada_order = next(o for o in okx.orders if o["instId"] == "ADA-USDT-SWAP")
        self.assertEqual(ada_order["side"], "buy")
        self.assertEqual(ada_order["sz"], "2")
        self.assertTrue(ada_order["reduceOnly"])

        bnb_order = next(o for o in okx.orders if o["instId"] == "BNB-USDT-SWAP")
        self.assertEqual(bnb_order["side"], "sell")
        self.assertEqual(bnb_order["sz"], "0.37")
        self.assertTrue(bnb_order["reduceOnly"])

    def test_sync_marks_stale_open_state_closed_when_exchange_has_no_positions(self):
        okx = FakeOKX(first_positions=[])
        pm = PositionManager(okx, FakeSpreadCalculator(), {})
        pm.state.is_open = True
        pm.state.long_basket = "basket1"
        pm.state.short_basket = "basket2"
        pm.state.entry_spread = -1.0
        pm.state.dca_count = 1
        pm.state.positions = {"ADA-USDT-SWAP": {"qty": 2, "side": "short"}}

        pm.sync_with_exchange()

        self.assertFalse(pm.state.is_open)
        self.assertIsNone(pm.state.long_basket)
        self.assertIsNone(pm.state.short_basket)
        self.assertEqual(pm.state.positions, {})


if __name__ == "__main__":
    unittest.main()
