from __future__ import annotations

import unittest
from datetime import datetime

from bot_runtime.trading.engine import TradingEngine


class FakeDB:
    def __init__(self) -> None:
        self.calls: list[tuple[object, tuple]] = []

    def execute(self, query, params=()) -> None:
        self.calls.append((query, params))


class FakeOKX:
    def get_ct_val(self, inst_id: str) -> float:
        return 1.0

    def get_fills_history(self, **kwargs) -> list[dict]:
        return [
            {"instId": "AAA-USDT-SWAP", "fillPnl": "2.0", "fee": "-0.05"},
            {"instId": "BBB-USDT-SWAP", "fillPnl": "-0.5", "fee": "-0.03"},
            {"instId": "OTHER-USDT-SWAP", "fillPnl": "100", "fee": "-1"},
        ]


class FakeSpreadCalculator:
    all_symbols = ["AAA-USDT-SWAP", "BBB-USDT-SWAP"]


class TradeHistoryTest(unittest.TestCase):
    def test_record_trade_uses_net_pnl_and_commission_from_okx_fills(self) -> None:
        engine = TradingEngine.__new__(TradingEngine)
        engine.user_id = 4
        engine.db = FakeDB()
        engine.okx = FakeOKX()
        engine.sc = FakeSpreadCalculator()

        snapshot = {
            "entry_time": "2026-04-29T09:49:49",
            "entry_spread": -1.0,
            "long_basket": "basket1",
            "short_basket": "basket2",
            "dca_count": 0,
            "positions": {
                "AAA-USDT-SWAP": {"qty": 10, "avg_price": 5, "upl": 2.0},
                "BBB-USDT-SWAP": {"qty": 10, "avg_price": 5, "upl": -0.5},
            },
        }

        engine._record_trade_from_snapshot("take_profit", -0.1, {}, snapshot)

        params = engine.db.calls[-1][1]
        self.assertEqual(params[9], 1.42)
        self.assertEqual(params[14], 0.08)
        self.assertEqual(params[10], 100.0)
        self.assertEqual(params[8], 1.42)


if __name__ == "__main__":
    unittest.main()
