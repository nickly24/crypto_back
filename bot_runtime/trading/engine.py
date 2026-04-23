from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime

from config import Config
from crypto.encryption import decrypt

from ..db.connection import Database
from ..db import queries as Q
from .okx_client import OKXClient
from .position import PositionManager
from .spread import BasketPair, SpreadCalculator

log = logging.getLogger("engine")


class TradingEngine:
    def __init__(self, user_id: int) -> None:
        self.user_id = user_id
        self.db = Database()
        self.okx: OKXClient | None = None
        self.sc: SpreadCalculator | None = None
        self.pm: PositionManager | None = None
        self._running = True
        self._close_requested = False
        self._last_state_update = 0.0

    def initialize(self) -> None:
        cfg = self._load_config()
        pairs = self._load_pairs(cfg["id"])
        api_key, secret, passphrase = self._load_keys()
        self.okx = OKXClient(api_key, secret, passphrase, demo=(Config.OKX_DEMO == "1"))
        self.okx.load_instruments()
        self.sc = SpreadCalculator(pairs)
        self.pm = PositionManager(self.okx, self.sc, cfg, log_event_cb=self._log_event)
        self.okx.set_position_mode_net()
        for sym in self.sc.all_symbols:
            try:
                self.okx.set_leverage(sym, self.pm.leverage)
            except Exception:
                log.warning("Failed to set leverage for %s", sym, exc_info=True)
        self._log_event("info", "Бот инициализирован")

    def _load_config(self) -> dict:
        rows = self.db.execute(Q.SELECT_CONFIG, (self.user_id,))
        if not rows:
            raise RuntimeError(f"No bot_config for user_id={self.user_id}")
        return rows[0]

    def _load_pairs(self, config_id: int) -> list[BasketPair]:
        rows = self.db.execute(Q.SELECT_BASKET_PAIRS, (config_id,))
        if not rows:
            raise RuntimeError(f"No basket_pairs for config_id={config_id}")
        return [
            BasketPair(index=r["pair_index"], symbol_b1=r["symbol_basket1"], symbol_b2=r["symbol_basket2"])
            for r in rows
        ]

    def _load_keys(self) -> tuple[str, str, str]:
        rows = self.db.execute(Q.SELECT_USER_KEYS, (self.user_id,))
        if not rows:
            raise RuntimeError(f"No API keys for user_id={self.user_id}")
        r = rows[0]
        return decrypt(r["okx_api_key"]), decrypt(r["okx_secret_key"]), decrypt(r["okx_passphrase"])

    async def run(self) -> None:
        assert self.okx and self.sc and self.pm
        await self.okx.subscribe_tickers(self.sc.all_symbols, callback=self._on_tick)
        rest_prices = self.okx.fetch_ticker_prices(self.sc.all_symbols)
        for sym, px in rest_prices.items():
            self.sc.update_price(sym, px)
        if rest_prices and not self.sc.has_reference() and self.sc.has_all_quotes():
            self.sc.fix_reference_prices()
        self._update_db_state("running")
        try:
            while self._running:
                if self._close_requested:
                    self.pm.close_all()
                    self._close_requested = False
                now = time.time()
                if now - self._last_state_update >= 3.0:
                    self._update_db_state("running")
                    self._last_state_update = now
                await asyncio.sleep(0.5)
        finally:
            await self.okx.close_ws()

    def _on_tick(self, raw_msg) -> None:
        if isinstance(raw_msg, str):
            msg = json.loads(raw_msg)
        else:
            msg = raw_msg
        data_list = msg.get("data")
        if not data_list:
            return
        data = data_list[0]
        inst_id = data.get("instId")
        last_price = data.get("last")
        if not inst_id or not last_price:
            return
        assert self.sc and self.pm
        self.sc.update_price(inst_id, float(last_price))
        if not self.sc.has_reference():
            if self.sc.has_all_quotes():
                self.sc.fix_reference_prices()
            return
        action = self.pm.evaluate()
        if action in ("take_profit", "stop_loss"):
            self.sc.refresh_reference_prices()
        self._update_db_state("running")

    def _update_db_state(self, actual_state: str) -> None:
        assert self.sc and self.pm and self.okx
        pnl = self.pm.get_pnl_for_dashboard()
        balance = self.okx.get_balance()
        spread = self.sc.spread() if self.sc.has_reference() else None
        long_b = self.pm.state.long_basket if self.pm.state.is_open else None
        short_b = self.pm.state.short_basket if self.pm.state.is_open else None
        self.db.execute(
            Q.UPDATE_STATE_FULL,
            (
                actual_state,
                round(spread, 4) if spread is not None else None,
                long_b,
                short_b,
                pnl.get("pnl_long_pct"),
                pnl.get("pnl_short_pct"),
                pnl.get("pnl_total_pct"),
                pnl.get("pnl_total_usdt"),
                balance.get("total_eq"),
                balance.get("avail_eq"),
                self.okx.ping_ms(),
                "connected",
                int(self.pm.state.is_open),
                round(self.pm.state.entry_spread, 4) if self.pm.state.is_open else None,
                self.pm.state.dca_count,
                long_b,
                short_b,
                json.dumps(self.sc.reference_prices) if self.sc.has_reference() else None,
                json.dumps(self.pm.state.positions),
                json.dumps(self.sc.quotes_snapshot()),
                os.getpid(),
                self.user_id,
            ),
        )

    def save_state_and_stop(self) -> None:
        self._running = False
        if self.sc and self.pm:
            self.db.execute(
                Q.SAVE_STATE_ON_SHUTDOWN,
                (
                    json.dumps(self.sc.reference_prices) if self.sc.has_reference() else None,
                    json.dumps(self.pm.state.positions),
                    round(self.pm.state.entry_spread, 4) if self.pm.state.is_open else None,
                    self.pm.state.dca_count,
                    int(self.pm.state.is_open),
                    self.pm.state.long_basket,
                    self.pm.state.short_basket,
                    self.user_id,
                ),
            )

    def request_close_positions(self) -> None:
        self._close_requested = True

    def _log_event(self, level: str, message: str, details: dict | None = None) -> None:
        self.db.execute(Q.INSERT_EVENT, (self.user_id, level, message, json.dumps(details) if details else None))

