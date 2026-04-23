from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Callable

import okx.Account as OkxAccount
import okx.MarketData as OkxMarket
import okx.PublicData as OkxPublic
import okx.Trade as OkxTrade
from okx.websocket.WsPublicAsync import WsPublicAsync

log = logging.getLogger("okx_client")


class OKXClient:
    def __init__(self, api_key: str, secret_key: str, passphrase: str, demo: bool = False) -> None:
        flag = "1" if demo else "0"
        self.account = OkxAccount.AccountAPI(api_key, secret_key, passphrase, False, flag)
        self.trade = OkxTrade.TradeAPI(api_key, secret_key, passphrase, False, flag)
        self.public = OkxPublic.PublicAPI("", "", "", False, flag)
        self.market = OkxMarket.MarketAPI(flag=flag)
        self._demo = demo
        self._ws: WsPublicAsync | None = None
        self._instruments_cache: dict[str, dict] = {}

    def load_instruments(self) -> dict[str, dict]:
        result = self.public.get_instruments(instType="SWAP")
        if result.get("code") != "0":
            raise RuntimeError(f"Failed to load instruments: {result}")
        for inst in result["data"]:
            if inst.get("settleCcy") == "USDT" and inst.get("state") == "live":
                self._instruments_cache[inst["instId"]] = inst
        return self._instruments_cache

    def get_ct_val(self, inst_id: str) -> float:
        return float(self._instruments_cache[inst_id]["ctVal"])

    def get_lot_sz(self, inst_id: str) -> float:
        return float(self._instruments_cache[inst_id].get("lotSz", "1"))

    def set_position_mode_net(self) -> None:
        self.account.set_position_mode(posMode="net_mode")

    def set_leverage(self, inst_id: str, lever: int) -> None:
        self.account.set_leverage(instId=inst_id, lever=str(lever), mgnMode="cross")

    def get_balance(self) -> dict:
        r = self.account.get_account_balance()
        if r.get("code") != "0":
            raise RuntimeError(f"get_balance failed: {r}")
        acc = (r.get("data") or [{}])[0]
        details = acc.get("details") or []
        usdt = next((d for d in details if d.get("ccy") == "USDT"), {})
        return {
            "total_eq": float(acc.get("totalEq") or 0),
            "avail_eq": float(usdt.get("availEq") or usdt.get("eq") or 0),
            "frozen": float(usdt.get("frozenBal") or 0),
            "upl": float(usdt.get("upl") or 0),
        }

    def get_positions(self) -> list[dict]:
        r = self.account.get_positions(instType="SWAP")
        if r.get("code") != "0":
            raise RuntimeError(f"get_positions failed: {r}")
        return r.get("data", [])

    def usdt_to_contracts(self, inst_id: str, usdt_amount: float, price: float) -> float:
        if usdt_amount <= 0 or price <= 0:
            return 0.0
        inst = self._instruments_cache.get(inst_id)
        if not inst:
            raise ValueError(f"Instrument {inst_id} not in cache")
        ct_val = float(inst.get("ctVal") or 0)
        ct_mult = float(inst.get("ctMult") or 1)
        step_sz = float(inst.get("stepSz") or inst.get("lotSz") or 1)
        lot_sz = float(inst.get("lotSz") or step_sz)
        min_sz = float(inst.get("minSz") or step_sz)
        max_sz = float(inst.get("maxSz") or 0) or float("inf")
        if ct_val <= 0 or ct_mult <= 0 or step_sz <= 0 or lot_sz <= 0:
            return 0.0
        raw = usdt_amount / (ct_val * ct_mult * price)
        chosen = math.floor(raw / step_sz) * step_sz
        if chosen < min_sz:
            return 0.0
        lots = math.ceil(chosen / lot_sz)
        chosen = lots * lot_sz
        return chosen if chosen <= max_sz else 0.0

    def place_batch_orders(self, orders: list[dict]) -> list[dict]:
        results = []
        for i in range(0, len(orders), 20):
            r = self.trade.place_multiple_orders(orders[i : i + 20])
            code = r.get("code")
            if code not in ("0", "2"):
                raise RuntimeError(f"OKX API error: {r}")
            results.extend(r.get("data", []))
        return results

    def fetch_ticker_prices(self, symbols: list[str]) -> dict[str, float]:
        out: dict[str, float] = {}
        for inst_id in symbols:
            try:
                r = self.market.get_ticker(instId=inst_id)
                if r.get("code") == "0" and r.get("data"):
                    out[inst_id] = float(r["data"][0].get("last") or 0)
            except Exception:
                log.warning("Failed ticker fetch for %s", inst_id, exc_info=True)
        return out

    async def subscribe_tickers(self, symbols: list[str], callback: Callable) -> WsPublicAsync:
        url = "wss://wspap.okx.com:8443/ws/v5/public" if self._demo else "wss://ws.okx.com:8443/ws/v5/public"
        self._ws = WsPublicAsync(url=url)
        await self._ws.start()
        await self._ws.subscribe(
            [{"channel": "tickers", "instId": s} for s in symbols],
            callback=callback,
        )
        return self._ws

    async def close_ws(self) -> None:
        if self._ws:
            try:
                await self._ws.stop()
            finally:
                self._ws = None

    def ping_ms(self) -> int:
        started = time.time()
        self.account.get_account_balance()
        return int((time.time() - started) * 1000)

