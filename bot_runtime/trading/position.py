from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from .okx_client import OKXClient
from .spread import SpreadCalculator

log = logging.getLogger("position")


@dataclass
class PositionState:
    is_open: bool = False
    long_basket: str | None = None
    short_basket: str | None = None
    entry_spread: float = 0.0
    entry_time: datetime | None = None
    dca_count: int = 0
    positions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "is_open": self.is_open,
            "long_basket": self.long_basket,
            "short_basket": self.short_basket,
            "entry_spread": self.entry_spread,
            "entry_time": self.entry_time.isoformat() if self.entry_time else None,
            "dca_count": self.dca_count,
            "positions": self.positions,
        }


class PositionManager:
    def __init__(
        self,
        okx: OKXClient,
        spread_calc: SpreadCalculator,
        config: dict,
        log_event_cb: Callable[[str, str, dict | None], None] | None = None,
    ) -> None:
        self.okx = okx
        self.sc = spread_calc
        self.cfg = config
        self.log_event = log_event_cb
        self.state = PositionState()
        self.entry_cooldown = False

    @property
    def entry_threshold(self) -> float:
        return float(self.cfg.get("entry_spread_pct", 2.0))

    @property
    def take_profit_pct(self) -> float:
        return float(self.cfg.get("take_profit_pct", 0.8))

    @property
    def stop_loss_pct(self) -> float:
        return float(self.cfg.get("stop_loss_pct", 4.0))

    @property
    def stop_loss_enabled(self) -> bool:
        return bool(self.cfg.get("stop_loss_enabled", False))

    @property
    def dca_max(self) -> int:
        return int(self.cfg.get("dca_count", 3))

    @property
    def dca_step(self) -> float:
        return float(self.cfg.get("dca_step_pct", 3.0))

    @property
    def no_new_position(self) -> bool:
        return bool(self.cfg.get("no_new_position", True))

    @property
    def simulation_mode(self) -> bool:
        return bool(self.cfg.get("simulation_mode", False))

    @property
    def leverage(self) -> int:
        return int(self.cfg.get("leverage", 20))

    @property
    def position_size_pct(self) -> float:
        return float(self.cfg.get("position_size_pct", 200.0))

    def restore(self, db_state: dict) -> None:
        self.state.is_open = bool(db_state.get("position_open"))
        self.state.long_basket = db_state.get("long_basket")
        self.state.short_basket = db_state.get("short_basket")
        self.state.entry_spread = float(db_state.get("entry_spread_pct") or 0)
        self.state.dca_count = int(db_state.get("dca_count_current") or 0)

    def evaluate(self) -> str | tuple[str, dict] | None:
        spread = self.sc.spread()
        abs_spread = abs(spread)
        if not self.state.is_open:
            if abs_spread >= self.entry_threshold and not (self.no_new_position or self.entry_cooldown):
                return self._open_position(spread)
            return None
        pnl = self._unrealised_pnl()
        if pnl >= self.take_profit_pct:
            snap = self.state.to_dict()
            self._close_position()
            return ("take_profit", snap)
        if self.stop_loss_enabled and pnl <= -self.stop_loss_pct:
            snap = self.state.to_dict()
            self._close_position()
            return ("stop_loss", snap)
        dca_threshold = self.entry_threshold + (self.state.dca_count + 1) * self.dca_step
        if abs_spread >= dca_threshold and self.state.dca_count < self.dca_max:
            self.state.dca_count += 1
            return "dca"
        return None

    def _open_position(self, spread: float) -> str:
        self.state.is_open = True
        self.state.long_basket, self.state.short_basket = self.sc.direction()
        self.state.entry_spread = spread
        self.state.entry_time = datetime.utcnow()
        self.state.dca_count = 0
        return "entry"

    def _close_position(self) -> None:
        self.state = PositionState()

    def _unrealised_pnl(self) -> float:
        if not self.state.is_open:
            return 0.0
        current_spread = self.sc.spread()
        if self.state.long_basket == "basket2":
            return self.state.entry_spread - current_spread
        return current_spread - self.state.entry_spread

    def get_pnl_breakdown(self) -> dict:
        pnl_total = self._unrealised_pnl() if self.state.is_open else 0.0
        return {
            "pnl_long_pct": round(pnl_total / 2, 4),
            "pnl_short_pct": round(pnl_total / 2, 4),
            "pnl_total_pct": round(pnl_total, 4),
            "pnl_total_usdt": None,
        }

    def get_pnl_for_dashboard(self) -> dict:
        return self.get_pnl_breakdown()

    def close_all(self) -> bool:
        self.state = PositionState()
        return True

    def sync_with_exchange(self) -> None:
        return

