from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

from .trading.engine import TradingEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [worker:%(name)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("bot_worker")


def main() -> None:
    parser = argparse.ArgumentParser(description="PairTrading Bot Worker")
    parser.add_argument("--user-id", type=int, required=True)
    args = parser.parse_args()
    user_id = args.user_id
    engine = TradingEngine(user_id)

    def on_sigterm(signum, frame):
        log.info("SIGTERM received, stopping worker")
        engine.save_state_and_stop()
        sys.exit(0)

    def on_sigusr1(signum, frame):
        log.info("SIGUSR1 received, closing positions")
        engine.request_close_positions()

    signal.signal(signal.SIGTERM, on_sigterm)
    signal.signal(signal.SIGUSR1, on_sigusr1)
    try:
        engine.initialize()
        asyncio.run(engine.run())
    except KeyboardInterrupt:
        engine.save_state_and_stop()
        sys.exit(0)
    except Exception:
        log.exception("Fatal error in worker user_id=%s", user_id)
        engine.save_state_and_stop()
        sys.exit(1)


if __name__ == "__main__":
    main()

