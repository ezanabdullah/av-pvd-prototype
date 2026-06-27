"""
AVPVDMonitor — top-level orchestrator.

Wires together: ingestor → risk → TRG → VPG → ATS → VScore → alerts.
"""

from typing import Optional, Callable

from .models import Block, Alert
from .vscore import VScoreEngine
from .ingestor import MockIngestor, Web3Ingestor


class AVPVDMonitor:
    """
    High-level monitor. Feed it blocks (or let it ingest them),
    and it calls your on_alert callback whenever VScore exceeds threshold.
    """

    def __init__(
        self,
        vscore_engine: Optional[VScoreEngine] = None,
        threshold: float = 0.6,
        on_alert: Optional[Callable[[Alert], None]] = None,
        verbose: bool = True,
    ):
        self.engine = vscore_engine or VScoreEngine(threshold=threshold)
        self.on_alert = on_alert or self._default_alert_handler
        self.verbose = verbose
        self._alerts: list[Alert] = []
        self._block_log: list[dict] = []

    def process_block(self, block: Block) -> tuple[float, Optional[Alert]]:
        vscore, alert = self.engine.process_block(block)

        entry = {
            "block": block.number,
            "tx_count": block.tx_count,
            "vscore": vscore,
            "alert": alert is not None,
        }
        self._block_log.append(entry)

        if self.verbose:
            flag = " [ALERT]" if alert else ""
            print(
                f"Block {block.number:>8} | "
                f"txs={block.tx_count:>3} | "
                f"VScore={vscore:.4f}{flag}"
            )

        if alert:
            self._alerts.append(alert)
            self.on_alert(alert)

        return vscore, alert

    def run_mock(
        self,
        start: int = 0,
        end: int = 200,
        attack_profile: Optional[dict] = None,
    ) -> "RunResult":
        """Convenience method: ingest synthetic blocks and return results."""
        ingestor = MockIngestor()
        for block in ingestor.iter_blocks(start, end, attack_profile=attack_profile):
            self.process_block(block)
        return RunResult(self._block_log, self._alerts, self.engine)

    def run_web3(
        self,
        start: int,
        end: int,
        rpc_url: Optional[str] = None,
    ) -> "RunResult":
        """Ingest real Ethereum blocks from an archive node."""
        ingestor = Web3Ingestor(rpc_url=rpc_url)
        for block in ingestor.iter_blocks(start, end):
            self.process_block(block)
        return RunResult(self._block_log, self._alerts, self.engine)

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts)

    @staticmethod
    def _default_alert_handler(alert: Alert) -> None:
        print(f"\n{'='*60}")
        print(f"  ALERT at block {alert.block_number}")
        print(f"  VScore:    {alert.vscore:.4f}  (threshold: {alert.threshold})")
        print(f"  Triggered: {', '.join(alert.triggered_by)}")
        if alert.top_suspicious_entities:
            print("  Suspicious addresses:")
            for addr, trust in alert.top_suspicious_entities[:3]:
                print(f"    {addr}  trust={trust:.3f}")
        print(f"{'='*60}\n")


class RunResult:
    """Holds the output of a monitor run."""

    def __init__(
        self,
        block_log: list[dict],
        alerts: list[Alert],
        engine: VScoreEngine,
    ):
        self.block_log = block_log
        self.alerts = alerts
        self.engine = engine

    @property
    def alert_blocks(self) -> list[int]:
        return [a.block_number for a in self.alerts]

    @property
    def vscore_series(self) -> list[tuple[int, float]]:
        return [(e["block"], e["vscore"]) for e in self.block_log]

    def print_summary(self) -> None:
        n_blocks = len(self.block_log)
        n_alerts = len(self.alerts)
        vscores = [e["vscore"] for e in self.block_log]
        peak = max(vscores) if vscores else 0.0
        print(f"\n{'='*60}")
        print(f"  AV-PVD Run Summary")
        print(f"  Blocks processed : {n_blocks}")
        print(f"  Alerts fired     : {n_alerts}")
        print(f"  Peak VScore      : {peak:.4f}")
        if self.alerts:
            print(f"  First alert at   : block {self.alert_blocks[0]}")
        print(f"{'='*60}\n")
