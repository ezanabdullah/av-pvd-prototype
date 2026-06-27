"""Core data models for AV-PVD."""

from dataclasses import dataclass, field
from typing import Optional
import math


@dataclass
class Transaction:
    tx_hash: str
    from_addr: str
    to_addr: Optional[str]          # None for contract deployments
    value_wei: int                  # ETH transferred in wei
    gas_used: int
    gas_price: int                  # wei per gas
    call_depth: int                 # max call stack depth
    input_data: str                 # raw calldata hex
    is_contract_call: bool
    block_number: int
    tx_index: int

    @property
    def gas_cost_gwei(self) -> float:
        return self.gas_used * self.gas_price / 1e9

    @property
    def value_eth(self) -> float:
        return self.value_wei / 1e18

    @property
    def calldata_bytes(self) -> int:
        raw = self.input_data[2:] if self.input_data.startswith("0x") else self.input_data
        return len(raw) // 2


@dataclass
class Block:
    number: int
    timestamp: int
    transactions: list[Transaction] = field(default_factory=list)

    @property
    def tx_count(self) -> int:
        return len(self.transactions)

    @property
    def total_gas_used(self) -> int:
        return sum(tx.gas_used for tx in self.transactions)

    @property
    def mean_gas_used(self) -> float:
        if not self.transactions:
            return 0.0
        return self.total_gas_used / self.tx_count


@dataclass
class Alert:
    block_number: int
    vscore: float
    threshold: float
    triggered_by: list[str]        # list of anomaly reasons
    top_suspicious_entities: list[tuple[str, float]]  # (address, ats)
