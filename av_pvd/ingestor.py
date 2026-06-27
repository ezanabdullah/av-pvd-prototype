"""
Ethereum block ingestor.

Supports two modes:
  1. Live/archive — real Web3 connection (Alchemy/QuickNode RPC endpoint)
  2. Mock — generates synthetic blocks for testing without an API key

The mock ingestor generates statistically realistic "normal" blocks
and can inject pre-defined attack patterns at specified block heights.
"""

import os
import random
import time
import math
from typing import Generator, Optional

from .models import Block, Transaction


# ------------------------------------------------------------------ #
# Real Web3 Ingestor
# ------------------------------------------------------------------ #

class Web3Ingestor:
    """
    Reads historical blocks from an Ethereum archive node via web3.py.

    Requires:
      - web3 installed: pip install web3
      - RPC_URL env var pointing to an archive node
        (e.g. https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY)

    For call depth: we use the tx receipt's internal trace.
    Requires `debug_traceTransaction` (archive node + Alchemy Growth+).
    Falls back to depth=1 if trace is unavailable.
    """

    def __init__(self, rpc_url: Optional[str] = None):
        try:
            from web3 import Web3
        except ImportError:
            raise ImportError("Install web3: pip install web3")

        url = rpc_url or os.environ.get("RPC_URL", "")
        if not url:
            raise ValueError(
                "Set RPC_URL env var or pass rpc_url= to Web3Ingestor.\n"
                "Get a free key at: https://www.alchemy.com/"
            )

        from web3 import Web3
        self.w3 = Web3(Web3.HTTPProvider(url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC endpoint: {url}")

    def get_block(self, block_number: int) -> Block:
        """Fetch a single block and all its transactions."""
        raw = self.w3.eth.get_block(block_number, full_transactions=True)
        txs = [self._parse_tx(tx, block_number) for tx in raw.transactions]
        return Block(
            number=block_number,
            timestamp=raw.timestamp,
            transactions=txs,
        )

    def iter_blocks(
        self,
        start: int,
        end: int,
        delay: float = 0.1,
    ) -> Generator[Block, None, None]:
        """Yield blocks from start to end (inclusive)."""
        for bn in range(start, end + 1):
            yield self.get_block(bn)
            if delay:
                time.sleep(delay)

    def _parse_tx(self, tx, block_number: int) -> Transaction:
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx.hash)
            call_depth = self._estimate_call_depth(tx, receipt)
        except Exception:
            call_depth = 1

        return Transaction(
            tx_hash=tx.hash.hex(),
            from_addr=tx["from"].lower(),
            to_addr=tx["to"].lower() if tx.get("to") else None,
            value_wei=tx.value,
            gas_used=receipt.gasUsed if receipt else tx.gas,
            gas_price=tx.gasPrice,
            call_depth=call_depth,
            input_data=tx.input.hex() if isinstance(tx.input, bytes) else tx.input,
            is_contract_call=bool(tx.get("to")),
            block_number=block_number,
            tx_index=tx.transactionIndex,
        )

    def _estimate_call_depth(self, tx, receipt) -> int:
        """
        Rough call depth heuristic from gas and input data.
        Real depth requires debug_traceTransaction (archive only).
        """
        input_hex = tx.input.hex() if isinstance(tx.input, bytes) else tx.input
        input_len = len(input_hex) // 2

        # Long input + high gas → likely deep contract interaction
        if receipt and receipt.gasUsed > 200_000 and input_len > 100:
            return min(int(math.log10(receipt.gasUsed)), 8)
        elif receipt and receipt.gasUsed > 100_000:
            return 3
        elif input_len > 4:
            return 2
        else:
            return 1


# ------------------------------------------------------------------ #
# Mock Ingestor — no API key needed
# ------------------------------------------------------------------ #

class MockIngestor:
    """
    Generates synthetic Ethereum blocks for testing.

    Normal blocks: log-normal gas distribution, depth 1-4, diverse values.
    Attack blocks: configurable gas spike, deep calls, concentrated values.
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._base_timestamp = 1_700_000_000  # Nov 2023
        self._block_time = 12  # seconds per block

    def iter_blocks(
        self,
        start: int,
        end: int,
        attack_profile: Optional[dict] = None,
    ) -> Generator[Block, None, None]:
        """
        Yield synthetic blocks.

        attack_profile (optional):
          {
            "start_block": int,
            "end_block": int,
            "type": "reentrancy" | "flash_loan" | "slow_drain",
          }
        """
        for bn in range(start, end + 1):
            ts = self._base_timestamp + bn * self._block_time
            is_attack = (
                attack_profile is not None
                and attack_profile["start_block"] <= bn <= attack_profile["end_block"]
            )
            if is_attack:
                block = self._make_attack_block(bn, ts, attack_profile["type"])
            else:
                block = self._make_normal_block(bn, ts)
            yield block

    # ------------------------------------------------------------------ #
    # Block generators
    # ------------------------------------------------------------------ #

    def _make_normal_block(self, number: int, timestamp: int) -> Block:
        n_txs = self._rng.randint(80, 200)
        txs = [self._make_normal_tx(number, i) for i in range(n_txs)]
        return Block(number=number, timestamp=timestamp, transactions=txs)

    def _make_attack_block(
        self, number: int, timestamp: int, attack_type: str
    ) -> Block:
        if attack_type == "reentrancy":
            return self._make_reentrancy_block(number, timestamp)
        elif attack_type == "flash_loan":
            return self._make_flash_loan_block(number, timestamp)
        elif attack_type == "slow_drain":
            return self._make_slow_drain_block(number, timestamp)
        else:
            return self._make_reentrancy_block(number, timestamp)

    def _make_normal_tx(self, block_num: int, idx: int) -> Transaction:
        # Gaussian gas around 65k, σ=15k — much tighter than lognormal.
        # Real Ethereum mainnet txs cluster tightly around common operations
        # (ERC20 transfer ~65k, swap ~130k, simple send 21k).
        gas_used = max(21_000, min(int(self._rng.gauss(65_000, 15_000)), 200_000))
        depth = self._rng.choices([1, 2, 3, 4], weights=[0.4, 0.3, 0.2, 0.1])[0]
        value = int(self._rng.lognormvariate(14, 1.5)) if self._rng.random() < 0.3 else 0

        return Transaction(
            tx_hash=f"0x{'a' * 60}{block_num:02x}{idx:02x}",
            from_addr=f"0x{self._rng.randbytes(20).hex()}",
            to_addr=f"0x{self._rng.randbytes(20).hex()}",
            value_wei=value,
            gas_used=gas_used,
            gas_price=self._rng.randint(20, 100) * int(1e9),
            call_depth=depth,
            input_data="0x" + "ab" * self._rng.randint(0, 50),
            is_contract_call=self._rng.random() < 0.6,
            block_number=block_num,
            tx_index=idx,
        )

    def _make_reentrancy_block(self, number: int, timestamp: int) -> Block:
        """Simulates reentrancy: few txs, extreme gas, deep call stacks, concentrated value."""
        n_txs = self._rng.randint(3, 8)
        attacker = f"0x{'de'*10}{'ad'*10}"
        victim = f"0x{'be'*10}{'ef'*10}"

        txs = []
        for i in range(n_txs):
            gas_used = self._rng.randint(800_000, 2_000_000)  # extreme
            depth = self._rng.randint(7, 12)                  # deep reentrancy
            value = int(100e18) if i == 0 else int(10e18)     # large ETH drain

            txs.append(Transaction(
                tx_hash=f"0x{'ee' * 30}{i:04x}",
                from_addr=attacker,
                to_addr=victim,
                value_wei=value,
                gas_used=gas_used,
                gas_price=500 * int(1e9),
                call_depth=depth,
                input_data="0x" + "ff" * 200,
                is_contract_call=True,
                block_number=number,
                tx_index=i,
            ))
        # Pad with normal-ish txs
        for i in range(n_txs, n_txs + 5):
            txs.append(self._make_normal_tx(number, i))

        return Block(number=number, timestamp=timestamp, transactions=txs)

    def _make_flash_loan_block(self, number: int, timestamp: int) -> Block:
        """Flash loan: single massive tx, extremely high gas, large borrowed value."""
        attacker = f"0x{'fa'*20}"
        protocol = f"0x{'fb'*20}"

        attack_tx = Transaction(
            tx_hash="0x" + "ff" * 32,
            from_addr=attacker,
            to_addr=protocol,
            value_wei=int(50_000e18),      # 50,000 ETH flash loan
            gas_used=3_000_000,
            gas_price=1000 * int(1e9),
            call_depth=9,
            input_data="0x" + "ab" * 500,
            is_contract_call=True,
            block_number=number,
            tx_index=0,
        )

        normal_txs = [self._make_normal_tx(number, i + 1) for i in range(20)]
        return Block(number=number, timestamp=timestamp, transactions=[attack_tx] + normal_txs)

    def _make_slow_drain_block(self, number: int, timestamp: int) -> Block:
        """Slow drain: many small withdrawals just below threshold."""
        attacker = f"0x{'aa'*20}"
        victim = f"0x{'bb'*20}"
        n_txs = 30
        txs = []
        for i in range(n_txs):
            txs.append(Transaction(
                tx_hash=f"0x{'cc'*30}{i:04x}",
                from_addr=attacker,
                to_addr=victim,
                value_wei=int(0.5e18),     # 0.5 ETH each — below anomaly threshold
                gas_used=50_000,
                gas_price=40 * int(1e9),
                call_depth=2,
                input_data="0xdeadbeef",
                is_contract_call=True,
                block_number=number,
                tx_index=i,
            ))
        return Block(number=number, timestamp=timestamp, transactions=txs)
