"""
AV-PVD Demo — Task 1 deliverable.

Runs the monitor over 200 synthetic blocks with an injected reentrancy
attack starting at block 100. Prints per-block VScore and fires an alert.

Usage:
    python examples/run_demo.py
    python examples/run_demo.py --attack flash_loan
    python examples/run_demo.py --attack slow_drain
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from av_pvd.monitor import AVPVDMonitor


def main():
    parser = argparse.ArgumentParser(description="AV-PVD prototype demo")
    parser.add_argument(
        "--attack",
        choices=["reentrancy", "flash_loan", "slow_drain", "none"],
        default="reentrancy",
        help="Attack type to inject at block 100",
    )
    parser.add_argument("--blocks", type=int, default=200, help="Total blocks to process")
    parser.add_argument("--threshold", type=float, default=0.6, help="VScore alert threshold")
    args = parser.parse_args()

    print(f"\nAV-PVD Prototype — Attack: {args.attack.upper()}, Threshold: {args.threshold}")
    print("=" * 65)

    attack_profile = None
    if args.attack != "none":
        attack_profile = {
            "start_block": 100,
            "end_block": 105,
            "type": args.attack,
        }

    monitor = AVPVDMonitor(threshold=args.threshold, verbose=True)
    result = monitor.run_mock(
        start=0,
        end=args.blocks,
        attack_profile=attack_profile,
    )
    result.print_summary()

    if result.alerts:
        print("Alert details:")
        for alert in result.alerts:
            print(f"  Block {alert.block_number}: VScore={alert.vscore:.4f}")
            for reason in alert.triggered_by:
                print(f"    - {reason}")
    else:
        print("No alerts fired. Try lowering --threshold.")


if __name__ == "__main__":
    main()
