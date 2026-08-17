#!/usr/bin/env python3
"""Generate offline mutation candidates from a captured CSV frame.

This tool never opens a serial port and has no transmission path. Its output is
for parser, dashboard, and decoding tests on a bench computer.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


BOUNDARY_VALUES = (0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF)


def parse_can_id(text: str) -> int:
    value = int(text, 0)
    if not 0 <= value <= 0x1FFFFFFF:
        raise ValueError("CAN ID is outside the CAN 2.0 range")
    return value


def load_seed(path: Path, can_id: int) -> tuple[str, int, list[int]]:
    selected: tuple[str, int, list[int]] | None = None
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if int(row["can_id_hex"], 0) != can_id:
                continue
            selected = (
                row["frame_type"],
                int(row["dlc"]),
                [int(row[f"d{index}"], 16) for index in range(8)],
            )
    if selected is None:
        raise ValueError(f"0x{can_id:X} was not found in {path}")
    return selected


def mutations(seed: list[int], byte_index: int, strategy: str):
    values = (
        [seed[byte_index] ^ (1 << bit) for bit in range(8)]
        if strategy == "bitflip"
        else list(BOUNDARY_VALUES)
    )
    for value in values:
        candidate = seed.copy()
        candidate[byte_index] = value
        yield value, candidate


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OFFLINE ONLY: create mutation candidates from a capture"
    )
    parser.add_argument("capture", type=Path)
    parser.add_argument("--id", required=True, type=parse_can_id)
    parser.add_argument("--byte", required=True, type=int, choices=range(8))
    parser.add_argument("--strategy", choices=("bitflip", "boundary"), default="bitflip")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    frame_type, dlc, seed = load_seed(arguments.capture, arguments.id)
    if arguments.byte >= dlc:
        parser.error("--byte must be below the seed frame DLC")

    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    with arguments.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "frame_type", "can_id_hex", "dlc", "mutated_byte", "value",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
        ])
        for value, candidate in mutations(seed, arguments.byte, arguments.strategy):
            writer.writerow([
                frame_type, f"0x{arguments.id:X}", dlc, arguments.byte,
                f"0x{value:02X}", *(f"{item:02X}" for item in candidate),
            ])

    print(f"Wrote offline candidates to {arguments.output}")
    print("No frames were transmitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

