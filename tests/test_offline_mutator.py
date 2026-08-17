from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from offline_mutator import mutations  # noqa: E402


class MutationTests(unittest.TestCase):
    def test_bitflip_changes_only_selected_byte(self) -> None:
        seed = [0x10, 0x20, 0, 0, 0, 0, 0, 0]
        generated = list(mutations(seed, 1, "bitflip"))
        self.assertEqual(len(generated), 8)
        self.assertEqual(generated[0][1][0], 0x10)
        self.assertEqual(generated[0][1][1], 0x21)
        self.assertEqual(seed[1], 0x20)


if __name__ == "__main__":
    unittest.main()

