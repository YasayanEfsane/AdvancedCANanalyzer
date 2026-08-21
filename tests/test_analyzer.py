from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analyzer"))

from can_analyzer import (  # noqa: E402
    Analyzer,
    CanFrame,
    DynamicFilters,
    FilterRule,
    parse_frame_line,
)


class ParserTests(unittest.TestCase):
    def test_standard_frame(self) -> None:
        frame = parse_frame_line("S123:2:AA,BB,00,00,00,00,00,00", 123)
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(frame.can_id, 0x123)
        self.assertEqual(frame.dlc, 2)
        self.assertEqual(frame.data[:2], (0xAA, 0xBB))
        self.assertFalse(frame.extended)

    def test_extended_remote_frame(self) -> None:
        frame = parse_frame_line("X18DAF110:0:00,00,00,00,00,00,00,00", 1)
        assert frame is not None
        self.assertTrue(frame.extended)
        self.assertTrue(frame.remote)
        self.assertEqual(frame.can_id, 0x18DAF110)

    def test_metadata_is_ignored(self) -> None:
        self.assertIsNone(parse_frame_line("#STAT:ready=1"))

    def test_invalid_payload_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_frame_line("S123:8:00,01")


class AnalyzerTests(unittest.TestCase):
    def test_changed_byte_markers(self) -> None:
        analyzer = Analyzer(DynamicFilters(), use_color=False)
        first = parse_frame_line("S100:2:10,20,00,00,00,00,00,00", 1)
        second = parse_frame_line("S100:2:11,1F,00,00,00,00,00,00", 2)
        assert first is not None and second is not None
        analyzer.process(first)
        rendered, _ = analyzer.process(second)
        assert rendered is not None
        self.assertIn("[+11]", rendered)
        self.assertIn("[-1F]", rendered)

    def test_ignore_rule_suppresses_display(self) -> None:
        filters = DynamicFilters()
        filters.rules[0x100] = FilterRule(ignored=True)
        analyzer = Analyzer(filters, use_color=False)
        frame = parse_frame_line("S100:1:01,00,00,00,00,00,00,00", 1)
        assert frame is not None
        rendered, _ = analyzer.process(frame)
        self.assertIsNone(rendered)

    def test_watch_mode_displays_only_selected_ids(self) -> None:
        filters = DynamicFilters()
        filters.watch_ids.add(0x123)
        analyzer = Analyzer(filters, use_color=False)
        selected = parse_frame_line("S123:1:01,00,00,00,00,00,00,00", 1)
        hidden = parse_frame_line("S124:1:01,00,00,00,00,00,00,00", 2)
        assert selected is not None and hidden is not None
        self.assertIsNotNone(analyzer.process(selected)[0])
        self.assertIsNone(analyzer.process(hidden)[0])

    def test_event_correlation_ranks_changed_bytes(self) -> None:
        filters = DynamicFilters()
        filters.rules[0x100] = FilterRule(ignored=True)
        analyzer = Analyzer(filters, use_color=False)
        baseline = parse_frame_line("S100:2:10,20,00,00,00,00,00,00", 1)
        changed = parse_frame_line("S100:2:18,20,00,00,00,00,00,00", 2)
        assert baseline is not None and changed is not None
        analyzer.process(baseline)
        analyzer.start_event("throttle", 5.0)
        analyzer.process(changed)
        report = analyzer.finish_event()
        self.assertIn("event 'throttle' candidates", report)
        self.assertIn("ID 0x100 byte 0", report)
        self.assertIn("changes=1", report)

    def test_empty_event_has_clear_report(self) -> None:
        analyzer = Analyzer(DynamicFilters(), use_color=False)
        analyzer.start_event("brake", 1.0)
        self.assertIn("no byte changes", analyzer.finish_event())


if __name__ == "__main__":
    unittest.main()
