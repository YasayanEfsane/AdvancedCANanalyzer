#!/usr/bin/env python3
"""High-throughput serial CAN logger and reverse-engineering console.

The live path is intentionally receive-only. Display filters never affect the
CSV log: every valid frame that reaches this process is recorded.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import queue
import shlex
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable, TextIO


ESC = "\x1b["
RESET = f"{ESC}0m"
DIM = f"{ESC}2m"
BOLD_CYAN = f"{ESC}1;36m"
GREEN = f"{ESC}1;32m"
RED = f"{ESC}1;31m"
YELLOW = f"{ESC}1;33m"


@dataclass(frozen=True, slots=True)
class CanFrame:
    timestamp_ns: int
    frame_type: str
    can_id: int
    dlc: int
    data: tuple[int, int, int, int, int, int, int, int]
    raw_line: str = ""

    @property
    def extended(self) -> bool:
        return self.frame_type in {"E", "X"}

    @property
    def remote(self) -> bool:
        return self.frame_type in {"R", "X"}

    @property
    def label(self) -> str:
        width = 8 if self.extended else 3
        return f"{self.frame_type}{self.can_id:0{width}X}"


def parse_frame_line(line: str, timestamp_ns: int | None = None) -> CanFrame | None:
    """Parse `S123:8:00,...,07`; metadata lines beginning with # are ignored."""

    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split(":")
    if len(parts) != 3:
        raise ValueError("expected TYPE+ID:DLC:8 comma-separated bytes")

    identity, dlc_text, payload_text = parts
    if len(identity) < 2 or identity[0].upper() not in {"S", "E", "R", "X"}:
        raise ValueError("frame type must be S, E, R, or X")

    frame_type = identity[0].upper()
    id_text = identity[1:]
    expected_width = 8 if frame_type in {"E", "X"} else 3
    if len(id_text) != expected_width:
        raise ValueError(f"{frame_type} identifiers require {expected_width} hex digits")

    try:
        can_id = int(id_text, 16)
        dlc = int(dlc_text, 10)
    except ValueError as exc:
        raise ValueError("identifier or DLC is not numeric") from exc

    maximum_id = 0x1FFFFFFF if frame_type in {"E", "X"} else 0x7FF
    if can_id > maximum_id or not 0 <= dlc <= 8:
        raise ValueError("identifier or DLC is outside the CAN 2.0 range")

    byte_fields = payload_text.split(",")
    if len(byte_fields) != 8:
        raise ValueError("firmware protocol always carries eight byte fields")
    try:
        values = tuple(int(value, 16) for value in byte_fields)
    except ValueError as exc:
        raise ValueError("payload contains a non-hexadecimal byte") from exc
    if any(not 0 <= value <= 0xFF or len(text) != 2
           for value, text in zip(values, byte_fields, strict=True)):
        raise ValueError("payload bytes must be exactly two hex digits")

    return CanFrame(
        timestamp_ns=time.time_ns() if timestamp_ns is None else timestamp_ns,
        frame_type=frame_type,
        can_id=can_id,
        dlc=dlc,
        data=values,  # type: ignore[arg-type]
        raw_line=stripped,
    )


@dataclass(slots=True)
class FilterRule:
    ignored: bool = False
    max_hz: float | None = None
    automatic: bool = False


@dataclass(slots=True)
class RateWindow:
    start_ns: int
    count: int = 0
    last_rate_hz: float = 0.0


class DynamicFilters:
    """Dictionary-backed ignore, rate-limit, and automatic hot-ID rules."""

    def __init__(self) -> None:
        self.rules: dict[int, FilterRule] = {}
        self.rate_windows: dict[int, RateWindow] = {}
        self.last_emit_ns: dict[int, int] = {}
        self.auto_ignore_above_hz: float | None = None
        self.changes_only = False
        # An empty watch set means "show every ID". Once populated, it acts as
        # a lightweight allow-list for console output only; CSV capture remains
        # complete and is intentionally unaffected.
        self.watch_ids: set[int] = set()

    def load(self, path: Path) -> None:
        document = json.loads(path.read_text(encoding="utf-8"))
        for item in document.get("ignore_ids", []):
            can_id = parse_can_id(str(item))
            self.rules.setdefault(can_id, FilterRule()).ignored = True
        for item, rate in document.get("rate_limits_hz", {}).items():
            can_id = parse_can_id(item)
            self.rules.setdefault(can_id, FilterRule()).max_hz = float(rate)
        automatic = document.get("auto_ignore_above_hz")
        self.auto_ignore_above_hz = None if automatic is None else float(automatic)
        self.changes_only = bool(document.get("changes_only", False))
        self.watch_ids = {
            parse_can_id(str(item)) for item in document.get("watch_ids", [])
        }

    def observe_rate(self, frame: CanFrame, now_ns: int) -> bool:
        """Return True exactly when an ID is newly auto-ignored."""

        window = self.rate_windows.get(frame.can_id)
        if window is None:
            self.rate_windows[frame.can_id] = RateWindow(now_ns, 1)
            return False

        window.count += 1
        elapsed_ns = now_ns - window.start_ns
        if elapsed_ns < 1_000_000_000:
            return False

        window.last_rate_hz = window.count * 1_000_000_000.0 / elapsed_ns
        window.start_ns = now_ns
        window.count = 0
        if (self.auto_ignore_above_hz is not None
                and window.last_rate_hz > self.auto_ignore_above_hz):
            rule = self.rules.setdefault(frame.can_id, FilterRule())
            if not rule.ignored:
                rule.ignored = True
                rule.automatic = True
                return True
        return False

    def should_display(self, frame: CanFrame, changed: set[int], now_ns: int) -> bool:
        if self.watch_ids and frame.can_id not in self.watch_ids:
            return False
        rule = self.rules.get(frame.can_id)
        if rule is not None and rule.ignored:
            return False
        if self.changes_only and not changed:
            return False
        if rule is not None and rule.max_hz is not None:
            interval_ns = int(1_000_000_000 / rule.max_hz)
            previous = self.last_emit_ns.get(frame.can_id, 0)
            if now_ns - previous < interval_ns:
                return False
        self.last_emit_ns[frame.can_id] = now_ns
        return True

    def clear_automatic(self) -> int:
        removed = 0
        for can_id in list(self.rules):
            rule = self.rules[can_id]
            if rule.automatic:
                rule.ignored = False
                rule.automatic = False
                if rule.max_hz is None:
                    del self.rules[can_id]
                removed += 1
        return removed


def parse_can_id(text: str) -> int:
    value = int(text.strip(), 0)
    if not 0 <= value <= 0x1FFFFFFF:
        raise ValueError("CAN ID must be between 0 and 0x1FFFFFFF")
    return value


class CsvCapture:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.handle: TextIO | None = None
        self.writer: csv.writer | None = None
        self.rows_since_flush = 0

    def __enter__(self) -> "CsvCapture":
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.handle = self.path.open("w", newline="", encoding="utf-8")
            self.writer = csv.writer(self.handle)
            self.writer.writerow([
                "time_utc", "timestamp_ns", "frame_type", "can_id_hex", "dlc",
                "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "raw_line",
            ])
        return self

    def write(self, frame: CanFrame) -> None:
        if self.writer is None:
            return
        wall_time = datetime.fromtimestamp(
            frame.timestamp_ns / 1_000_000_000, tz=timezone.utc
        ).isoformat(timespec="microseconds")
        self.writer.writerow([
            wall_time,
            frame.timestamp_ns,
            frame.frame_type,
            f"0x{frame.can_id:X}",
            frame.dlc,
            *(f"{value:02X}" for value in frame.data),
            frame.raw_line,
        ])
        self.rows_since_flush += 1
        if self.rows_since_flush >= 250:
            self.handle.flush()  # type: ignore[union-attr]
            self.rows_since_flush = 0

    def __exit__(self, *_: object) -> None:
        if self.handle is not None:
            self.handle.flush()
            self.handle.close()


@dataclass(slots=True)
class ReaderStats:
    valid: int = 0
    metadata: int = 0
    malformed: int = 0
    queue_drops: int = 0
    last_device_status: str = ""


class LineFrameReader(threading.Thread):
    """Read large byte chunks so the OS serial buffer is drained efficiently."""

    def __init__(self, source: BinaryIO, output: queue.Queue[CanFrame],
                 stop_event: threading.Event, stats: ReaderStats) -> None:
        super().__init__(name="frame-reader", daemon=True)
        self.source = source
        self.output = output
        self.stop_event = stop_event
        self.stats = stats

    def run(self) -> None:
        pending = bytearray()
        while not self.stop_event.is_set():
            chunk = self.source.read(4096)
            if not chunk:
                if getattr(self.source, "is_open", True):
                    continue
                break
            pending.extend(chunk)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    break
                raw = bytes(pending[:newline]).rstrip(b"\r")
                del pending[:newline + 1]
                self._handle_line(raw)

    def _handle_line(self, raw: bytes) -> None:
        line = raw.decode("ascii", errors="replace")
        if line.startswith("#"):
            self.stats.metadata += 1
            if line.startswith("#STAT:") or line.startswith("#FATAL:"):
                self.stats.last_device_status = line
            return
        try:
            frame = parse_frame_line(line)
        except ValueError:
            self.stats.malformed += 1
            return
        if frame is None:
            return
        self.stats.valid += 1
        try:
            self.output.put_nowait(frame)
        except queue.Full:
            self.stats.queue_drops += 1


class ReplayReader(threading.Thread):
    def __init__(self, lines: Iterable[str], output: queue.Queue[CanFrame],
                 stop_event: threading.Event, stats: ReaderStats,
                 interval_s: float) -> None:
        super().__init__(name="replay-reader", daemon=True)
        self.lines = lines
        self.output = output
        self.stop_event = stop_event
        self.stats = stats
        self.interval_s = interval_s

    def run(self) -> None:
        for line in self.lines:
            if self.stop_event.is_set():
                break
            try:
                frame = parse_frame_line(line)
            except ValueError:
                self.stats.malformed += 1
                continue
            if frame is None:
                continue
            self.stats.valid += 1
            try:
                self.output.put(frame, timeout=0.5)
            except queue.Full:
                self.stats.queue_drops += 1
            if self.interval_s > 0:
                self.stop_event.wait(self.interval_s)


@dataclass(slots=True)
class EventMetric:
    changes: int = 0
    total_delta: int = 0
    bit_flips: int = 0
    minimum: int = 0xFF
    maximum: int = 0


@dataclass(slots=True)
class EventSession:
    label: str
    deadline_ns: int
    metrics: dict[tuple[int, int], EventMetric] = field(default_factory=dict)


@dataclass(slots=True)
class ExperimentMetric:
    samples: int = 0
    transitions: int = 0
    changes: int = 0
    total_delta: int = 0
    bit_flips: int = 0
    total_value: int = 0
    minimum: int = 0xFF
    maximum: int = 0

    def observe(self, value: int, previous: int | None) -> None:
        self.samples += 1
        self.total_value += value
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)
        if previous is None:
            return
        self.transitions += 1
        if value != previous:
            self.changes += 1
            self.total_delta += abs(value - previous)
            self.bit_flips += (value ^ previous).bit_count()

    @property
    def mean(self) -> float:
        return self.total_value / self.samples if self.samples else 0.0

    @property
    def span(self) -> int:
        return self.maximum - self.minimum if self.samples else 0

    @property
    def change_ratio(self) -> float:
        return self.changes / self.transitions if self.transitions else 0.0


@dataclass(slots=True)
class ExperimentTrial:
    baseline: dict[tuple[int, int], ExperimentMetric] = field(default_factory=dict)
    action: dict[tuple[int, int], ExperimentMetric] = field(default_factory=dict)


@dataclass(slots=True)
class GuidedExperiment:
    label: str
    baseline_s: float
    action_s: float
    target_trials: int
    phase: str
    deadline_ns: int
    trials: list[ExperimentTrial] = field(default_factory=list)
    current: ExperimentTrial = field(default_factory=ExperimentTrial)
    last_values: dict[int, tuple[int, ...]] = field(default_factory=dict)

    @property
    def trial_number(self) -> int:
        return len(self.trials) + 1

    def observe(self, frame: CanFrame) -> None:
        if frame.remote or frame.dlc == 0:
            return
        metrics = self.current.baseline if self.phase == "baseline" else self.current.action
        previous = self.last_values.get(frame.can_id)
        for index in range(frame.dlc):
            metric = metrics.setdefault((frame.can_id, index), ExperimentMetric())
            prior_value = None if previous is None else previous[index]
            metric.observe(frame.data[index], prior_value)
        self.last_values[frame.can_id] = frame.data

    def advance(self, now_ns: int) -> str | None:
        if now_ns < self.deadline_ns:
            return None
        if self.phase == "baseline":
            self.phase = "action"
            self.deadline_ns = now_ns + int(self.action_s * 1_000_000_000)
            self.last_values.clear()
            return (
                f"experiment '{self.label}': baseline {self.trial_number}/"
                f"{self.target_trials} complete; ACTION now for {self.action_s:g}s"
            )

        completed = self.trial_number
        self.trials.append(self.current)
        if completed >= self.target_trials:
            self.phase = "complete"
            return (
                f"experiment '{self.label}': action {completed}/"
                f"{self.target_trials} complete"
            )

        self.current = ExperimentTrial()
        self.phase = "baseline"
        self.deadline_ns = now_ns + int(self.baseline_s * 1_000_000_000)
        self.last_values.clear()
        return (
            f"experiment '{self.label}': action {completed}/{self.target_trials} "
            f"complete; trial {completed + 1}/{self.target_trials} BASELINE for "
            f"{self.baseline_s:g}s; keep the control untouched"
        )


@dataclass(frozen=True, slots=True)
class ExperimentCandidate:
    can_id: int
    byte_index: int
    confidence: float
    hits: int
    trials: int
    baseline_change_ratio: float
    action_change_ratio: float
    mean_shift: float
    trend: str


class Analyzer:
    def __init__(self, filters: DynamicFilters, use_color: bool) -> None:
        self.filters = filters
        self.use_color = use_color
        self.last_displayed: dict[int, tuple[int, ...]] = {}
        # Correlation observes valid frames before console filters are applied.
        self.last_observed: dict[int, tuple[int, ...]] = {}
        self.event_session: EventSession | None = None
        self.experiment: GuidedExperiment | None = None
        self.last_experiment_report: str | None = None
        self.displayed = 0

    def start_event(self, label: str, duration_s: float = 5.0) -> str:
        label = label.strip()
        if not label:
            raise ValueError("event label cannot be empty")
        if not 0.2 <= duration_s <= 60.0:
            raise ValueError("duration must be between 0.2 and 60 seconds")
        self.event_session = EventSession(
            label=label,
            deadline_ns=time.monotonic_ns() + int(duration_s * 1_000_000_000),
        )
        return f"event '{label}' armed for {duration_s:g}s; perform the action now"

    def observe_event(self, frame: CanFrame, now_ns: int) -> str | None:
        previous = self.last_observed.get(frame.can_id)
        self.last_observed[frame.can_id] = frame.data
        session = self.event_session
        if session is None:
            return None
        if now_ns >= session.deadline_ns:
            return self.finish_event()
        if previous is None:
            return None

        for index in range(frame.dlc):
            before, after = previous[index], frame.data[index]
            if before == after:
                continue
            metric = session.metrics.setdefault((frame.can_id, index), EventMetric())
            metric.changes += 1
            metric.total_delta += abs(after - before)
            metric.bit_flips += (before ^ after).bit_count()
            metric.minimum = min(metric.minimum, before, after)
            metric.maximum = max(metric.maximum, before, after)
        return None

    def finish_event(self, limit: int = 10) -> str:
        session = self.event_session
        if session is None:
            return "no active event"
        self.event_session = None
        ranked = sorted(
            session.metrics.items(),
            key=lambda item: (
                item[1].changes,
                item[1].maximum - item[1].minimum,
                item[1].bit_flips,
                item[1].total_delta,
            ),
            reverse=True,
        )[:limit]
        if not ranked:
            return f"event '{session.label}' complete: no byte changes observed"

        rows = [f"event '{session.label}' candidates:"]
        for rank, ((can_id, index), metric) in enumerate(ranked, 1):
            rows.append(
                f"  {rank}. ID 0x{can_id:X} byte {index}: "
                f"changes={metric.changes}, range={metric.minimum:02X}-"
                f"{metric.maximum:02X}, bit_flips={metric.bit_flips}"
            )
        return "\n".join(rows)

    def cancel_event(self) -> str:
        if self.event_session is None:
            return "no active event"
        label = self.event_session.label
        self.event_session = None
        return f"event '{label}' cancelled"

    def start_experiment(self, label: str, baseline_s: float = 10.0,
                         action_s: float = 5.0, trials: int = 3,
                         now_ns: int | None = None) -> str:
        label = label.strip()
        if not label:
            raise ValueError("experiment label cannot be empty")
        if self.experiment is not None:
            raise ValueError("an experiment is already active; stop or cancel it first")
        if not 0.5 <= baseline_s <= 300.0:
            raise ValueError("baseline duration must be between 0.5 and 300 seconds")
        if not 0.5 <= action_s <= 300.0:
            raise ValueError("action duration must be between 0.5 and 300 seconds")
        if not 1 <= trials <= 20:
            raise ValueError("trial count must be between 1 and 20")

        started_ns = time.monotonic_ns() if now_ns is None else now_ns
        self.experiment = GuidedExperiment(
            label=label,
            baseline_s=baseline_s,
            action_s=action_s,
            target_trials=trials,
            phase="baseline",
            deadline_ns=started_ns + int(baseline_s * 1_000_000_000),
        )
        return (
            f"experiment '{label}' started: trial 1/{trials} BASELINE for "
            f"{baseline_s:g}s; keep the control untouched"
        )

    def poll_experiment(self, now_ns: int | None = None) -> str | None:
        session = self.experiment
        if session is None:
            return None
        current_ns = time.monotonic_ns() if now_ns is None else now_ns
        notice = session.advance(current_ns)
        if session.phase != "complete":
            return notice

        report = self._format_experiment_report(session)
        self.last_experiment_report = report
        self.experiment = None
        return f"{notice}\n{report}" if notice else report

    def observe_experiment(self, frame: CanFrame, now_ns: int) -> str | None:
        notice = self.poll_experiment(now_ns)
        if self.experiment is not None:
            self.experiment.observe(frame)
        return notice

    def experiment_status(self, now_ns: int | None = None) -> str:
        session = self.experiment
        if session is None:
            return "no active experiment"
        current_ns = time.monotonic_ns() if now_ns is None else now_ns
        remaining_s = max(0.0, (session.deadline_ns - current_ns) / 1_000_000_000)
        return (
            f"experiment '{session.label}': phase={session.phase}, "
            f"trial={session.trial_number}/{session.target_trials}, "
            f"remaining={remaining_s:.1f}s"
        )

    def finish_experiment(self) -> str:
        session = self.experiment
        if session is None:
            return "no active experiment"
        if (session.phase == "action" and session.current.baseline
                and session.current.action):
            session.trials.append(session.current)
        self.experiment = None
        report = self._format_experiment_report(session)
        self.last_experiment_report = report
        return report

    def cancel_experiment(self) -> str:
        if self.experiment is None:
            return "no active experiment"
        label = self.experiment.label
        self.experiment = None
        return f"experiment '{label}' cancelled; captured trials discarded"

    def _experiment_candidates(
        self, session: GuidedExperiment
    ) -> list[ExperimentCandidate]:
        keys = {
            key
            for trial in session.trials
            for phase in (trial.baseline, trial.action)
            for key in phase
        }
        candidates: list[ExperimentCandidate] = []
        trial_count = len(session.trials)
        for can_id, byte_index in keys:
            effects: list[float] = []
            shifts: list[float] = []
            baseline_ratios: list[float] = []
            action_ratios: list[float] = []
            directions: list[int] = []

            for trial in session.trials:
                baseline = trial.baseline.get((can_id, byte_index), ExperimentMetric())
                action = trial.action.get((can_id, byte_index), ExperimentMetric())
                baseline_ratios.append(baseline.change_ratio)
                action_ratios.append(action.change_ratio)

                combined_min = min(
                    metric.minimum
                    for metric in (baseline, action)
                    if metric.samples
                ) if baseline.samples or action.samples else 0
                combined_max = max(
                    metric.maximum
                    for metric in (baseline, action)
                    if metric.samples
                ) if baseline.samples or action.samples else 0
                observed_span = max(1, combined_max - combined_min)

                if baseline.samples and action.samples:
                    shift = action.mean - baseline.mean
                    mean_effect = min(1.0, abs(shift) / observed_span)
                    # A rolling counter can have a large mean shift simply
                    # because the action window follows the baseline. Discount
                    # separation when the byte was already changing constantly.
                    mean_effect *= max(0.0, 1.0 - baseline.change_ratio)
                    shifts.append(shift)
                    directions.append(1 if shift > 0 else -1 if shift < 0 else 0)
                else:
                    mean_effect = 0.0

                activity_lift = max(0.0, action.change_ratio - baseline.change_ratio)
                range_lift = max(0.0, action.span - baseline.span) / max(1, action.span)
                baseline_rate = baseline.samples / session.baseline_s
                action_rate = action.samples / session.action_s
                presence_lift = max(0.0, action_rate - baseline_rate) / max(
                    1.0, action_rate, baseline_rate
                )
                components = (mean_effect, activity_lift, range_lift, presence_lift)
                weighted_evidence = (
                    0.55 * mean_effect
                    + 0.25 * activity_lift
                    + 0.15 * range_lift
                    + 0.05 * presence_lift
                )
                # Strong evidence of any one kind should remain visible. The
                # weighted part rewards candidates supported by multiple cues.
                effects.append(0.65 * max(components) + 0.35 * weighted_evidence)

            hits = sum(effect >= 0.10 for effect in effects)
            repeatability = hits / trial_count
            direction_counts = [directions.count(value) for value in (-1, 0, 1)]
            direction_consistency = (
                max(direction_counts) / len(directions) if directions else repeatability
            )
            mean_effect = sum(effects) / trial_count
            confidence = 100.0 * min(
                1.0,
                mean_effect
                * (0.55 + 0.25 * repeatability + 0.20 * direction_consistency),
            )
            confidence *= 0.70 + 0.30 * min(1.0, trial_count / session.target_trials)
            if confidence < 5.0:
                continue

            mean_shift = sum(shifts) / len(shifts) if shifts else 0.0
            if mean_shift > 0:
                trend = "increasing"
            elif mean_shift < 0:
                trend = "decreasing"
            else:
                trend = "activity-only"
            candidates.append(ExperimentCandidate(
                can_id=can_id,
                byte_index=byte_index,
                confidence=confidence,
                hits=hits,
                trials=trial_count,
                baseline_change_ratio=sum(baseline_ratios) / trial_count,
                action_change_ratio=sum(action_ratios) / trial_count,
                mean_shift=mean_shift,
                trend=trend,
            ))

        return sorted(
            candidates,
            key=lambda candidate: (
                candidate.confidence,
                candidate.hits,
                candidate.action_change_ratio - candidate.baseline_change_ratio,
            ),
            reverse=True,
        )

    def _format_experiment_report(self, session: GuidedExperiment,
                                  limit: int = 10) -> str:
        completed = len(session.trials)
        if not completed:
            return (
                f"experiment '{session.label}' stopped: no complete "
                "baseline/action trials"
            )
        ranked = self._experiment_candidates(session)[:limit]
        if not ranked:
            return (
                f"experiment '{session.label}' complete ({completed}/"
                f"{session.target_trials} trials): no action-specific candidates"
            )

        rows = [
            f"experiment '{session.label}' candidates "
            f"({completed}/{session.target_trials} trials):"
        ]
        for rank, candidate in enumerate(ranked, 1):
            rows.append(
                f"  {rank}. ID 0x{candidate.can_id:X} byte {candidate.byte_index}: "
                f"confidence={candidate.confidence:.1f}%, repeats="
                f"{candidate.hits}/{candidate.trials}, baseline_change="
                f"{candidate.baseline_change_ratio * 100:.1f}%, action_change="
                f"{candidate.action_change_ratio * 100:.1f}%, mean_shift="
                f"{candidate.mean_shift:+.1f}, trend={candidate.trend}"
            )
        rows.append("  confidence is heuristic; validate candidates independently")
        return "\n".join(rows)

    def differences(self, frame: CanFrame) -> tuple[set[int], tuple[int, ...] | None]:
        previous = self.last_displayed.get(frame.can_id)
        if previous is None:
            return set(range(frame.dlc)), None
        changed = {
            index for index in range(frame.dlc)
            if frame.data[index] != previous[index]
        }
        return changed, previous

    def process(self, frame: CanFrame) -> tuple[str | None, str | None]:
        now_ns = time.monotonic_ns()
        notices: list[str] = []
        experiment_notice = self.observe_experiment(frame, now_ns)
        if experiment_notice:
            notices.append(experiment_notice)
        event_notice = self.observe_event(frame, now_ns)
        if event_notice:
            notices.append(event_notice)
        if self.filters.observe_rate(frame, now_ns):
            notices.append(
                f"auto-ignored 0x{frame.can_id:X} at "
                f"{self.filters.rate_windows[frame.can_id].last_rate_hz:.1f} fps"
            )

        changed, previous = self.differences(frame)
        if not self.filters.should_display(frame, changed, now_ns):
            return None, "\n".join(notices) if notices else None

        self.last_displayed[frame.can_id] = frame.data
        self.displayed += 1
        return self.format(frame, changed, previous), "\n".join(notices) if notices else None

    def format(self, frame: CanFrame, changed: set[int],
               previous: tuple[int, ...] | None) -> str:
        timestamp = datetime.fromtimestamp(
            frame.timestamp_ns / 1_000_000_000
        ).strftime("%H:%M:%S.%f")[:-3]
        label = self._paint(BOLD_CYAN, frame.label)
        rendered: list[str] = []
        for index, value in enumerate(frame.data):
            if index >= frame.dlc:
                rendered.append(self._paint(DIM, " -- "))
            elif index not in changed:
                rendered.append(f" {value:02X} ")
            elif previous is None:
                rendered.append(self._paint(YELLOW, f"[*{value:02X}]"))
            elif value > previous[index]:
                rendered.append(self._paint(GREEN, f"[+{value:02X}]"))
            else:
                rendered.append(self._paint(RED, f"[-{value:02X}]"))
        return (
            f"{timestamp} {label} DLC={frame.dlc} "
            f"{' '.join(rendered)}  changed={len(changed)}"
        )

    def _paint(self, color: str, value: str) -> str:
        return f"{color}{value}{RESET}" if self.use_color else value


HELP_TEXT = """Interactive commands (type a command and press Enter):
  ignore ID              hide an ID, for example: ignore 0x201
  allow ID               remove the ID's ignore rule
  throttle ID HZ         cap only that ID's console rate
  unthrottle ID          remove its console-rate cap
  auto-ignore HZ|off     auto-hide IDs measured above the threshold
  clear-auto             remove automatically created ignore rules
  changes-only on|off    show only frames changed since last display
  watch ID               focus the console on one or more CAN IDs
  unwatch ID             remove an ID from the focus set
  watch-clear            disable focus mode and show all IDs
  mark LABEL [SECONDS]   rank bytes changing during a labeled action
  mark-stop              finish early and print event candidates
  mark-cancel            discard the active event capture
  experiment start LABEL [BASELINE_S ACTION_S TRIALS]
                         compare repeated baseline/action windows
  experiment status      show the active phase and remaining time
  experiment stop        finish early using completed trial pairs
  experiment cancel      discard the active guided experiment
  experiment report      print the most recent experiment report
  list                   show the dictionary-backed filter rules
  stats                  print reader and display counters
  help                   show this help
  quit                   stop cleanly and flush the CSV file
"""


def command_reader(commands: queue.Queue[str], stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        line = sys.stdin.readline()
        if not line:
            return
        commands.put(line.strip())


def handle_command(command: str, filters: DynamicFilters, stats: ReaderStats,
                   analyzer: Analyzer, stop_event: threading.Event) -> str | None:
    if not command:
        return None
    try:
        tokens = shlex.split(command)
        verb = tokens[0].lower()
        if verb in {"quit", "exit", "q"}:
            stop_event.set()
            return "stopping"
        if verb in {"help", "?"}:
            return HELP_TEXT.rstrip()
        if verb == "ignore" and len(tokens) == 2:
            can_id = parse_can_id(tokens[1])
            filters.rules.setdefault(can_id, FilterRule()).ignored = True
            return f"ignored 0x{can_id:X}"
        if verb == "allow" and len(tokens) == 2:
            can_id = parse_can_id(tokens[1])
            rule = filters.rules.get(can_id)
            if rule is not None:
                rule.ignored = False
                rule.automatic = False
            return f"allowed 0x{can_id:X}"
        if verb == "throttle" and len(tokens) == 3:
            can_id = parse_can_id(tokens[1])
            rate = float(tokens[2])
            if rate <= 0:
                raise ValueError("HZ must be greater than zero")
            filters.rules.setdefault(can_id, FilterRule()).max_hz = rate
            return f"throttled 0x{can_id:X} to {rate:g} Hz"
        if verb == "unthrottle" and len(tokens) == 2:
            can_id = parse_can_id(tokens[1])
            if can_id in filters.rules:
                filters.rules[can_id].max_hz = None
            return f"unthrottled 0x{can_id:X}"
        if verb == "auto-ignore" and len(tokens) == 2:
            filters.auto_ignore_above_hz = (
                None if tokens[1].lower() == "off" else float(tokens[1])
            )
            if (filters.auto_ignore_above_hz is not None
                    and filters.auto_ignore_above_hz <= 0):
                raise ValueError("HZ must be greater than zero")
            return f"auto-ignore={filters.auto_ignore_above_hz or 'off'}"
        if verb == "clear-auto" and len(tokens) == 1:
            return f"removed {filters.clear_automatic()} automatic rules"
        if verb == "changes-only" and len(tokens) == 2:
            if tokens[1].lower() not in {"on", "off"}:
                raise ValueError("use on or off")
            filters.changes_only = tokens[1].lower() == "on"
            return f"changes-only={'on' if filters.changes_only else 'off'}"
        if verb == "watch" and len(tokens) == 2:
            can_id = parse_can_id(tokens[1])
            filters.watch_ids.add(can_id)
            return f"watching 0x{can_id:X} ({len(filters.watch_ids)} ID(s))"
        if verb == "unwatch" and len(tokens) == 2:
            can_id = parse_can_id(tokens[1])
            filters.watch_ids.discard(can_id)
            state = "all IDs" if not filters.watch_ids else f"{len(filters.watch_ids)} ID(s)"
            return f"stopped watching 0x{can_id:X}; showing {state}"
        if verb == "watch-clear" and len(tokens) == 1:
            count = len(filters.watch_ids)
            filters.watch_ids.clear()
            return f"focus mode disabled; cleared {count} watched ID(s)"
        if verb == "mark" and len(tokens) in {2, 3}:
            duration = 5.0 if len(tokens) == 2 else float(tokens[2])
            return analyzer.start_event(tokens[1], duration)
        if verb == "mark-stop" and len(tokens) == 1:
            return analyzer.finish_event()
        if verb == "mark-cancel" and len(tokens) == 1:
            return analyzer.cancel_event()
        if verb == "experiment" and len(tokens) >= 2:
            action = tokens[1].lower()
            if action == "start" and len(tokens) in {3, 6}:
                baseline_s = 10.0 if len(tokens) == 3 else float(tokens[3])
                action_s = 5.0 if len(tokens) == 3 else float(tokens[4])
                trials = 3 if len(tokens) == 3 else int(tokens[5])
                return analyzer.start_experiment(
                    tokens[2], baseline_s, action_s, trials
                )
            if action == "status" and len(tokens) == 2:
                return analyzer.experiment_status()
            if action == "stop" and len(tokens) == 2:
                return analyzer.finish_experiment()
            if action == "cancel" and len(tokens) == 2:
                return analyzer.cancel_experiment()
            if action == "report" and len(tokens) == 2:
                return analyzer.last_experiment_report or "no completed experiment report"
            raise ValueError(
                "use: experiment start LABEL [BASELINE_S ACTION_S TRIALS], "
                "status, stop, cancel, or report"
            )
        if verb == "list" and len(tokens) == 1:
            rows = []
            watched = ", ".join(f"0x{can_id:X}" for can_id in sorted(filters.watch_ids))
            rows.append(f"watch={watched or 'all IDs'}")
            for can_id, rule in sorted(filters.rules.items()):
                rows.append(
                    f"0x{can_id:X}: ignored={rule.ignored}, "
                    f"max_hz={rule.max_hz}, automatic={rule.automatic}"
                )
            return "\n".join(rows)
        if verb == "stats" and len(tokens) == 1:
            return (
                f"valid={stats.valid} malformed={stats.malformed} "
                f"pc_queue_drop={stats.queue_drops} displayed={analyzer.displayed} "
                f"device={stats.last_device_status or 'no status yet'}"
            )
    except (ValueError, IndexError) as exc:
        return f"command error: {exc}"
    return "unknown command; type help"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Receive-only CAN logger with changed-byte highlighting"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--port", help="serial port, e.g. COM5 or /dev/ttyUSB0")
    source.add_argument("--replay", type=Path, help="replay firmware-format text")
    parser.add_argument("--baud", type=int, default=921600)
    parser.add_argument("--log", type=Path, help="CSV path; display filters do not affect it")
    parser.add_argument("--config", type=Path, help="JSON filter configuration")
    parser.add_argument("--ignore", action="append", default=[], metavar="ID")
    parser.add_argument("--watch", action="append", default=[], metavar="ID",
                        help="show only selected CAN ID(s); may be repeated")
    parser.add_argument("--changes-only", action="store_true")
    parser.add_argument("--auto-ignore-hz", type=float)
    parser.add_argument("--queue-size", type=int, default=20000)
    parser.add_argument("--replay-interval-ms", type=float, default=50.0)
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-input", action="store_true", help="disable interactive stdin")
    return parser


def open_serial(port: str, baud: int) -> BinaryIO:
    try:
        import serial  # Imported lazily so parser/tests do not require pyserial.
    except ImportError as exc:
        raise SystemExit("pyserial is missing; run: pip install -r analyzer/requirements.txt") from exc
    return serial.Serial(port=port, baudrate=baud, timeout=0.1)


def run(arguments: argparse.Namespace) -> int:
    if arguments.queue_size <= 0:
        raise SystemExit("--queue-size must be greater than zero")

    filters = DynamicFilters()
    if arguments.config:
        filters.load(arguments.config)
    for item in arguments.ignore:
        filters.rules.setdefault(parse_can_id(item), FilterRule()).ignored = True
    for item in arguments.watch:
        filters.watch_ids.add(parse_can_id(item))
    if arguments.changes_only:
        filters.changes_only = True
    if arguments.auto_ignore_hz is not None:
        filters.auto_ignore_above_hz = arguments.auto_ignore_hz
    if (filters.auto_ignore_above_hz is not None
            and filters.auto_ignore_above_hz <= 0):
        raise SystemExit("auto-ignore threshold must be greater than zero")

    use_color = not arguments.no_color and sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    analyzer = Analyzer(filters, use_color)
    frames: queue.Queue[CanFrame] = queue.Queue(maxsize=arguments.queue_size)
    commands: queue.Queue[str] = queue.Queue()
    stop_event = threading.Event()
    stats = ReaderStats()

    def stop_handler(*_: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_handler)

    source_handle: BinaryIO | None = None
    replay_handle: TextIO | None = None
    if arguments.port:
        source_handle = open_serial(arguments.port, arguments.baud)
        reader: threading.Thread = LineFrameReader(source_handle, frames, stop_event, stats)
        source_description = f"serial={arguments.port}@{arguments.baud}"
    else:
        replay_handle = arguments.replay.open("r", encoding="ascii")
        reader = ReplayReader(
            replay_handle,
            frames,
            stop_event,
            stats,
            max(0.0, arguments.replay_interval_ms / 1000.0),
        )
        source_description = f"replay={arguments.replay}"

    print(f"# AdvancedCANAnalyzer started ({source_description})")
    print("# Changed byte markers: [*XX]=baseline, [+XX]=increased, [-XX]=decreased")
    if not arguments.no_input:
        print("# Type 'help' for dynamic filter commands.")
        threading.Thread(
            target=command_reader,
            args=(commands, stop_event),
            name="command-reader",
            daemon=True,
        ).start()

    reader.start()
    try:
        with CsvCapture(arguments.log) as capture:
            while not stop_event.is_set():
                experiment_notice = analyzer.poll_experiment()
                if experiment_notice:
                    print(f"# {experiment_notice}")
                while True:
                    try:
                        command = commands.get_nowait()
                    except queue.Empty:
                        break
                    response = handle_command(
                        command, filters, stats, analyzer, stop_event
                    )
                    if response:
                        print(f"# {response}")

                try:
                    frame = frames.get(timeout=0.05)
                except queue.Empty:
                    if not reader.is_alive() and frames.empty():
                        break
                    continue
                capture.write(frame)
                rendered, notice = analyzer.process(frame)
                if notice:
                    print(f"# {notice}")
                if rendered:
                    print(rendered)
    finally:
        stop_event.set()
        if source_handle is not None:
            source_handle.close()
        if replay_handle is not None:
            replay_handle.close()
        reader.join(timeout=1.0)
        print(
            f"# stopped: valid={stats.valid}, malformed={stats.malformed}, "
            f"pc_queue_drop={stats.queue_drops}, displayed={analyzer.displayed}"
        )
    return 0


def main() -> int:
    return run(build_parser().parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
