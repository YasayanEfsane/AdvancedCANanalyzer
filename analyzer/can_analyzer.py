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


class Analyzer:
    def __init__(self, filters: DynamicFilters, use_color: bool) -> None:
        self.filters = filters
        self.use_color = use_color
        self.last_displayed: dict[int, tuple[int, ...]] = {}
        # Correlation observes valid frames before console filters are applied.
        self.last_observed: dict[int, tuple[int, ...]] = {}
        self.event_session: EventSession | None = None
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
