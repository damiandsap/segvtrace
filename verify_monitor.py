#!/usr/bin/env python3
"""
Verification test for sigsegv-monitor.

Launches sigsegv_monitor and sample_segfault, then uses unittest assertions
to verify that the monitor correctly recorded:
  - A SIGSEGV event for the sample program
  - Page faults whose cr2 addresses fall within the pages allocated by the sample
  - The SIGSEGV fault address (cr2 == 0 for null pointer dereference)

Usage:
    sudo python3 verify_monitor.py          # normal run
    sudo python3 verify_monitor.py -v       # verbose
"""

import json
import os
import signal
import subprocess
import time
import unittest
from typing import Any, Dict, List, NamedTuple, Optional, Set

# ---------------------------------------------------------------------------
# Configuration – tailored to sample_segfault
# ---------------------------------------------------------------------------
MONITOR_BIN: str = "./sigsegv_monitor"
SAMPLE_BIN: str = "./sample_segfault"

# The kernel's comm field is 16 bytes including NUL, so at most 15 chars.
_COMM_MAX: int = 15
PROCESS_NAME: str = os.path.basename(SAMPLE_BIN)[:_COMM_MAX]

# sample_segfault allocates and touches 4 pages and then loads from the null page.
MIN_PAGE_FAULTS: int = 4+1

# Page size is determined at runtime.
PAGE_SIZE: int = os.sysconf("SC_PAGESIZE")


# ---------------------------------------------------------------------------
# Data classes – sample_segfault output
# ---------------------------------------------------------------------------

class SampleOutput(NamedTuple):
    """JSON output emitted by sample_segfault on stdout."""
    page_size: int
    pages: List[int]
    segfault_addr: int

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "SampleOutput":
        return SampleOutput(
            page_size=raw["page_size"],
            pages=[int(p, 16) for p in raw["pages"]],
            segfault_addr=int(raw["segfault_addr"], 16),
        )


# ---------------------------------------------------------------------------
# Data classes – sigsegv_monitor output
# ---------------------------------------------------------------------------

class ProcessInfo(NamedTuple):
    rootns_pid: int
    ns_pid: int
    comm: str

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "ProcessInfo":
        return ProcessInfo(
            rootns_pid=raw["rootns_pid"],
            ns_pid=raw["ns_pid"],
            comm=raw["comm"],
        )


class ThreadInfo(NamedTuple):
    rootns_tid: int
    ns_tid: int
    comm: str

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "ThreadInfo":
        return ThreadInfo(
            rootns_tid=raw["rootns_tid"],
            ns_tid=raw["ns_tid"],
            comm=raw["comm"],
        )


class Registers(NamedTuple):
    rip: int
    rsp: int
    rax: int
    rbx: int
    rcx: int
    rdx: int
    rsi: int
    rdi: int
    rbp: int
    r8: int
    r9: int
    r10: int
    r11: int
    r12: int
    r13: int
    r14: int
    r15: int
    flags: int
    trapno: int
    err: int
    cr2: int

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "Registers":
        return Registers(**{name: int(raw[name], 16) for name in cls._fields})


class PageFault(NamedTuple):
    cr2: int
    err: int
    tai: int

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "PageFault":
        return PageFault(
            cr2=int(raw["cr2"], 16),
            err=int(raw["err"], 16),
            tai=raw["tai"],
        )


class LbrEntry(NamedTuple):
    from_addr: int
    to_addr: int

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "LbrEntry":
        return LbrEntry(
            from_addr=int(raw["from"], 16),
            to_addr=int(raw["to"], 16),
        )


class MonitorEvent(NamedTuple):
    """A single JSON record emitted by sigsegv_monitor."""
    cpu: int
    tai: int
    process: ProcessInfo
    thread: ThreadInfo
    si_code: int
    registers: Registers
    page_faults: List[PageFault]
    lbr: List[Optional[LbrEntry]]

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "MonitorEvent":
        return MonitorEvent(
            cpu=raw["cpu"],
            tai=raw["tai"],
            process=ProcessInfo.from_json(raw["process"]),
            thread=ThreadInfo.from_json(raw["thread"]),
            si_code=raw["si_code"],
            registers=Registers.from_json(raw["registers"]),
            page_faults=[PageFault.from_json(pf) for pf in raw["page_faults"]],
            lbr=[
                LbrEntry.from_json(e) if e is not None else None
                for e in raw["lbr"]
            ],
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_monitor_events(text: str) -> List[MonitorEvent]:
    """Parse newline-delimited JSON into MonitorEvent objects."""
    return [
        MonitorEvent.from_json(json.loads(line))
        for line in text.splitlines()
        if line.strip()
    ]


def parse_sample_output(text: str) -> SampleOutput:
    """Parse the single JSON line from sample_segfault."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        return SampleOutput.from_json(json.loads(line))
    raise ValueError("No JSON found in sample output")


def addr_in_page(addr: int, page_base: int) -> bool:
    """Return True if *addr* falls within [page_base, page_base + PAGE_SIZE)."""
    return page_base <= addr < page_base + PAGE_SIZE


# ---------------------------------------------------------------------------
# Test fixture
# ---------------------------------------------------------------------------

class TestSigsegvMonitor(unittest.TestCase):
    """End-to-end test: launch monitor + sample, verify output."""

    sample: Optional[SampleOutput] = None
    event: Optional[MonitorEvent] = None

    @classmethod
    def setUpClass(cls) -> None:
        """Start monitor, run sample, stop monitor, collect outputs."""
        # 1. Start monitor
        monitor_proc = subprocess.Popen(
            [MONITOR_BIN],
            stdout=subprocess.PIPE,
        )
        # Give the BPF program a moment to attach.
        time.sleep(1)

        # Verify the monitor is still running.  If it exited already the
        # BPF program was never loaded (common causes: missing root
        # privileges, BPF verification failure, missing binary).
        if monitor_proc.poll() is not None:
            stdout_bytes, _ = monitor_proc.communicate()
            rc = monitor_proc.returncode
            raise RuntimeError(
                f"{MONITOR_BIN} exited prematurely (rc={rc}) before the "
                f"sample was started.  The BPF program was never loaded.\n"
                f"Common causes: not running as root, BPF verifier "
                f"rejection, or the binary is missing.")

        # 2. Run sample
        sample_proc = subprocess.Popen(
            [SAMPLE_BIN],
            stdout=subprocess.PIPE,
        )
        stdout, _ = sample_proc.communicate(timeout=10)
        cls.sample = parse_sample_output(stdout.decode())

        # Small grace period so the monitor can pick up the event from the
        # kernel queue.  Note that it handles the SIGINT below, so
        # processing / writing out the JSON should not be an issue.
        time.sleep(0.5)

        # 3. Stop monitor & collect output
        monitor_proc.send_signal(signal.SIGINT)
        try:
            stdout, _ = monitor_proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            monitor_proc.kill()
            stdout, _ = monitor_proc.communicate()

        events = parse_monitor_events(stdout.decode())

        # 4. Filter events by the known child PID; expect exactly one.
        pid = sample_proc.pid
        matching = [e for e in events if e.process.rootns_pid == pid]
        if len(matching) != 1:
            all_pids = [e.process.rootns_pid for e in events]
            raise AssertionError(
                f"Expected exactly 1 event for PID {pid}, "
                f"got {len(matching)} (all pids: {all_pids})")
        cls.event = matching[0]

    # -- tests --

    def test_sigsegv_fault_address(self) -> None:
        """The SIGSEGV cr2 must equal the expected fault address (0 for NULL)."""
        cr2 = self.event.registers.cr2
        expected = self.sample.segfault_addr
        self.assertEqual(cr2, expected)

    def test_sigsegv_process_info(self) -> None:
        """Process and thread info must be populated."""
        self.assertGreater(self.event.process.rootns_pid, 0)
        self.assertGreater(self.event.thread.rootns_tid, 0)
        self.assertEqual(PROCESS_NAME, self.event.process.comm)

    def test_minimum_page_faults(self) -> None:
        """The monitor must record at least MIN_PAGE_FAULTS page faults."""
        self.assertGreaterEqual(
            len(self.event.page_faults), MIN_PAGE_FAULTS,
            f"Expected >= {MIN_PAGE_FAULTS} page faults, "
            f"got {len(self.event.page_faults)}",
        )

    def test_page_fault_addresses_match_expected_pages(self) -> None:
        """Every page allocated by the sample must appear in the PF list."""
        expected_pages = self.sample.pages

        matched: Set[int] = set()
        for pf in self.event.page_faults:
            for pg_idx, pg_base in enumerate(expected_pages):
                if addr_in_page(pf.cr2, pg_base):
                    matched.add(pg_idx)
                    break

        for pg_idx, pg_base in enumerate(expected_pages):
            self.assertIn(
                pg_idx, matched,
                f"Expected page {pg_idx} at 0x{pg_base:x} "
                f"(range [0x{pg_base:x}, 0x{pg_base + PAGE_SIZE:x})) "
                f"was not matched by any recorded page fault",
            )


if __name__ == "__main__":
    unittest.main()
