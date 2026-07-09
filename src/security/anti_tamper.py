"""Runtime integrity monitoring: file hashes, process whitelist, debugger detection."""

import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Set

import psutil

from src.utils.termux_notify import notifier

logger = logging.getLogger(__name__)


class RuntimeProtection:
    """Monitor critical files and processes for tampering at runtime."""

    PROCESS_WHITELIST = {
        "python", "python3", "bash", "sh",
        "termux-wake-lock", "termux-sensor", "termux-wifi-scaninfo",
        "sshd", "logcat", "uvicorn",
    }

    def __init__(self, critical_files: Set[Path]):
        self.critical_files = critical_files
        self._baseline_hashes: Dict[Path, str] = self._hash_files()
        self._thread = None
        self._running = False
        self.violations: List[str] = []

    def _hash_files(self) -> Dict[Path, str]:
        return {p: hashlib.sha512(p.read_bytes()).hexdigest() for p in self.critical_files if p.exists()}

    def verify_files(self) -> bool:
        current = self._hash_files()
        for path, original in self._baseline_hashes.items():
            if path not in current:
                self.violations.append(f"File missing: {path}")
                return False
            if current[path] != original:
                self.violations.append(f"File modified: {path}")
                return False
        return True

    def verify_no_debugger(self) -> bool:
        try:
            status = Path(f"/proc/{os.getpid()}/status").read_text()
            for line in status.splitlines():
                if line.startswith("TracerPid:"):
                    tracer_pid = int(line.split(":")[1].strip())
                    if tracer_pid != 0:
                        self.violations.append(f"Debugger attached (PID {tracer_pid})")
                        return False
        except OSError:
            pass
        return True

    def verify_processes(self) -> bool:
        """Check running process names against the whitelist.

        Returns ``True`` when every running process is whitelisted. Any
        non-whitelisted process is appended to ``self.violations``. Process
        names are inherently noisy, so this check is exposed for callers to use
        deliberately and is not wired into the auto-alarm loop by default.
        """
        try:
            names = {
                p.info["name"]
                for p in psutil.process_iter(["name"])
                if p.info.get("name")
            }
        except Exception as e:  # psutil unavailable or permission denied
            logger.debug(f"Process enumeration failed: {e}")
            return True

        unexpected = names - self.PROCESS_WHITELIST
        for name in sorted(unexpected):
            self.violations.append(f"Non-whitelisted process: {name}")
        return not unexpected

    def start_monitoring(self, interval: int = 30):
        self._running = True
        self._thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self._thread.start()
        logger.info("Runtime protection active")

    def stop_monitoring(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self, interval: int):
        while self._running:
            self.violations.clear()
            if not self.verify_files():
                self._alarm("File integrity violation")
            if not self.verify_no_debugger():
                self._alarm("Debugger detected")
            time.sleep(interval)

    def _alarm(self, reason: str):
        logger.critical(f"TAMPER ALARM: {reason}")
        alert_log = Path("data/alerts/tamper.log")
        alert_log.parent.mkdir(exist_ok=True, parents=True)
        with open(alert_log, "a") as f:
            f.write(f"{time.time():.0f}: {reason}\n")
        notifier.send(
            title="🚨 TIGRESS — Tamper Detected",
            content=reason,
            priority="max",
            vibrate=True,
            ongoing=True,
        )
