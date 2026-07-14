"""Unified shutdown coordinator for MITM resources."""

import atexit
import signal
from collections.abc import Callable
from types import FrameType


class ShutdownCoordinator:
    """Run registered cleanup callbacks once on shutdown."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self._cleanup_callbacks: list[Callable[[], None]] = []
        self._cleaned = False
        self._handlers_installed = False

    def register(self, callback: Callable[[], None]) -> None:
        """Register a cleanup callback (last registered runs first)."""
        self._cleanup_callbacks.append(callback)

    def install_handlers(self) -> None:
        """Install signal and atexit handlers exactly once."""
        if self._handlers_installed:
            return
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        atexit.register(self.cleanup)
        self._handlers_installed = True

    def _handle_signal(self, signum: int, frame: FrameType | None) -> None:
        if self.verbose:
            print(f"\nReceived signal {signum}, cleaning up...")
        self.cleanup()
        raise SystemExit(0)

    def cleanup(self) -> None:
        """Run all registered cleanup callbacks once."""
        if self._cleaned:
            return
        self._cleaned = True
        for callback in reversed(self._cleanup_callbacks):
            try:
                callback()
            except Exception as exc:
                if self.verbose:
                    print(f"Cleanup error: {exc}")
