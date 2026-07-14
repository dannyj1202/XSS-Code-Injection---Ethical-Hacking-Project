"""Tests for ShutdownCoordinator."""

import signal
from unittest.mock import Mock, patch

import pytest

from src.mitm.shutdown import ShutdownCoordinator


class TestShutdownCoordinator:
    def test_cleanup_runs_callbacks_in_reverse_order(self):
        coordinator = ShutdownCoordinator()

        results = []
        coordinator.register(lambda: results.append(1))
        coordinator.register(lambda: results.append(2))
        coordinator.register(lambda: results.append(3))

        coordinator.cleanup()

        assert results == [3, 2, 1]

    def test_cleanup_is_idempotent(self):
        coordinator = ShutdownCoordinator()

        mock_callback = Mock()
        coordinator.register(mock_callback)

        coordinator.cleanup()
        coordinator.cleanup()
        coordinator.cleanup()

        # Should only be called once
        mock_callback.assert_called_once()

    def test_cleanup_continues_on_callback_exception(self):
        coordinator = ShutdownCoordinator()

        mock_callback_before = Mock()
        mock_callback_after = Mock()

        def failing_callback():
            raise ValueError("Intentional error")

        # Register in order: after, failing, before
        # They run in reverse order: before, failing, after
        coordinator.register(mock_callback_after)
        coordinator.register(failing_callback)
        coordinator.register(mock_callback_before)

        coordinator.cleanup()

        mock_callback_before.assert_called_once()
        mock_callback_after.assert_called_once()

    @patch("signal.signal")
    @patch("atexit.register")
    def test_install_handlers_only_once(self, mock_atexit, mock_signal):
        coordinator = ShutdownCoordinator()

        coordinator.install_handlers()
        coordinator.install_handlers()

        # signal is called for SIGINT and SIGTERM once
        assert mock_signal.call_count == 2
        mock_signal.assert_any_call(signal.SIGINT, coordinator._handle_signal)
        mock_signal.assert_any_call(signal.SIGTERM, coordinator._handle_signal)

        # atexit called once
        mock_atexit.assert_called_once_with(coordinator.cleanup)

    def test_signal_handler_calls_cleanup_and_raises_systemexit(self):
        coordinator = ShutdownCoordinator()
        mock_callback = Mock()
        coordinator.register(mock_callback)

        with pytest.raises(SystemExit) as exc_info:
            coordinator._handle_signal(signal.SIGINT, None)

        assert exc_info.value.code == 0
        mock_callback.assert_called_once()
