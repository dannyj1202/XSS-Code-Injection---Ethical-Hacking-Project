"""
Logging configuration for XSS Code Injection tool.

This module provides structured, colored logging with support for
request/response tracing.
"""

import logging
import sys
from pathlib import Path

from .config.settings import LoggingConfig

_logging_configured = False


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""

    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with color support.
    """

    COLORS = {
        logging.DEBUG: Colors.CYAN,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED + Colors.BOLD,
    }

    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record with colors.

        Args:
            record: Log record to format

        Returns:
            Formatted log string with colors
        """
        log_color = self.COLORS.get(record.levelno, Colors.RESET)
        record.levelname = f"{log_color}{record.levelname}{Colors.RESET}"
        return super().format(record)


def setup_logging(config: LoggingConfig, force: bool = False) -> None:
    """
    Setup logging configuration.

    Args:
        config: Logging configuration
        force: Force reconfiguration even if already configured
    """
    global _logging_configured
    if _logging_configured and not force:
        return
    _logging_configured = True
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, config.level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, config.level.upper()))

    if config.verbose:
        formatter = ColoredFormatter(
            "%(asctime)s - %(levelname)s - %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        formatter = ColoredFormatter("%(levelname)s - %(message)s")

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if specified
    if config.log_file:
        log_path = Path(config.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(getattr(logging, config.level.upper()))
        file_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(name)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # Request/response logging
    if config.log_requests or config.log_responses:
        http_logger = logging.getLogger("http")
        http_logger.setLevel(logging.DEBUG)

        http_handler = logging.StreamHandler(sys.stdout)
        http_handler.setLevel(logging.DEBUG)
        http_formatter = ColoredFormatter(
            "%(asctime)s - HTTP - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        http_handler.setFormatter(http_formatter)
        http_logger.addHandler(http_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
