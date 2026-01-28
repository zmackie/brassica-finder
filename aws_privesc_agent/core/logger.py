"""Logging configuration with debug support."""

import logging
import sys
from datetime import datetime
from pathlib import Path

# Global debug flag
DEBUG = False


class ColoredFormatter(logging.Formatter):
    """Formatter with color support for terminal output."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


def setup_logging(debug: bool = False, log_file: str | None = None) -> None:
    """Configure logging for the agent.

    Args:
        debug: Enable debug logging
        log_file: Optional file path for log output
    """
    global DEBUG
    DEBUG = debug

    level = logging.DEBUG if debug else logging.INFO
    root_logger = logging.getLogger("aws_privesc_agent")
    root_logger.setLevel(level)
    root_logger.handlers.clear()

    # Console handler with colors
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console_fmt = ColoredFormatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    console.setFormatter(console_fmt)
    root_logger.addHandler(console)

    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(logging.DEBUG)  # Always debug in file
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        )
        file_handler.setFormatter(file_fmt)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger for a module.

    Args:
        name: Module name

    Returns:
        Configured logger
    """
    return logging.getLogger(f"aws_privesc_agent.{name}")


def log_api_call(logger: logging.Logger, service: str, operation: str, **kwargs) -> None:
    """Log an AWS API call.

    Args:
        logger: Logger instance
        service: AWS service name
        operation: API operation name
        **kwargs: Additional context
    """
    if DEBUG:
        logger.debug(f"AWS API: {service}.{operation} | {kwargs}")
    else:
        logger.debug(f"AWS API: {service}.{operation}")


def log_finding(
    logger: logging.Logger, severity: str, title: str, details: str | None = None
) -> None:
    """Log a security finding.

    Args:
        logger: Logger instance
        severity: Finding severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        title: Finding title
        details: Optional details
    """
    severity_colors = {
        "CRITICAL": "\033[35m",
        "HIGH": "\033[31m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[36m",
        "INFO": "\033[32m",
    }
    color = severity_colors.get(severity, "")
    reset = "\033[0m"
    msg = f"{color}[{severity}]{reset} {title}"
    if details and DEBUG:
        msg += f"\n  {details}"
    logger.info(msg)
