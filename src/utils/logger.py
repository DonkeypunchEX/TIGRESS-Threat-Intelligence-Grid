"""Shared logging configuration helper."""

import logging


def get_logger(name: str) -> logging.Logger:
    """Return a module logger with the shared TIGRESS format."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    return logging.getLogger(name)
