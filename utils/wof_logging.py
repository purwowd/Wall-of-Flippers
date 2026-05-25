#!/usr/bin/python3
"""File logging for Wall of Flippers."""

import logging
import os

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(_PROJECT_ROOT, "logs")
LOG_PATH = os.path.join(LOG_DIR, "wof.log")

_logger = None


def setup():
    global _logger
    if _logger is not None:
        return _logger
    os.makedirs(LOG_DIR, exist_ok=True)
    _logger = logging.getLogger("wall_of_flippers")
    _logger.setLevel(logging.INFO)
    if not _logger.handlers:
        handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        _logger.addHandler(handler)
    return _logger


def info(message):
    setup().info(message)


def warning(message):
    setup().warning(message)


def error(message):
    setup().error(message)
