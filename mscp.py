#! /usr/bin/env python3
# filename: mscp.py

# Standard python modules
import sys
from pathlib import Path

# Local python modules
from src.mscp.cli import parse_cli
from src.mscp.common_utils import logger, set_logger

logger.enable("mscp")


def main() -> None:
    logger = set_logger()
    logger.info("=== Logging Initialized ===")
    logger.info("LOGGING LEVEL: ERROR")

    parse_cli(parse_cli(Path(__file__).name))


if __name__ == "__main__":
    sys.exit(main())
