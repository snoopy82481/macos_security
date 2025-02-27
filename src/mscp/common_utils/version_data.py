# mscp/generate/checklist.py

# Standard python modules
from pathlib import Path
from typing import Any

# Additional python modules
from loguru import logger

# Local python modules
from .config import config
from .file_handling import open_yaml


def get_version_data(os_name: str, os_version: int) -> dict[str, Any]:
    """
    Retrieve version data for a given operating system name and version.

    Args:
        os_name (str): The name of the operating system.
        os_version (int): The version of the operating system.

    Returns:
        dict[str, Any]: A dictionary containing the version data for the specified OS name and version.
                        If no matching version data is found, an empty dictionary is returned.

    Raises:
        FileNotFoundError: If the version file is not found.
        Exception: If there is an error parsing the version file.
    """

    os_version_float: float = float(os_version)
    version_file: Path = Path(config["includes_dir"], "version.yaml")
    try:
        logger.info("Attempting to open version file: {}", version_file)
        version_data: dict = open_yaml(version_file)
        platforms = version_data.get("platforms", {})
        os_entries = platforms.get(os_name, [])

        return next(
            (
                entry
                for entry in os_entries
                if entry.get("os_version") == os_version_float
            ),
            {},
        )

    except FileNotFoundError:
        logger.error("Version file not found: {}", version_file)
        return {}

    except Exception as e:
        logger.error("Error parsing version file: {}", e)
        return {}
