# common_utils/__init__.py
"""Shared cross-cutting helpers used throughout mSCP.

Re-exports the loguru logger (`logger`), file I/O helpers
(create / open / remove for YAML, JSON, plist, CSV, text), the
configuration model (`config`, `set_custom_dir`, `ensure_custom_dirs`,
`search_paths`),
input validation utilities (`sanitize_input`, `prompt_for_odv`,
`validate_yaml_file`, `validate_rule_folder_structure`), localization
helpers (`get_supported_languages`), version metadata accessors
(`get_version_data`, `get_mscp_data`, `mscp_data`), the shell-command
runner (`run_command`), and the spinner decorator
(`conditional_inject_spinner`).
"""

from .config import (
    CONFIG_PATH,
    config,
    ensure_custom_dirs,
    search_paths,
    set_custom_dir,
)
from .constants import APPLE_OS, NIX_OS, PLATFORM_MAP, SCHEMA_PATH
from .customization import collect_overrides
from .file_handling import (
    append_text,
    create_csv,
    create_file,
    create_json,
    create_plist,
    create_text,
    create_yaml,
    make_dir,
    open_csv,
    open_file,
    open_plist,
    open_text,
    open_yaml,
    remove_dir,
    remove_dir_contents,
    remove_file,
)
from .localization import get_supported_languages
from .logger_instance import logger
from .logging_config import set_logger
from .mscp_data import get_mscp_data, mscp_data
from .prompt_for_odv import prompt_for_odv
from .run_command import run_command
from .sanitize_input import sanitize_input
from .spinner_utils import conditional_inject_spinner
from .validate_rules import validate_rule_folder_structure, validate_yaml_file
from .version_data import get_version_data

__all__ = [
    "APPLE_OS",
    "CONFIG_PATH",
    "NIX_OS",
    "PLATFORM_MAP",
    "SCHEMA_PATH",
    "append_text",
    "collect_overrides",
    "conditional_inject_spinner",
    "config",
    "create_csv",
    "create_file",
    "create_json",
    "create_plist",
    "create_text",
    "create_yaml",
    "ensure_custom_dirs",
    "get_mscp_data",
    "get_supported_languages",
    "get_version_data",
    "logger",
    "make_dir",
    "mscp_data",
    "open_csv",
    "open_file",
    "open_plist",
    "open_text",
    "open_yaml",
    "prompt_for_odv",
    "remove_dir",
    "remove_dir_contents",
    "remove_file",
    "run_command",
    "sanitize_input",
    "search_paths",
    "set_custom_dir",
    "set_logger",
    "validate_rule_folder_structure",
    "validate_yaml_file",
]
