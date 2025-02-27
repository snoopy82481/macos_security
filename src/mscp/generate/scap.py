# mscp/generate/scap.py

# Standard python modules
import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from icecream import ic

# Additional python modules
from jinja2 import Environment, FileSystemLoader
from loguru import logger

# Local python modules
from src.mscp.classes import Macsecurityrule
from src.mscp.common_utils import config, get_version_data


def create_scap(
    output_path: Path,
    version_info: dict[str, Any],
    rules: list[Macsecurityrule],
    baselines: list[str],
    export_as: str,
) -> None:
    date_time: str = datetime.now().isoformat(timespec="seconds")
    os_type: str = ""
    env: Environment = Environment(
        loader=FileSystemLoader(config["defaults"]["scap_templates_dir"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    try:
        os_name, os_version = version_info["cpe"].split(":")[2:4]
    except (IndexError, ValueError) as e:
        logger.error(f"Error parsing os_name and os_version from CPE: {e}")
        sys.exit(1)

    match os_name:
        case "ios":
            os_type = "iOS/iPadOS"
        case "visionos":
            os_type = "visionOS"
        case _:
            os_type = "macOS"

    match export_as:
        case "oval":
            scap_template = env.get_template("oval_main.xml.jinja")
        case "xccdf":
            scap_template = env.get_template("xccdf_main.xml.jinja")
        case _:
            scap_template = env.get_template("main.xml.jinja")

    rule_dict_list: list[dict] = [rule.to_dict() for rule in rules]

    for rule_dict in rule_dict_list:
        odv = rule_dict.get("odv", {})
        if "hint" in odv:
            odv.pop("hint")

    rendered_output = scap_template.render(
        date_time=date_time,
        guidance=version_info.get("version", ""),
        os_version=os_version,
        os_name=os_name,
        cpe=version_info.get("cpe", ""),
        os_type=os_type,
        rules=rule_dict_list,
        export_as=export_as,
        baselines=baselines,
    )

    output_path.write_text(rendered_output, encoding="utf-8")
    logger.info(f"SCAP file created: {output_path}")


def generate_scap(args: argparse.Namespace) -> None:
    export_as: str = "scap"
    output_file: Path = Path(config["output_dir"])
    all_baselines: list[str] = [args.baseline.stem if args.baseline else ""]

    current_version_data: dict = get_version_data(args.os_name, args.os_version)
    # all_rules: list[Macsecurityrule] = Macsecurityrule.collect_all_rules(args.os_name, args.os_version, parent_values="Default")
    # all_tags: list[str] = Macsecurityrule.get_tags(all_rules)

    # if args.list_tags:
    #     for tag in all_tags:
    #         print(tag)

    #     sys.exit()

    ic(all_baselines)
    ic(len(all_baselines))
    sys.exit()
    all_rules_pruned: list[Macsecurityrule] = [
        rule for rule in all_rules if baseline_name in rule.tags
    ]

    filenameversion = (
        current_version_data["version"].split(", ", maxsplit=1)[-1].replace(" ", "_")
    )
    base_filename: str = (
        f"{args.os_name}_{current_version_data.get('os', None)}_Security_Compliance_Benchmark-{filenameversion}.xml"
    )

    if args.oval:
        export_as = "oval"
        base_filename = base_filename.replace(".xml", "_oval.xml")

    if args.xccdf:
        export_as = "xccdf"
        base_filename = base_filename.replace(".xml", "_xccdf.xml")

    if ("ios" or "visionos") in args.os_name and args.oval:
        logger.error("OVAL generation is only avalilable for MacOS")
        sys.exit()

    if not (args.oval and args.xccdf) and args.os_name != "macos":
        export_as = "xccdf"
        base_filename = base_filename.replace(".xml", "_xccdf.xml")

        logger.info(f"{args.os_name} will only export as XCCDF")

    output_file = output_file / base_filename

    ic(args)
