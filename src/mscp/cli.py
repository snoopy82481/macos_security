import argparse
import logging
import sys

from pathlib import Path
from icecream import ic
from src.mscp.generate.guidance import generate_guidance
from src.mscp.generate.baseline import generate_baseline

logger = logging.getLogger(__name__)

def validate_file(arg):
    if (file := Path(arg)).is_file():
        return Path(arg)
    else:
        logger.error(f"File Not found: {arg}")
        sys.exit()

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CLI tool for managing baseline and compliance documents.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )


    parser.add_argument(
        "baseline",
        default=None,
        help="Baseline YAML file used to create the guide.",
        type=validate_file
    )

    parser.add_argument(
        "--os_name",
        choices=["macos","ios","visionos"],
        default="macos",
        help="Which operating system being checked.",
        type=str
    )

    parser.add_argument(
        "--os_version",
        default=15,
        type=int,
        help="Operating system version (eg: 14, 15)."
    )

    # Sub Parsers for individual commands
    subparsers = parser.add_subparsers(
        title="Subcommands",
        required=True,
        description="Valid Subcommands",
        dest="subcommand"
    )

    # 'baseline' subcommand
    baseline_parser = subparsers.add_parser("baseline", help="Given a keyword tag, generate a generic baseline.yaml file containing rules with the tag.")
    baseline_parser.add_argument(
        "-c",
        "--controls",
        help="Output the 800-53 controls covered by the rules.",
        action="store_true"
    )
    baseline_parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword tag to collect rules containing the tag.",
        action="store"
    )
    baseline_parser.add_argument(
        "-l",
        "--list_tags",
        help="List the available keyword tags to search for.",
        action="store_true"
    )
    baseline_parser.add_argument(
        "-t",
        "--tailor",
        help="Customize the baseline to your organizations values.",
        action="store_true"
    )

    # 'guidance' subcommand
    guidance_parser = subparsers.add_parser("guidance", help="Given a baseline, create guidance documents and files.")
    guidance_parser.add_argument(
        "-c",
        "--clean",
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-d",
        "--debug",
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-D",
        "--ddm",
        help="Generate declarative management artifacts for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-l",
        "--logo",
        default=None,
        help="Full path to logo file to be included in the guide.",
        action="store",
        type=validate_file
    )
    guidance_parser.add_argument(
        "-p",
        "--profiles",
        help="Generate configuration profiles for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-r",
        "--reference",
        default=None,
        help="Use the reference ID instead of rule ID for identification.",
        action="store"
    )
    guidance_parser.add_argument(
        "-s",
        "--script",
        help="Generate the compliance script for the rules.",
        action="store_true"
    )
    # add gary argument to include tags for XCCDF generation, with a nod to Gary the SCAP guru
    guidance_parser.add_argument(
        "-g",
        "--gary",
        help=argparse.SUPPRESS,
        action="store_true"
    )
    guidance_parser.add_argument(
        "-x",
        "--xlsx",
        help="Generate the excel (xlsx) document for the rules.",
        action="store_true"
    )
    guidance_parser.add_argument(
        "-H",
        "--hash",
        default=None,
        help="sign the configuration profiles with subject key ID (hash value without spaces)",
        action="store"
    )
    guidance_parser.add_argument(
        "-a",
        "--audit_name",
        default=None,
        help="name of audit plist and log - defaults to baseline name",
        action="store"
    )


    args = parser.parse_args()

    match args.subcommand:
        case "guidance":
            logger.info("CLI guidance entry")

            generate_guidance(args)
        case "baseline":
            logger.info("CLI baseline entry")

            generate_baseline(args)
        case _:
            parser.print_help()

if __name__ == '__main__':
    main()
