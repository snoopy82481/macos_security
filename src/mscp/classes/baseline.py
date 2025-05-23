# mscp/classes/baseline.py

# Standard python modules
import re
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any

# Additional python modules
import pandas as pd
from loguru import logger
from pydantic import BaseModel, Field

# Local python modules
from src.mscp.common_utils import config, create_yaml, open_file

from .macsecurityrule import Macsecurityrule


class Author(BaseModel):
    name: str | None
    organization: str | None


class Profile(BaseModel):
    section: str
    description: str
    rules: list[Macsecurityrule]

    def get(self, attr, default=None):
        return getattr(self, attr, default)


class Baseline(BaseModel):
    authors: list[Author]
    profile: list[Profile]
    name: str
    title: str = Field(default="")
    description: str = Field(default="")
    parent_values: str = ""

    @classmethod
    def from_yaml(
        cls, file_path: Path, os_name: str, os_version: int, custom: bool = False
    ) -> "Baseline":
        """
        Load a Baseline object from a YAML file, including profiles and associated rules.

        Args:
            file_path (Path): Path to the baseline YAML file.
            custom (bool, optional): Whether to load custom configurations. Defaults to False.
            os_version (int): Operating system version.
            custom (bool): Whether to load custom configurations.

        Returns:
            Baseline: A fully populated Baseline instance.
        """

        logger.info(f"Attempting to open Baseline file: {file_path}")

        section_dir: Path = Path(config["defaults"]["sections_dir"])
        if custom:
            section_dir = Path(config["custom"]["sections_dir"])

        baseline_data = open_file(file_path)
        authors = [Author(**author) for author in baseline_data.get("authors", [])]

        # Parse profiles
        profiles: list[Profile] = []
        for prof in baseline_data.get("profile", []):
            logger.debug(f"Section Name: {prof['section']}")
            section_data: dict[str, str] = open_file(
                Path(section_dir, f"{prof['section']}.yaml")
            )
            logger.debug(f"Section Data: {section_data}")
            profiles.append(
                Profile(
                    section=section_data.get("name", "").strip(),
                    description=section_data.get("description", "").strip(),
                    rules=Macsecurityrule.load_rules(
                        prof.get("rules", []),
                        os_name,
                        os_version,
                        baseline_data.get("parent_values", ""),
                        section_data.get("name", "").strip(),
                        custom,
                    ),
                )
            )

        # Instantiate Baseline object
        baseline = cls(
            authors=authors,
            profile=profiles,
            name=file_path.stem,
            title=baseline_data.get("title", ""),
            description=baseline_data.get("description", ""),
            parent_values=baseline_data.get("parent_values", ""),
        )

        return baseline

    @classmethod
    @logger.catch
    def create_new(
        cls,
        output_file: Path,
        rules: list[Macsecurityrule],
        version_data: dict[str, Any],
        baseline_name: str,
        authors: list[Author],
        full_title: str,
        benchmark: str = "recommended",
    ) -> None:
        """
        Create and save a Baseline object as a YAML file with grouped and sorted rules.

        Args:
            output_file (Path): Path to save the baseline YAML file.
            rules (list[Macsecurityrule]): List of rules to include in the baseline.
            version_data (Dict[str, Any]): Version information, including OS and CPE.
            baseline_name (str): Name of the baseline.
            authors (list[Authors]): List of authors.
            full_title (str): Full title for the baseline.
            benchmark (str, optional): Benchmark type. Defaults to recommended.
        """

        os_name: str = re.search(
            r"(macos|ios|visionos)", version_data["cpe"], re.IGNORECASE
        ).group()
        os_version: float = version_data["os_version"]
        baseline_title: str = (
            f"{os_name} {os_version}: Security Configuration - {full_title} {baseline_name}"
        )
        description: str = (
            f"|\n  This guide describes the actions to take when securing a {os_name} {os_version} system against the {full_title} {baseline_name} security baseline.\n"
        )

        if benchmark == "recommended":
            description += "\n  Information System Security Officers and benchmark creators can use this catalog of settings in order to assist them in security benchmark creation. This list is a catalog, not a checklist or benchmark, and satisfaction of every item is not likely to be possible or sensible in many operational scenarios."

        special_sections: dict = {
            "inherent": "Inherent",
            "permanent": "Permanent",
            "n_a": "Not Applicable",
            "supplemental": "Supplemental",
        }

        grouped_rules = defaultdict(list)
        section_descriptions: dict = {}

        for yaml_file in Path(config["defaults"]["sections_dir"]).glob("*.y*ml"):
            section_data: dict = open_file(yaml_file)

            section_descriptions[section_data.get("name")] = section_data.get(
                "description", ""
            )

        for rule in rules:
            matched: bool = False
            for tag, section_name in special_sections.items():
                if tag in rule.tags:
                    grouped_rules[section_name].append(rule)
                    matched = True
                    break

            if not matched:
                grouped_rules[rule.section].append(rule)

        for section in grouped_rules:
            grouped_rules[section] = sorted(
                grouped_rules[section], key=lambda r: r.rule_id
            )

        profiles = [
            Profile(
                section=section,
                description=section_descriptions.get(
                    section, "No description available"
                ),
                rules=grouped_rules[section],
            )
            for section in grouped_rules
        ]

        baseline = cls(
            authors=authors,
            profile=profiles,
            name=output_file.stem,
            title=baseline_title.strip(),
            description=description.strip(),
            parent_values=benchmark,
        )

        baseline.to_yaml(output_path=output_file)

    @logger.catch
    def to_dataframe(self) -> pd.DataFrame:
        """
        Convert the profiles and rules from the Baseline object into a Pandas DataFrame.

        Returns:
            pd.DataFrame: A DataFrame containing rules with their associated profile sections.
        """

        rules: list[dict] = []
        for profile in self.profile:
            for rule in profile.rules:
                rule_data = rule.model_dump()
                references = rule_data.pop("references", {})

                for ref_key, ref_value in references.items():
                    rule_data[ref_key] = ref_value

                rules.append(rule_data)

        return pd.DataFrame(rules)

    @logger.catch
    def to_yaml(self, output_path: Path) -> None:
        """
        Serializes the baseline model to a YAML file with a specific order for keys and profiles.

        Args:
            output_path (Path): The path where the YAML file will be created.

        Returns:
            None

        The method performs the following steps:
        1. Logs the start of the YAML creation process.
        2. Serializes the model data.
        3. Defines the order for the main keys and profile sections.
        4. Removes the "name" key from the serialized data.
        5. Sorts the rules within each profile by their rule IDs.
        6. Orders the profiles based on the predefined profile order.
        7. Constructs an ordered dictionary with the specified key order.
        8. Creates the YAML file using the ordered data.
        9. Logs the completion of the YAML creation process.
        """

        logger.info("Creating baseline yaml")
        serialized_data = self.model_dump()
        key_order: list[str] = [
            "title",
            "description",
            "authors",
            "parent_values",
            "profile",
        ]
        profile_order: list[str] = [
            "Auditing",
            "Authentication",
            "iCloud",
            "Operating System",
            "Password Policy",
            "System Settings",
            "Inherent",
            "Permanent",
            "Not Applicable",
            "Supplemental",
        ]
        ordered_data: OrderedDict = OrderedDict()

        serialized_data.pop("name")
        for profile in serialized_data["profile"]:
            profile.pop("description", None)
            profile["rules"] = sorted([rule["rule_id"] for rule in profile["rules"]])

        ordered_profiles = sorted(
            serialized_data["profile"],
            key=lambda p: (
                profile_order.index(p["section"])
                if p["section"] in profile_order
                else len(profile_order)
            ),
        )

        for key in key_order:
            if key in serialized_data:
                if key == "profile":
                    ordered_data[key] = ordered_profiles
                else:
                    ordered_data[key] = serialized_data[key]

        create_yaml(output_path, ordered_data)
        logger.success("Created baseline yaml: {}", output_path)

    def get(self, attr, default=None):
        return getattr(self, attr, default)

    @classmethod
    @logger.catch
    def load_all_from_folder(
        cls, folder_path: Path, os_name: str, os_version: int, custom: bool = False
    ) -> list["Baseline"]:
        """
        Load all Baseline objects from YAML files in a specified folder.

        Args:
            folder_path (Path): Path to the folder containing baseline YAML files.
            os_name (str): Operating system name.
            os_version (int): Operating system version.
            custom (bool): Whether to load custom configurations.

        Returns:
            list[Baseline]: A list of fully populated Baseline instances.
        """

        logger.debug("=== LOADING ALL BASELINES ===")
        baseline_folder: Path = Path(folder_path, os_name, str(os_version))
        logger.debug(f"Folder: {baseline_folder}")
        baselines: list["Baseline"] = []

        for yaml_file in baseline_folder.glob("*.yaml"):
            logger.debug(f"Loading YAML file: {yaml_file}")
            baseline = cls.from_yaml(yaml_file, os_name, os_version, custom)
            baselines.append(baseline)

        logger.success("Loaded {} baselines", len(baselines))
        return baselines
