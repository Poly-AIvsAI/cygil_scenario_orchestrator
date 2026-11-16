"""Chemins et conventions de nommage utilisés par l'ensemble du projet."""

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent.parent
DEFAULT_OBS_PROFILE = PROJECT_ROOT / "profiles" / "obs_standard.yml"

GENERATED_FILENAMES = {
    "network": "{name}_network_config.yml",
    "command_center": "{name}_command_center_config.yml",
    "reward": "{name}_reward_config.yml",
    "obs": "{name}_obs_config.yml",
}
