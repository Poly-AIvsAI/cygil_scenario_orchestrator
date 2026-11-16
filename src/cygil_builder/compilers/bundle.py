"""Compilation groupée, empreintes SHA-256 et manifeste des quatre fichiers CyGIL."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from ..exceptions import CompilationError, ScenarioValidationError
from ..coherence import synchronize_scenario
from ..models import Scenario
from ..settings import GENERATED_FILENAMES
from ..validation import validate_scenario
from .command_center import compile_command_center
from .network import compile_network
from .observation import compile_observation
from .reward import compile_reward


@dataclass(frozen=True)
class CompilationBundle:
    """Chemins des quatre fichiers générés et de leur manifeste."""
    output_directory: Path
    files: dict[str, Path]
    manifest: Path


def _dump_yaml(data: dict, destination: Path) -> None:
    """Écrit un YAML UTF-8 stable et relisible par les outils CyGIL."""
    with destination.open("w", encoding="utf-8", newline="\n") as stream:
        yaml.safe_dump(data, stream, sort_keys=False, allow_unicode=True, default_flow_style=False)


def compile_bundle(
    scenario: Scenario,
    output_directory: str | Path,
    *,
    inject_secrets: bool = False,
    base_dir: str | Path | None = None,
    require_verified_macs: bool = False,
    secret_values: dict[str, str] | None = None,
) -> CompilationBundle:
    """Valide puis génère l'ensemble indivisible des configurations du scénario."""
    synchronize_scenario(scenario)
    validation = validate_scenario(scenario)
    if validation.errors:
        raise ScenarioValidationError("; ".join(issue.message for issue in validation.errors))

    compiled = {
        "network": compile_network(
            scenario,
            inject_secrets,
            require_verified_macs=require_verified_macs,
            secret_values=secret_values,
        ),
        "command_center": compile_command_center(scenario),
        "reward": compile_reward(scenario),
        "obs": compile_observation(scenario, Path(base_dir) if base_dir else None),
    }
    ability_ids = [item["action_id"] for item in compiled["command_center"]["simulator"]["red_abilities"]]
    if len(ability_ids) != len(set(ability_ids)):
        raise CompilationError("Les action_id CALDERA compilés ne sont pas uniques")

    destination = Path(output_directory)
    destination.mkdir(parents=True, exist_ok=True)
    files: dict[str, Path] = {}
    hashes: dict[str, str] = {}
    for kind, data in compiled.items():
        path = destination / GENERATED_FILENAMES[kind].format(name=scenario.metadata.name)
        _dump_yaml(data, path)
        files[kind] = path
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()

    manifest = destination / f"{scenario.metadata.name}_manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "scenario": scenario.metadata.name,
                "version": scenario.metadata.version,
                "generated_at_utc": datetime.now(UTC).isoformat(),
                "secrets_injected": inject_secrets,
                "vmware_macs_verified": require_verified_macs,
                "files_sha256": hashes,
                "warnings": [issue.message for issue in validation.warnings],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return CompilationBundle(destination, files, manifest)
