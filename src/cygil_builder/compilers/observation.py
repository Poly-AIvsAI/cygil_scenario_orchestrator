"""Chargement contrôlé du profil d'observation validé pour la version CyGIL cible."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..exceptions import CompilationError
from ..models import Scenario
from ..settings import PROJECT_ROOT


def compile_observation(scenario: Scenario, base_dir: Path | None = None) -> dict:
    """Résout le profil relativement au scénario puis retourne son objet YAML."""
    configured = Path(scenario.observation.profile_path)
    candidates = [configured]
    if not configured.is_absolute():
        if base_dir:
            candidates.append(base_dir / configured)
        candidates.append(PROJECT_ROOT / configured)
    source = next((path for path in candidates if path.is_file()), None)
    if source is None:
        raise CompilationError(f"Profil d'observation introuvable: {configured}")
    with source.open("r", encoding="utf-8") as stream:
        content = yaml.safe_load(stream)
    if not isinstance(content, dict):
        raise CompilationError(f"Le profil d'observation {source} n'est pas un objet YAML")
    return content
