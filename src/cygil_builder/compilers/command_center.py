"""Compilation des abilities, faits et règles vers le schéma command-center de CyGIL."""

from __future__ import annotations

from ..models import Scenario


def compile_command_center(scenario: Scenario) -> dict:
    """Génère les deux profils CALDERA et la table d'actions du simulateur."""
    config = scenario.command_center
    ordered = sorted(config.abilities, key=lambda item: item.action_id)
    provider_payload = {
        "red_abilities": [ability.ability_id for ability in ordered],
        "red_default_facts": [fact.model_dump(mode="json") for fact in config.initial_facts],
        "red_default_rules": [rule.model_dump(mode="json") for rule in config.rules],
    }
    return {
        "provider_type": config.provider.value,
        "provider_config": {
            "caldera_three": provider_payload,
            "caldera_four": {
                "red_abilities": list(provider_payload["red_abilities"]),
                "red_default_facts": list(provider_payload["red_default_facts"]),
                "red_default_rules": list(provider_payload["red_default_rules"]),
            },
        },
        "simulator": {
            "red_abilities": [
                {"action_id": ability.action_id, "ability_id": ability.ability_id}
                for ability in ordered
            ]
        },
    }
