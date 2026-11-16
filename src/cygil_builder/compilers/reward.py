"""Compilation des coûts et objectifs, dont le fichier cible choisi dans l'assistant."""

from __future__ import annotations

from copy import deepcopy

from ..models import ObjectiveType, RewardConfig, RewardObjective, Scenario


def _objective_payload(objective) -> dict:
    """Émet uniquement les champs admis par le type d'objectif CyGIL concerné."""
    common = {"type": objective.type.value}
    if objective.type.value == "hand_on_host":
        return {
            **common,
            "privilege": objective.privilege,
            "host_name": objective.host_name,
            "worth": objective.worth,
            "enabled": objective.enabled,
        }
    if objective.type.value == "trait_value_pair":
        return {
            **common,
            "trait": objective.trait,
            "value": objective.value,
            "count": objective.count,
            "operator": objective.operator,
            "worth": objective.worth,
            "enabled": objective.enabled,
        }
    return {
        **common,
        "file_path": objective.file_path,
        "worth": objective.worth,
        "host_name": objective.host_name,
        "enabled": objective.enabled,
    }


def load_reward_document(reward: RewardConfig, document: dict) -> None:
    """Charge les champs connus tout en conservant le document CyGIL complet."""

    reward.raw_config = deepcopy(document)
    if "action_cost" in document:
        reward.action_cost = int(document["action_cost"])
    if "no_action_dispatched_cost" in document:
        reward.no_action_dispatched_cost = int(document["no_action_dispatched_cost"])

    known: list[RewardObjective] = []
    for item in document.get("game_end_criteria", []):
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "max_steps":
            reward.max_steps = int(item.get("value", reward.max_steps))
            continue
        if kind not in {member.value for member in ObjectiveType}:
            continue
        known.append(
            RewardObjective(
                type=ObjectiveType(kind),
                enabled=bool(item.get("enabled", True)),
                worth=int(item.get("worth", 100)),
                host_name=item.get("host_name"),
                privilege=item.get("privilege"),
                trait=item.get("trait"),
                value=item.get("value"),
                count=int(item.get("count", 1)),
                operator=item.get("operator", "=="),
                file_path=item.get("file_path"),
                source="reward_document",
            )
        )
    # Les objectifs issus des fichiers cibles sont recalculés par coherence.py.
    derived = [item for item in reward.objectives if item.source.startswith("target_file:")]
    reward.objectives = [*known, *derived]


def _merge_known_game_end_criteria(reward: RewardConfig, document: dict) -> None:
    """Remplace seulement les critères connus et laisse les extensions intactes."""

    existing = document.get("game_end_criteria", [])
    queues: dict[str, list[dict]] = {member.value: [] for member in ObjectiveType}
    for objective in reward.objectives:
        queues[objective.type.value].append(_objective_payload(objective))

    merged: list[dict] = []
    max_steps_seen = False
    for item in existing:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "max_steps":
            merged.append({"type": "max_steps", "value": reward.max_steps})
            max_steps_seen = True
        elif kind in queues:
            if queues[kind]:
                merged.append(queues[kind].pop(0))
            # Un objectif connu supprimé dans l'application disparaît aussi du document.
        else:
            merged.append(deepcopy(item))
    if not max_steps_seen:
        merged.insert(0, {"type": "max_steps", "value": reward.max_steps})
    for kind in (member.value for member in ObjectiveType):
        merged.extend(queues[kind])
    document["game_end_criteria"] = merged


def compile_reward(scenario: Scenario) -> dict:
    """Construit les critères de fin et les listes de valeurs par type."""
    reward = scenario.reward
    objectives = [_objective_payload(objective) for objective in reward.objectives]
    if reward.raw_config:
        document = deepcopy(reward.raw_config)
        document["action_cost"] = reward.action_cost
        document["no_action_dispatched_cost"] = reward.no_action_dispatched_cost
        _merge_known_game_end_criteria(reward, document)
        return document
    worth_by_type = {
        "hand_on_host": [],
        "trait_value_pair": [],
        "file_exfiltration": [],
    }
    for objective in objectives:
        worth_by_type.setdefault(objective["type"], []).append(dict(objective))
    return {
        "action_cost": reward.action_cost,
        "no_action_dispatched_cost": reward.no_action_dispatched_cost,
        "game_end_criteria": [{"type": "max_steps", "value": reward.max_steps}, *objectives],
        "hand_on_host_worth": worth_by_type["hand_on_host"],
        "trait_value_pair_worth": worth_by_type["trait_value_pair"],
        "trait_pairs_worth": [],
        "file_exfiltration_worth": worth_by_type["file_exfiltration"],
        "trait_worth": {},
    }
