"""Utilitaires communs pour les liens bidirectionnels entre switches Mininet."""

from __future__ import annotations

from collections.abc import Iterator

from .models import MininetInstance, Scenario


SwitchLink = tuple[MininetInstance, str, str]


def switch_owners(scenario: Scenario) -> dict[str, str]:
    """Associe chaque switch explicite à son instance Mininet propriétaire."""

    return {switch.name: switch.mininet_instance for switch in scenario.switches}


def iter_switch_links(scenario: Scenario) -> Iterator[SwitchLink]:
    """Parcourt les déclarations brutes sans masquer les doublons à valider."""

    for instance in scenario.mininet_instances:
        for source, destinations in instance.switch_links.items():
            for destination in destinations:
                yield instance, source, destination


def canonical_switch_pair(source: str, destination: str) -> tuple[str, str]:
    """Retourne une clé non orientée stable pour une liaison physique."""

    return tuple(sorted((source, destination)))


def unique_switch_links(scenario: Scenario) -> list[SwitchLink]:
    """Conserve une seule déclaration de chaque lien bidirectionnel."""

    unique: list[SwitchLink] = []
    seen: set[tuple[str, str]] = set()
    for instance, source, destination in iter_switch_links(scenario):
        pair = canonical_switch_pair(source, destination)
        if pair in seen:
            continue
        seen.add(pair)
        unique.append((instance, source, destination))
    return unique


def add_switch_link(scenario: Scenario, source: str, destination: str) -> None:
    """Ajoute un lien bidirectionnel stocké une seule fois sur l'instance source."""

    owners = switch_owners(scenario)
    if source not in owners or destination not in owners:
        raise ValueError("Les deux switches doivent appartenir à la topologie")
    if source == destination:
        raise ValueError("Un switch ne peut pas être relié à lui-même")

    requested_pair = canonical_switch_pair(source, destination)
    if any(canonical_switch_pair(left, right) == requested_pair for _, left, right in iter_switch_links(scenario)):
        raise ValueError(f"Le lien {source} ↔ {destination} existe déjà")

    instance = next(item for item in scenario.mininet_instances if item.name == owners[source])
    instance.switch_links.setdefault(source, []).append(destination)


def remove_switch_link(scenario: Scenario, source: str, destination: str) -> None:
    """Supprime uniquement l'arc demandé, sans toucher à son éventuel inverse."""

    requested_pair = canonical_switch_pair(source, destination)
    for instance in scenario.mininet_instances:
        cleaned: dict[str, list[str]] = {}
        for declared_source, destinations in instance.switch_links.items():
            remaining = [
                declared_destination
                for declared_destination in destinations
                if canonical_switch_pair(declared_source, declared_destination) != requested_pair
            ]
            if remaining:
                cleaned[declared_source] = remaining
        instance.switch_links = cleaned


def remove_switch_references(scenario: Scenario, switch: str) -> None:
    """Nettoie les liens d'un switch lorsqu'on supprime le sous-réseau qui le porte."""

    for instance in scenario.mininet_instances:
        cleaned: dict[str, list[str]] = {}
        for source, destinations in instance.switch_links.items():
            if source == switch:
                continue
            remaining = [destination for destination in destinations if destination != switch]
            if remaining:
                cleaned[source] = remaining
        instance.switch_links = cleaned
