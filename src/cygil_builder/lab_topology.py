"""Dérivation de la topologie permanente et des chemins de ping du banc.

Le réseau DHCP d'amorçage et les cartes de gestion temporaires sont exclus de
ces calculs : ils servent au déploiement, jamais à décrire le scénario CyGIL.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_interface

from .models import InfrastructureRole, InterfacePurpose, MachineInterface, Scenario


VMWARE_MAX_NICS = 10


@dataclass(frozen=True)
class PingRoute:
    """Adresse de destination atteignable depuis une interface de la source."""

    source_id: str
    destination_id: str
    network: str
    source_interface: str
    source_address: str
    destination_interface: str
    destination_address: str


@dataclass(frozen=True)
class PermanentNetworkExpectation:
    """Réseaux permanents attendus pour une VM d'infrastructure."""

    machine_id: str
    required_networks: frozenset[str]


def _machines(scenario: Scenario) -> dict[str, object]:
    """Indexe toutes les VM sans transférer la propriété des réservées."""

    return {
        machine.id: machine
        for machine in [*scenario.infrastructure, *scenario.targets]
    }


def _scenario_interfaces(machine: object) -> list[MachineInterface]:
    """Écarte explicitement les interfaces de gestion et d'amorçage."""

    return [
        interface
        for interface in getattr(machine, "interfaces", [])
        if interface.purpose == InterfacePurpose.SCENARIO and interface.network
    ]


def resolve_ping_routes(scenario: Scenario, source_id: str, destination_id: str) -> list[PingRoute]:
    """Retourne tous les chemins explicites communs, sans inventer de route."""

    if source_id == destination_id:
        return []
    machines = _machines(scenario)
    source = machines.get(source_id)
    destination = machines.get(destination_id)
    if source is None or destination is None:
        return []

    routes: list[PingRoute] = []
    for source_interface in _scenario_interfaces(source):
        for destination_interface in _scenario_interfaces(destination):
            if source_interface.network != destination_interface.network:
                continue
            try:
                source_address = str(ip_interface(source_interface.address).ip)
                destination_address = str(ip_interface(destination_interface.address).ip)
            except ValueError:
                # La validation générale signalera l'adresse invalide; le centre
                # de contrôle ne doit jamais proposer un ping ambigu malgré cela.
                continue
            routes.append(
                PingRoute(
                    source_id=source_id,
                    destination_id=destination_id,
                    network=source_interface.network,
                    source_interface=source_interface.name,
                    source_address=source_address,
                    destination_interface=destination_interface.name,
                    destination_address=destination_address,
                )
            )
    return routes


def permanent_network_expectations(scenario: Scenario) -> dict[str, PermanentNetworkExpectation]:
    """Dérive les réseaux permanents requis par le rôle et les hands activés."""

    compromised = next((target for target in scenario.targets if target.compromised), None)
    caldera_network = compromised.caldera_vmware_network if compromised else None
    mininet_owners = {
        instance.infrastructure_vm_id
        for instance in scenario.mininet_instances
        if instance.infrastructure_vm_id
    }
    attachment_networks: dict[str, set[str]] = {}
    for target in scenario.targets:
        for interface in _scenario_interfaces(target):
            if interface.vmware_network and interface.mininet_instance:
                instance = next(
                    (
                        item
                        for item in scenario.mininet_instances
                        if item.name == interface.mininet_instance
                    ),
                    None,
                )
                if instance and instance.infrastructure_vm_id:
                    attachment_networks.setdefault(instance.infrastructure_vm_id, set()).add(
                        interface.vmware_network
                    )
    if compromised and caldera_network:
        interface = next(iter(_scenario_interfaces(compromised)), None)
        instance = next(
            (
                item
                for item in scenario.mininet_instances
                if interface and item.name == interface.mininet_instance
            ),
            None,
        )
        if instance and instance.infrastructure_vm_id:
            attachment_networks.setdefault(instance.infrastructure_vm_id, set()).add(
                caldera_network
            )
    expectations: dict[str, PermanentNetworkExpectation] = {}
    for machine in scenario.infrastructure:
        if machine.role == InfrastructureRole.CYGIL:
            expectations[machine.id] = PermanentNetworkExpectation(
                machine.id,
                frozenset({"VMnet0"}),
            )
        elif machine.role == InfrastructureRole.CALDERA:
            expectations[machine.id] = PermanentNetworkExpectation(
                machine.id,
                frozenset({"VMnet0", *([caldera_network] if caldera_network else [])}),
            )
        elif machine.role == InfrastructureRole.MININET or machine.id in mininet_owners:
            # Les réseaux cible/interne précis demeurent déclarés sur la VM ou
            # l'instance; VMnet0 est le seul ajout systématique du rôle Mininet.
            declared = {
                interface.vmware_network or interface.network
                for interface in machine.interfaces
                if interface.purpose != InterfacePurpose.MANAGEMENT
                and (interface.vmware_network or interface.network)
            }
            expectations[machine.id] = PermanentNetworkExpectation(
                machine.id,
                frozenset({"VMnet0", *declared, *attachment_networks.get(machine.id, set())}),
            )
        else:
            # Toute VM réservée, y compris un ONOS séparé, rejoint le
            # réseau d'orchestration VMnet0. Les cibles en restent exclues.
            declared = {
                interface.vmware_network or interface.network
                for interface in machine.interfaces
                if interface.purpose != InterfacePurpose.MANAGEMENT
                and (interface.vmware_network or interface.network)
            }
            expectations[machine.id] = PermanentNetworkExpectation(
                machine.id, frozenset({"VMnet0", *declared})
            )
    return expectations
