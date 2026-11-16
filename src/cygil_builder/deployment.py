"""Allocation VMnet0 et état persistant des déploiements de VM cibles.

Ce module ne lance aucun hyperviseur. Il prépare des allocations reproductibles
et conserve les preuves nécessaires à une reprise sans créer de doublon.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_address, ip_interface, ip_network
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable

from pydantic import Field

from .models import (
    InfrastructureRole,
    InterfacePurpose,
    MachineInterface,
    NetworkReconstructionState,
    Scenario,
    StrictModel,
    VmwareNetworkAdapter,
)


class TargetDeploymentPhase(StrEnum):
    """Phases persistantes permettant une reprise par VM plutôt qu'un tout-ou-rien."""

    PLANNED = "planned"
    ADDRESS_RESERVED = "address_reserved"
    CREATING = "creating"
    RUNNING = "running"
    GUEST_REACHABLE = "guest_reachable"
    CONFIGURED = "configured"
    MANAGEMENT_DETACHED = "management_detached"
    AIR_GAP_VERIFIED = "air_gap_verified"
    SNAPSHOTTED = "snapshotted"
    COMPLETE = "complete"
    FAILED = "failed"


class TargetDeploymentState(StrictModel):
    """Valeurs réelles et dernier résultat connu pour une cible."""

    target_id: str
    phase: TargetDeploymentPhase = TargetDeploymentPhase.PLANNED
    assigned_address: IPv4Interface | None = None
    vagrant_machine_id: str | None = None
    vmx_path: str | None = None
    mac_addresses: dict[str, str] = Field(default_factory=dict)
    interface_names: dict[str, str] = Field(default_factory=dict)
    air_gap_verified: bool = False
    snapshot_id: str | None = None
    last_error: str | None = None
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class PingSessionState(StrictModel):
    """Trace d'un terminal de ping lancé manuellement dans une VM source."""

    source_id: str
    destination_id: str
    destination_address: str
    network: str
    launched_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    active_confirmed_by_user: bool = False


class LabControlState(StrictModel):
    """Verrou persistant qui interdit un snapshot prématuré."""

    ping_sessions: list[PingSessionState] = Field(default_factory=list)
    bench_confirmed: bool = False
    disabled_networks: list[str] = Field(default_factory=list)
    air_gap_verified: bool = False
    all_vms_running: bool = False
    snapshots_authorized: bool = False
    confirmed_at: str | None = None


class ReservedVMDeploymentState(StrictModel):
    """Preuves persistantes de la reconstruction d'une VM réservée."""

    machine_id: str
    vmware_id: str | None = None
    vmx_path: str | None = None
    management_address: IPv4Interface | None = None
    observed_adapters: list[VmwareNetworkAdapter] = Field(default_factory=list)
    expected_adapters: list[VmwareNetworkAdapter] = Field(default_factory=list)
    reconstruction_state: NetworkReconstructionState = NetworkReconstructionState.NOT_PLANNED
    inventory_fingerprint: str | None = None
    plan_fingerprint: str | None = None
    rollback_manifest: str | None = None
    last_error: str | None = None
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class DeploymentState(StrictModel):
    """Journal de déploiement local sans secret ni propriété des VM réservées."""

    schema_version: int = 1
    scenario_name: str
    vmnet_cidr: IPv4Network | None = None
    vagrant_working_directory: str | None = None
    provider: str = "vmware_desktop"
    targets: dict[str, TargetDeploymentState] = Field(default_factory=dict)
    reserved_vms: dict[str, ReservedVMDeploymentState] = Field(default_factory=dict)
    lab_control: LabControlState = Field(default_factory=LabControlState)
    updated_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class DeploymentStateStore:
    """Charge et écrit atomiquement l'état afin de survivre à une interruption."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self, scenario_name: str) -> DeploymentState:
        """Retourne l'état existant ou initialise un journal vide du scénario."""

        if not self.path.is_file():
            return DeploymentState(scenario_name=scenario_name)
        return DeploymentState.model_validate_json(self.path.read_text(encoding="utf-8"))

    def save(self, state: DeploymentState) -> Path:
        """Remplace l'ancien journal seulement après écriture complète du nouveau."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        state.updated_at = datetime.now(UTC).isoformat()
        payload = state.model_dump_json(indent=2)
        # Le fichier temporaire reste dans le même dossier pour garantir que
        # os.replace demeure atomique sur le volume Windows concerné.
        with NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as stream:
            stream.write(payload)
            temporary = Path(stream.name)
        os.replace(temporary, self.path)
        return self.path


def refresh_snapshot_authorization(state: DeploymentState) -> bool:
    """Autorise les snapshots seulement après toutes les preuves explicites."""

    pings_confirmed = bool(state.lab_control.ping_sessions) and all(
        session.active_confirmed_by_user
        for session in state.lab_control.ping_sessions
    )
    state.lab_control.snapshots_authorized = all(
        (
            state.lab_control.bench_confirmed,
            pings_confirmed,
            state.lab_control.air_gap_verified,
            state.lab_control.all_vms_running,
        )
    )
    if state.lab_control.snapshots_authorized:
        state.lab_control.confirmed_at = datetime.now(UTC).isoformat()
    return state.lab_control.snapshots_authorized


def allocate_management_addresses(
    scenario: Scenario,
    cidr: str | IPv4Network,
    *,
    host_addresses: set[str] | None = None,
    occupied_addresses: set[str] | None = None,
    is_in_use: Callable[[IPv4Address], bool] | None = None,
) -> dict[str, IPv4Interface]:
    """Attribue exactement une IPv4 libre à chaque cible de gestion activée.

    Les allocations déjà valides sont conservées. Le rappel ``is_in_use``
    permet à l'inventaire Windows d'ajouter une preuve ARP juste avant la
    réservation, sans lier les tests unitaires au système hôte.
    """

    network = ip_network(cidr, strict=True)
    if not isinstance(network, IPv4Network):
        raise ValueError("VMnet0 doit utiliser un réseau IPv4")

    excluded: set[IPv4Address] = {network.network_address, network.broadcast_address}
    for raw in (host_addresses or set()) | (occupied_addresses or set()):
        parsed = ip_address(raw)
        if isinstance(parsed, IPv4Address) and parsed in network:
            excluded.add(parsed)
    for raw in scenario.vagrant.reserved_management_addresses:
        if raw in network:
            excluded.add(raw)
    # Les VM d'infrastructure peuvent être arrêtées et silencieuses : leurs
    # adresses déclarées restent donc réservées sans dépendre d'un ping.
    for machine in scenario.infrastructure:
        if machine.management_ip_confirmed and machine.management_ip:
            parsed = ip_address(machine.management_ip)
            if isinstance(parsed, IPv4Address) and parsed in network:
                excluded.add(parsed)

    allocations: dict[str, IPv4Interface] = {}
    targets = [target for target in scenario.targets if target.temporary_management.enabled]
    for target in targets:
        current = target.temporary_management.assigned_address
        if current and current.network == network and current.ip not in excluded:
            allocations[target.id] = current
            excluded.add(current.ip)

    candidates = (address for address in network.hosts() if address not in excluded)
    for target in targets:
        if target.id in allocations:
            continue
        for candidate in candidates:
            if is_in_use and is_in_use(candidate):
                excluded.add(candidate)
                continue
            assigned = ip_interface(f"{candidate}/{network.prefixlen}")
            target.temporary_management.assigned_address = assigned
            allocations[target.id] = assigned
            excluded.add(candidate)
            break
        else:
            raise ValueError(f"VMnet0 {network} ne contient pas assez d'adresses libres pour les cibles")
    return allocations


def allocate_reserved_management_addresses(
    scenario: Scenario,
    cidr: str | IPv4Network,
    *,
    host_addresses: set[str] | None = None,
    occupied_addresses: set[str] | None = None,
    target_allocations: dict[str, IPv4Interface] | None = None,
    is_in_use: Callable[[IPv4Address], bool] | None = None,
) -> dict[str, IPv4Interface]:
    """Attribue VMnet0 aux VM réservées, sauf réservation manuelle confirmée.

    Les allocations des cibles sont exclues du même pool. Une adresse existante
    n'est conservée que si ``management_ip_confirmed`` atteste explicitement la
    dépendance externe; elle subit les mêmes contrôles de conflit.
    """

    network = ip_network(cidr, strict=True)
    if not isinstance(network, IPv4Network):
        raise ValueError("VMnet0 doit utiliser un réseau IPv4")
    excluded: set[IPv4Address] = {network.network_address, network.broadcast_address}
    for raw in (host_addresses or set()) | (occupied_addresses or set()):
        parsed = ip_address(raw)
        if isinstance(parsed, IPv4Address) and parsed in network:
            excluded.add(parsed)
    for raw in scenario.vagrant.reserved_management_addresses:
        if raw in network:
            excluded.add(raw)
    for assigned in (target_allocations or {}).values():
        if assigned.ip in network:
            excluded.add(assigned.ip)

    allocations: dict[str, IPv4Interface] = {}
    manual_owners: dict[IPv4Address, str] = {}
    for machine in scenario.infrastructure:
        if not machine.management_ip_confirmed or not machine.management_ip:
            continue
        current = ip_interface(
            machine.management_ip
            if "/" in machine.management_ip
            else f"{machine.management_ip}/{network.prefixlen}"
        )
        if current.ip not in network:
            raise ValueError(f"La réservation VMnet0 de {machine.id} est hors de {network}")
        if current.ip in excluded or current.ip in manual_owners:
            owner = manual_owners.get(current.ip, "l'inventaire hôte")
            raise ValueError(f"Adresse VMnet0 {current.ip} de {machine.id} déjà utilisée par {owner}")
        allocations[machine.id] = current
        manual_owners[current.ip] = machine.id
        excluded.add(current.ip)

    candidates = (address for address in network.hosts() if address not in excluded)
    for machine in scenario.infrastructure:
        if machine.id in allocations:
            continue
        for candidate in candidates:
            if is_in_use and is_in_use(candidate):
                excluded.add(candidate)
                continue
            assigned = ip_interface(f"{candidate}/{network.prefixlen}")
            machine.management_ip = str(candidate)
            allocations[machine.id] = assigned
            excluded.add(candidate)
            break
        else:
            raise ValueError(f"VMnet0 {network} ne contient pas assez d'adresses libres pour les VM réservées")

    for machine in scenario.infrastructure:
        assigned = allocations[machine.id]
        machine.management_ip = str(assigned.ip)
        _upsert_allocated_interface(
            machine,
            purpose=InterfacePurpose.MANAGEMENT,
            vmnet="VMnet0",
            address=str(assigned),
        )
    # Les instances recopient ensuite les valeurs des VM réservées; l'allocateur
    # ne leur attribue jamais une adresse indépendante.
    scenario.synchronize_mininet_bindings()
    return allocations


def _upsert_allocated_interface(
    machine,
    *,
    purpose: InterfacePurpose,
    vmnet: str,
    address: str,
) -> MachineInterface:
    """Met à jour la carte logique unique pilotée par un VMnet alloué."""

    candidates = [
        interface
        for interface in machine.interfaces
        if interface.vmware_network == vmnet
        or (interface.purpose == purpose and not interface.vmware_network)
    ]
    if len(candidates) > 1:
        raise ValueError(f"Plusieurs interfaces de {machine.id} correspondent à {vmnet}")
    if candidates:
        interface = candidates[0]
        interface.address = address
        interface.purpose = purpose
        interface.vmware_network = vmnet
        interface.gateway = None
        return interface
    interface = MachineInterface(
        name="",
        address=address,
        purpose=purpose,
        vmware_network=vmnet,
        gateway=None,
        disable_dns=True,
    )
    machine.interfaces.append(interface)
    return interface


def allocate_mininet_internal_addresses(
    scenario: Scenario,
    cidr: str | IPv4Network,
    vmnet: str,
    *,
    occupied_addresses: set[str] | None = None,
    is_in_use: Callable[[IPv4Address], bool] | None = None,
) -> dict[str, IPv4Interface]:
    """Alloue le réseau de contrôle aux seules instances Mininet/ONOS.

    L'ordre est stable. CyGIL reste exclusivement sur VMnet0 et ne reçoit donc
    jamais de carte ni d'adresse sur ce réseau de contrôle.
    Toutes les anciennes adresses gérées sur ce VMnet sont recalculées lorsque
    le CIDR ou l'inventaire change.
    """

    network = ip_network(cidr, strict=True)
    if not isinstance(network, IPv4Network):
        raise ValueError("Le réseau interne Mininet doit être IPv4")
    if not vmnet or vmnet == "VMnet0":
        raise ValueError("Le réseau interne Mininet doit être distinct de VMnet0")
    for logical in scenario.networks:
        if not logical.cidr:
            continue
        logical_network = ip_network(logical.cidr, strict=True)
        if network.version == logical_network.version and network.overlaps(logical_network):
            raise ValueError(
                f"Le réseau interne {network} chevauche le sous-réseau de scénario "
                f"{logical.id} ({logical_network})"
            )
    for machine in scenario.infrastructure:
        for interface in machine.interfaces:
            if interface.purpose != InterfacePurpose.MANAGEMENT:
                continue
            management_network = ip_interface(interface.address).network
            if network.version == management_network.version and network.overlaps(management_network):
                raise ValueError(
                    f"Le réseau interne {network} chevauche le réseau de gestion "
                    f"{management_network} de {machine.id}"
                )

    infrastructure_by_id = {machine.id: machine for machine in scenario.infrastructure}
    participants = []
    for instance in scenario.mininet_instances:
        machine = infrastructure_by_id.get(instance.infrastructure_vm_id or "")
        if machine is None:
            raise ValueError(f"VM hôte introuvable pour l'instance Mininet {instance.name}")
        participants.append((machine, instance))
    cygil = next(
        (machine for machine in scenario.infrastructure if machine.role == InfrastructureRole.CYGIL),
        None,
    )
    if cygil is not None:
        cygil.internal_ip = None
        cygil.interfaces = [
            interface
            for interface in cygil.interfaces
            if interface.vmware_network != vmnet
        ]

    participant_ids = {machine.id for machine, _ in participants}
    excluded = {network.network_address, network.broadcast_address}
    for raw in occupied_addresses or set():
        parsed = ip_address(raw)
        if isinstance(parsed, IPv4Address) and parsed in network:
            excluded.add(parsed)
    for machine in [*scenario.infrastructure, *scenario.targets]:
        if machine.id in participant_ids:
            continue
        for interface in machine.interfaces:
            try:
                parsed = ip_interface(interface.address)
            except ValueError:
                continue
            if isinstance(parsed.ip, IPv4Address) and parsed.ip in network:
                excluded.add(parsed.ip)

    allocations: dict[str, IPv4Interface] = {}
    ordered = participants

    # Conserver les allocations persistées qui sont encore valides. Une
    # seconde préparation ne doit pas déplacer les adresses simplement parce
    # que les VM répondent maintenant à l'ARP sur leurs propres adresses.
    pending = []
    for machine, instance in ordered:
        # La VM est l'unique source persistée. La copie de l'instance ne doit
        # jamais ressusciter une allocation ancienne après modification de la VM.
        raw_current = machine.internal_ip
        if not raw_current:
            matching = next(
                (
                    interface
                    for interface in machine.interfaces
                    if interface.vmware_network == vmnet
                    and interface.purpose == InterfacePurpose.OTHER
                ),
                None,
            )
            raw_current = matching.address if matching else None
        try:
            current = ip_interface(
                raw_current
                if raw_current and "/" in str(raw_current)
                else f"{raw_current}/{network.prefixlen}"
            )
        except ValueError:
            current = None
        if (
            isinstance(current, IPv4Interface)
            and current.ip in network
            and current.ip not in excluded
        ):
            allocations[machine.id] = ip_interface(f"{current.ip}/{network.prefixlen}")
            excluded.add(current.ip)
        else:
            pending.append((machine, instance))

    candidates = (address for address in network.hosts() if address not in excluded)
    for machine, instance in pending:
        for candidate in candidates:
            if is_in_use and is_in_use(candidate):
                excluded.add(candidate)
                continue
            assigned = ip_interface(f"{candidate}/{network.prefixlen}")
            allocations[machine.id] = assigned
            excluded.add(candidate)
            break
        else:
            raise ValueError(f"Le réseau interne {network} ne contient pas assez d'adresses libres")

    for machine, instance in ordered:
        assigned = allocations[machine.id]
        machine.internal_ip = str(assigned.ip)
        _upsert_allocated_interface(
            machine,
            purpose=InterfacePurpose.OTHER,
            vmnet=vmnet,
            address=str(assigned),
        )
    scenario.vagrant.mininet_internal_network = vmnet
    scenario.vagrant.mininet_internal_cidr = network
    scenario.synchronize_mininet_bindings()
    return allocations


def synchronize_deployment_allocations(
    state: DeploymentState,
    allocations: dict[str, IPv4Interface],
    cidr: str | IPv4Network,
) -> DeploymentState:
    """Copie les réservations approuvées dans le journal persistant par cible."""

    state.vmnet_cidr = ip_network(cidr, strict=True)
    for target_id, assigned in allocations.items():
        target_state = state.targets.setdefault(target_id, TargetDeploymentState(target_id=target_id))
        target_state.assigned_address = assigned
        target_state.phase = TargetDeploymentPhase.ADDRESS_RESERVED
        target_state.updated_at = datetime.now(UTC).isoformat()
    return state
