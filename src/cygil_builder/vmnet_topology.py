"""Planification des raccordements physiques cible ↔ VMnet ↔ Mininet."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from .models import InfrastructureRole, InterfacePurpose, LinkScope, Scenario
from .vagrant_environment import VmnetRecord


@dataclass(frozen=True)
class ScenarioVmnetAttachment:
    """Un segment VMware dédié à un accès cible ou CALDERA."""

    target_id: str
    interface_index: int
    interface_name: str
    logical_network: str
    mininet_instance: str
    mininet_vm_id: str
    vmnet: str
    create_required: bool
    kind: str = "target_access"

    @property
    def attachment_id(self) -> str:
        if self.kind == "caldera_access":
            return f"caldera:{self.target_id}"
        return f"{self.target_id}:interface{self.interface_index}"


@dataclass(frozen=True)
class ScenarioVmnetPlan:
    """Plan stable des VMnet dédiés, sans mutation VMware."""

    attachments: tuple[ScenarioVmnetAttachment, ...]
    isolated_vmnets: tuple[str, ...]
    host_connected_vmnets: tuple[str, ...]
    host_connection_unknown: tuple[str, ...]
    dhcp_disable_vmnets: tuple[str, ...]
    required_host_vmnets: tuple[str, ...]
    required_host_disconnected: tuple[str, ...]
    required_host_unknown: tuple[str, ...]

    @property
    def missing_vmnets(self) -> tuple[str, ...]:
        return tuple(item.vmnet for item in self.attachments if item.create_required)

    @property
    def confirmation_token(self) -> str:
        payload = {
            "attachments": [item.__dict__ for item in self.attachments],
            "isolated_vmnets": self.isolated_vmnets,
            "host_connected_vmnets": self.host_connected_vmnets,
            "host_connection_unknown": self.host_connection_unknown,
            "dhcp_disable_vmnets": self.dhcp_disable_vmnets,
            "required_host_vmnets": self.required_host_vmnets,
            "required_host_disconnected": self.required_host_disconnected,
            "required_host_unknown": self.required_host_unknown,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:12].upper()

    @property
    def changes_required(self) -> bool:
        return bool(
            self.missing_vmnets
            or self.host_connected_vmnets
            or self.dhcp_disable_vmnets
            or self.required_host_disconnected
        )

    @property
    def host_isolation_confirmed(self) -> bool:
        return not (
            self.host_connected_vmnets
            or self.host_connection_unknown
            or self.required_host_disconnected
            or self.required_host_unknown
        )

    @property
    def dhcp_policy_confirmed(self) -> bool:
        """Confirme que les VMnet d'accès gérés par l'application sont sans DHCP."""

        return not self.dhcp_disable_vmnets


def _vmnet_number(name: str) -> int | None:
    match = re.fullmatch(r"VMnet(\d+)", name, re.IGNORECASE)
    return int(match.group(1)) if match else None


def plan_scenario_vmnets(
    scenario: Scenario,
    records: tuple[VmnetRecord, ...],
    *,
    first_dynamic: int = 2,
    last_dynamic: int = 19,
) -> ScenarioVmnetPlan:
    """Alloue un VMnet unique à chaque carte de scénario d'une cible.

    Une valeur déjà persistée est conservée uniquement si elle est unique et ne
    désigne ni VMnet0, ni l'amorçage, ni le réseau de contrôle interne. Les
    nouveaux noms sont choisis parmi les emplacements VMnet absents de
    l'inventaire; l'exécution séparée pourra alors les créer par VMREST.
    """

    instances = {instance.name: instance for instance in scenario.mininet_instances}
    observed_names = {record.name for record in records}
    observed_by_name = {record.name: record for record in records}
    reserved = {
        "VMnet0",
        scenario.vagrant.bootstrap_network,
        scenario.vagrant.mininet_internal_network,
    } - {None, ""}
    claimed: set[str] = set()
    pending = []

    for target in scenario.targets:
        for index, interface in enumerate(target.interfaces):
            if interface.purpose != InterfacePurpose.SCENARIO:
                continue
            instance = instances.get(interface.mininet_instance or "")
            if instance is None or not instance.infrastructure_vm_id:
                raise ValueError(
                    f"Aucune VM Mininet n'est associée à {target.id}/{interface.name or index}"
                )
            current = interface.vmware_network
            if current in reserved or current in claimed:
                current = None
            if current:
                number = _vmnet_number(current)
                if number is None or not first_dynamic <= number <= last_dynamic:
                    current = None
                elif (
                    current in observed_by_name
                    and observed_by_name[current].network_type.casefold() != "hostonly"
                ):
                    current = None
            pending.append((target, index, interface, instance, current))
            if current:
                claimed.add(current)

    compromised = next((target for target in scenario.targets if target.compromised), None)
    caldera_current = compromised.caldera_vmware_network if compromised else None
    if caldera_current in reserved or caldera_current in claimed:
        caldera_current = None
    if caldera_current:
        number = _vmnet_number(caldera_current)
        if number is None or not first_dynamic <= number <= last_dynamic:
            caldera_current = None
        elif (
            caldera_current in observed_by_name
            and observed_by_name[caldera_current].network_type.casefold() != "hostonly"
        ):
            caldera_current = None
    if caldera_current:
        claimed.add(caldera_current)

    unavailable = observed_names | reserved | claimed
    available_names = [
        f"VMnet{number}"
        for number in range(first_dynamic, last_dynamic + 1)
        if f"VMnet{number}" not in unavailable
    ]
    attachments = []
    for target, index, interface, instance, current in pending:
        vmnet = current
        if not vmnet:
            if not available_names:
                raise ValueError(
                    "VMware ne contient pas assez d'emplacements VMnet libres pour "
                    "tous les raccordements de cible"
                )
            vmnet = available_names.pop(0)
            interface.vmware_network = vmnet
        claimed.add(vmnet)
        attachments.append(
            ScenarioVmnetAttachment(
                target_id=target.id,
                interface_index=index,
                interface_name=interface.name,
                logical_network=interface.network or "",
                mininet_instance=instance.name,
                mininet_vm_id=instance.infrastructure_vm_id,
                vmnet=vmnet,
                create_required=vmnet not in observed_names,
            )
        )

    # CALDERA obtient un lien physique séparé vers la VM Mininet qui dessert
    # l'unique cible compromise. Ce VMnet ne touche jamais directement la cible.
    if compromised:
        interface = next(
            (
                item
                for item in compromised.interfaces
                if item.purpose == InterfacePurpose.SCENARIO
            ),
            None,
        )
        instance = instances.get(interface.mininet_instance if interface else "")
        if interface is None or instance is None or not instance.infrastructure_vm_id:
            raise ValueError(
                "La cible compromise doit avoir un accès local vers une instance Mininet"
            )
        vmnet = caldera_current
        if not vmnet:
            if not available_names:
                raise ValueError(
                    "VMware ne contient pas d'emplacement VMnet libre pour le lien CALDERA"
                )
            vmnet = available_names.pop(0)
            compromised.caldera_vmware_network = vmnet
        caldera = next(
            (
                machine
                for machine in scenario.infrastructure
                if machine.role == InfrastructureRole.CALDERA
            ),
            None,
        )
        caldera_interface = next(
            (
                item
                for item in (caldera.interfaces if caldera else [])
                if item.purpose == InterfacePurpose.SCENARIO
            ),
            None,
        )
        if caldera_interface is not None:
            # Ces valeurs dérivées maintiennent les contrats du compilateur,
            # de la reconstruction VMware et du provisionnement invité.
            caldera_interface.network = interface.network
            caldera_interface.mininet_instance = instance.name
            caldera_interface.connected_switch = interface.connected_switch
            caldera_interface.scope = LinkScope.LOCAL
            caldera_interface.vmware_network = vmnet
        attachments.append(
            ScenarioVmnetAttachment(
                target_id=compromised.id,
                interface_index=-1,
                interface_name="caldera_access",
                logical_network=interface.network or "",
                mininet_instance=instance.name,
                mininet_vm_id=instance.infrastructure_vm_id,
                vmnet=vmnet,
                create_required=vmnet not in observed_names,
                kind="caldera_access",
            )
        )

    # La correspondance physique appartient désormais au raccordement, jamais
    # au sous-réseau logique partagé par plusieurs cibles.
    for network in scenario.networks:
        network.vmware_network = None
    isolated_vmnets = tuple(
        sorted(
            {
                *(item.vmnet for item in attachments),
                *(
                    [scenario.vagrant.mininet_internal_network]
                    if scenario.vagrant.mininet_internal_network
                    else []
                ),
            },
            key=lambda name: (_vmnet_number(name) is None, _vmnet_number(name) or 0, name),
        )
    )
    connected = tuple(
        name
        for name in isolated_vmnets
        if name in observed_by_name and observed_by_name[name].host_connected is True
    )
    unknown = tuple(
        name
        for name in isolated_vmnets
        if name not in observed_by_name or observed_by_name[name].host_connected is None
    )
    attachment_vmnets = {item.vmnet for item in attachments}
    dhcp_disable_vmnets = tuple(
        sorted(
            (
                name
                for name in attachment_vmnets
                if name not in observed_by_name
                or observed_by_name[name].dhcp_enabled
            ),
            key=lambda name: (_vmnet_number(name) is None, _vmnet_number(name) or 0, name),
        )
    )
    required_host_vmnets = tuple(
        name
        for name in ("VMnet0", scenario.vagrant.bootstrap_network)
        if name
    )
    required_host_disconnected = tuple(
        name
        for name in required_host_vmnets
        if name in observed_by_name and observed_by_name[name].host_connected is False
    )
    required_host_unknown = tuple(
        name
        for name in required_host_vmnets
        if name not in observed_by_name or observed_by_name[name].host_connected is None
    )
    return ScenarioVmnetPlan(
        tuple(attachments),
        isolated_vmnets,
        connected,
        unknown,
        dhcp_disable_vmnets,
        required_host_vmnets,
        required_host_disconnected,
        required_host_unknown,
    )
