"""Inventaire et reconstruction transactionnelle des cartes VMware réservées.

Le module sépare strictement la lecture, la planification et la mutation. Un plan
est lié à l'inventaire complet par SHA-256; l'écriture d'un VMX n'est permise
qu'après sauvegarde, confirmation exacte et preuve que la VM est éteinte.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import UTC, datetime
from ipaddress import IPv4Interface
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable, Iterable

import httpx
from pydantic import Field

from .lab_topology import VMWARE_MAX_NICS, permanent_network_expectations
from .models import (
    InfrastructureRole,
    IsolationInterfaceConfig,
    MacAddressSource,
    NetworkReconstructionState,
    Scenario,
    StrictModel,
    VmwareNetworkAdapter,
)


_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")
_VMX_SETTING = re.compile(r'^\s*([^#][^=]+?)\s*=\s*"(.*)"\s*$')
_VMX_NIC_KEY = re.compile(r"^ethernet(\d+)\.(.+)$", re.IGNORECASE)


class VmwareNetworkError(RuntimeError):
    """Refus explicite d'un inventaire incomplet ou d'une mutation dangereuse."""


def normalize_mac(value: str) -> str:
    """Retourne une MAC canonique ``xx:xx:xx:xx:xx:xx`` et exige l'unicast."""

    compact = re.sub(r"[^0-9A-Fa-f]", "", value or "").casefold()
    if not _MAC_HEX.fullmatch(compact):
        raise VmwareNetworkError(f"Adresse MAC invalide : {value!r}")
    octets = [int(compact[index:index + 2], 16) for index in range(0, 12, 2)]
    if octets[0] & 1:
        raise VmwareNetworkError(f"Une MAC multicast n'est pas autorisée : {value}")
    return ":".join(f"{octet:02x}" for octet in octets)


class StaticMacPolicy(StrictModel):
    """Plage statique confirmée pour la version VMware réellement installée."""

    workstation_version: str
    first_mac: str
    last_mac: str
    validated: bool = False
    validation_source: str | None = None

    def integer_bounds(self) -> tuple[int, int]:
        """Valide la plage fournie sans présupposer un préfixe VMware universel."""

        if not self.validated or not self.validation_source:
            raise VmwareNetworkError(
                "La plage MAC statique doit être confirmée pour la version VMware installée"
            )
        lower = int(normalize_mac(self.first_mac).replace(":", ""), 16)
        upper = int(normalize_mac(self.last_mac).replace(":", ""), 16)
        if lower > upper:
            raise VmwareNetworkError("La plage MAC VMware confirmée est inversée")
        return lower, upper


class VmwareVMInventory(StrictModel):
    """Identité et cartes observées d'une VM VMware, y compris hors scénario."""

    vmware_id: str
    name: str
    vmx_path: str
    power_state: str | None = None
    adapters: list[VmwareNetworkAdapter] = Field(default_factory=list)


class VmwareInventorySnapshot(StrictModel):
    """Instantané global normalisé dont l'empreinte invalide les vieux plans."""

    captured_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    complete: bool
    errors: list[str] = Field(default_factory=list)
    vms: list[VmwareVMInventory] = Field(default_factory=list)
    fingerprint: str = ""

    def seal(self) -> "VmwareInventorySnapshot":
        """Calcule une empreinte stable qui ignore uniquement l'heure de capture."""

        payload = {
            "complete": self.complete,
            "errors": sorted(self.errors),
            "vms": [vm.model_dump(mode="json") for vm in sorted(self.vms, key=lambda item: item.vmware_id)],
        }
        self.fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return self

    def mac_owners(self) -> dict[str, list[str]]:
        """Indexe chaque MAC avec VM et carte pour détecter toute collision globale."""

        owners: dict[str, list[str]] = {}
        for vm in self.vms:
            for adapter in vm.adapters:
                if adapter.applied_mac:
                    mac = normalize_mac(adapter.applied_mac)
                    owners.setdefault(mac, []).append(f"{vm.vmware_id}:ethernet{adapter.vmware_adapter_index}")
        return owners


class ReservedVMNetworkPlan(StrictModel):
    """Diff complet observé-vers-attendu pour une seule VM réservée."""

    machine_id: str
    vmware_id: str
    vmx_path: str
    observed: list[VmwareNetworkAdapter]
    expected: list[VmwareNetworkAdapter]
    management_address: IPv4Interface | None = None


class NetworkReconstructionPlan(StrictModel):
    """Plan destructif confirmable, lié à un inventaire global précis."""

    scenario_name: str
    inventory_fingerprint: str
    machines: list[ReservedVMNetworkPlan]
    fingerprint: str = ""

    def seal(self) -> "NetworkReconstructionPlan":
        """Scelle toutes les suppressions et créations, adresses et MAC incluses."""

        payload = self.model_dump(mode="json", exclude={"fingerprint"})
        self.fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return self

    @property
    def confirmation_token(self) -> str:
        """Jeton court affichable; la comparaison interne conserve le SHA-256 complet."""

        return self.fingerprint[:12].upper()


class NetworkRollbackBundle(StrictModel):
    """Sauvegarde de retour contenant le VMX original de chaque VM sélectionnée."""

    plan_fingerprint: str
    inventory_fingerprint: str
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    vmx_backups: dict[str, str] = Field(default_factory=dict)
    manifest_path: str | None = None


def _adapter_from_vmx(index: int, settings: dict[str, str]) -> VmwareNetworkAdapter | None:
    """Convertit les clés d'un seul ethernetN sans interpréter les autres périphériques."""

    if settings.get("present", "TRUE").casefold() == "false":
        return None
    vmnet = settings.get("vnet") or settings.get("networkName")
    if not vmnet:
        return None
    raw_mac = settings.get("address") or settings.get("generatedAddress")
    return VmwareNetworkAdapter(
        vmware_adapter_index=index,
        vmnet=vmnet,
        connection_type=settings.get("connectionType", "custom"),
        applied_mac=normalize_mac(raw_mac) if raw_mac else None,
        mac_source=MacAddressSource.OBSERVED if raw_mac else None,
        permanent=True,
        verified=bool(raw_mac),
    )


def read_vmx_adapters(path: str | Path) -> list[VmwareNetworkAdapter]:
    """Inventorie les seules clés réseau d'un VMX local en lecture seule."""

    source = Path(path)
    if not source.is_file():
        raise VmwareNetworkError(f"VMX inaccessible : {source}")
    grouped: dict[int, dict[str, str]] = {}
    for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _VMX_SETTING.match(line)
        if not match:
            continue
        nic = _VMX_NIC_KEY.match(match.group(1).strip())
        if nic:
            grouped.setdefault(int(nic.group(1)), {})[nic.group(2)] = match.group(2)
    adapters = [_adapter_from_vmx(index, settings) for index, settings in sorted(grouped.items())]
    return [adapter for adapter in adapters if adapter is not None]


class VmwareNetworkInventoryService:
    """Inventorie toutes les VM enregistrées puis toutes leurs cartes via les VMX."""

    def __init__(self, scenario: Scenario, username: str, password: str) -> None:
        self.scenario = scenario
        self.username = username
        self.password = password

    def inspect_all(self) -> VmwareInventorySnapshot:
        """Bloque implicitement la planification si une VM ou un VMX manque."""

        if not self.username or not self.password:
            raise VmwareNetworkError("Les identifiants vmrest sont requis pour l'inventaire global")
        base = f"https://127.0.0.1:{self.scenario.vmware.api_port}"
        errors: list[str] = []
        records: list[VmwareVMInventory] = []
        try:
            response = httpx.get(f"{base}/api/vms", auth=(self.username, self.password), verify=False, timeout=15)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise VmwareNetworkError(f"Inventaire VMware impossible : {exc}") from exc
        items = payload.get("vms", payload) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise VmwareNetworkError("vmrest a retourné une liste de VM invalide")
        for item in items:
            if not isinstance(item, dict):
                errors.append("Entrée VM non structurée dans l'inventaire vmrest")
                continue
            vmware_id = str(item.get("id") or item.get("vmid") or item.get("uuid") or "").strip()
            vmx_path = str(item.get("path") or item.get("vmx_path") or "").strip()
            if not vmware_id or not vmx_path:
                errors.append(f"Identité ou chemin VMX incomplet : {item.get('name', '<sans nom>')}")
                continue
            try:
                adapters = read_vmx_adapters(vmx_path)
            except VmwareNetworkError as exc:
                errors.append(str(exc))
                adapters = []
            records.append(VmwareVMInventory(
                vmware_id=vmware_id,
                name=str(item.get("name") or item.get("displayName") or vmware_id),
                vmx_path=vmx_path,
                power_state=item.get("power_state") or item.get("state"),
                adapters=adapters,
            ))
        snapshot = VmwareInventorySnapshot(complete=not errors and len(records) == len(items), errors=errors, vms=records)
        return snapshot.seal()

    @staticmethod
    def persist(snapshot: VmwareInventorySnapshot, path: str | Path) -> Path:
        """Persiste atomiquement l'instantané normalisé pour audit et reprise."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as stream:
            stream.write(snapshot.model_dump_json(indent=2))
            temporary = Path(stream.name)
        os.replace(temporary, destination)
        return destination


def validate_requested_macs(scenario: Scenario, inventory: VmwareInventorySnapshot) -> dict[str, str]:
    """Valide les MAC explicites des cibles contre toutes les VM VMware observées."""

    if not inventory.complete:
        raise VmwareNetworkError("L'inventaire MAC global est incomplet")
    observed: dict[str, list[VmwareVMInventory]] = {}
    for vm in inventory.vms:
        for adapter in vm.adapters:
            if adapter.applied_mac:
                observed.setdefault(normalize_mac(adapter.applied_mac), []).append(vm)
    requested: dict[str, str] = {}
    for target in scenario.targets:
        permanent = [interface for interface in target.interfaces if interface.purpose.value == "scenario"]
        for interface in permanent:
            raw = interface.mac
            if not raw:
                continue
            mac = normalize_mac(raw)
            if mac in requested:
                raise VmwareNetworkError(f"MAC demandée en double par {requested[mac]} et {target.id}")
            target_path = str(Path(target.vmx_path)) if target.vmx_path else None
            foreign = [
                vm.vmware_id
                for vm in observed.get(mac, [])
                if target_path is None or str(Path(vm.vmx_path)) != target_path
            ]
            if foreign:
                raise VmwareNetworkError(f"MAC {mac} de {target.id} déjà utilisée par {foreign}")
            requested[mac] = target.id
    return requested


def generate_stable_mac(
    policy: StaticMacPolicy,
    scenario_name: str,
    machine_id: str,
    adapter_index: int,
    excluded: set[str],
    *,
    attempts: int = 1024,
) -> str:
    """Génère un candidat stable dans la plage confirmée avec essais bornés."""

    lower, upper = policy.integer_bounds()
    span = upper - lower + 1
    if span <= 0:
        raise VmwareNetworkError("La plage MAC confirmée est vide")
    for attempt in range(min(attempts, span)):
        seed = f"{scenario_name}\0{machine_id}\0{adapter_index}\0{attempt}".encode("utf-8")
        candidate = lower + int.from_bytes(hashlib.sha256(seed).digest()[:8], "big") % span
        raw = f"{candidate:012x}"
        mac = normalize_mac(raw)
        if mac not in excluded:
            return mac
    raise VmwareNetworkError(f"Aucune MAC unique trouvée pour {machine_id}:ethernet{adapter_index}")


def _network_vmnet_map(scenario: Scenario) -> dict[str, str]:
    """Charge seulement les anciennes correspondances réseau-vers-VMnet."""

    return {
        network.id: network.vmware_network
        for network in scenario.networks
        if network.vmware_network
    }


def plan_target_interfaces(
    scenario: Scenario,
    inventory: VmwareInventorySnapshot,
    policy: StaticMacPolicy,
) -> None:
    """Calcule les VMnet, indices et MAC des cibles depuis une seule vue globale."""

    if not inventory.complete:
        raise VmwareNetworkError("Impossible de planifier les cibles depuis un inventaire global incomplet")
    excluded = set(inventory.mac_owners())
    excluded.update(validate_requested_macs(scenario, inventory))

    for target in scenario.targets:
        temporary_access = target.temporary_management
        # ethernet0 est l'amorçage DHCP des cibles. VMnet0 n'est jamais ajouté
        # à une cible; les cartes de scénario commencent donc à ethernet1.
        next_index = 1 if temporary_access.enabled and scenario.vagrant.bootstrap_network else 0
        for interface in [item for item in target.interfaces if item.purpose.value == "scenario"]:
            if not interface.vmware_network:
                raise VmwareNetworkError(
                    f"Aucun VMnet confirmé pour {target.id}/{interface.name} ({interface.network})"
                )
            index = interface.vmware_adapter_index
            if index is None:
                index = next_index
                interface.vmware_adapter_index = index
            next_index = max(next_index, index + 1)
            if interface.mac:
                mac = normalize_mac(interface.mac)
            else:
                mac = generate_stable_mac(
                    policy,
                    scenario.metadata.name,
                    target.id,
                    index,
                    excluded,
                )
                interface.mac = mac
                interface.mac_source = MacAddressSource.GENERATED
            if mac in excluded and interface.mac_source == MacAddressSource.GENERATED:
                # Une valeur générée déjà persistée reste valide pour sa carte.
                pass
            excluded.add(mac)


def build_reconstruction_plan(
    scenario: Scenario,
    inventory: VmwareInventorySnapshot,
    policy: StaticMacPolicy,
    *,
    management_addresses: dict[str, IPv4Interface] | None = None,
) -> NetworkReconstructionPlan:
    """Dérive toutes les cartes réservées sans modifier le banc."""

    if not inventory.complete:
        raise VmwareNetworkError("Impossible de planifier depuis un inventaire global incomplet")
    validate_requested_macs(scenario, inventory)
    inventory_by_id = {vm.vmware_id: vm for vm in inventory.vms}
    if len(inventory_by_id) != len(inventory.vms):
        raise VmwareNetworkError("L'inventaire contient des identités VMware dupliquées")
    vmnet_by_network = _network_vmnet_map(scenario)
    bootstrap = scenario.vagrant.bootstrap_network
    if not bootstrap or bootstrap == "VMnet0":
        raise VmwareNetworkError("Le VMnet DHCP d'amorçage distinct de VMnet0 doit être confirmé")
    expectations = permanent_network_expectations(scenario)
    excluded = set(inventory.mac_owners())
    excluded.update(validate_requested_macs(scenario, inventory))
    machine_plans: list[ReservedVMNetworkPlan] = []
    management_addresses = management_addresses or {}

    for machine in scenario.infrastructure:
        if not machine.inventory_confirmed or not machine.vmware_id:
            raise VmwareNetworkError(f"L'identité VMware de {machine.id} n'est pas confirmée")
        observed_vm = inventory_by_id.get(machine.vmware_id)
        if observed_vm is None:
            raise VmwareNetworkError(f"La VM réservée {machine.id} est absente de l'inventaire global")
        if machine.vmx_path and Path(machine.vmx_path) != Path(observed_vm.vmx_path):
            raise VmwareNetworkError(f"Le chemin VMX observé de {machine.id} a changé")
        required = expectations[machine.id].required_networks
        vmnets: list[tuple[str, bool]] = []
        for network in sorted(required, key=lambda value: (value != "VMnet0", value)):
            if network == "VMnet0":
                vmnets.append((network, True))
            elif network.casefold().startswith("vmnet"):
                vmnets.append((network, True))
            elif network in vmnet_by_network:
                vmnets.append((vmnet_by_network[network], True))
            else:
                raise VmwareNetworkError(
                    f"Aucun VMnet confirmé pour le réseau {network} requis par {machine.id}"
                )
        vmnets.append((bootstrap, False))
        # Une seule carte par VMnet est conservée, même si plusieurs cibles
        # CALDERA ou liens Mininet dérivent la même connexion.
        unique_vmnets = list(dict.fromkeys(vmnets))
        if len(unique_vmnets) > VMWARE_MAX_NICS:
            raise VmwareNetworkError(
                f"{machine.id} exige {len(unique_vmnets)} cartes, au-delà de la limite "
                f"VMware de {VMWARE_MAX_NICS}; répartissez les cibles sur plusieurs instances Mininet"
            )
        observed_by_vmnet = {adapter.vmnet: adapter for adapter in observed_vm.adapters}
        expected: list[VmwareNetworkAdapter] = []
        for index, (vmnet, permanent) in enumerate(unique_vmnets):
            previous = observed_by_vmnet.get(vmnet)
            if previous and previous.applied_mac:
                mac = normalize_mac(previous.applied_mac)
                source = MacAddressSource.OBSERVED
            else:
                mac = generate_stable_mac(policy, scenario.metadata.name, machine.id, index, excluded)
                source = MacAddressSource.GENERATED
            excluded.add(mac)
            declared_interface = next(
                (item for item in machine.interfaces if item.vmware_network == vmnet),
                None,
            )
            expected.append(VmwareNetworkAdapter(
                vmware_adapter_index=index,
                vmnet=vmnet,
                connection_type="custom",
                requested_mac=mac,
                mac_source=source,
                guest_name=declared_interface.name if declared_interface else None,
                address=(
                    str(management_addresses[machine.id])
                    if vmnet == "VMnet0" and machine.id in management_addresses
                    else (declared_interface.address if declared_interface else None)
                ),
                permanent=permanent,
            ))
        machine.observed_adapters = [adapter.model_copy(deep=True) for adapter in observed_vm.adapters]
        machine.expected_adapters = [adapter.model_copy(deep=True) for adapter in expected]
        machine.network_reconstruction_state = NetworkReconstructionState.PLANNED
        machine_plans.append(ReservedVMNetworkPlan(
            machine_id=machine.id,
            vmware_id=machine.vmware_id,
            vmx_path=observed_vm.vmx_path,
            observed=observed_vm.adapters,
            expected=expected,
            management_address=management_addresses.get(machine.id),
        ))
    return NetworkReconstructionPlan(
        scenario_name=scenario.metadata.name,
        inventory_fingerprint=inventory.fingerprint,
        machines=machine_plans,
    ).seal()


def _render_vmx_with_adapters(original: str, adapters: Iterable[VmwareNetworkAdapter]) -> str:
    """Remplace seulement les clés ethernetN.* et préserve disques et autres options."""

    retained = []
    for line in original.splitlines():
        match = _VMX_SETTING.match(line)
        if match and _VMX_NIC_KEY.match(match.group(1).strip()):
            continue
        retained.append(line)
    for adapter in adapters:
        index = adapter.vmware_adapter_index
        mac = normalize_mac(adapter.requested_mac or adapter.applied_mac or "")
        retained.extend((
            f'ethernet{index}.present = "TRUE"',
            f'ethernet{index}.connectionType = "{adapter.connection_type}"',
            f'ethernet{index}.vnet = "{adapter.vmnet}"',
            f'ethernet{index}.addressType = "static"',
            f'ethernet{index}.address = "{mac}"',
            f'ethernet{index}.startConnected = "TRUE"',
        ))
    return "\n".join(retained) + "\n"


class VmxNetworkReconstructor:
    """Applique et restaure les seuls blocs ethernet d'un VMX hors tension."""

    def __init__(self, state_reader: Callable[[str], str], backup_directory: str | Path) -> None:
        self.state_reader = state_reader
        self.backup_directory = Path(backup_directory)

    def create_backup(self, plan: NetworkReconstructionPlan) -> NetworkRollbackBundle:
        """Copie chaque VMX avant mutation et produit un manifeste de restauration."""

        self.backup_directory.mkdir(parents=True, exist_ok=True)
        bundle = NetworkRollbackBundle(
            plan_fingerprint=plan.fingerprint,
            inventory_fingerprint=plan.inventory_fingerprint,
        )
        for machine in plan.machines:
            source = Path(machine.vmx_path)
            if not source.is_file():
                raise VmwareNetworkError(f"Sauvegarde impossible, VMX absent : {source}")
            destination = self.backup_directory / f"{machine.vmware_id}-{plan.fingerprint[:12]}.vmx.bak"
            shutil.copy2(source, destination)
            bundle.vmx_backups[machine.vmware_id] = str(destination)
        manifest = self.backup_directory / f"rollback-{plan.fingerprint[:12]}.json"
        bundle.manifest_path = str(manifest)
        manifest.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
        return bundle

    def apply(
        self,
        plan: NetworkReconstructionPlan,
        inventory: VmwareInventorySnapshot,
        rollback: NetworkRollbackBundle,
        *,
        confirmation_token: str,
    ) -> None:
        """Refuse inventaire changé, VM active, sauvegarde absente ou jeton obsolète."""

        if confirmation_token != plan.confirmation_token:
            raise VmwareNetworkError("La confirmation destructive ne correspond pas au plan exact")
        if inventory.fingerprint != plan.inventory_fingerprint:
            raise VmwareNetworkError("L'inventaire VMware a changé depuis la prévisualisation")
        if rollback.plan_fingerprint != plan.fingerprint:
            raise VmwareNetworkError("La sauvegarde de retour n'appartient pas à ce plan")
        for machine in plan.machines:
            state = self.state_reader(machine.vmware_id).casefold()
            if state != "poweredoff":
                raise VmwareNetworkError(
                    f"{machine.machine_id} doit être poweredOff, pas {state or 'inconnu'}"
                )
            if machine.vmware_id not in rollback.vmx_backups:
                raise VmwareNetworkError(f"Sauvegarde de retour absente pour {machine.machine_id}")
        for machine in plan.machines:
            path = Path(machine.vmx_path)
            original = path.read_text(encoding="utf-8", errors="strict")
            rendered = _render_vmx_with_adapters(original, machine.expected)
            with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
                stream.write(rendered)
                temporary = Path(stream.name)
            os.replace(temporary, path)

    def restore(
        self,
        plan: NetworkReconstructionPlan,
        rollback: NetworkRollbackBundle,
        *,
        confirmation_token: str,
    ) -> None:
        """Restaure les VMX sélectionnés seulement, toujours hors tension."""

        expected = hashlib.sha256(f"RESTORE:{plan.fingerprint}".encode("utf-8")).hexdigest()[:12].upper()
        if confirmation_token != expected:
            raise VmwareNetworkError("La restauration exacte n'a pas été confirmée")
        for machine in plan.machines:
            if self.state_reader(machine.vmware_id).casefold() != "poweredoff":
                raise VmwareNetworkError(f"Restauration interdite tant que {machine.machine_id} n'est pas éteinte")
            backup = Path(rollback.vmx_backups.get(machine.vmware_id, ""))
            if not backup.is_file():
                raise VmwareNetworkError(f"Sauvegarde introuvable pour {machine.machine_id}")
            shutil.copy2(backup, machine.vmx_path)

    @staticmethod
    def restore_confirmation_token(plan: NetworkReconstructionPlan) -> str:
        """Retourne le jeton distinct exigé pour la restauration."""

        return hashlib.sha256(f"RESTORE:{plan.fingerprint}".encode("utf-8")).hexdigest()[:12].upper()


def reconcile_applied_adapters(
    scenario: Scenario,
    plan: NetworkReconstructionPlan,
    observed: VmwareInventorySnapshot,
) -> None:
    """Compare la relecture au plan et propage uniquement les MAC effectivement vues."""

    observed_by_id = {vm.vmware_id: vm for vm in observed.vms}
    machine_by_id = {machine.id: machine for machine in scenario.infrastructure}
    for machine_plan in plan.machines:
        machine = machine_by_id[machine_plan.machine_id]
        current = observed_by_id.get(machine_plan.vmware_id)
        if current is None:
            machine.network_reconstruction_state = NetworkReconstructionState.FAILED
            raise VmwareNetworkError(f"{machine.id} manque dans la relecture VMware")
        expected_keys = [
            (item.vmware_adapter_index, item.vmnet, normalize_mac(item.requested_mac or ""))
            for item in machine_plan.expected
        ]
        actual_keys = [
            (item.vmware_adapter_index, item.vmnet, normalize_mac(item.applied_mac or ""))
            for item in current.adapters
        ]
        if actual_keys != expected_keys:
            machine.network_reconstruction_state = NetworkReconstructionState.FAILED
            raise VmwareNetworkError(f"Les cartes relues de {machine.id} diffèrent du plan confirmé")
        machine.observed_adapters = [item.model_copy(update={"verified": True}) for item in current.adapters]
        machine.expected_adapters = [
            item.model_copy(update={"applied_mac": actual[2], "verified": True})
            for item, actual in zip(machine_plan.expected, actual_keys, strict=True)
        ]
        for interface in machine.interfaces:
            vmnet = interface.vmware_network
            if not vmnet and interface.purpose.value == "management":
                vmnet = "VMnet0"
                interface.vmware_network = vmnet
            candidates = [adapter for adapter in current.adapters if adapter.vmnet == vmnet]
            if len(candidates) != 1 or not candidates[0].applied_mac:
                continue
            adapter = candidates[0]
            interface.vmware_adapter_index = adapter.vmware_adapter_index
            interface.mac = normalize_mac(adapter.applied_mac)
            interface.applied_mac = normalize_mac(adapter.applied_mac)
            interface.mac_source = MacAddressSource.VMWARE
            interface.mac_verified = True
            if adapter.guest_name:
                interface.name = adapter.guest_name
        bootstrap = scenario.vagrant.bootstrap_network
        if bootstrap:
            bootstrap_adapters = [
                adapter
                for adapter in current.adapters
                if adapter.vmnet.casefold() == bootstrap.casefold() and adapter.applied_mac
            ]
            if len(bootstrap_adapters) == 1:
                adapter = bootstrap_adapters[0]
                machine.isolation_interfaces = [
                    item
                    for item in machine.isolation_interfaces
                    if item.network.casefold() != bootstrap.casefold()
                ]
                machine.isolation_interfaces.append(
                    IsolationInterfaceConfig(
                        network=adapter.vmnet,
                        guest_name=adapter.guest_name,
                        mac=normalize_mac(adapter.applied_mac),
                        vmware_adapter_index=adapter.vmware_adapter_index,
                    )
                )
        machine.network_reconstruction_state = NetworkReconstructionState.VERIFIED


def associate_bootstrap_leases(scenario: Scenario, leases: dict[str, str]) -> dict[str, str]:
    """Associe les baux DHCP aux VM par la MAC VMware confirmée d'amorçage."""

    bootstrap = scenario.vagrant.bootstrap_network
    if not bootstrap:
        raise VmwareNetworkError("Le VMnet DHCP d'amorçage n'est pas configuré")
    normalized_leases: dict[str, str] = {}
    for mac, address in leases.items():
        try:
            normalized_leases[normalize_mac(mac)] = address
        except VmwareNetworkError:
            continue

    matched: dict[str, str] = {}
    for machine in [*scenario.infrastructure, *scenario.targets]:
        identities = [
            item.mac
            for item in machine.isolation_interfaces
            if item.network.casefold() == bootstrap.casefold() and item.mac
        ]
        vmware_adapters = [
            *getattr(machine, "observed_adapters", []),
            *getattr(machine, "expected_adapters", []),
        ]
        identities.extend(
            adapter.applied_mac or adapter.requested_mac
            for adapter in vmware_adapters
            if adapter.vmnet.casefold() == bootstrap.casefold()
            and (adapter.applied_mac or adapter.requested_mac)
        )
        addresses: set[str] = set()
        for mac in identities:
            try:
                address = normalized_leases.get(normalize_mac(mac))
            except VmwareNetworkError:
                continue
            if address:
                addresses.add(address)
        if len(addresses) != 1 or machine.guest_access is None:
            continue
        address = addresses.pop()
        machine.guest_access.connection_address = address
        matched[machine.id] = address
    return matched


def apply_verified_target_macs(scenario: Scenario, observed_by_vmx: dict[str, list[VmwareNetworkAdapter]]) -> None:
    """Alimente les interfaces cibles depuis la relecture VMware, jamais depuis une supposition."""

    for target in scenario.targets:
        if not target.vmx_path:
            continue
        observed = observed_by_vmx.get(str(Path(target.vmx_path)))
        if observed is None:
            continue
        scenario_interfaces = [interface for interface in target.interfaces if interface.purpose.value == "scenario"]
        for interface in scenario_interfaces:
            candidates = [
                adapter
                for adapter in observed
                if (
                    interface.vmware_adapter_index is not None
                    and adapter.vmware_adapter_index == interface.vmware_adapter_index
                )
                or (
                    interface.vmware_adapter_index is None
                    and adapter.vmnet == interface.vmware_network
                )
            ]
            if len(candidates) != 1 or not candidates[0].applied_mac:
                raise VmwareNetworkError(f"MAC VMware finale ambiguë pour {target.id}/{interface.name}")
            interface.applied_mac = normalize_mac(candidates[0].applied_mac)
            interface.mac_source = MacAddressSource.VMWARE
            interface.mac_verified = True

        isolation_networks = {
            target.temporary_management.vmware_network
        } - {""}
        if scenario.vagrant.bootstrap_network:
            isolation_networks.add(scenario.vagrant.bootstrap_network)
        retained = [
            item for item in target.isolation_interfaces if item.network not in isolation_networks
        ]
        for network in sorted(isolation_networks):
            candidates = [adapter for adapter in observed if adapter.vmnet == network]
            if len(candidates) != 1:
                continue
            adapter = candidates[0]
            retained.append(
                IsolationInterfaceConfig(
                    network=network,
                    guest_name=adapter.guest_name,
                    mac=(normalize_mac(adapter.applied_mac) if adapter.applied_mac else None),
                    vmware_adapter_index=adapter.vmware_adapter_index,
                )
            )
        target.isolation_interfaces = retained
