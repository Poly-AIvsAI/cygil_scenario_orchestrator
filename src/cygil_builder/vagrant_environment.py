"""Inventaires en lecture seule et sélecteurs locaux pour la phase Vagrant.

Les inspections sont conçues pour être appelées avec ``run.io_bound``. Elles ne
lancent aucune VM et ne modifient ni Vagrant, ni VMware, ni la configuration IP.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, ip_interface, ip_network
from pathlib import Path
from urllib.parse import unquote

import httpx

from .models import Scenario


class EnvironmentInventoryError(RuntimeError):
    """Erreur lisible produite par une inspection locale non destructive."""


def _canonical_vmnet_name(name: str) -> str:
    """Conserve ``VMnetN`` en interne malgré la casse variable de VMware."""

    match = re.fullmatch(r"vmnet(\d+)", name.strip(), flags=re.IGNORECASE)
    return f"VMnet{int(match.group(1))}" if match else name.strip()


@lru_cache(maxsize=64)
def _cached_box_provider(resolved_path: str, size_bytes: int, modified_ns: int) -> str:
    """Lit le fournisseur une fois par version physique d'une archive locale.

    La taille et la date de modification font partie de la clé : remplacer une
    box au même chemin invalide automatiquement le cache, sans minuteur global.
    Les arguments de version ne sont pas relus ici; ils rendent seulement la clé
    sensible aux changements observés par ``validate_box_file``.
    """

    del size_bytes, modified_ns
    path = Path(resolved_path)
    with tarfile.open(path, "r:*") as archive:
        member = next(
            (item for item in archive.getmembers() if Path(item.name).name == "metadata.json"),
            None,
        )
        if member is None or member.size > 64 * 1024:
            raise EnvironmentInventoryError("La box ne contient pas un metadata.json valide")
        stream = archive.extractfile(member)
        metadata = json.loads(stream.read().decode("utf-8")) if stream else {}
    provider = str(metadata.get("provider") or "").casefold()
    if provider != "vmware_desktop":
        raise EnvironmentInventoryError(
            f"La box annonce le fournisseur {provider or 'inconnu'}, pas VMware Desktop"
        )
    return provider


@dataclass(frozen=True)
class LocalBoxRecord:
    """Résultat de validation d'un fichier box choisi pour un modèle cible."""

    template: str
    path: str
    provider: str | None
    size_bytes: int | None
    valid: bool
    message: str


@dataclass(frozen=True)
class VagrantInventory:
    """Ressources installées et fichiers box locaux visibles sur l'hôte."""

    executable: str | None
    version: str | None
    plugins: tuple[str, ...] = ()
    boxes: tuple[str, ...] = ()
    vmware_utility_service: str = "absent"
    local_boxes: tuple[LocalBoxRecord, ...] = ()

    @property
    def provider_available(self) -> bool:
        """Confirme le fournisseur seulement si le plugin et l'Utility sont visibles."""

        return self.vmware_utility_service.casefold() == "running" and any(
            "vagrant-vmware-desktop" in plugin for plugin in self.plugins
        )


@dataclass(frozen=True)
class VmnetInventory:
    """CIDR, adresses hôte et voisins observés sur VMnet0."""

    adapter_name: str
    cidr: IPv4Network
    host_addresses: frozenset[str]
    occupied_addresses: frozenset[str]
    dhcp_enabled: bool


@dataclass(frozen=True)
class VmnetRecord:
    """Réseau VMware retourné en lecture seule par vmrest."""

    name: str
    network_type: str
    dhcp_enabled: bool
    subnet: str | None
    mask: str | None
    # ``None`` signifie que l'inventaire Windows n'a pas pu confirmer l'état.
    # ``False`` correspond à « Connect a host virtual adapter » décoché.
    host_connected: bool | None = None

    @property
    def cidr(self) -> IPv4Network | None:
        """Retourne le CIDR annoncé par VMware, sans supposer de masque."""

        if not self.subnet or not self.mask:
            return None
        try:
            network = ip_network(f"{self.subnet}/{self.mask}", strict=False)
        except ValueError:
            return None
        return network if isinstance(network, IPv4Network) else None


@dataclass(frozen=True)
class VmwareVMRecord:
    """VM enregistrée retournée par vmrest avant association à un rôle."""

    vmware_id: str
    name: str
    vmx_path: str | None = None
    power_state: str | None = None
    raw: dict = field(default_factory=dict, repr=False)


def _vmx_friendly_name(vmx_path: str | None) -> str | None:
    """Lit le titre ``displayName`` du VMX, puis utilise son nom de fichier.

    Certaines versions de VMREST ne retournent qu'un identifiant opaque et un
    chemin. Cette lecture locale reste strictement non destructive et fournit le
    libellé humain attendu dans la liste d'association.
    """

    if not vmx_path:
        return None
    source = Path(unquote(vmx_path))
    if source.is_file():
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            match = re.match(r'^\s*displayName\s*=\s*"(.*)"\s*$', line, re.IGNORECASE)
            if match and match.group(1).strip():
                return match.group(1).strip()
    stem = source.stem.strip()
    return stem or None


def associate_reserved_vm_roles(
    scenario: Scenario,
    records: tuple[VmwareVMRecord, ...],
    assignments: dict[str, str | None],
) -> None:
    """Associe chaque rôle réservé à une VM VMware unique et observée.

    ``assignments`` utilise l'identifiant canonique de la VM réservée comme
    clé et l'identifiant VMware comme valeur. L'application remplace toutes les
    associations en une transaction logique afin d'éviter les doublons laissés
    par une succession de boutons indépendants.
    """

    expected_ids = {machine.id for machine in scenario.infrastructure}
    missing_roles = sorted(machine_id for machine_id in expected_ids if not assignments.get(machine_id))
    if missing_roles:
        raise EnvironmentInventoryError(
            "Toutes les VM réservées doivent être associées : " + ", ".join(missing_roles)
        )
    unknown_roles = sorted(set(assignments) - expected_ids)
    if unknown_roles:
        raise EnvironmentInventoryError(
            "Rôles réservés inconnus : " + ", ".join(unknown_roles)
        )

    selected_ids = [str(assignments[machine.id]) for machine in scenario.infrastructure]
    if len(selected_ids) != len(set(selected_ids)):
        raise EnvironmentInventoryError(
            "Une même VM VMware ne peut pas être associée à plusieurs rôles réservés"
        )
    records_by_id = {record.vmware_id: record for record in records}
    if len(records_by_id) != len(records):
        raise EnvironmentInventoryError("L'inventaire VMware contient des identifiants dupliqués")
    unknown_vms = sorted(set(selected_ids) - set(records_by_id))
    if unknown_vms:
        raise EnvironmentInventoryError(
            "VM absentes du dernier inventaire VMware : " + ", ".join(unknown_vms)
        )
    selected_names = [records_by_id[vmware_id].name for vmware_id in selected_ids]
    if len(selected_names) != len(set(selected_names)):
        raise EnvironmentInventoryError("Les noms VMware associés doivent être uniques")

    # Effacer d'abord toutes les anciennes identités garantit qu'une permutation
    # de deux rôles ne produit jamais un état intermédiaire ambigu.
    for machine in scenario.infrastructure:
        machine.vmware_id = None
        machine.vmware_uuid = None
        machine.inventory_confirmed = False
    renames: dict[str, str] = {}
    for machine in scenario.infrastructure:
        original_id = machine.id
        record = records_by_id[str(assignments[machine.id])]
        machine.vmware_id = record.vmware_id
        machine.vmware_uuid = str(record.raw.get("uuid") or "") or None
        machine.inventory_confirmed = True
        if record.vmx_path:
            machine.vmx_path = record.vmx_path
        if record.name and record.name != original_id:
            machine.id = record.name
            renames[original_id] = record.name

    for instance in scenario.mininet_instances:
        if instance.infrastructure_vm_id in renames:
            instance.infrastructure_vm_id = renames[instance.infrastructure_vm_id]
    for intent in scenario.onos_intents:
        if intent.host_one in renames:
            intent.host_one = renames[intent.host_one]
        if intent.host_two in renames:
            intent.host_two = renames[intent.host_two]
    for objective in scenario.reward.objectives:
        if objective.host_name in renames:
            objective.host_name = renames[objective.host_name]


@dataclass(frozen=True)
class InstallationResult:
    """Résultat d'une étape d'installation explicitement confirmée."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class VagrantEnvironmentService:
    """Centralise les contrôles préalables et les choix de chemins Windows."""

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario

    def inspect_vagrant(self) -> VagrantInventory:
        """Inventorie Vagrant et valide les fichiers locaux sans les importer.

        ``vagrant box list`` ne montre que les boxes déjà installées. Les
        fichiers choisis dans la GUI sont donc inspectés séparément afin de
        ne jamais déclencher implicitement un ``vagrant box add``.
        """

        executable = self._find_vagrant()
        service_state = self._windows_service_state("vagrant-vmware-utility")
        local_boxes = self.inspect_local_boxes()
        if executable is None:
            return VagrantInventory(
                None,
                None,
                vmware_utility_service=service_state,
                local_boxes=local_boxes,
            )
        version = self._run_read_only([executable, "--version"])
        plugins = tuple(line for line in self._run_read_only([executable, "plugin", "list"]).splitlines() if line)
        boxes = tuple(line for line in self._run_read_only([executable, "box", "list"]).splitlines() if line)
        if len(plugins) == 1 and "no plugins" in plugins[0].casefold():
            plugins = ()
        if len(boxes) == 1 and "no installed boxes" in boxes[0].casefold():
            boxes = ()
        return VagrantInventory(
            executable,
            version,
            plugins,
            boxes,
            service_state,
            local_boxes,
        )

    def inspect_local_boxes(self) -> tuple[LocalBoxRecord, ...]:
        """Valide chaque chemin choisi sans modifier le catalogue Vagrant."""

        records: list[LocalBoxRecord] = []
        for template, raw_path in sorted(self.scenario.vagrant.box_paths.items()):
            path = Path(raw_path)
            try:
                provider = self.validate_box_file(path)
                records.append(
                    LocalBoxRecord(
                        template=template,
                        path=str(path),
                        provider=provider,
                        size_bytes=path.stat().st_size,
                        valid=True,
                        message="Box locale VMware valide; pas encore importée automatiquement",
                    )
                )
            except (EnvironmentInventoryError, OSError) as exc:
                records.append(
                    LocalBoxRecord(
                        template=template,
                        path=str(path),
                        provider=None,
                        size_bytes=path.stat().st_size if path.is_file() else None,
                        valid=False,
                        message=str(exc),
                    )
                )
        return tuple(records)

    def inspect_vmnet0(self) -> VmnetInventory:
        """Détecte VMnet0 et refuse toute ambiguïté de CIDR ou de DHCP hôte."""

        script = r"""
$adapter = Get-NetAdapter -IncludeHidden | Where-Object {
    $_.Name -eq 'VMware Network Adapter VMnet0' -or $_.InterfaceDescription -like '*VMnet0*'
} | Select-Object -First 1
if (-not $adapter) { throw 'VMnet0 est introuvable' }
$addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 |
    Where-Object { $_.AddressState -eq 'Preferred' } |
    ForEach-Object { @{ ip = $_.IPAddress; prefix = $_.PrefixLength } })
$interface = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
$neighbors = @(Get-NetNeighbor -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 |
    Where-Object { $_.State -notin @('Unreachable','Incomplete','Permanent') -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
    ForEach-Object { $_.IPAddress })
@{ name=$adapter.Name; addresses=$addresses; dhcp=[string]$interface.Dhcp; neighbors=$neighbors } |
    ConvertTo-Json -Depth 5 -Compress
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise EnvironmentInventoryError(result.stderr.strip() or "Inspection de VMnet0 impossible")
        payload = json.loads(result.stdout)
        addresses = payload.get("addresses") or []
        if isinstance(addresses, dict):
            addresses = [addresses]
        interfaces = [ip_interface(f"{item['ip']}/{item['prefix']}") for item in addresses]
        if len({item.network for item in interfaces}) != 1:
            raise EnvironmentInventoryError("VMnet0 doit exposer un unique CIDR IPv4 non ambigu")
        network = interfaces[0].network
        neighbors = payload.get("neighbors") or []
        if isinstance(neighbors, str):
            neighbors = [neighbors]
        return VmnetInventory(
            adapter_name=payload["name"],
            cidr=network,
            host_addresses=frozenset(str(item.ip) for item in interfaces),
            occupied_addresses=frozenset(str(item) for item in neighbors),
            dhcp_enabled=str(payload.get("dhcp", "")).casefold() == "enabled",
        )

    def discover_vmware_vms(self, username: str, password: str) -> tuple[VmwareVMRecord, ...]:
        """Liste les VM enregistrées par vmrest sans changer leur alimentation."""

        if not username or not password:
            raise EnvironmentInventoryError("Les identifiants vmrest sont requis pour inventorier les VM")
        url = f"https://127.0.0.1:{self.scenario.vmware.api_port}/api/vms"
        try:
            response = httpx.get(url, auth=(username, password), verify=False, timeout=10)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise EnvironmentInventoryError(f"Inventaire vmrest impossible : {exc}") from exc
        raw_items = payload.get("vms", payload) if isinstance(payload, dict) else payload
        if not isinstance(raw_items, list):
            raise EnvironmentInventoryError("vmrest a retourné un inventaire de format inattendu")
        records: list[VmwareVMRecord] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            vmware_id = str(item.get("id") or item.get("vmid") or item.get("uuid") or "").strip()
            if not vmware_id:
                continue
            vmx_path = str(item.get("path") or item.get("vmx_path") or "").strip() or None
            api_name = str(item.get("name") or item.get("displayName") or "").strip()
            # Le VMX est prioritaire car VMREST 1.2.1 peut exposer l'identifiant
            # opaque dans le champ qui ressemble à un nom.
            name = _vmx_friendly_name(vmx_path) or api_name or vmware_id
            records.append(
                VmwareVMRecord(
                    vmware_id=vmware_id,
                    name=name,
                    vmx_path=vmx_path,
                    power_state=item.get("power_state") or item.get("state"),
                    raw=item,
                )
            )
        return tuple(records)

    def inspect_vmnets(self, username: str, password: str) -> tuple[VmnetRecord, ...]:
        """Fusionne l'inventaire VMREST avec les VMnet isolés du registre actif.

        Workstation 17 peut omettre de ``GET /api/vmnet`` un réseau qui n'a
        plus ni serveur DHCP ni adaptateur hôte. Ce cas est précisément celui
        des raccordements Mininet. Le registre ``VMnetLib`` reste alors la
        source active utilisée par l'éditeur de réseau virtuel. Seuls les
        VMnet déjà référencés par le scénario et possédant un sous-réseau,
        un état DHCP et un état d'adaptateur explicites sont fusionnés : les
        emplacements VMware vides ne deviennent jamais des réseaux inventés.
        """

        # L'API Workstation 1.2.1 est volontairement asymétrique : la liste
        # est GET /api/vmnet (singulier), alors que la création est
        # POST /api/vmnets (pluriel). Ne pas normaliser ces deux routes.
        payload = self._vmrest_get("/api/vmnet", username, password)
        raw_items = payload.get("vmnets", []) if isinstance(payload, dict) else []
        try:
            host_connected = self.inspect_host_connected_vmnets()
        except EnvironmentInventoryError:
            # VMREST reste exploitable si PowerShell ne peut pas interroger les
            # cartes. L'état demeure alors inconnu et le plan ne pourra pas
            # prétendre que l'isolation est validée.
            host_connected = None
        records = []
        for item in raw_items:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            canonical_name = _canonical_vmnet_name(str(item["name"]))
            records.append(
                VmnetRecord(
                    name=canonical_name,
                    network_type=str(item.get("type") or "inconnu"),
                    dhcp_enabled=str(item.get("dhcp") or "").casefold() == "true",
                    subnet=str(item.get("subnet")) if item.get("subnet") else None,
                    mask=str(item.get("mask")) if item.get("mask") else None,
                    host_connected=(
                        canonical_name in {
                            _canonical_vmnet_name(name) for name in host_connected
                        }
                        if host_connected is not None
                        else None
                    ),
                )
            )
        observed_names = {record.name for record in records}
        expected_names = self._scenario_vmnet_names()
        for record in self.inspect_locally_registered_vmnets():
            if record.name in expected_names and record.name not in observed_names:
                records.append(record)
                observed_names.add(record.name)
        return tuple(records)

    def _scenario_vmnet_names(self) -> frozenset[str]:
        """Retourne les seuls VMnet physiques que le scénario peut revendiquer."""

        names = {
            "VMnet0",
            self.scenario.vagrant.bootstrap_network,
            self.scenario.vagrant.mininet_internal_network,
            *(target.caldera_vmware_network for target in self.scenario.targets),
            *(
                interface.vmware_network
                for target in self.scenario.targets
                for interface in target.interfaces
            ),
        } - {None, ""}
        return frozenset(_canonical_vmnet_name(str(name)) for name in names)

    @staticmethod
    def inspect_locally_registered_vmnets() -> tuple[VmnetRecord, ...]:
        """Lit sans mutation les VMnet actifs que VMREST omet après isolation.

        ``VMnetConfig`` contient aussi des emplacements numérotés encore
        inutilisés. Un enregistrement local n'est donc recevable que si VMware
        lui a attribué un sous-réseau et a persisté explicitement les deux
        politiques qui nous intéressent : adaptateur hôte et DHCP.
        """

        if os.name != "nt":
            return ()
        try:
            import winreg
        except ImportError:
            return ()

        roots = (
            r"SOFTWARE\WOW6432Node\VMware, Inc.\VMnetLib\VMnetConfig",
            r"SOFTWARE\VMware, Inc.\VMnetLib\VMnetConfig",
        )

        def value(key, name: str):
            try:
                return winreg.QueryValueEx(key, name)[0]
            except OSError:
                return None

        def child_value(parent, child: str, name: str):
            try:
                with winreg.OpenKey(parent, child) as key:
                    return value(key, name)
            except OSError:
                return None

        records: dict[str, VmnetRecord] = {}
        for root_path in roots:
            try:
                root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root_path)
            except OSError:
                continue
            with root:
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    canonical_name = _canonical_vmnet_name(subkey_name)
                    if not re.fullmatch(r"VMnet(?:0|[1-9]|1[0-9])", canonical_name):
                        continue
                    try:
                        vmnet_key = winreg.OpenKey(root, subkey_name)
                    except OSError:
                        continue
                    with vmnet_key:
                        subnet = value(vmnet_key, "IPSubnetAddress")
                        mask = value(vmnet_key, "IPSubnetMask")
                        use_adapter = child_value(vmnet_key, "Adapter", "UseAdapter")
                        adapter_installed = child_value(
                            vmnet_key, "Adapter", "AdapterInstalled"
                        )
                        use_dhcp = child_value(vmnet_key, "DHCP", "UseDHCP")
                        use_nat = child_value(vmnet_key, "NAT", "UseNAT")
                    if (
                        not subnet
                        or use_adapter is None
                        or adapter_installed is None
                        or use_dhcp is None
                    ):
                        continue
                    records[canonical_name] = VmnetRecord(
                        name=canonical_name,
                        network_type="nat" if bool(use_nat) else "hostOnly",
                        dhcp_enabled=bool(use_dhcp),
                        subnet=str(subnet),
                        mask=str(mask) if mask else None,
                        host_connected=bool(use_adapter) and adapter_installed != 0,
                    )
            if records:
                break
        return tuple(
            records[name]
            for name in sorted(
                records,
                key=lambda item: int(item[5:]) if item[5:].isdigit() else 1000,
            )
        )

    @staticmethod
    def inspect_host_connected_vmnets() -> frozenset[str]:
        """Relit les adaptateurs hôte VMware visibles par Windows.

        Dans l'éditeur de réseau virtuel, la case « Connect a host virtual
        adapter to this network » ajoute un adaptateur Windows portant le nom du
        VMnet. Son absence constitue donc la preuve attendue pour afficher
        ``Host Connection = No``.
        """

        script = r"""
$names = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
    $_.Name -match '(?i)VMnet\d+$' -or $_.InterfaceDescription -match '(?i)VMnet\d+$'
} | ForEach-Object {
    $match = [regex]::Match(($_.Name + ' ' + $_.InterfaceDescription), '(?i)VMnet\d+')
    if ($match.Success) { $match.Value }
} | Sort-Object -Unique)
@{ names = $names } | ConvertTo-Json -Compress
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise EnvironmentInventoryError(
                result.stderr.strip() or "Inspection des connexions hôte VMnet impossible"
            )
        try:
            payload = json.loads(result.stdout)
        except ValueError as exc:
            raise EnvironmentInventoryError(
                "Windows a retourné un inventaire d'adaptateurs VMnet illisible"
            ) from exc
        names = payload.get("names") or []
        if isinstance(names, str):
            names = [names]
        return frozenset(str(name) for name in names)

    def disconnect_host_from_vmnets(
        self,
        names: tuple[str, ...],
        *,
        bootstrap_vmnet: str | None,
    ) -> frozenset[str]:
        """Retire uniquement les adaptateurs hôte du plan Mininet confirmé.

        Le réseau virtuel lui-même n'est pas supprimé : seules les cartes
        Windows correspondant à la case « Host Connection » sont retirées.
        VMnet0 et le VMnet d'amorçage sont des barrières absolues.
        """

        unique = tuple(dict.fromkeys(names))
        if len(unique) != len(names):
            raise EnvironmentInventoryError("Le plan d'isolation contient des VMnet dupliqués")
        protected = {"VMnet0", bootstrap_vmnet} - {None, ""}
        forbidden = sorted(set(unique) & protected)
        if forbidden:
            raise EnvironmentInventoryError(
                "Refus de retirer la connexion hôte protégée : " + ", ".join(forbidden)
            )
        for name in unique:
            if not re.fullmatch(r"VMnet(?:[1-9]|1[0-9])", name):
                raise EnvironmentInventoryError(f"VMnet non autorisé dans le plan d'isolation : {name}")

        connected = self.inspect_host_connected_vmnets()
        pending = tuple(name for name in unique if name in connected)
        if not pending:
            return connected
        executable = self._find_vnetlib()
        if executable is None:
            raise EnvironmentInventoryError(
                "vnetlib64.exe est introuvable dans le dossier VMware Workstation"
            )
        self._run_vnetlib_elevated(executable, "remove", pending)
        remaining = self.inspect_host_connected_vmnets()
        failures = sorted(set(unique) & remaining)
        if failures:
            raise EnvironmentInventoryError(
                "Host Connection reste actif après relecture pour : " + ", ".join(failures)
            )
        return remaining

    def connect_host_to_management_vmnets(
        self,
        names: tuple[str, ...],
        *,
        bootstrap_vmnet: str | None,
    ) -> frozenset[str]:
        """Ajoute l'adaptateur hôte uniquement à VMnet0 et à l'amorçage."""

        unique = tuple(dict.fromkeys(names))
        allowed = {"VMnet0", bootstrap_vmnet} - {None, ""}
        forbidden = sorted(set(unique) - allowed)
        if forbidden:
            raise EnvironmentInventoryError(
                "Connexion hôte autorisée uniquement pour VMnet0 et l'amorçage; refus : "
                + ", ".join(forbidden)
            )
        for name in unique:
            if not re.fullmatch(r"VMnet(?:0|[1-9]|1[0-9])", name):
                raise EnvironmentInventoryError(f"VMnet non autorisé : {name}")
        connected = self.inspect_host_connected_vmnets()
        pending = tuple(name for name in unique if name not in connected)
        if not pending:
            return connected
        executable = self._find_vnetlib()
        if executable is None:
            raise EnvironmentInventoryError(
                "vnetlib64.exe est introuvable dans le dossier VMware Workstation"
            )
        self._run_vnetlib_elevated(executable, "add", pending)
        observed = self.inspect_host_connected_vmnets()
        failures = sorted(set(unique) - observed)
        if failures:
            raise EnvironmentInventoryError(
                "Host Connection reste à No après relecture pour : " + ", ".join(failures)
            )
        return observed

    def create_hostonly_vmnets(
        self,
        names: tuple[str, ...],
        username: str,
        password: str,
    ) -> tuple[VmnetRecord, ...]:
        """Crée uniquement les VMnet host-only explicitement planifiés.

        VMware choisit leur sous-réseau hôte. Une relecture complète fait foi;
        aucune adresse, aucun masque et aucun réglage DHCP ne sont inventés par
        l'application.
        """

        if not username or not password:
            raise EnvironmentInventoryError("Les identifiants vmrest sont requis pour créer les VMnet")
        if len(names) != len(set(names)):
            raise EnvironmentInventoryError("Le plan contient des VMnet dupliqués")
        for name in names:
            if not re.fullmatch(r"VMnet(?:[2-9]|1[0-9])", name):
                raise EnvironmentInventoryError(f"Nom de VMnet non autorisé dans ce plan : {name}")
            url = f"https://127.0.0.1:{self.scenario.vmware.api_port}/api/vmnets"
            try:
                response = httpx.post(
                    url,
                    auth=(username, password),
                    verify=False,
                    timeout=15,
                    headers={"Content-Type": "application/vnd.vmware.vmw.rest-v1+json"},
                    # L'API 1.2.1 expose les VMnet en minuscules et refuse sur
                    # certaines versions Windows le nom d'affichage ``VMnetN``.
                    json={"name": name.casefold(), "type": "hostOnly"},
                )
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # Le modèle d'erreur VMware contient souvent la raison précise
                # du 400; la perdre derrière le texte générique ralentit le diagnostic.
                details = exc.response.text.strip()[:1000]
                suffix = f" — VMware : {details}" if details else ""
                raise EnvironmentInventoryError(
                    f"Création de {name} interrompue : {exc}{suffix}"
                ) from exc
            except httpx.HTTPError as exc:
                raise EnvironmentInventoryError(
                    f"Création de {name} interrompue : {exc}"
                ) from exc

        observed = self.inspect_vmnets(username, password)
        by_name = {record.name: record for record in observed}
        missing = [name for name in names if name not in by_name]
        wrong_type = [
            name
            for name in names
            if name in by_name and by_name[name].network_type.casefold() != "hostonly"
        ]
        if missing or wrong_type:
            raise EnvironmentInventoryError(
                f"Relecture VMware incohérente; absents={missing}, mauvais type={wrong_type}"
            )
        return tuple(by_name[name] for name in names)

    def disable_dhcp_on_vmnets(
        self,
        names: tuple[str, ...],
        username: str,
        password: str,
    ) -> tuple[VmnetRecord, ...]:
        """Retire par UAC le DHCP des seuls VMnet d'accès gérés par le plan.

        VMnet0 et VMnet1 sont volontairement exclus de cette opération. La
        relecture vmrest après mutation constitue la preuve; un retour ambigu
        de vnetlib ne suffit jamais à déclarer le DHCP désactivé.
        """

        unique = tuple(dict.fromkeys(names))
        if len(unique) != len(names):
            raise EnvironmentInventoryError("Le plan DHCP contient des VMnet dupliqués")
        for name in unique:
            if not re.fullmatch(r"VMnet(?:[2-9]|1[0-9])", name):
                raise EnvironmentInventoryError(
                    f"Refus de modifier le DHCP du VMnet non géré : {name}"
                )
        if not unique:
            return self.inspect_vmnets(username, password)
        executable = self._find_vnetlib()
        if executable is None:
            raise EnvironmentInventoryError(
                "vnetlib64.exe est introuvable dans le dossier VMware Workstation"
            )
        self._run_vnetlib_elevated(
            executable,
            "remove",
            unique,
            component="dhcp",
        )
        observed = self.inspect_vmnets(username, password)
        by_name = {record.name: record for record in observed}
        failures = [
            name
            for name in unique
            if name not in by_name or by_name[name].dhcp_enabled
        ]
        if failures:
            raise EnvironmentInventoryError(
                "La relecture VMware indique que le DHCP reste actif ou inconnu sur : "
                + ", ".join(failures)
            )
        return tuple(by_name[name] for name in unique)

    def inspect_dhcp_leases(
        self,
        vmnet: str,
        username: str,
        password: str,
    ) -> dict[str, str]:
        """Retourne les baux MAC/IP du seul VMnet explicitement choisi."""

        canonical_vmnet = _canonical_vmnet_name(vmnet or "")
        if not canonical_vmnet or canonical_vmnet.casefold() == "vmnet0":
            raise EnvironmentInventoryError(
                "Les baux DHCP ne peuvent être lus que sur le VMnet d'amorçage distinct de VMnet0"
            )
        if not re.fullmatch(r"VMnet(?:[1-9]|1[0-9])", canonical_vmnet):
            raise EnvironmentInventoryError(f"Nom de VMnet DHCP invalide : {vmnet}")
        # Les noms restent canoniques dans le scénario, mais vmrest 1.2.1
        # attend l'identifiant natif minuscule dans ce segment d'URL.
        native_vmnet = canonical_vmnet.casefold()
        payload = self._vmrest_get(
            f"/api/vmnet/{native_vmnet}/mactoip",
            username,
            password,
        )
        raw_items = payload.get("mactoips", []) if isinstance(payload, dict) else []
        return {
            str(item["mac"]).replace("-", ":").casefold(): str(item["ip"])
            for item in raw_items
            if isinstance(item, dict) and item.get("mac") and item.get("ip")
        }

    def _vmrest_get(self, path: str, username: str, password: str):
        """Centralise les GET vmrest afin de ne jamais confondre inventaire et mutation."""

        if not username or not password:
            raise EnvironmentInventoryError("Les identifiants vmrest sont requis")
        url = f"https://127.0.0.1:{self.scenario.vmware.api_port}{path}"
        try:
            response = httpx.get(url, auth=(username, password), verify=False, timeout=10)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as exc:
            details = exc.response.text.strip()[:1000]
            suffix = f" — VMware : {details}" if details else ""
            raise EnvironmentInventoryError(
                f"Inventaire vmrest impossible : {exc}{suffix}"
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise EnvironmentInventoryError(f"Inventaire vmrest impossible : {exc}") from exc

    def choose_box_file(self, template: str) -> str | None:
        """Retourne immédiatement le chemin choisi sans parcourir l'archive.

        La validation peut prendre plusieurs secondes pour une box compressée de
        grande taille. Elle est volontairement laissée à l'appelant afin que la
        GUI affiche d'abord le chemin, puis un état de validation en arrière-plan.
        """

        selected = self._choose_windows_path(
            f"Choisir la box Vagrant pour {template}",
            folder=False,
            file_filter="Boxes Vagrant (*.box)|*.box|Tous les fichiers (*.*)|*.*",
        )
        return selected

    @staticmethod
    def validate_box_file(file_path: str | Path) -> str:
        """Vérifie que l'archive locale annonce explicitement un fournisseur VMware."""

        path = Path(file_path)
        # Le sélecteur et le validateur partagent le même contrat : seules les
        # archives Vagrant .box destinées à VMware Desktop sont acceptées.
        if path.suffix.casefold() != ".box":
            raise EnvironmentInventoryError("Le fichier choisi doit être une archive Vagrant .box")
        if not path.is_file():
            raise EnvironmentInventoryError(f"Fichier de box introuvable : {path}")
        try:
            stat = path.stat()
            return _cached_box_provider(str(path.resolve()), stat.st_size, stat.st_mtime_ns)
        except EnvironmentInventoryError:
            raise
        except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
            raise EnvironmentInventoryError(f"Impossible de lire les métadonnées de la box : {exc}") from exc

    def choose_clone_directory(self) -> str | None:
        """Choisit le dossier qui recevra exclusivement les nouvelles VM cibles."""

        return self._choose_windows_path("Choisir le répertoire des nouvelles VM", folder=True)

    VAGRANT_VERSION = "2.4.9"
    UTILITY_VERSION = "1.0.24"
    UTILITY_SHA256 = "8ee7bea062d7552a484b7d9ade369744e5cd9ab1b55eed8b7bd35a1b006666d6"

    def installation_commands(self, staged_msi: str = "<MSI_HASHICORP_VERIFIE>") -> tuple[tuple[str, ...], ...]:
        """Retourne le plan d'installation affichable, sans l'exécuter."""

        return (
            (
                "winget",
                "install",
                "--id",
                "Hashicorp.Vagrant",
                "--exact",
                "--version",
                self.VAGRANT_VERSION,
                "--accept-package-agreements",
                "--accept-source-agreements",
            ),
            ("msiexec.exe", "/i", staged_msi, "/passive", "/norestart"),
            ("vagrant", "plugin", "install", "vagrant-vmware-desktop"),
        )

    def installation_confirmation_token(self, staged_msi: str = "<MSI_HASHICORP_VERIFIE>") -> str:
        """Calcule l'empreinte des versions et commandes montrées dans la GUI."""

        payload = json.dumps(self.installation_commands(staged_msi), ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12].upper()

    def install_vagrant_stack(self, staging_directory: str | Path, confirmation_token: str) -> tuple[InstallationResult, ...]:
        """Installe la pile officielle uniquement si son plan exact a été confirmé.

        Le MSI de l'Utility est téléchargé depuis releases.hashicorp.com et son
        SHA-256 est vérifié avant que Windows puisse l'exécuter.
        """

        filename = f"vagrant-vmware-utility_{self.UTILITY_VERSION}_windows_amd64.msi"
        staging = Path(staging_directory)
        installer = staging / filename
        expected = self.installation_confirmation_token(str(installer.resolve()))
        if confirmation_token.strip().upper() != expected:
            raise EnvironmentInventoryError("Le jeton d'installation ne correspond pas au plan affiché")
        staging.mkdir(parents=True, exist_ok=True)
        url = f"https://releases.hashicorp.com/vagrant-vmware-utility/{self.UTILITY_VERSION}/{filename}"
        try:
            with httpx.stream("GET", url, follow_redirects=True, timeout=120) as response:
                response.raise_for_status()
                with installer.open("wb") as stream:
                    for chunk in response.iter_bytes():
                        stream.write(chunk)
        except (OSError, httpx.HTTPError) as exc:
            raise EnvironmentInventoryError(f"Téléchargement de l'Utility impossible : {exc}") from exc
        digest = hashlib.sha256(installer.read_bytes()).hexdigest()
        if digest.casefold() != self.UTILITY_SHA256:
            raise EnvironmentInventoryError(
                f"SHA-256 inattendu pour Vagrant VMware Utility : {digest}; installation annulée"
            )

        commands = list(self.installation_commands(str(installer.resolve())))
        results: list[InstallationResult] = []
        for index, command in enumerate(commands):
            resolved = list(command)
            # winget actualise l'installation système mais pas toujours le PATH du
            # processus NiceGUI courant; le plugin utilise donc le chemin redétecté.
            if index == 2:
                executable = self._find_vagrant()
                if not executable:
                    raise EnvironmentInventoryError("Vagrant reste introuvable après son installation")
                resolved[0] = executable
            result = subprocess.run(
                resolved,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=None,
                check=False,
            )
            results.append(
                InstallationResult(tuple(resolved), result.returncode, result.stdout, result.stderr)
            )
            if result.returncode != 0:
                break
        return tuple(results)

    def address_responds_to_arp(self, address: IPv4Address) -> bool:
        """Utilise SendARP pour ajouter une preuve de conflit avant réservation."""

        if os.name != "nt":
            return False
        destination = int.from_bytes(address.packed, byteorder="little")
        mac = ctypes.create_string_buffer(6)
        length = ctypes.c_ulong(len(mac))
        result = ctypes.windll.Iphlpapi.SendARP(destination, 0, mac, ctypes.byref(length))
        return result == 0 and length.value > 0

    def _find_vagrant(self) -> str | None:
        """Respecte le chemin choisi puis les emplacements Windows usuels."""

        configured = self.scenario.vagrant.executable_path
        candidates = [
            configured,
            shutil.which("vagrant.exe"),
            r"C:\HashiCorp\Vagrant\bin\vagrant.exe",
            r"C:\Program Files\HashiCorp\Vagrant\bin\vagrant.exe",
            r"C:\Program Files\Vagrant\bin\vagrant.exe",
        ]
        return next((str(Path(item)) for item in candidates if item and Path(item).is_file()), None)

    def _find_vnetlib(self) -> str | None:
        """Localise l'outil réseau livré avec VMware Workstation."""

        configured_raw = self.scenario.vmware.workstation_directory
        configured = Path(configured_raw) if configured_raw else None
        candidates = [
            configured / "vnetlib64.exe" if configured else None,
            configured / "vnetlib.exe" if configured else None,
            Path(r"C:\Program Files (x86)\VMware\VMware Workstation\vnetlib64.exe"),
            Path(r"C:\Program Files\VMware\VMware Workstation\vnetlib64.exe"),
        ]
        return next((str(item) for item in candidates if item and item.is_file()), None)

    def _run_vnetlib_elevated(
        self,
        executable: str,
        operation: str,
        names: tuple[str, ...],
        *,
        component: str = "adapter",
    ) -> None:
        """Exécute en une UAC les ajouts ou retraits déjà confirmés dans la GUI.

        Les arguments sont encodés avant leur insertion dans PowerShell. Cette
        étape permet de garder l'application en utilisateur normal tout en
        accordant à VMware les droits requis uniquement pendant la mutation.
        """

        if operation not in {"add", "remove"}:
            raise EnvironmentInventoryError(f"Opération vnetlib non autorisée : {operation}")
        if component not in {"adapter", "dhcp"}:
            raise EnvironmentInventoryError(f"Composant vnetlib non autorisé : {component}")
        if os.name != "nt":
            raise EnvironmentInventoryError("L'élévation vnetlib n'est disponible que sous Windows")

        # Import local : le service d'inventaire reste utilisable sans charger
        # les dépendances de préparation de l'hôte tant qu'aucune mutation n'a lieu.
        from .host_setup import HostSetupError, HostSetupService

        executable_b64 = base64.b64encode(executable.encode("utf-8")).decode("ascii")
        encoded_names = ", ".join(
            # vnetlib documente et attend les identifiants natifs ``vmnetN``;
            # le modèle conserve séparément la forme d'affichage ``VMnetN``.
            f"'{base64.b64encode(name.casefold().encode('utf-8')).decode('ascii')}'"
            for name in names
        )
        script = f"""
$executable = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{executable_b64}'))
$encodedNames = @({encoded_names})
foreach ($encodedName in $encodedNames) {{
    $name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedName))
    $messages = @(& $executable '--' '{operation}' '{component}' $name 2>&1)
    $exitCode = $LASTEXITCODE
    # Certaines versions de vnetlib64 ne publient aucun code de sortie. Null
    # n'est donc pas une preuve d'échec : la relecture Get-NetAdapter qui suit
    # reste l'autorité. Seul un code numérique non nul interrompt l'opération.
    if ($null -ne $exitCode -and $exitCode -ne 0) {{
        $details = (($messages | ForEach-Object {{ $_.ToString() }}) -join [Environment]::NewLine).Trim()
        if (-not $details) {{ $details = 'aucun détail retourné par VMware' }}
        throw "vnetlib {operation} {component} $name a échoué (code $exitCode) : $details"
    }}
}}
"""
        if component == "dhcp":
            action = "Désactivation du DHCP VMware"
        else:
            action = "Ajout" if operation == "add" else "Retrait"
        try:
            HostSetupService(self.scenario.vmware)._run_elevated_powershell(
                script,
                (
                    action
                    if component == "dhcp"
                    else f"{action} des adaptateurs hôte VMware"
                ),
            )
        except HostSetupError as exc:
            raise EnvironmentInventoryError(str(exc)) from exc

    @staticmethod
    def _run_read_only(arguments: list[str]) -> str:
        """Exécute une commande d'inventaire bornée et retourne son texte."""

        result = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
        if result.returncode != 0:
            raise EnvironmentInventoryError(result.stderr.strip() or f"Échec de {' '.join(arguments)}")
        return result.stdout.strip()

    @staticmethod
    def _windows_service_state(name: str) -> str:
        """Lit l'état d'un service sans essayer de le démarrer."""

        script = f"$s=Get-Service -Name '{name}' -ErrorAction SilentlyContinue; if($s){{$s.Status}}else{{'Absent'}}"
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )
        return result.stdout.strip().casefold() or "absent"

    @staticmethod
    def choose_guest_file() -> str | None:
        """Choisit un fichier local destiné à être copié dans un OS invité."""

        return VagrantEnvironmentService._choose_windows_path(
            "Choisir le fichier à déposer dans la VM",
            folder=False,
            file_filter="Tous les fichiers (*.*)|*.*",
        )

    @staticmethod
    def choose_scenario_file() -> str | None:
        """Ouvre le sélecteur Windows limité aux sauvegardes YAML de scénario."""

        return VagrantEnvironmentService._choose_windows_path(
            "Charger une sauvegarde de scénario CyGIL",
            folder=False,
            file_filter="Scénarios YAML (*.yml;*.yaml)|*.yml;*.yaml|Tous les fichiers (*.*)|*.*",
        )

    @staticmethod
    def _choose_windows_path(title: str, *, folder: bool, file_filter: str = "") -> str | None:
        """Ouvre un dialogue STA en encodant les libellés pour éviter l'injection."""

        title_b64 = base64.b64encode(title.encode("utf-8")).decode("ascii")
        filter_b64 = base64.b64encode(file_filter.encode("utf-8")).decode("ascii")
        if folder:
            body = "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog\n$dialog.Description = $title"
        else:
            body = (
                "$dialog = New-Object System.Windows.Forms.OpenFileDialog\n"
                "$dialog.Title = $title\n"
                "$dialog.Filter = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
                + filter_b64
                + "'))\n$dialog.CheckFileExists = $true\n$dialog.Multiselect = $false"
            )
        selected_property = "SelectedPath" if folder else "FileName"
        script = f"""
Add-Type -AssemblyName System.Windows.Forms
$title = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{title_b64}'))
{body}
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $dialog.{selected_property}
}}
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise EnvironmentInventoryError(result.stderr.strip() or "Impossible d'ouvrir le sélecteur")
        selected = result.stdout.strip()
        if not selected:
            return None
        path = Path(selected)
        if folder and not path.is_dir():
            raise EnvironmentInventoryError("Le répertoire choisi n'existe pas")
        if not folder and not path.is_file():
            raise EnvironmentInventoryError("Le fichier choisi n'existe pas")
        return str(path.resolve())
