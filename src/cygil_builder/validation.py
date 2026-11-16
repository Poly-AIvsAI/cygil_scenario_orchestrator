"""Validation métier globale du scénario avant planification ou compilation."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address, ip_interface, ip_network
from pathlib import Path

from .models import GuestNetworkBackend, InfrastructureRole, InterfacePurpose, LinkScope, ObjectiveType, OSFamily, Scenario
from .lab_topology import VMWARE_MAX_NICS, permanent_network_expectations
from .topology import canonical_switch_pair, iter_switch_links, switch_owners
from .vmware_network import VmwareNetworkError, normalize_mac


@dataclass(frozen=True)
class ValidationIssue:
    """Erreur ou avertissement localisé dans le modèle canonique."""

    level: str
    code: str
    message: str
    path: str = ""


@dataclass
class ValidationResult:
    """Résultat filtrable retourné à la CLI et aux panneaux dynamiques."""

    issues: list[ValidationIssue]

    @property
    def errors(self) -> list[ValidationIssue]:
        """Retourne uniquement les problèmes qui bloquent le déploiement."""

        return [issue for issue in self.issues if issue.level == "error"]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Retourne les problèmes non bloquants mais utiles à l'utilisateur."""

        return [issue for issue in self.issues if issue.level == "warning"]

    @property
    def is_valid(self) -> bool:
        """Indique si aucune erreur bloquante n'a été détectée."""

        return not self.errors


def validate_scenario(scenario: Scenario) -> ValidationResult:
    """Contrôle les réseaux, toutes les interfaces et les références croisées."""

    issues: list[ValidationIssue] = []
    network_by_id = {}
    parsed_networks = {}

    # region Sous-réseaux et instances Mininet
    for index, network in enumerate(scenario.networks):
        path = f"networks[{index}]"
        if network.id in network_by_id:
            issues.append(ValidationIssue("error", "network.duplicate_id", f"Réseau dupliqué : {network.id}", path))
            continue
        network_by_id[network.id] = network
        parsed = None
        if network.cidr:
            try:
                parsed = ip_network(network.cidr, strict=True)
                parsed_networks[network.id] = parsed
            except ValueError as exc:
                issues.append(ValidationIssue("error", "network.invalid_cidr", str(exc), f"{path}.cidr"))
                continue
        if not network.subnet_label and not network.cidr:
            issues.append(ValidationIssue("error", "network.missing_subnet", f"Le segment {network.id} exige subnet_label ou cidr", path))
        if network.gateway:
            try:
                gateway = ip_address(network.gateway)
                if parsed and gateway not in parsed:
                    issues.append(ValidationIssue("error", "network.gateway_outside", f"La passerelle {gateway} n'appartient pas à {parsed}", f"{path}.gateway"))
            except ValueError:
                issues.append(ValidationIssue("error", "network.invalid_gateway", f"Passerelle invalide : {network.gateway}", f"{path}.gateway"))

    network_items = list(parsed_networks.items())
    for left_index, (left_name, left) in enumerate(network_items):
        for right_name, right in network_items[left_index + 1:]:
            if left.overlaps(right):
                issues.append(ValidationIssue("error", "network.overlap", f"Les réseaux {left_name} ({left}) et {right_name} ({right}) se chevauchent"))

    if any(network.vmware_network for network in scenario.networks):
        issues.append(
            ValidationIssue(
                "warning",
                "network.legacy_vmnet_mapping",
                "Les correspondances réseau → VMnet sont obsolètes; chaque raccordement cible possède désormais son VMnet dédié",
                "networks",
            )
        )

    mininet_names = [instance.name for instance in scenario.mininet_instances]
    mininet_set = set(mininet_names)
    if not mininet_names:
        issues.append(ValidationIssue("error", "mininet.missing", "Au moins une instance Mininet est requise", "mininet_instances"))
    if len(mininet_names) != len(mininet_set):
        issues.append(ValidationIssue("error", "mininet.duplicate", "Les noms d'instances Mininet doivent être uniques"))

    # Chaque section Mininet du YAML doit correspondre à une VM VMware distincte.
    # Cette association permet d'en gérer plusieurs sans relâcher l'unicité de
    # CYGIL, CALDERA et ONOS.
    infrastructure_by_id = {machine.id: machine for machine in scenario.infrastructure}
    onos_vms = [
        machine
        for machine in scenario.infrastructure
        if machine.role == InfrastructureRole.ONOS
    ]
    if len(onos_vms) != 1:
        issues.append(
            ValidationIssue(
                "error",
                "infrastructure.onos_count",
                "L'architecture doit contenir exactement une VM ONOS",
                "infrastructure",
            )
        )
    mininet_vm_ids = {machine.id for machine in scenario.infrastructure if machine.role == InfrastructureRole.MININET}
    mapped_vm_ids: list[str] = []
    external_ips: set[str] = set()
    internal_ips: set[str] = set()
    for index, instance in enumerate(scenario.mininet_instances):
        path = f"mininet_instances[{index}]"
        for field_name, raw_address, known_addresses in (
            ("external_ip", instance.external_ip, external_ips),
            ("internal_ip", instance.internal_ip, internal_ips),
        ):
            if not raw_address:
                issues.append(
                    ValidationIssue(
                        "error",
                        "mininet.address_unallocated",
                        f"L'adresse {field_name} de la VM associée à {instance.name} n'a pas encore été allouée",
                        f"{path}.{field_name}",
                    )
                )
                continue
            try:
                parsed_address = str(ip_address(raw_address))
                if parsed_address in known_addresses:
                    issues.append(ValidationIssue("error", "mininet.duplicate_ip", f"Adresse Mininet dupliquée : {parsed_address}", f"{path}.{field_name}"))
                known_addresses.add(parsed_address)
            except (TypeError, ValueError):
                issues.append(ValidationIssue("error", "mininet.invalid_ip", f"Adresse Mininet invalide : {raw_address}", f"{path}.{field_name}"))

        vm_id = instance.infrastructure_vm_id
        if not vm_id:
            issues.append(ValidationIssue("error", "mininet.vm_missing", f"L'instance {instance.name} n'est associée à aucune VM Mininet", path))
            continue
        mapped_vm_ids.append(vm_id)
        machine = infrastructure_by_id.get(vm_id)
        if machine is None:
            issues.append(ValidationIssue("error", "mininet.vm_unknown", f"VM Mininet inconnue : {vm_id}", f"{path}.infrastructure_vm_id"))
            continue
        if machine.role not in {InfrastructureRole.MININET, InfrastructureRole.ONOS}:
            issues.append(ValidationIssue("error", "mininet.vm_wrong_role", f"La VM {vm_id} n'héberge ni Mininet ni ONOS/Mininet", f"{path}.infrastructure_vm_id"))

    if len(mapped_vm_ids) != len(set(mapped_vm_ids)):
        issues.append(ValidationIssue("error", "mininet.vm_reused", "Une VM Mininet ne peut héberger qu'une seule instance déclarée"))
    for vm_id in sorted(mininet_vm_ids - set(mapped_vm_ids)):
        issues.append(ValidationIssue("error", "mininet.vm_unmapped", f"La VM Mininet {vm_id} n'est associée à aucune instance"))

    internal_network = scenario.vagrant.mininet_internal_cidr
    internal_vmnet = scenario.vagrant.mininet_internal_network
    if scenario.mininet_instances and not internal_vmnet:
        issues.append(
            ValidationIssue(
                "warning",
                "mininet.internal_vmnet_missing",
                "Le VMnet interne Mininet/ONOS doit être choisi depuis l'inventaire VMware",
                "vagrant.mininet_internal_network",
            )
        )
    if scenario.mininet_instances and internal_network is None:
        issues.append(
            ValidationIssue(
                "warning",
                "mininet.internal_cidr_missing",
                "Le CIDR interne Mininet/ONOS doit être observé depuis VMware",
                "vagrant.mininet_internal_cidr",
            )
        )
    if (internal_vmnet or "").casefold() == "vmnet0" or (
        internal_vmnet
        and scenario.vagrant.bootstrap_network
        and internal_vmnet.casefold() == scenario.vagrant.bootstrap_network.casefold()
    ):
        issues.append(
            ValidationIssue(
                "error",
                "mininet.internal_vmnet_collision",
                "Le VMnet interne doit être distinct de VMnet0 et du VMnet d'amorçage",
                "vagrant.mininet_internal_network",
            )
        )
    if internal_network is not None:
        for logical_name, logical_network in parsed_networks.items():
            if internal_network.version == logical_network.version and internal_network.overlaps(logical_network):
                issues.append(
                    ValidationIssue(
                        "error",
                        "mininet.internal_network_overlap",
                        f"Le réseau de contrôle {internal_network} chevauche {logical_name} ({logical_network})",
                        "vagrant.mininet_internal_cidr",
                    )
                )

    if internal_vmnet and internal_network is not None:
        internal_participants = []
        for instance in scenario.mininet_instances:
            machine = infrastructure_by_id.get(instance.infrastructure_vm_id or "")
            if machine is not None:
                internal_participants.append((machine, instance.internal_ip))
        for machine, raw_address in internal_participants:
            try:
                address = ip_address(raw_address or "")
            except ValueError:
                continue  # L'erreur d'adresse Mininet est déjà émise plus haut.
            if address not in internal_network:
                issues.append(ValidationIssue("error", "mininet.internal_address_outside", f"{address} n'appartient pas au réseau de contrôle {internal_network}", f"infrastructure[{machine.id}].internal_ip"))
                continue
            matching = []
            for interface in machine.interfaces:
                try:
                    interface_address = ip_interface(interface.address).ip
                except ValueError:
                    continue
                if interface.vmware_network == internal_vmnet and interface_address == address:
                    matching.append(interface)
            if len(matching) != 1:
                issues.append(ValidationIssue("error", "mininet.internal_interface_mismatch", f"{machine.id} doit avoir exactement une carte {internal_vmnet} portant {address}", f"infrastructure[{machine.id}].interfaces"))
    switch_names = [switch.name for switch in scenario.switches]
    switch_set = set(switch_names)
    if len(switch_names) != len(switch_set):
        issues.append(ValidationIssue("error", "switch.duplicate", "Les noms de switches doivent être uniques dans toute la topologie"))
    for index, switch in enumerate(scenario.switches):
        if switch.mininet_instance not in mininet_set:
            issues.append(ValidationIssue("error", "switch.unknown_mininet", f"Le switch {switch.name} référence l'instance inconnue {switch.mininet_instance}", f"switches[{index}]"))

    # Les liens OVS/GRE sont bidirectionnels : une déclaration inverse est le
    # même lien et doit être refusée comme doublon.
    owners = switch_owners(scenario)
    declared_pairs: set[tuple[str, str]] = set()
    for instance, source, destination in iter_switch_links(scenario):
        path = f"mininet_instances[{instance.name}].switch_links.{source}"
        if source not in owners:
            issues.append(ValidationIssue("error", "switch_link.unknown_source", f"Switch source inconnu : {source}", path))
        elif owners[source] != instance.name:
            issues.append(ValidationIssue("error", "switch_link.wrong_instance", f"Le switch {source} appartient à {owners[source]}, pas à {instance.name}", path))
        if destination not in owners:
            issues.append(ValidationIssue("error", "switch_link.unknown_destination", f"Switch destination inconnu : {destination}", path))
        if source == destination:
            issues.append(ValidationIssue("error", "switch_link.self_link", f"Le switch {source} ne peut pas être relié à lui-même", path))
            continue

        pair = canonical_switch_pair(source, destination)
        if pair in declared_pairs:
            issues.append(ValidationIssue("error", "switch_link.duplicate", f"Le lien {source} ↔ {destination} est déclaré plusieurs fois", path))
        declared_pairs.add(pair)
    # endregion

    # region Identités et interfaces multiples
    target_ids = {target.id for target in scenario.targets}
    infra_ids = {machine.id for machine in scenario.infrastructure}
    all_hosts = target_ids | infra_ids
    if len(target_ids) != len(scenario.targets):
        issues.append(ValidationIssue("error", "target.duplicate", "Les identifiants de VM cibles doivent être uniques"))
    if len(infra_ids) != len(scenario.infrastructure):
        issues.append(ValidationIssue("error", "infrastructure.duplicate", "Les identifiants de VM d'infrastructure doivent être uniques"))
    if target_ids & infra_ids:
        issues.append(ValidationIssue("error", "machine.id_collision", f"Identifiants partagés : {sorted(target_ids & infra_ids)}"))

    addresses: dict[str, str] = {}
    requested_macs: dict[str, str] = {}

    def validate_interfaces(machine_id: str, interfaces, base_path: str, require_scenario_network: bool) -> None:
        """Valide une liste d'interfaces et détecte les IP dupliquées globalement."""

        interface_names: set[str] = set()
        for index, interface in enumerate(interfaces):
            path = f"{base_path}.interfaces[{index}]"
            # Une carte allouée avant sa relecture dans l'invité n'a pas encore
            # de nom OS. Plusieurs noms vides ne constituent donc pas un conflit;
            # ils seront remplacés par les noms observés avant configuration.
            if interface.name and interface.name in interface_names:
                issues.append(ValidationIssue("error", "interface.duplicate_name", f"Interface {interface.name} dupliquée sur {machine_id}", path))
            if interface.name:
                interface_names.add(interface.name)
            if interface.mac:
                try:
                    normalized_mac = normalize_mac(interface.mac)
                    owner = requested_macs.get(normalized_mac)
                    if owner and owner != machine_id:
                        issues.append(ValidationIssue("error", "mac.duplicate", f"MAC {normalized_mac} demandée par {owner} et {machine_id}", f"{path}.mac"))
                    requested_macs[normalized_mac] = machine_id
                except VmwareNetworkError as exc:
                    issues.append(ValidationIssue("error", "mac.invalid", str(exc), f"{path}.mac"))
            try:
                parsed_interface = ip_interface(interface.address)
                address_key = str(parsed_interface.ip)
                if address_key in addresses:
                    issues.append(ValidationIssue("error", "interface.duplicate_address", f"Adresse {address_key} utilisée par {addresses[address_key]} et {machine_id}", f"{path}.address"))
                addresses[address_key] = machine_id
            except ValueError:
                issues.append(ValidationIssue("error", "interface.invalid_address", f"Adresse invalide : {interface.address}", f"{path}.address"))
                continue
            if interface.gateway:
                try:
                    gateway = ip_address(interface.gateway)
                    if gateway not in parsed_interface.network:
                        issues.append(ValidationIssue("error", "interface.gateway_outside", f"La passerelle {gateway} n'appartient pas à {parsed_interface.network}", f"{path}.gateway"))
                except ValueError:
                    issues.append(ValidationIssue("error", "interface.invalid_gateway", f"Passerelle invalide : {interface.gateway}", f"{path}.gateway"))

            is_scenario = interface.purpose == InterfacePurpose.SCENARIO or require_scenario_network
            if not is_scenario:
                continue
            if not interface.network or interface.network not in network_by_id:
                issues.append(ValidationIssue("error", "interface.unknown_network", f"Réseau inconnu : {interface.network}", path))
                continue
            if interface.mininet_instance not in mininet_set:
                issues.append(ValidationIssue("error", "interface.unknown_mininet", f"Instance Mininet inconnue : {interface.mininet_instance}", path))
            if interface.connected_switch not in switch_set:
                issues.append(ValidationIssue("error", "interface.unknown_switch", f"Commutateur inconnu : {interface.connected_switch}", path))
            else:
                expected_scope = (
                    LinkScope.LOCAL
                    if owners.get(interface.connected_switch) == interface.mininet_instance
                    else LinkScope.REMOTE
                )
                if interface.scope != expected_scope:
                    issues.append(ValidationIssue("error", "interface.scope_mismatch", f"La portée de {interface.name} doit être {expected_scope.value}", path))
            expected_network = parsed_networks.get(interface.network)
            if expected_network and parsed_interface.ip not in expected_network:
                issues.append(ValidationIssue("error", "interface.address_outside", f"L'adresse {parsed_interface.ip} de {machine_id} n'appartient pas à {expected_network}", f"{path}.address"))

    checked_box_templates: set[str] = set()
    scenario_vmnet_owners: dict[str, str] = {}
    for index, target in enumerate(scenario.targets):
        scenario_interfaces = [
            interface
            for interface in target.interfaces
            if interface.purpose == InterfacePurpose.SCENARIO
        ]
        if len(scenario_interfaces) != 1:
            issues.append(
                ValidationIssue(
                    "error",
                    "target.scenario_interface_count",
                    f"La cible {target.id} doit avoir exactement une interface d'accès au switch",
                    f"targets[{index}].interfaces",
                )
            )
        management = target.temporary_management
        if management.enabled and not management.vmware_network.strip():
            issues.append(ValidationIssue("warning", "bootstrap.network_missing", f"La cible {target.id} n'a pas encore de réseau d'amorçage temporaire", f"targets[{index}].temporary_management"))
        if (
            management.enabled
            and scenario.vagrant.bootstrap_network
            and management.vmware_network != scenario.vagrant.bootstrap_network
        ):
            issues.append(ValidationIssue("error", "bootstrap.target_network_mismatch", f"La cible {target.id} doit utiliser le VMnet d'amorçage choisi", f"targets[{index}].temporary_management.vmware_network"))
        if management.enabled and target.snapshot and not management.detach_before_snapshot:
            issues.append(ValidationIssue("error", "management.air_gap_required", f"L'interface de gestion temporaire de {target.id} doit être désactivée dans l'OS invité avant le snapshot", f"targets[{index}].temporary_management"))
        if management.enabled and management.assigned_address:
            address_key = str(management.assigned_address.ip)
            if address_key in addresses:
                issues.append(ValidationIssue("error", "management.duplicate_address", f"Adresse de gestion {address_key} déjà utilisée par {addresses[address_key]}", f"targets[{index}].temporary_management.assigned_address"))
            addresses[address_key] = target.id
        if scenario.vagrant.enabled and not target.guest_access:
            issues.append(ValidationIssue("warning", "vagrant.guest_access_missing", f"SSH ou WinRM doit être confirmé pour la box de {target.id}", f"targets[{index}].guest_access"))
        if (
            scenario.vagrant.enabled
            and target.template not in checked_box_templates
            and not scenario.vagrant.box_paths.get(target.template)
        ):
            issues.append(ValidationIssue("warning", "vagrant.box_path_missing", f"Aucun fichier .box choisi pour {target.template}", f"vagrant.box_paths.{target.template}"))
        checked_box_templates.add(target.template)
        adapter_indices: set[int] = set()
        reserved_adapter_indices = (
            {0} if management.enabled and scenario.vagrant.bootstrap_network else set()
        )
        for interface_index, interface in enumerate(target.interfaces):
            if (
                interface.purpose == InterfacePurpose.SCENARIO
                and interface.connected_switch in owners
                and interface.mininet_instance != owners[interface.connected_switch]
            ):
                issues.append(
                    ValidationIssue(
                        "error",
                        "target.remote_switch_forbidden",
                        f"La cible {target.id} doit appartenir à l'instance qui héberge {interface.connected_switch}",
                        f"targets[{index}].interfaces[{interface_index}]",
                    )
                )
            if interface.purpose == InterfacePurpose.SCENARIO and interface.vmware_network:
                owner = scenario_vmnet_owners.get(interface.vmware_network)
                current_owner = f"{target.id}/{interface.name or interface_index}"
                if interface.vmware_network in {
                    "VMnet0",
                    scenario.vagrant.bootstrap_network,
                    scenario.vagrant.mininet_internal_network,
                }:
                    issues.append(ValidationIssue("error", "vmware.attachment_reserved_vmnet", f"{current_owner} utilise le VMnet réservé {interface.vmware_network}", f"targets[{index}].interfaces[{interface_index}].vmware_network"))
                if owner and owner != current_owner:
                    issues.append(ValidationIssue("error", "vmware.attachment_vmnet_reused", f"{interface.vmware_network} relie à la fois {owner} et {current_owner}; chaque raccordement exige un VMnet dédié", f"targets[{index}].interfaces[{interface_index}].vmware_network"))
                scenario_vmnet_owners[interface.vmware_network] = current_owner
            if interface.vmware_adapter_index is not None:
                if interface.vmware_adapter_index in reserved_adapter_indices:
                    issues.append(ValidationIssue("error", "vmware.management_index_collision", f"L'indice VMware {interface.vmware_adapter_index} de {target.id} est réservé à une interface temporaire", f"targets[{index}].interfaces[{interface_index}].vmware_adapter_index"))
                if interface.vmware_adapter_index in adapter_indices:
                    issues.append(ValidationIssue("error", "vmware.adapter_index_duplicate", f"Indice VMware {interface.vmware_adapter_index} dupliqué sur {target.id}", f"targets[{index}].interfaces[{interface_index}]"))
                adapter_indices.add(interface.vmware_adapter_index)
            if scenario.vagrant.enabled and interface.purpose == InterfacePurpose.SCENARIO and not interface.vmware_network:
                issues.append(ValidationIssue("warning", "vmware.network_mapping_missing", f"Le VMnet correspondant à {target.id}/{interface.name} n'est pas encore confirmé", f"targets[{index}].interfaces[{interface_index}].vmware_network"))
        validate_interfaces(target.id, target.interfaces, f"targets[{index}]", False)

    for index, machine in enumerate(scenario.infrastructure):
        # Le nombre de cartes réservées est désormais dérivé du rôle et
        # de la topologie; une liste vide n'impose donc plus une saisie manuelle.
        if machine.guest_access and not machine.os_family:
            issues.append(ValidationIssue("error", "infrastructure.os_missing", f"L'OS de {machine.id} est requis pour exécuter des commandes invitées", f"infrastructure[{index}].os_family"))
        validate_interfaces(machine.id, machine.interfaces, f"infrastructure[{index}]", False)
        if machine.role == InfrastructureRole.CYGIL and any(
            interface.purpose != InterfacePurpose.MANAGEMENT
            for interface in machine.interfaces
        ):
            issues.append(
                ValidationIssue(
                    "error",
                    "cygil.non_management_interface",
                    "CyGIL doit rester exclusivement connecté à VMnet0",
                    f"infrastructure[{index}].interfaces",
                )
            )

    # Ces attentes sont dérivées des rôles et des hands. Elles restent des
    # avertissements tant que les VMnet réels n'ont pas été associés dans la GUI.
    expectations = permanent_network_expectations(scenario)
    for index, machine in enumerate(scenario.infrastructure):
        expectation = expectations[machine.id]
        declared = {
            interface.vmware_network or interface.network
            for interface in machine.interfaces
            if interface.vmware_network or interface.network
        }
        if any(interface.purpose == InterfacePurpose.MANAGEMENT for interface in machine.interfaces):
            declared.add("VMnet0")
        missing = expectation.required_networks - declared
        if missing:
            issues.append(ValidationIssue("warning", "infrastructure.networks_missing", f"Réseaux permanents à confirmer pour {machine.id} : {sorted(missing)}", f"infrastructure[{index}].interfaces"))
        expected_count = len(expectation.required_networks)
        if (
            scenario.vagrant.bootstrap_network
            and scenario.vagrant.bootstrap_network not in expectation.required_networks
        ):
            expected_count += 1
        if expected_count > VMWARE_MAX_NICS:
            issues.append(
                ValidationIssue(
                    "error",
                    "vmware.adapter_capacity_exceeded",
                    f"{machine.id} exige {expected_count} cartes VMware, au-delà de la limite prise en charge de {VMWARE_MAX_NICS}; répartissez les raccordements sur une autre instance Mininet",
                    f"infrastructure[{index}]",
                )
            )
    # endregion

    # region Infrastructure, ONOS, hands et récompenses
    required_roles = set(InfrastructureRole)
    actual_roles = {machine.role for machine in scenario.infrastructure}
    for missing_role in sorted(required_roles - actual_roles):
        # ONOS possède un diagnostic unique et plus précis ci-dessus afin de
        # couvrir aussi bien l'absence que les doublons.
        if missing_role == InfrastructureRole.ONOS:
            continue
        issues.append(ValidationIssue("error", "infrastructure.missing_role", f"VM d'infrastructure manquante : {missing_role.value}"))

    for index, intent in enumerate(scenario.onos_intents):
        for field_name, host in (("host_one", intent.host_one), ("host_two", intent.host_two)):
            if host not in all_hosts:
                issues.append(ValidationIssue("error", "onos.unknown_host", f"L'intention ONOS référence l'hôte inconnu {host}", f"onos_intents[{index}].{field_name}"))
        if intent.host_one == intent.host_two:
            issues.append(ValidationIssue("error", "onos.self_intent", "Une intention ONOS doit relier deux hôtes distincts", f"onos_intents[{index}]"))

    action_ids = [ability.action_id for ability in scenario.command_center.abilities]
    ability_ids = [ability.ability_id for ability in scenario.command_center.abilities]
    if len(action_ids) != len(set(action_ids)):
        issues.append(ValidationIssue("error", "command_center.duplicate_action", "Les action_id doivent être uniques"))
    if len(ability_ids) != len(set(ability_ids)):
        issues.append(ValidationIssue("warning", "command_center.duplicate_ability", "Une ability CALDERA est associée à plusieurs actions"))

    for index, target in enumerate(scenario.targets):
        if target.target_file_path and not target.target_file_source_path:
            issues.append(ValidationIssue("warning", "target_file.source_missing", f"Le fichier cible de {target.id} n'a pas encore de source locale à transférer", f"targets[{index}].target_file_source_path"))
        if target.target_file_source_path and not Path(target.target_file_source_path).is_file():
            issues.append(ValidationIssue("error", "target_file.source_not_found", f"Le fichier source de {target.id} est introuvable", f"targets[{index}].target_file_source_path"))
        for file_index, deployment_file in enumerate(target.guest_files):
            if not Path(deployment_file.source_path).is_file():
                issues.append(ValidationIssue("error", "guest_file.source_not_found", f"Le fichier source de {target.id} est introuvable : {deployment_file.source_path}", f"targets[{index}].guest_files[{file_index}].source_path"))
        if target.hand.enabled and not target.hand.generated_command:
            issues.append(ValidationIssue("warning", "hand.command_missing", f"Le hand de {target.id} est activé mais sa commande n'est pas encore générée", f"targets[{index}].hand"))

    compromised = [target for target in scenario.targets if target.compromised]
    if len(compromised) != 1:
        issues.append(
            ValidationIssue(
                "error",
                "target.compromised_count",
                "Le scénario doit contenir exactement une cible compromise",
                "targets",
            )
        )
    for index, target in enumerate(scenario.targets):
        if target.hand.enabled != target.compromised or target.initial_red_hand != target.compromised:
            issues.append(
                ValidationIssue(
                    "error",
                    "target.compromised_state_mismatch",
                    f"L'état compromis, le hand et le hand initial divergent pour {target.id}",
                    f"targets[{index}]",
                )
            )
    if len(compromised) == 1:
        target = compromised[0]
        caldera = next(
            (machine for machine in scenario.infrastructure if machine.role == InfrastructureRole.CALDERA),
            None,
        )
        caldera_interfaces = [
            interface
            for interface in (caldera.interfaces if caldera else [])
            if interface.purpose == InterfacePurpose.SCENARIO
        ]
        if len(caldera_interfaces) != 1:
            issues.append(
                ValidationIssue(
                    "error",
                    "caldera.scenario_interface_count",
                    "CALDERA doit posséder exactement une interface vers la VM Mininet de la cible compromise",
                    "infrastructure",
                )
            )
        else:
            target_interface = next(
                (
                    interface
                    for interface in target.interfaces
                    if interface.purpose == InterfacePurpose.SCENARIO
                ),
                None,
            )
            caldera_interface = caldera_interfaces[0]
            if not caldera_interface.name:
                issues.append(
                    ValidationIssue(
                        "warning",
                        "caldera.interface_name_pending",
                        "Le nom invité de l'interface CALDERA sera requis après sa découverte par MAC",
                        "infrastructure",
                    )
                )
            if target_interface and (
                caldera_interface.network != target_interface.network
                or caldera_interface.mininet_instance != target_interface.mininet_instance
                or caldera_interface.connected_switch != target_interface.connected_switch
                or caldera_interface.scope != LinkScope.LOCAL
            ):
                issues.append(
                    ValidationIssue(
                        "error",
                        "caldera.topology_mismatch",
                        "L'accès CALDERA doit rejoindre le même switch local, le même réseau logique et la même instance Mininet que la cible compromise",
                        "infrastructure",
                    )
                )
        access_vmnet = next(
            (
                interface.vmware_network
                for interface in target.interfaces
                if interface.purpose == InterfacePurpose.SCENARIO
            ),
            None,
        )
        if target.caldera_vmware_network and target.caldera_vmware_network in {
            access_vmnet,
            "VMnet0",
            scenario.vagrant.bootstrap_network,
            scenario.vagrant.mininet_internal_network,
        }:
            issues.append(
                ValidationIssue(
                    "error",
                    "caldera.vmnet_not_dedicated",
                    "Le lien CALDERA-Mininet doit utiliser un VMnet dédié distinct de l'accès cible",
                    f"targets[{scenario.targets.index(target)}].caldera_vmware_network",
                )
            )
        if scenario.vagrant.enabled and not target.caldera_vmware_network:
            issues.append(
                ValidationIssue(
                    "warning",
                    "caldera.vmnet_mapping_missing",
                    "Le VMnet CALDERA-Mininet n'est pas encore calculé",
                    f"targets[{scenario.targets.index(target)}].caldera_vmware_network",
                )
            )

    for kind, machines in (("infrastructure", scenario.infrastructure), ("targets", scenario.targets)):
        for index, machine in enumerate(machines):
            path = f"{kind}[{index}]"
            scenario_interfaces = [
                interface
                for interface in machine.interfaces
                if interface.purpose == InterfacePurpose.SCENARIO
            ]
            if scenario_interfaces and machine.guest_access and not machine.network_backend:
                issues.append(ValidationIssue("warning", "guest_network.backend_missing", f"Backend réseau invité à confirmer pour {machine.id}", f"{path}.network_backend"))
            if machine.network_backend == GuestNetworkBackend.WINDOWS_POWERSHELL and machine.os_family != OSFamily.WINDOWS:
                issues.append(ValidationIssue("error", "guest_network.backend_os_mismatch", f"Le backend Windows ne correspond pas à l'OS de {machine.id}", f"{path}.network_backend"))
            if machine.network_backend in {GuestNetworkBackend.LINUX_NMCLI, GuestNetworkBackend.LINUX_NETPLAN} and machine.os_family != OSFamily.LINUX:
                issues.append(ValidationIssue("error", "guest_network.backend_os_mismatch", f"Le backend Linux ne correspond pas à l'OS de {machine.id}", f"{path}.network_backend"))
            isolation_networks: set[str] = set()
            for isolation_index, interface in enumerate(machine.isolation_interfaces):
                interface_path = f"{path}.isolation_interfaces[{isolation_index}]"
                if interface.network in isolation_networks:
                    issues.append(ValidationIssue("error", "isolation.duplicate_network", f"Plusieurs interfaces d'isolation {interface.network} sont déclarées sur {machine.id}", interface_path))
                isolation_networks.add(interface.network)
                if interface.disable_before_snapshot and not interface.guest_name:
                    issues.append(ValidationIssue("error", "isolation.guest_name_missing", f"Le nom invité de {interface.network} est requis sur {machine.id}", interface_path))
                if interface.disable_before_snapshot and not interface.mac:
                    issues.append(ValidationIssue("warning", "isolation.mac_missing", f"La MAC de {interface.network} devrait être confirmée sur {machine.id}", interface_path))

    for index, objective in enumerate(scenario.reward.objectives):
        path = f"reward.objectives[{index}]"
        if objective.type == ObjectiveType.HAND_ON_HOST:
            if not objective.host_name or objective.host_name not in all_hosts:
                issues.append(ValidationIssue("error", "reward.unknown_host", f"Objectif hand_on_host sans hôte valide : {objective.host_name}", path))
            if not objective.privilege:
                issues.append(ValidationIssue("error", "reward.missing_privilege", "Le privilège est requis pour hand_on_host", path))
        elif objective.type == ObjectiveType.FILE_EXFILTRATION:
            if not objective.file_path or objective.host_name not in all_hosts:
                issues.append(ValidationIssue("error", "reward.incomplete_file", "file_exfiltration exige un chemin et un hôte valides", path))
        elif objective.type == ObjectiveType.TRAIT_VALUE_PAIR and (not objective.trait or objective.value is None):
            issues.append(ValidationIssue("error", "reward.incomplete_trait", "trait_value_pair exige trait et value", path))
    # endregion

    if not scenario.vmware.snapshot_name.strip():
        issues.append(ValidationIssue("error", "snapshot.missing_name", "Le nom de snapshot est requis", "vmware.snapshot_name"))
    if scenario.lab_control.snapshot_with_memory is None:
        issues.append(ValidationIssue("warning", "snapshot.memory_choice_missing", "Confirmez si les snapshots doivent inclure la mémoire; vmrun 1.17 ne fournit pas cette option", "lab_control.snapshot_with_memory"))
    if not scenario.cygil_runtime.launch_commands:
        issues.append(ValidationIssue("warning", "cygil.no_launch_command", "Aucune commande CyGIL n'est encore configurée", "cygil_runtime.launch_commands"))
    if scenario.vagrant.enabled and not scenario.vagrant.clone_directory:
        issues.append(ValidationIssue("warning", "vagrant.clone_directory_missing", "Le répertoire des nouvelles VM cibles n'est pas encore choisi", "vagrant.clone_directory"))
    if scenario.vagrant.bootstrap_network == "VMnet0":
        issues.append(ValidationIssue("error", "bootstrap.vmnet0_forbidden", "Le réseau DHCP d'amorçage doit être distinct de VMnet0", "vagrant.bootstrap_network"))
    if scenario.vagrant.bootstrap_dhcp_enabled and not scenario.vagrant.bootstrap_network:
        issues.append(ValidationIssue("error", "bootstrap.network_missing", "Choisissez le VMnet avant d'activer son DHCP temporaire", "vagrant.bootstrap_network"))
    return ValidationResult(issues)
