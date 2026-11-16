"""Règles de synchronisation entre les écrans et les artefacts dérivés du scénario."""

from __future__ import annotations

from ipaddress import ip_address, ip_interface, ip_network

from .models import (
    GuestFilePurpose,
    InfrastructureRole,
    InterfacePurpose,
    LinkScope,
    MachineInterface,
    ObjectiveType,
    RewardObjective,
    Scenario,
)
from .topology import switch_owners


def select_compromised_target(
    scenario: Scenario,
    target_id: str,
    caldera_address: str,
) -> None:
    """Sélectionne l'unique cible compromise et dérive l'accès CALDERA.

    Le nom de la carte invitée n'est jamais inventé : il reste vide jusqu'à
    sa découverte par la MAC, ou conserve une valeur déjà observée. Le lien
    logique rejoint toujours le même switch OVS que l'accès de la cible.
    """

    target = next((item for item in scenario.targets if item.id == target_id), None)
    if target is None:
        raise ValueError(f"Cible inconnue : {target_id}")
    target_interfaces = [
        item for item in target.interfaces if item.purpose == InterfacePurpose.SCENARIO
    ]
    if len(target_interfaces) != 1:
        raise ValueError(
            f"La cible {target.id} doit posséder exactement une interface d'accès"
        )
    target_interface = target_interfaces[0]
    network = next(
        (item for item in scenario.networks if item.id == target_interface.network),
        None,
    )
    if network is None or not network.cidr:
        raise ValueError("Le réseau de la cible compromise doit posséder un CIDR")
    try:
        parsed_address = ip_interface(caldera_address)
        logical_network = ip_network(network.cidr, strict=False)
    except ValueError as exc:
        raise ValueError("L'adresse CALDERA doit être une adresse avec préfixe valide") from exc
    if parsed_address.ip not in logical_network:
        raise ValueError(
            f"L'adresse CALDERA {parsed_address.ip} n'appartient pas à {logical_network}"
        )

    caldera = next(
        (
            machine
            for machine in scenario.infrastructure
            if machine.role == InfrastructureRole.CALDERA
        ),
        None,
    )
    if caldera is None:
        raise ValueError("La VM d'infrastructure CALDERA est absente")

    current_caldera_interfaces = {
        id(item)
        for item in caldera.interfaces
        if item.purpose == InterfacePurpose.SCENARIO
    }
    for machine in [*scenario.infrastructure, *scenario.targets]:
        for interface in machine.interfaces:
            if id(interface) in current_caldera_interfaces:
                continue
            try:
                occupied = ip_interface(interface.address).ip
            except ValueError:
                continue
            if occupied == parsed_address.ip:
                raise ValueError(
                    f"L'adresse CALDERA {parsed_address.ip} est déjà utilisée par {machine.id}"
                )
    if network.gateway and ip_address(network.gateway) == parsed_address.ip:
        raise ValueError(
            f"L'adresse CALDERA {parsed_address.ip} est réservée à la passerelle"
        )

    previous = next((item for item in scenario.targets if item.compromised), None)
    inherited_vmnet = target.caldera_vmware_network
    if previous is not None and previous is not target and not inherited_vmnet:
        # La même carte CALDERA peut être rebranchée par le plan VMware;
        # conserver son segment évite de créer un VMnet orphelin.
        inherited_vmnet = previous.caldera_vmware_network

    for item in scenario.targets:
        selected = item is target
        item.compromised = selected
        item.hand.enabled = selected
        item.initial_red_hand = selected
        if not selected:
            item.caldera_vmware_network = None
            item.hand.generated_command = None
    target.caldera_vmware_network = inherited_vmnet
    target.hand.generated_command = None

    caldera_interfaces = [
        item for item in caldera.interfaces if item.purpose == InterfacePurpose.SCENARIO
    ]
    if caldera_interfaces:
        derived = caldera_interfaces[0]
        caldera.interfaces = [
            item
            for item in caldera.interfaces
            if item.purpose != InterfacePurpose.SCENARIO or item is derived
        ]
        derived.address = str(parsed_address)
        derived.network = target_interface.network
        derived.mininet_instance = target_interface.mininet_instance
        derived.connected_switch = target_interface.connected_switch
        derived.scope = LinkScope.LOCAL
        derived.vmware_network = inherited_vmnet
        derived.disable_dns = True
    else:
        caldera.interfaces.append(
            MachineInterface(
                name="",
                address=str(parsed_address),
                purpose=InterfacePurpose.SCENARIO,
                network=target_interface.network,
                mininet_instance=target_interface.mininet_instance,
                connected_switch=target_interface.connected_switch,
                scope=LinkScope.LOCAL,
                vmware_network=inherited_vmnet,
                disable_dns=True,
            )
        )
    synchronize_scenario(scenario)


def synchronize_scenario(scenario: Scenario) -> None:
    """Met à jour les informations dérivées après chaque mutation de l'interface.

    Les objectifs provenant d'un fichier cible sont reconstruits depuis les VM. Leur champ
    ``source`` permet de préserver tous les objectifs saisis manuellement par l'utilisateur.
    """

    # Les sections Mininet conservent des champs historiques pour le YAML CyGIL,
    # mais les VM réservées sont les seules sources de leurs adresses. L'unique
    # VM ONOS remplace également toute référence provenant d'un ancien scénario.
    scenario.synchronize_mininet_bindings()

    manual_objectives = [
        objective
        for objective in scenario.reward.objectives
        if not objective.source.startswith("target_file:")
    ]
    derived_objectives: list[RewardObjective] = []
    for target in scenario.targets:
        # ``compromised`` est l'unique choix métier. Les champs historiques
        # restent identiques pour les adaptateurs CALDERA et le YAML CyGIL.
        target.hand.enabled = target.compromised
        target.initial_red_hand = target.compromised
        # Les champs historiques restent prioritaires pour charger les scénarios
        # existants. Les nouveaux dépôts autorisent ensuite plusieurs fichiers
        # CyGIL sur une même VM sans exporter leur chemin source local.
        candidates = []
        if target.target_file_path:
            candidates.append((target.target_file_path, target.target_file_worth, "legacy"))
        candidates.extend(
            (item.destination_path, item.worth, str(index))
            for index, item in enumerate(target.guest_files)
            if item.purpose == GuestFilePurpose.CYGIL_TARGET
        )
        seen_destinations: set[str] = set()
        for destination, worth, suffix in candidates:
            if destination in seen_destinations:
                continue
            seen_destinations.add(destination)
            derived_objectives.append(
                RewardObjective(
                    type=ObjectiveType.FILE_EXFILTRATION,
                    host_name=target.id,
                    file_path=destination,
                    worth=worth,
                    enabled=True,
                    source=(f"target_file:{target.id}" if suffix == "legacy" else f"target_file:{target.id}:{suffix}"),
                )
            )
    scenario.reward.objectives = [*manual_objectives, *derived_objectives]

    # Une cible appartient toujours à l'instance propriétaire de son switch.
    # ``remote`` reste chargeable pour diagnostiquer un ancien scénario, mais
    # la synchronisation des scénarios conformes produit uniquement ``local``.
    owners = switch_owners(scenario)
    networks = {network.id: network for network in scenario.networks}
    for machine in [*scenario.infrastructure, *scenario.targets]:
        for interface in machine.interfaces:
            if interface.mininet_instance and interface.connected_switch in owners:
                if machine in scenario.targets:
                    interface.mininet_instance = owners[interface.connected_switch]
                    interface.scope = LinkScope.LOCAL
                else:
                    interface.scope = (
                        LinkScope.LOCAL
                        if owners[interface.connected_switch] == interface.mininet_instance
                        else LinkScope.REMOTE
                    )

    # L'unique carte de scénario CALDERA suit toujours l'accès de la cible
    # compromise. Son nom et son adresse restent des saisies utilisateur; les
    # références topologiques et le VMnet sont, elles, dérivées.
    compromised = next((target for target in scenario.targets if target.compromised), None)
    caldera = next(
        (machine for machine in scenario.infrastructure if machine.role == InfrastructureRole.CALDERA),
        None,
    )
    target_interface = next(
        (
            item
            for item in (compromised.interfaces if compromised else [])
            if item.purpose == InterfacePurpose.SCENARIO
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
    if compromised and target_interface and caldera_interface:
        caldera_interface.network = target_interface.network
        caldera_interface.mininet_instance = target_interface.mininet_instance
        caldera_interface.connected_switch = target_interface.connected_switch
        caldera_interface.scope = LinkScope.LOCAL
        caldera_interface.vmware_network = compromised.caldera_vmware_network

    # Les intentions qui référencent une VM supprimée ne doivent jamais survivre dans ONOS.
    known_hosts = {machine.id for machine in scenario.infrastructure} | {
        target.id for target in scenario.targets
    }
    scenario.onos_intents = [
        intent
        for intent in scenario.onos_intents
        if intent.host_one in known_hosts and intent.host_two in known_hosts
    ]
