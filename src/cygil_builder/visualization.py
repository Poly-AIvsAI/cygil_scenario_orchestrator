"""Génération de deux vues Mermaid séparant VMware de la topologie SDN."""

from __future__ import annotations

import hashlib
import re

from .models import InfrastructureRole, InterfacePurpose, Scenario
from .topology import switch_owners, unique_switch_links


def _safe_id(value: str) -> str:
    """Produit un identifiant Mermaid stable à partir d'un nom utilisateur."""

    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", value)


def _escape(value: str) -> str:
    """Neutralise les caractères qui casseraient une étiquette Mermaid."""

    return value.replace('"', "'").replace("\n", " ")


def _instance_class(name: str, *, controller: bool) -> tuple[str, str]:
    """Retourne une classe et sa définition avec une palette déterministe."""

    if controller:
        return "controller_instance", (
            "classDef controller_instance fill:#dcecff,stroke:#1769aa,"
            "stroke-width:3px,color:#173b67;"
        )
    palette = [
        ("#f3e5f5", "#8e44ad"),
        ("#e0f2f1", "#00897b"),
        ("#fff3e0", "#ef6c00"),
        ("#fce4ec", "#c2185b"),
        ("#ede7f6", "#5e35b1"),
    ]
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    index = int.from_bytes(digest[:2], "big") % len(palette)
    fill, stroke = palette[index]
    class_name = f"instance_{index}"
    return class_name, (
        f"classDef {class_name} fill:{fill},stroke:{stroke},"
        "stroke-width:3px,color:#173b67;"
    )


def render_infrastructure_view(scenario: Scenario) -> str:
    """Affiche les VM, adaptateurs et segments VMware sans éléments OVS."""

    lines = [
        "flowchart LR",
        "classDef network fill:#eceff1,stroke:#607d8b,stroke-width:2px,color:#263238;",
        "classDef adapter fill:#ffffff,stroke:#78909c,color:#263238;",
        "classDef infra fill:#e8f5e9,stroke:#388e3c,stroke-width:2px,color:#1b5e20;",
        "classDef target fill:#fff8e1,stroke:#f9a825,stroke-width:2px,color:#5d4037;",
        "classDef compromised fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#7f0000;",
        "classDef hypervisor fill:#ede7f6,stroke:#5e35b1,stroke-width:2px,color:#311b92;",
    ]
    management_id = _safe_id("network_management_VMnet0")
    lines.append(f'{management_id}(["Management Network<br/>VMnet0 · statique"]):::network')
    bootstrap_id = None
    if scenario.vagrant.bootstrap_network:
        bootstrap_id = _safe_id("network_orchestration")
        lines.append(
            f'{bootstrap_id}(["Orchestration Network<br/>{_escape(scenario.vagrant.bootstrap_network)} · DHCP temporaire"]):::network'
        )
    control_id = None
    if scenario.vagrant.mininet_internal_network:
        control_id = _safe_id("network_control_channel")
        lines.append(
            f'{control_id}(["Control-Channel Network<br/>{_escape(scenario.vagrant.mininet_internal_network)}"]):::network'
        )

    hypervisor_id = _safe_id("hypervisor")
    lines.append(f'{hypervisor_id}{{{{"Hyperviseur VMware"}}}}:::hypervisor')
    lines.append(f"{hypervisor_id} --- {management_id}")
    if bootstrap_id:
        lines.append(f"{hypervisor_id} --- {bootstrap_id}")

    infrastructure_by_id = {machine.id: machine for machine in scenario.infrastructure}
    instance_by_vm = {
        instance.infrastructure_vm_id: instance
        for instance in scenario.mininet_instances
        if instance.infrastructure_vm_id
    }
    machine_adapter_nodes: dict[tuple[str, str], str] = {}

    for machine in sorted([*scenario.infrastructure, *scenario.targets], key=lambda item: item.id):
        machine_id = _safe_id(f"vm_{machine.id}")
        is_target = machine in scenario.targets
        class_name = "compromised" if is_target and machine.compromised else ("target" if is_target else "infra")
        role = "cible compromise" if is_target and machine.compromised else ("cible" if is_target else machine.role.value)
        lines.append(f'subgraph {machine_id}["{_escape(machine.id)} · {role}"]')
        summary_id = _safe_id(f"vm_{machine.id}_summary")
        lines.append(f'  {summary_id}["{_escape(machine.id)}"]:::{class_name}')

        compromised = next((target for target in scenario.targets if target.compromised), None)
        # La clé sert aux raccordements Mermaid; l'étiquette contient les
        # valeurs modifiables afin qu'un changement de nom ou d'IP soit visible.
        adapters: list[tuple[str, str, str]] = []
        if not is_target:
            management_interface = next(
                (
                    item
                    for item in machine.interfaces
                    if item.purpose == InterfacePurpose.MANAGEMENT
                ),
                None,
            )
            management_label = (
                f"{management_interface.name} · {management_interface.address}"
                if management_interface
                else "management"
            )
            adapters.append(("management", "VMnet0", management_label))
        if bootstrap_id:
            orchestration_identity = next(
                (
                    item
                    for item in machine.isolation_interfaces
                    if item.network == scenario.vagrant.bootstrap_network
                ),
                None,
            )
            orchestration_label = (
                orchestration_identity.guest_name
                if orchestration_identity and orchestration_identity.guest_name
                else "orchestration"
            )
            adapters.append((
                "orchestration",
                scenario.vagrant.bootstrap_network or "orchestration",
                orchestration_label,
            ))
        if machine.id in instance_by_vm and control_id:
            adapters.append(("control", scenario.vagrant.mininet_internal_network or "control", "control"))
            instance = instance_by_vm[machine.id]
            for target in sorted(scenario.targets, key=lambda item: item.id):
                interface = next(
                    (
                        item
                        for item in target.interfaces
                        if item.purpose == InterfacePurpose.SCENARIO
                        and item.mininet_instance == instance.name
                        and item.vmware_network
                    ),
                    None,
                )
                if interface:
                    adapters.append((
                        f"access_{target.id}",
                        interface.vmware_network or "",
                        f"vers {target.id}",
                    ))
            compromised_interface = (
                next(
                    (
                        item
                        for item in compromised.interfaces
                        if item.purpose == InterfacePurpose.SCENARIO
                    ),
                    None,
                )
                if compromised
                else None
            )
            if (
                compromised
                and compromised_interface
                and compromised_interface.mininet_instance == instance.name
                and compromised.caldera_vmware_network
            ):
                adapters.append(("caldera_access", compromised.caldera_vmware_network, "vers CALDERA"))
        if not is_target and machine.role == InfrastructureRole.ONOS and control_id:
            adapters.append(("control", scenario.vagrant.mininet_internal_network or "control", "control"))
        for interface in machine.interfaces:
            if interface.purpose == InterfacePurpose.SCENARIO and interface.vmware_network:
                if not (
                    not is_target
                    and machine.role == InfrastructureRole.CALDERA
                    and compromised
                    and interface.vmware_network == compromised.caldera_vmware_network
                ):
                    adapters.append((
                        f"access_{interface.name}",
                        interface.vmware_network,
                        f"{interface.name} · {interface.address}",
                    ))
        if not is_target and machine.role == InfrastructureRole.CALDERA:
            if compromised and compromised.caldera_vmware_network:
                caldera_interface = next(
                    (
                        item
                        for item in machine.interfaces
                        if item.purpose == InterfacePurpose.SCENARIO
                    ),
                    None,
                )
                caldera_label = (
                    f"{caldera_interface.name} · {caldera_interface.address}"
                    if caldera_interface
                    else "vers Mininet"
                )
                adapters.append(("caldera_access", compromised.caldera_vmware_network, caldera_label))
        for adapter_name, vmnet, adapter_label in dict.fromkeys(adapters):
            adapter_id = _safe_id(f"adapter_{machine.id}_{adapter_name}")
            lines.append(
                f'  {adapter_id}["{_escape(adapter_label)}<br/>{_escape(vmnet)}"]:::adapter'
            )
            lines.append(f"  {summary_id} --- {adapter_id}")
            machine_adapter_nodes[(machine.id, adapter_name)] = adapter_id
        lines.append("end")

    for machine in sorted(scenario.infrastructure, key=lambda item: item.id):
        adapter = machine_adapter_nodes.get((machine.id, "management"))
        if adapter:
            lines.append(f"{adapter} --- {management_id}")
    if bootstrap_id:
        for machine in sorted([*scenario.infrastructure, *scenario.targets], key=lambda item: item.id):
            adapter = machine_adapter_nodes.get((machine.id, "orchestration"))
            if adapter:
                lines.append(f"{adapter} --- {bootstrap_id}")
    if control_id:
        control_members = {
            *(instance.infrastructure_vm_id for instance in scenario.mininet_instances if instance.infrastructure_vm_id),
            *(instance.onos_controller_id for instance in scenario.mininet_instances if instance.onos_controller_id),
        }
        for machine_id in sorted(control_members):
            adapter = machine_adapter_nodes.get((machine_id, "control"))
            if adapter:
                lines.append(f"{adapter} --- {control_id}")

    # Chaque cible possède son propre VMnet d'accès vers la VM Mininet.
    for target in sorted(scenario.targets, key=lambda item: item.id):
        interface = next(
            (item for item in target.interfaces if item.purpose == InterfacePurpose.SCENARIO),
            None,
        )
        if not interface or not interface.vmware_network:
            continue
        instance = next(
            (item for item in scenario.mininet_instances if item.name == interface.mininet_instance),
            None,
        )
        if not instance or not instance.infrastructure_vm_id:
            continue
        network_id = _safe_id(f"network_access_{target.id}")
        lines.append(f'{network_id}(["Access-Link { _escape(target.id) }<br/>{_escape(interface.vmware_network)}"]):::network')
        target_adapter = machine_adapter_nodes.get((target.id, f"access_{interface.name}"))
        mininet_adapter = machine_adapter_nodes.get(
            (instance.infrastructure_vm_id, f"access_{target.id}")
        )
        if target_adapter:
            lines.append(f"{target_adapter} --- {network_id}")
        if mininet_adapter:
            lines.append(f"{mininet_adapter} --- {network_id}")

    compromised = next((target for target in scenario.targets if target.compromised), None)
    if compromised and compromised.caldera_vmware_network:
        interface = next(
            (item for item in compromised.interfaces if item.purpose == InterfacePurpose.SCENARIO),
            None,
        )
        instance = next(
            (item for item in scenario.mininet_instances if interface and item.name == interface.mininet_instance),
            None,
        )
        caldera = next(
            (item for item in scenario.infrastructure if item.role == InfrastructureRole.CALDERA),
            None,
        )
        if instance and instance.infrastructure_vm_id and caldera:
            network_id = _safe_id("network_caldera_access")
            lines.append(
                f'{network_id}(["CALDERA-Link<br/>{_escape(compromised.caldera_vmware_network)}"]):::network'
            )
            caldera_adapter = machine_adapter_nodes.get((caldera.id, "caldera_access"))
            mininet_adapter = machine_adapter_nodes.get(
                (instance.infrastructure_vm_id, "caldera_access")
            )
            if caldera_adapter:
                lines.append(f"{caldera_adapter} --- {network_id}")
            if mininet_adapter:
                lines.append(f"{mininet_adapter} --- {network_id}")

    return "\n".join(lines)


def render_sdn_view(scenario: Scenario) -> str:
    """Affiche switches, hôtes, ONOS, OpenFlow et GRE sans VMnet VMware."""

    lines = [
        "flowchart LR",
        "classDef switch fill:#ffffff,stroke:#37474f,stroke-width:2px,color:#263238;",
        "classDef target fill:#fff8e1,stroke:#f9a825,stroke-width:2px,color:#5d4037;",
        "classDef compromised fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#7f0000;",
        "classDef controller fill:#e3f2fd,stroke:#1565c0,stroke-width:3px,color:#0d47a1;",
        "classDef service fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20;",
        "classDef anchor fill:transparent,stroke:transparent,color:transparent;",
    ]
    infrastructure_by_id = {machine.id: machine for machine in scenario.infrastructure}
    owners = switch_owners(scenario)
    instance_classes: dict[str, str] = {}
    definitions: set[str] = set()
    onos_id = _safe_id("onos_controller")

    for instance in sorted(scenario.mininet_instances, key=lambda item: item.name):
        combined = instance.infrastructure_vm_id == instance.onos_controller_id
        class_name, definition = _instance_class(instance.name, controller=combined)
        instance_classes[instance.name] = class_name
        if definition not in definitions:
            lines.append(definition)
            definitions.add(definition)
        graph_id = _safe_id(f"instance_{instance.name}")
        lines.append(f'subgraph {graph_id}["{_escape(instance.name)}"]')
        anchor_id = _safe_id(f"instance_anchor_{instance.name}")
        lines.append(f'  {anchor_id}((" ")):::anchor')
        if combined:
            lines.append(f'  {onos_id}{{{{"ONOS Controller"}}}}:::controller')
        for switch in sorted(
            (item for item in scenario.switches if item.mininet_instance == instance.name),
            key=lambda item: item.name,
        ):
            switch_id = _safe_id(f"switch_{switch.name}")
            lines.append(f'  {switch_id}{{{{"{_escape(switch.name)}"}}}}:::switch')
        lines.append("end")

    if not any(
        instance.infrastructure_vm_id == instance.onos_controller_id
        for instance in scenario.mininet_instances
    ):
        lines.append(f'{onos_id}{{{{"ONOS Controller"}}}}:::controller')

    for target in sorted(scenario.targets, key=lambda item: item.id):
        class_name = "compromised" if target.compromised else "target"
        marker = " ⚠ compromise" if target.compromised else ""
        target_id = _safe_id(f"target_{target.id}")
        lines.append(f'{target_id}["{_escape(target.id + marker)}"]:::{class_name}')
        interface = next(
            (item for item in target.interfaces if item.purpose == InterfacePurpose.SCENARIO),
            None,
        )
        if interface and interface.connected_switch:
            lines.append(f'{target_id} ---|"Access"| {_safe_id(f"switch_{interface.connected_switch}")}')

    for _, source, destination in unique_switch_links(scenario):
        source_id = _safe_id(f"switch_{source}")
        destination_id = _safe_id(f"switch_{destination}")
        if owners.get(source) == owners.get(destination):
            lines.append(f'{source_id} ---|"OVS local"| {destination_id}')
        else:
            lines.append(f'{source_id} -. "GRE" .- {destination_id}')

    # Tous les switches utilisent le contrôleur unique, local ou distant.
    for switch in sorted(scenario.switches, key=lambda item: item.name):
        lines.append(f'{_safe_id(f"switch_{switch.name}")} -->|"OF:6653"| {onos_id}')

    cygil = next(
        (machine for machine in scenario.infrastructure if machine.role == InfrastructureRole.CYGIL),
        None,
    )
    caldera = next(
        (machine for machine in scenario.infrastructure if machine.role == InfrastructureRole.CALDERA),
        None,
    )
    if cygil:
        cygil_id = _safe_id("service_cygil")
        lines.append(f'{cygil_id}{{{{"CyGIL"}}}}:::service')
        for instance in sorted(scenario.mininet_instances, key=lambda item: item.name):
            lines.append(
                f'{cygil_id} ---|"management"| {_safe_id(f"instance_anchor_{instance.name}")}'
            )
        if caldera:
            lines.append(f'{cygil_id} ---|"management"| {_safe_id("service_caldera")}')
    if caldera:
        caldera_id = _safe_id("service_caldera")
        lines.append(f'{caldera_id}{{{{"CALDERA"}}}}:::service')
        compromised = next((target for target in scenario.targets if target.compromised), None)
        if compromised:
            compromised_interface = next(
                (
                    interface
                    for interface in compromised.interfaces
                    if interface.purpose == InterfacePurpose.SCENARIO
                ),
                None,
            )
            if compromised_interface and compromised_interface.connected_switch:
                lines.append(
                    f'{caldera_id} ---|"Access CALDERA"| '
                    f'{_safe_id(f"switch_{compromised_interface.connected_switch}")}'
                )

    return "\n".join(lines)


def scenario_to_mermaid(scenario: Scenario) -> str:
    """Compatibilité API : retourne désormais la vue logique SDN."""

    return render_sdn_view(scenario)
