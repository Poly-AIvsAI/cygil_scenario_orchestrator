"""Compilation de la topologie multi-interface vers le schéma network de CyGIL."""

from __future__ import annotations

from ipaddress import ip_interface, ip_network

from ..exceptions import CompilationError
from ..models import InfrastructureRole, Scenario
from ..topology import unique_switch_links
from .secrets import secret_value


def compile_network(
    scenario: Scenario,
    inject_secrets: bool = False,
    *,
    require_verified_macs: bool = False,
    secret_values: dict[str, str] | None = None,
) -> dict:
    """Compile le réseau et, en mode final, exige les MAC relues dans VMware."""
    by_role = {machine.role: machine for machine in scenario.infrastructure}
    caldera = by_role[InfrastructureRole.CALDERA]
    onos = by_role[InfrastructureRole.ONOS]

    compromised_targets = [target for target in scenario.targets if target.compromised]
    if len(compromised_targets) != 1:
        raise CompilationError("Le fichier network exige exactement une cible compromise")
    compromised = compromised_targets[0]
    compromised_interface = next(
        (
            interface
            for interface in compromised.interfaces
            if interface.purpose.value == "scenario"
        ),
        None,
    )
    if compromised_interface is None:
        raise CompilationError("La cible compromise ne possède pas son unique interface de scénario")

    caldera_vmnet = compromised.caldera_vmware_network
    caldera_interface = next(
        (
            interface
            for interface in caldera.interfaces
            if caldera_vmnet and interface.vmware_network == caldera_vmnet
        ),
        None,
    )
    caldera_adapter = next(
        (
            adapter
            for adapter in [*caldera.observed_adapters, *caldera.expected_adapters]
            if caldera_vmnet and adapter.vmnet == caldera_vmnet
        ),
        None,
    )

    def caldera_ip() -> str:
        """Retourne l'IP réellement associée au lien CALDERA-Mininet."""

        raw = (
            (caldera_interface.address if caldera_interface else None)
            or (caldera_adapter.address if caldera_adapter else None)
            or caldera.scenario_ip
            or caldera.internal_ip
            or ""
        )
        try:
            return str(ip_interface(raw).ip)
        except ValueError:
            return raw

    caldera_mac = (
        (caldera_interface.applied_mac if caldera_interface else None)
        or (caldera_adapter.applied_mac if caldera_adapter else None)
        or caldera.mac
        or ""
    )
    if require_verified_macs and caldera_vmnet and not (
        (caldera_interface and caldera_interface.mac_verified)
        or (caldera_adapter and caldera_adapter.verified)
    ):
        raise CompilationError(
            "La MAC CALDERA-Mininet doit être relue dans VMware avant la compilation finale"
        )
    resolved_caldera_name = (
        (caldera_interface.name if caldera_interface else None)
        or (caldera_adapter.guest_name if caldera_adapter else None)
        or caldera.interface_name
        or ""
    )
    if require_verified_macs and not resolved_caldera_name:
        raise CompilationError(
            "Le nom invité de la carte CALDERA-Mininet doit être découvert par sa MAC avant la compilation finale"
        )

    initial_hands = [compromised.vmx_path] if compromised.vmx_path else []
    critical = [target.vmx_path for target in scenario.targets if target.critical_reset and target.vmx_path]
    host = scenario.vmware
    host_config = {
        "no_vm_resetting": [],
        "windows": [],
        "esxi_server": {},
        "vxrails": [],
        "linux": [],
    }
    host_config[host.host_type] = {
        "vms_host_machine_external_ip": host.external_ip,
        "vms_host_machine_ssh_user": host.ssh_user,
        "userauth_publickey_file_path": host.ssh_private_key_path,
        "vmware_workstation_directory": host.workstation_directory,
        "vmware_workstation_api_port": str(host.api_port),
        "vmware_workstation_api_creds": {
            "username": secret_value(host.api_username_secret, inject_secrets, secret_values),
            "password": secret_value(host.api_password_secret, inject_secrets, secret_values),
        },
        "command_center_server_vm_path_for_periodic_resetting": caldera.vmx_path or "",
        "command_center_server_vm_reset_episode_interval": host.caldera_reset_interval,
        "vm_file_paths_with_initial_red_hands_on_them": initial_hands,
        "critical_vm_paths_for_periodic_resetting": critical,
        "num_of_critical_vms_to_reset_every_episode": len(critical),
        "scenario_vm_snapshot_name": host.snapshot_name,
    }

    # Déduplique la paire non orientée; chaque extrémité sera ensuite inscrite
    # comme voisine de l'autre dans le document CyGIL.
    canonical_links = unique_switch_links(scenario)
    instances: list[dict] = []
    for instance in scenario.mininet_instances:
        hosts: dict[str, dict] = {}
        for target in scenario.targets:
            for interface in target.interfaces:
                if interface.mininet_instance != instance.name:
                    continue
                network = next(item for item in scenario.networks if item.id == interface.network)
                entry = {
                    "name": interface.name,
                    "connected_switch": interface.connected_switch,
                    "subnet": network.subnet_label or str(ip_network(network.cidr).network_address),
                    "ip": str(ip_interface(interface.address).ip),
                }
                if require_verified_macs and (not interface.mac_verified or not interface.applied_mac):
                    raise CompilationError(
                        f"La MAC VMware finale de {target.id} n'a pas été relue et confirmée"
                    )
                compiled_mac = interface.applied_mac if interface.mac_verified else interface.mac
                host_entry = hosts.setdefault(
                    target.id,
                    {"name": target.id, "mac": compiled_mac or "", "local_interfaces": [], "remote_interfaces": []},
                )
                # Une cible est toujours physiquement raccordée à la VM qui
                # héberge son switch. Les interfaces distantes sont réservées
                # aux liens inter-switch GRE, jamais aux hôtes finaux.
                host_entry["local_interfaces"].append(entry)
        instance_switches = {switch.name for switch in scenario.switches if switch.mininet_instance == instance.name}
        links_by_source: dict[str, list[str]] = {}
        for _, source, destination in canonical_links:
            # Le format CyGIL porte les voisins sur chaque switch. La paire
            # canonique est donc matérialisée dans les deux sens.
            links_by_source.setdefault(source, []).append(destination)
            links_by_source.setdefault(destination, []).append(source)
        instances.append(
            {
                "name": instance.name,
                "external_ip": instance.external_ip,
                "internal_ip": instance.internal_ip,
                "hosts": list(hosts.values()),
                "switches": [
                    {
                        "name": switch,
                        "local_switch_links": [{"name": link} for link in links_by_source.get(switch, []) if link in instance_switches],
                        "remote_switch_links": [{"name": link} for link in links_by_source.get(switch, []) if link not in instance_switches],
                    }
                    # Un switch sans lien sortant doit tout de même exister dans le
                    # YAML, notamment la destination s2 de l'unique lien s1 -> s2.
                    for switch in sorted(instance_switches)
                ],
            }
        )

    return {
        "vms_host_machine": host.host_type,
        "vms_host_machine_config": host_config,
        "mininet_instances": instances,
        "caldera_server": {
            "name": caldera.id,
            "mac": caldera_mac,
            "mininet_instance_name": compromised_interface.mininet_instance or "",
            "local_interface": {
                "name": (
                    resolved_caldera_name
                ),
                "connected_switch": compromised_interface.connected_switch or "",
                "subnet": next(
                    (
                        network.subnet_label or network.cidr or ""
                        for network in scenario.networks
                        if network.id == compromised_interface.network
                    ),
                    "",
                ),
                "ip": caldera_ip(),
            },
            "external_ip": caldera.management_ip or "",
            "ssh_user": caldera.ssh_user or "",
            "ssh_password": secret_value(caldera.ssh_password_secret, inject_secrets, secret_values),
            "blue_api_key": secret_value(caldera.blue_api_key_secret, inject_secrets, secret_values),
            "red_api_key": secret_value(caldera.red_api_key_secret, inject_secrets, secret_values),
        },
        "onos": {
            "onos_external_ip": onos.management_ip or "",
            "onos_internal_ip": onos.internal_ip or "",
            "onos_host_to_host_intents": [intent.model_dump(mode="json") for intent in scenario.onos_intents],
        },
    }
