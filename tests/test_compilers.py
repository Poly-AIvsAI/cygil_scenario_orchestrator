"""Vérifie la génération groupée et la compatibilité structurelle des quatre YAML."""

from pathlib import Path

import pytest
import yaml

from cygil_builder.compilers import compile_bundle
from cygil_builder.compilers.network import compile_network
from cygil_builder.exceptions import CompilationError
from cygil_builder.models import InfrastructureRole, InfrastructureVM, MininetInstance, Network, NetworkSwitch


ROOT = Path(__file__).resolve().parents[1]


def test_final_network_refuses_an_unresolved_caldera_guest_name(scenario):
    compromised = next(target for target in scenario.targets if target.compromised)
    compromised.caldera_vmware_network = "VMnet17"
    for target in scenario.targets:
        for interface in target.interfaces:
            interface.applied_mac = interface.mac
            interface.mac_verified = True
    caldera = next(
        machine
        for machine in scenario.infrastructure
        if machine.role == InfrastructureRole.CALDERA
    )
    caldera_interface = next(interface for interface in caldera.interfaces if interface.purpose.value == "scenario")
    caldera_interface.name = ""
    caldera.interface_name = None
    caldera_interface.vmware_network = "VMnet17"
    caldera_interface.applied_mac = "00:50:56:aa:00:21"
    caldera_interface.mac_verified = True

    with pytest.raises(CompilationError, match="nom invité"):
        compile_network(scenario, require_verified_macs=True)


def test_bundle_contains_four_yaml_and_no_secret_placeholders(scenario, tmp_path):
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    assert set(bundle.files) == {"network", "command_center", "reward", "obs"}
    assert all(path.is_file() for path in bundle.files.values())
    network_text = bundle.files["network"].read_text(encoding="utf-8")
    assert "${" not in network_text
    assert bundle.manifest.is_file()


def test_vmrest_secret_values_are_injected_without_variable_markers(scenario, tmp_path):
    bundle = compile_bundle(
        scenario,
        tmp_path,
        base_dir=ROOT,
        inject_secrets=True,
        secret_values={
            scenario.vmware.api_username_secret: "vmrest-user",
            scenario.vmware.api_password_secret: "vmrest-password",
        },
    )
    network_text = bundle.files["network"].read_text(encoding="utf-8")
    assert "vmrest-user" in network_text
    assert "vmrest-password" in network_text
    assert "${" not in network_text


def test_generated_yaml_can_be_parsed(scenario, tmp_path):
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    for path in bundle.files.values():
        assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), dict)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    command_center = yaml.safe_load(bundle.files["command_center"].read_text(encoding="utf-8"))
    reward = yaml.safe_load(bundle.files["reward"].read_text(encoding="utf-8"))
    assert set(network) == {"vms_host_machine", "vms_host_machine_config", "mininet_instances", "caldera_server", "onos"}
    assert set(command_center) == {"provider_type", "provider_config", "simulator"}
    assert "hand_on_host_worth" in reward
    assert reward["file_exfiltration_worth"][0]["host_name"] == "server_01"
    assert reward["file_exfiltration_worth"][0]["file_path"] == "/home/lab/target/secret.txt"


def test_three_target_simulation_matches_cygil_network_shape(scenario, tmp_path):
    """La simulation demandée produit trois hôtes uniques au format CyGIL."""

    assert len(scenario.targets) == 3
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    hosts = [
        host
        for instance in network["mininet_instances"]
        for host in instance["hosts"]
    ]
    assert {host["name"] for host in hosts} == {
        "workstation_01",
        "server_01",
        "workstation_02",
    }
    assert len({host["mac"] for host in hosts}) == 3
    assert all(host["mac"].startswith("00:50:56:") for host in hosts)
    assert all(
        host["local_interfaces"] or host["remote_interfaces"]
        for host in hosts
    )


def test_network_yaml_declares_bidirectional_switch_neighbours(scenario, tmp_path):
    """Chaque extrémité du lien OVS déclare l'autre comme voisine."""

    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    primary = next(item for item in network["mininet_instances"] if item["name"] == "mininet_primary")
    switches = {item["name"]: item for item in primary["switches"]}

    assert switches["s1"]["local_switch_links"] == [{"name": "s2"}]
    assert switches["s2"]["local_switch_links"] == [{"name": "s1"}]


def test_remote_switch_link_is_emitted_on_both_gre_endpoints(scenario, tmp_path):
    """Le tunnel GRE bidirectionnel apparaît sur ses deux switches."""

    scenario.infrastructure.append(
        InfrastructureVM(
            id="mininet_secondary_vm",
            role=InfrastructureRole.MININET,
            management_ip="192.168.10.24",
            internal_ip="10.99.0.1",
            mininet_instance="mininet_secondary",
            interfaces=[
                {
                    "name": "ens32",
                    "address": "192.168.10.24/24",
                    "purpose": "management",
                },
                {
                    "name": "ens33",
                    "address": "10.99.0.2/24",
                    "purpose": "scenario",
                    "network": "remote_lab",
                    "mininet_instance": "mininet_secondary",
                    "connected_switch": "s3",
                },
            ],
        )
    )
    scenario.mininet_instances.append(
        MininetInstance(
            name="mininet_secondary",
            infrastructure_vm_id="mininet_secondary_vm",
            external_ip="192.168.10.24",
            internal_ip="10.99.0.1",
        )
    )
    scenario.networks.append(
        Network(
            id="remote_lab",
            cidr="10.99.0.0/24",
            gateway="10.99.0.1",
        )
    )
    scenario.switches.append(NetworkSwitch(name="s3", mininet_instance="mininet_secondary"))
    scenario.mininet_instances[0].switch_links["s1"].append("s3")

    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    instances = {item["name"]: item for item in network["mininet_instances"]}
    primary_switches = {item["name"]: item for item in instances["mininet_primary"]["switches"]}
    secondary_switches = {item["name"]: item for item in instances["mininet_secondary"]["switches"]}

    assert primary_switches["s1"]["remote_switch_links"] == [{"name": "s3"}]
    assert secondary_switches["s3"]["local_switch_links"] == []
    assert secondary_switches["s3"]["remote_switch_links"] == [{"name": "s1"}]
