"""Vérifie que le scénario par défaut reste aligné sur les quatre YAML scenario_two."""

from copy import deepcopy
from pathlib import Path

import yaml

from cygil_builder.compilers import compile_bundle
from cygil_builder.compilers.reward import load_reward_document
from cygil_builder.coherence import synchronize_scenario
from cygil_builder.deployment import (
    allocate_management_addresses,
    allocate_mininet_internal_addresses,
    allocate_reserved_management_addresses,
)
from cygil_builder.models import (
    HandConfig,
    InfrastructureRole,
    InterfacePurpose,
    MachineInterface,
    MininetInstance,
    Network,
    NetworkSwitch,
    OSFamily,
    Scenario,
    TargetVM,
    VagrantConfig,
)
from cygil_builder.orchestrator import ScenarioOrchestrator
from cygil_builder.planner import build_plan
from cygil_builder.service import ScenarioService
from cygil_builder.validation import validate_scenario
from cygil_builder.visualization import render_infrastructure_view, render_sdn_view
from cygil_builder.vmware_network import (
    StaticMacPolicy,
    VmwareInventorySnapshot,
    plan_target_interfaces,
)
from cygil_builder.vagrant_environment import VmnetRecord
from cygil_builder.vmnet_topology import plan_scenario_vmnets


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCENARIO = ROOT / "examples" / "scenario_two.yml"


def _configure_test_bootstrap(scenario: Scenario, vmnet: str = "VMnet19") -> None:
    """Configure l'amorçage fictif requis par les plans d'isolation."""

    scenario.vagrant.bootstrap_network = vmnet
    for target in scenario.targets:
        target.temporary_management.vmware_network = vmnet


def test_blank_scenario_can_build_arbitrary_targets_and_complete_network(tmp_path):
    """Construit sans copie d'exemple un réseau compilable de trois cibles."""

    scenario = Scenario.new_blank("blank_gui_equivalent")
    scenario.vagrant.enabled = False
    scenario.networks = [
        Network(id="lan", subnet_label="10.42.0.0", cidr="10.42.0.0/24")
    ]
    scenario.mininet_instances = [
        MininetInstance(
            name="mininet_primary",
            infrastructure_vm_id="mininet",
            onos_controller_id="onos",
        )
    ]
    mininet_vm = next(
        machine for machine in scenario.infrastructure if machine.id == "mininet"
    )
    mininet_vm.management_ip = "192.168.10.20"
    mininet_vm.internal_ip = "192.170.20.1"
    scenario.switches = [
        NetworkSwitch(name="s1", mininet_instance="mininet_primary")
    ]
    for index in range(1, 4):
        compromised = index == 2
        scenario.targets.append(
            TargetVM(
                id=f"target_{index}",
                hostname=f"target-{index}",
                os_family=OSFamily.LINUX,
                compromised=compromised,
                initial_red_hand=compromised,
                hand=HandConfig(enabled=compromised),
                interfaces=[
                    MachineInterface(
                        name="eth0",
                        address=f"10.42.0.{10 + index}/24",
                        network="lan",
                        mininet_instance="mininet_primary",
                        connected_switch="s1",
                    )
                ],
            )
        )
    caldera = next(
        machine
        for machine in scenario.infrastructure
        if machine.role == InfrastructureRole.CALDERA
    )
    caldera.interfaces = [
        MachineInterface(
            name="ens40",
            address="10.42.0.5/24",
            network="lan",
            mininet_instance="mininet_primary",
            connected_switch="s1",
        )
    ]

    synchronize_scenario(scenario)
    attachment_plan = plan_scenario_vmnets(scenario, ())
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))

    assert validate_scenario(scenario).is_valid
    assert len(attachment_plan.attachments) == 4  # trois cibles + CALDERA
    assert len(network["mininet_instances"][0]["hosts"]) == 3
    assert network["caldera_server"]["local_interface"] == {
        "name": "ens40",
        "connected_switch": "s1",
        "subnet": "10.42.0.0",
        "ip": "10.42.0.5",
    }
    saved = scenario.to_yaml(tmp_path / "blank_gui_equivalent.yml")
    reloaded = Scenario.from_yaml(saved)
    assert len(reloaded.targets) == 3
    assert next(
        machine
        for machine in reloaded.infrastructure
        if machine.role == InfrastructureRole.CALDERA
    ).interfaces[0].address == "10.42.0.5/24"


def test_default_scenario_two_topology_is_valid():
    """Le modèle canonique contient les quantités et propriétaires de référence."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    result = validate_scenario(scenario)

    assert result.is_valid
    assert len(scenario.mininet_instances) == 2
    assert len(scenario.switches) == 4
    assert len(scenario.targets) == 9
    assert {switch.name: switch.mininet_instance for switch in scenario.switches} == {
        "s1": "Mininet-and-Onos-VM",
        "s2": "Mininet-and-Onos-VM",
        "s3": "Mininet-VM-Two",
        "s4": "Mininet-VM-Two",
    }


def test_scenario_two_network_yaml_uses_local_hosts_and_bidirectional_links(tmp_path):
    """Les cibles restent locales et chaque voisinage OVS/GRE est symétrique."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    instances = {item["name"]: item for item in network["mininet_instances"]}
    primary_switches = {item["name"]: item for item in instances["Mininet-and-Onos-VM"]["switches"]}
    primary_hosts = {item["name"]: item for item in instances["Mininet-and-Onos-VM"]["hosts"]}

    assert primary_switches["s1"]["local_switch_links"] == [{"name": "s2"}]
    assert primary_switches["s1"]["remote_switch_links"] == [{"name": "s3"}, {"name": "s4"}]
    assert primary_switches["s2"]["local_switch_links"] == [{"name": "s1"}]
    assert primary_hosts["3-WINDOWS"]["remote_interfaces"] == []
    assert primary_hosts["3-WINDOWS"]["local_interfaces"] == [
        {
            "name": "ens38",
            "connected_switch": "s2",
            "subnet": "10.0.2.0",
            "ip": "10.0.0.3",
        }
    ]
    compromised = next(target for target in scenario.targets if target.compromised)
    assert network["vms_host_machine_config"]["windows"]["vm_file_paths_with_initial_red_hands_on_them"] == [
        compromised.vmx_path
    ]
    assert network["caldera_server"]["mininet_instance_name"] == "Mininet-and-Onos-VM"
    assert network["caldera_server"]["local_interface"]["connected_switch"] == "s1"


def test_dns_is_an_os_disable_option_not_a_cygil_server_list(tmp_path):
    """Le modèle pilote la désactivation invitée sans altérer le schéma CyGIL."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    assert all(interface.disable_dns for target in scenario.targets for interface in target.interfaces)

    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    compiled_interfaces = [
        interface
        for instance in network["mininet_instances"]
        for host in instance["hosts"]
        for interface in [*host["local_interfaces"], *host["remote_interfaces"]]
    ]
    # CyGIL ne déclare aucun champ DNS : ce booléen sera appliqué dans l'OS.
    assert all("dns" not in key.lower() for interface in compiled_interfaces for key in interface)


def test_transient_dns_server_fields_are_migrated_without_breaking_saved_files():
    """Les sauvegardes créées avec l'ancien formulaire restent chargeables."""

    interface = MachineInterface.model_validate(
        {"name": "ens38", "address": "10.0.0.1/8", "dns_servers": ["192.0.2.53"]}
    )
    vagrant = VagrantConfig.model_validate({"management_dns": ["192.0.2.53"]})

    assert interface.disable_dns is True
    assert "dns_servers" not in interface.model_dump()
    assert "management_dns" not in vagrant.model_dump()


def test_other_three_generated_files_follow_scenario_two_reference(tmp_path):
    """CALDERA, récompense et observation conservent les valeurs structurantes du sample."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    command = yaml.safe_load(bundle.files["command_center"].read_text(encoding="utf-8"))
    reward = yaml.safe_load(bundle.files["reward"].read_text(encoding="utf-8"))
    observation = yaml.safe_load(bundle.files["obs"].read_text(encoding="utf-8"))
    reference_observation = yaml.safe_load(
        (ROOT.parent / "scenario_two" / "scenario_two_obs_config.yml").read_text(encoding="utf-8")
    )

    assert command["provider_type"] == "caldera_three"
    assert len(command["simulator"]["red_abilities"]) == 16
    assert command["simulator"]["red_abilities"][0]["action_id"] == 0
    assert command["simulator"]["red_abilities"][-1]["action_id"] == 15
    assert reward["action_cost"] == 1
    assert reward["no_action_dispatched_cost"] == 8
    assert reward["game_end_criteria"][0] == {"type": "max_steps", "value": 80}
    assert observation == reference_observation


def test_reward_reference_unknown_fields_are_preserved(tmp_path):
    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    reference = yaml.safe_load(
        (ROOT.parent / "scenario_two" / "scenario_two_reward_config.yml").read_text(encoding="utf-8")
    )
    load_reward_document(scenario.reward, reference)
    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    generated = yaml.safe_load(bundle.files["reward"].read_text(encoding="utf-8"))

    assert generated["trait_pairs_worth"] == reference["trait_pairs_worth"]
    assert generated["trait_worth"] == reference["trait_worth"]
    assert next(item for item in generated["game_end_criteria"] if item["type"] == "trait_pairs") == next(
        item for item in reference["game_end_criteria"] if item["type"] == "trait_pairs"
    )


def test_temporary_management_is_detached_before_snapshots_and_not_compiled(tmp_path):
    """La NIC reste hors du YAML CyGIL et est désactivée avant capture."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    _configure_test_bootstrap(scenario)
    plan = build_plan(scenario)
    detach_orders = [step.order for step in plan if step.action == "detach_temporary_management"]
    snapshot_orders = [step.order for step in plan if step.action == "create_snapshot"]
    assert len(detach_orders) == len(scenario.targets)
    assert max(detach_orders) < min(snapshot_orders)

    bundle = compile_bundle(scenario, tmp_path, base_dir=ROOT)
    network = yaml.safe_load(bundle.files["network"].read_text(encoding="utf-8"))
    compiled_interfaces = [
        interface
        for instance in network["mininet_instances"]
        for host in instance["hosts"]
        for interface in [*host["local_interfaces"], *host["remote_interfaces"]]
    ]
    assert all(interface["name"] != "temporary_management" for interface in compiled_interfaces)


def test_live_snapshot_requires_running_vms_and_continuous_pings():
    """Le plan démarre les pings avant l'isolement et les revérifie avant capture."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    _configure_test_bootstrap(scenario)
    plan = build_plan(scenario)
    actions = {step.action: step.order for step in plan}
    first_detach = min(step.order for step in plan if step.action == "detach_temporary_management")
    first_snapshot = min(step.order for step in plan if step.action == "create_snapshot")

    assert actions["start_continuous_pings"] < first_detach
    assert actions["confirm_bench_ready"] < first_detach
    assert actions["prepare_live_snapshot"] < first_snapshot
    assert actions["verify_continuous_pings"] < first_snapshot


def test_graph_separates_sdn_and_vmware_layers():
    """Les instances SDN et les adaptateurs VMware vivent dans deux vues."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    sdn = render_sdn_view(scenario)
    infrastructure = render_infrastructure_view(scenario)
    assert 'subgraph n_instance_Mininet_and_Onos_VM["Mininet-and-Onos-VM"]' in sdn
    assert 'n_onos_controller{{"ONOS Controller"}}' in sdn
    assert "OF:6653" in sdn
    assert "VMnet0" not in sdn
    assert 'subgraph n_vm_Mininet_and_Onos_VM["Mininet-and-Onos-VM · onos"]' in infrastructure
    assert "Management Network" in infrastructure
    # scenario_two n'a pas encore de VMnet d'orchestration choisi dans sa sauvegarde.
    assert "Orchestration Network" not in infrastructure


def test_scenario_can_be_saved_and_loaded_from_a_user_path(tmp_path):
    """La façade utilisée par la GUI préserve le scénario dans un autre fichier."""

    service = ScenarioService()
    scenario = service.load(DEFAULT_SCENARIO)
    destination = tmp_path / "saved_scenario.yml"
    service.save(scenario, destination)
    reloaded = service.load(destination)

    assert reloaded.metadata.name == "scenario_two"
    assert len(reloaded.switches) == 4
    assert len(reloaded.mininet_instances) == 2


def test_dry_run_detaches_management_before_any_snapshot(tmp_path):
    """L'orchestrateur applique l'isolation, pas seulement la table de planification."""

    scenario = Scenario.from_yaml(DEFAULT_SCENARIO)
    _configure_test_bootstrap(scenario)
    result = ScenarioOrchestrator().prepare_dry_run(scenario, tmp_path, base_dir=ROOT)
    action_names = [action["action"] for action in result.actions]

    assert action_names.count("attach_temporary_management") == len(scenario.targets)
    assert action_names.count("detach_temporary_management") == len(scenario.targets)
    assert max(index for index, action in enumerate(action_names) if action == "detach_temporary_management") < min(
        index for index, action in enumerate(action_names) if action == "snapshot"
    )


def test_new_scenario_rebuild_allocates_every_calculable_network_value(tmp_path):
    """Rejoue les entités scenario2 depuis Nouveau sans saisir IP de gestion/interne ni MAC."""

    reference = Scenario.from_yaml(DEFAULT_SCENARIO)
    scenario = Scenario.new_blank("scenario_two_rebuilt_auto")
    scenario.metadata = deepcopy(reference.metadata)
    scenario.metadata.name = "scenario_two_rebuilt_auto"
    for field in (
        "vmware", "command_center", "reward", "observation", "cygil_runtime",
        "lab_control", "networks", "switches", "targets", "infrastructure",
        "mininet_instances", "onos_intents",
    ):
        setattr(scenario, field, deepcopy(getattr(reference, field)))

    for instance in scenario.mininet_instances:
        instance.external_ip = None
        instance.internal_ip = None
    for machine in scenario.infrastructure:
        machine.management_ip = None
        machine.internal_ip = None
        machine.management_ip_confirmed = False
        machine.interfaces = [
            interface
            for interface in machine.interfaces
            if interface.purpose == InterfacePurpose.SCENARIO
        ]
    for target in scenario.targets:
        target.temporary_management.assigned_address = None
        for interface in target.interfaces:
            interface.mac = None
            interface.applied_mac = None
            interface.mac_verified = False
            interface.vmware_adapter_index = None
            interface.vmware_network = None

    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.bootstrap_validated = True
    scenario.vagrant.mininet_internal_network = "VMnet18"
    scenario.vagrant.mininet_internal_cidr = "192.170.20.0/24"
    attachment_plan = plan_scenario_vmnets(
        scenario,
        (
            VmnetRecord(name="VMnet0", network_type="hostOnly", dhcp_enabled=False, subnet="192.168.10.0", mask="255.255.255.0"),
            VmnetRecord(name="VMnet18", network_type="hostOnly", dhcp_enabled=False, subnet="192.170.20.0", mask="255.255.255.0"),
            VmnetRecord(name="VMnet19", network_type="hostOnly", dhcp_enabled=True, subnet="192.168.190.0", mask="255.255.255.0"),
        ),
    )
    synchronize_scenario(scenario)

    assert len(attachment_plan.attachments) == 1 + sum(
        len(target.interfaces) for target in scenario.targets
    )
    assert len({item.vmnet for item in attachment_plan.attachments}) == len(
        attachment_plan.attachments
    )

    plan_target_interfaces(
        scenario,
        VmwareInventorySnapshot(complete=True).seal(),
        StaticMacPolicy(
            workstation_version="simulation",
            first_mac="00:50:56:00:00:00",
            last_mac="00:50:56:3f:ff:ff",
            validated=True,
            validation_source="simulation contrôlée sans banc",
        ),
    )
    host_addresses = {"192.168.10.1", scenario.vmware.external_ip}
    targets = allocate_management_addresses(
        scenario, "192.168.10.0/24", host_addresses=host_addresses
    )
    reserved = allocate_reserved_management_addresses(
        scenario,
        "192.168.10.0/24",
        host_addresses=host_addresses,
        target_allocations=targets,
    )
    internal = allocate_mininet_internal_addresses(
        scenario, "192.170.20.0/24", "VMnet18"
    )
    synchronize_scenario(scenario)

    assert validate_scenario(scenario).is_valid
    assert not ({item.ip for item in targets.values()} & {item.ip for item in reserved.values()})
    assert [str(internal[item.infrastructure_vm_id].ip) for item in scenario.mininet_instances] == [
        "192.170.20.1",
        "192.170.20.2",
    ]
    assert "cygil" not in internal
    assert next(machine for machine in scenario.infrastructure if machine.id == "cygil").internal_ip is None

    result = ScenarioOrchestrator().prepare_dry_run(
        scenario,
        tmp_path,
        base_dir=ROOT,
        secret_values={
            scenario.vmware.api_username_secret: "vmrest-simulation-user",
            scenario.vmware.api_password_secret: "vmrest-simulation-password",
        },
    )
    generated = yaml.safe_load(result.bundle.files["network"].read_text(encoding="utf-8"))
    reference_network = yaml.safe_load(
        (ROOT.parent / "scenario_two" / "scenario_two_network_config.yml").read_text(encoding="utf-8")
    )
    assert set(generated) == set(reference_network)
    assert len(generated["mininet_instances"]) == len(reference_network["mininet_instances"])
    assert sum(len(item["hosts"]) for item in generated["mininet_instances"]) == 9
    assert all("${" not in path.read_text(encoding="utf-8") for path in result.bundle.files.values())
