"""Vérifie qu'un raccordement physique ne partage jamais son VMnet."""

from copy import deepcopy

from cygil_builder.lab_topology import permanent_network_expectations
from cygil_builder.models import InterfacePurpose, MachineInterface
from cygil_builder.vagrant_environment import VmnetRecord
from cygil_builder.vmnet_topology import plan_scenario_vmnets
from cygil_builder.validation import validate_scenario
from cygil_builder.vmware_network import (
    StaticMacPolicy,
    VmwareInventorySnapshot,
    VmwareVMInventory,
    build_reconstruction_plan,
)


def _record(
    name: str,
    *,
    host_connected: bool | None = None,
    dhcp_enabled: bool = False,
) -> VmnetRecord:
    return VmnetRecord(
        name=name,
        network_type="hostOnly",
        dhcp_enabled=dhcp_enabled,
        subnet="192.168.200.0",
        mask="255.255.255.0",
        host_connected=host_connected,
    )


def test_two_targets_on_same_logical_network_get_two_vmnet_and_two_mininet_nics(scenario):
    first, second = scenario.targets[0], scenario.targets[2]
    assert first.interfaces[0].network == second.interfaces[0].network
    for target in scenario.targets:
        for interface in target.interfaces:
            interface.vmware_network = None
    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet18"

    plan = plan_scenario_vmnets(
        scenario,
        (_record("VMnet0"), _record("VMnet18"), _record("VMnet19")),
    )

    first_link = next(item for item in plan.attachments if item.target_id == first.id)
    second_link = next(item for item in plan.attachments if item.target_id == second.id)
    assert first_link.logical_network == second_link.logical_network
    assert first_link.vmnet != second_link.vmnet
    assert len({item.vmnet for item in plan.attachments}) == len(plan.attachments)

    compromised = next(target for target in scenario.targets if target.compromised)
    compromised_access = next(
        item
        for item in plan.attachments
        if item.target_id == compromised.id and item.kind == "target_access"
    )
    caldera_access = next(item for item in plan.attachments if item.kind == "caldera_access")
    assert caldera_access.vmnet != compromised_access.vmnet
    assert compromised.caldera_vmware_network == caldera_access.vmnet

    expectations = permanent_network_expectations(scenario)
    host_id = first_link.mininet_vm_id
    assert first_link.vmnet in expectations[host_id].required_networks
    assert second_link.vmnet in expectations[host_id].required_networks
    caldera = next(machine for machine in scenario.infrastructure if machine.role.value == "caldera")
    assert expectations[caldera.id].required_networks == frozenset(
        {"VMnet0", caldera_access.vmnet}
    )
    assert caldera_access.vmnet in expectations[caldera_access.mininet_vm_id].required_networks


def test_all_mininet_vmnets_require_host_connection_no(scenario):
    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet18"
    initial = plan_scenario_vmnets(
        scenario,
        (
            _record("VMnet0", host_connected=True),
            _record("VMnet18", host_connected=True),
            _record("VMnet19", host_connected=True),
        ),
    )
    attachment_records = tuple(
        _record(item.vmnet, host_connected=True) for item in initial.attachments
    )
    connected = plan_scenario_vmnets(
        scenario,
        (
            _record("VMnet0", host_connected=True),
            _record("VMnet18", host_connected=True),
            _record("VMnet19", host_connected=True),
            *attachment_records,
        ),
    )

    assert "VMnet0" not in connected.isolated_vmnets
    assert "VMnet19" not in connected.isolated_vmnets
    assert "VMnet18" in connected.isolated_vmnets
    assert set(connected.host_connected_vmnets) == set(connected.isolated_vmnets)
    assert connected.host_isolation_confirmed is False

    isolated_records = tuple(
        _record(name, host_connected=False) for name in connected.isolated_vmnets
    )
    verified = plan_scenario_vmnets(
        scenario,
        (
            _record("VMnet0", host_connected=True),
            _record("VMnet19", host_connected=True),
            *isolated_records,
        ),
    )
    assert verified.host_connected_vmnets == ()
    assert verified.host_connection_unknown == ()
    assert verified.host_isolation_confirmed is True


def test_only_managed_access_vmnets_require_dhcp_removal(scenario):
    """Le plan ne doit jamais modifier le DHCP des VMnet manuels hors raccordements."""

    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet1"
    initial = plan_scenario_vmnets(
        scenario,
        (
            _record("VMnet0", dhcp_enabled=True),
            _record("VMnet1", dhcp_enabled=True),
            _record("VMnet19", dhcp_enabled=True),
        ),
    )
    attachment_records = tuple(
        _record(
            item.vmnet,
            host_connected=False,
            dhcp_enabled=index == 0,
        )
        for index, item in enumerate(initial.attachments)
    )

    plan = plan_scenario_vmnets(
        scenario,
        (
            _record("VMnet0", dhcp_enabled=True),
            _record("VMnet1", host_connected=True, dhcp_enabled=True),
            _record("VMnet19", dhcp_enabled=True),
            *attachment_records,
        ),
    )

    assert plan.dhcp_disable_vmnets == (initial.attachments[0].vmnet,)
    assert "VMnet0" not in plan.dhcp_disable_vmnets
    assert "VMnet1" not in plan.dhcp_disable_vmnets
    assert "VMnet19" not in plan.dhcp_disable_vmnets
    assert plan.dhcp_policy_confirmed is False


def test_planner_preserves_unique_saved_attachment_but_splits_legacy_shared_vmnet(scenario):
    first, second = scenario.targets[:2]
    first.interfaces[0].vmware_network = "VMnet2"
    second.interfaces[0].vmware_network = "VMnet2"
    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet18"

    plan = plan_scenario_vmnets(
        scenario,
        (_record("VMnet0"), _record("VMnet2"), _record("VMnet18"), _record("VMnet19")),
    )

    links = [item for item in plan.attachments if item.target_id in {first.id, second.id}]
    assert links[0].vmnet == "VMnet2"
    assert links[1].vmnet != "VMnet2"
    assert links[1].create_required is True


def test_reconstruction_creates_one_mininet_adapter_per_target_attachment(scenario, tmp_path):
    for target in scenario.targets:
        for interface in target.interfaces:
            interface.vmware_network = None
    for machine in scenario.infrastructure:
        machine.interfaces = [
            interface
            for interface in machine.interfaces
            if interface.purpose == InterfacePurpose.MANAGEMENT
        ]
        machine.vmware_id = f"vm-{machine.id}"
        machine.inventory_confirmed = True
        machine.vmx_path = str(tmp_path / f"{machine.id}.vmx")
    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet18"
    attachment_plan = plan_scenario_vmnets(
        scenario,
        (_record("VMnet0"), _record("VMnet18"), _record("VMnet19")),
    )
    inventory = VmwareInventorySnapshot(
        complete=True,
        vms=[
            VmwareVMInventory(
                vmware_id=machine.vmware_id,
                name=machine.id,
                vmx_path=machine.vmx_path,
                power_state="poweredOff",
                adapters=[],
            )
            for machine in scenario.infrastructure
        ],
    ).seal()
    reconstruction = build_reconstruction_plan(
        scenario,
        inventory,
        StaticMacPolicy(
            workstation_version="test",
            first_mac="00:50:56:00:00:00",
            last_mac="00:50:56:00:ff:ff",
            validated=True,
            validation_source="test",
        ),
    )

    mininet_vm_id = scenario.mininet_instances[0].infrastructure_vm_id
    machine_plan = next(item for item in reconstruction.machines if item.machine_id == mininet_vm_id)
    served = [item for item in attachment_plan.attachments if item.mininet_vm_id == mininet_vm_id]
    expected_permanent = {"VMnet0", *(item.vmnet for item in served)}
    actual_permanent = {item.vmnet for item in machine_plan.expected if item.permanent}
    assert expected_permanent <= actual_permanent
    assert len({item.vmnet for item in served}) == len(served)


def test_validation_blocks_mininet_instance_above_vmware_nic_capacity(scenario):
    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet18"
    source = scenario.targets[0]
    # Huit raccordements, VMnet0, le réseau interne et l'amorçage exigeraient
    # onze cartes sur la même VM Mininet.
    while len(scenario.targets) < 8:
        clone = deepcopy(source)
        clone.id = f"extra_{len(scenario.targets)}"
        clone.hostname = clone.id
        clone.interfaces[0].address = f"10.10.1.{30 + len(scenario.targets)}/24"
        clone.interfaces[0].mac = f"00:50:56:20:00:{len(scenario.targets):02x}"
        scenario.targets.append(clone)
    for index, target in enumerate(scenario.targets):
        target.interfaces[0].vmware_network = f"VMnet{index + 2}"
    mininet = next(
        machine
        for machine in scenario.infrastructure
        if machine.id == scenario.mininet_instances[0].infrastructure_vm_id
    )
    mininet.interfaces.append(
        MachineInterface(
            name="ens-internal",
            address="192.170.20.1/24",
            purpose="other",
            vmware_network="VMnet18",
        )
    )

    result = validate_scenario(scenario)
    assert any(issue.code == "vmware.adapter_capacity_exceeded" for issue in result.errors)
