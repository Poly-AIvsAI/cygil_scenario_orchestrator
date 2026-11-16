"""Contrôles des plans invités sans contacter le banc réel."""

from subprocess import CompletedProcess

from cygil_builder.deployment import (
    DeploymentState,
    PingSessionState,
    refresh_snapshot_authorization,
)
from cygil_builder.guest_control import GuestControlService, guest_confirmation_token
from cygil_builder.guest_files import GuestFileService, file_confirmation_token
from cygil_builder.guest_network import GuestNetworkService
from cygil_builder.lab_topology import permanent_network_expectations, resolve_ping_routes
from cygil_builder.models import (
    GuestAccessConfig,
    GuestCommunicator,
    GuestDesktopConfig,
    GuestNetworkBackend,
    IsolationInterfaceConfig,
    Scenario,
)
from cygil_builder.snapshot_control import SnapshotSafetyError, SnapshotService
from cygil_builder.vmware_control import VmwareReservedAdapter, vmrest_confirmation_token
import pytest


def _prepared_scenario() -> Scenario:
    scenario = Scenario.from_yaml("examples/scenario_two.yml")
    windows = next(target for target in scenario.targets if target.id == "2-WINDOWS")
    windows.caldera_vmware_network = "VMnet17"
    windows.temporary_management.assigned_address = "192.168.10.30/24"
    windows.guest_access = GuestAccessConfig(
        communicator=GuestCommunicator.WINRM,
        username="lab-admin",
        password_secret="WINDOWS_LAB_PASSWORD",
    )
    windows.guest_desktop = GuestDesktopConfig(
        session_user="lab-admin",
        terminal_executable="powershell.exe",
        visible_terminal_validated=True,
    )
    windows.isolation_interfaces = [
        IsolationInterfaceConfig(
            network="VMnet0",
            guest_name="Ethernet 2",
            mac="00:50:56:aa:bb:cc",
        )
    ]
    return scenario


def test_ping_routes_use_only_an_explicit_common_scenario_network():
    scenario = _prepared_scenario()
    routes = resolve_ping_routes(scenario, "2-WINDOWS", "1-UBUNTU")

    assert routes
    assert {route.network for route in routes} == {"subnet_1"}
    assert routes[0].destination_address == "10.0.0.1"
    assert resolve_ping_routes(scenario, "cygil", "2-WINDOWS") == []


def test_role_topology_separates_cygil_and_caldera_mininet_access():
    scenario = _prepared_scenario()
    expectations = permanent_network_expectations(scenario)

    assert expectations["cygil"].required_networks == frozenset({"VMnet0"})
    assert expectations["5-Caldera-Server-VM"].required_networks == frozenset(
        {"VMnet0", "VMnet17"}
    )


def test_visible_windows_command_is_confirmable_and_contains_no_password():
    service = GuestControlService(_prepared_scenario())
    plan = service.build_visible_command_plan(
        "2-WINDOWS",
        "Get-NetAdapter",
        elevated=True,
    )

    assert "New-ScheduledTaskAction" in plan.remote_command
    assert "WINDOWS_LAB_PASSWORD" not in plan.preview()
    assert len(guest_confirmation_token([plan])) == 12
    assert service.execute([plan])[0].mode == "dry-run"


def test_isolation_disables_guest_interface_and_never_hot_removes_adapter():
    service = GuestControlService(_prepared_scenario())
    plans = service.build_isolation_plans("VMnet0")

    assert len(plans) == 1
    assert plans[0].expected_disconnect is True
    assert "Disable-NetAdapter" not in plans[0].remote_command
    assert "EncodedCommand" in plans[0].remote_command
    assert "vmrun" not in plans[0].remote_command.casefold()
    assert "delete" not in plans[0].remote_command.casefold()


def test_snapshot_lock_requires_every_explicit_proof():
    state = DeploymentState(scenario_name="scenario_two")
    state.lab_control.ping_sessions.append(
        PingSessionState(
            source_id="2-WINDOWS",
            destination_id="1-UBUNTU",
            destination_address="10.0.0.1",
            network="subnet_1",
            active_confirmed_by_user=True,
        )
    )
    state.lab_control.bench_confirmed = True
    state.lab_control.air_gap_verified = True

    assert refresh_snapshot_authorization(state) is False
    state.lab_control.all_vms_running = True
    assert refresh_snapshot_authorization(state) is True


def test_guest_file_plan_keeps_local_source_out_of_cygil_payload(tmp_path):
    scenario = _prepared_scenario()
    source = tmp_path / "evidence.txt"
    source.write_text("lab", encoding="utf-8")
    windows = next(target for target in scenario.targets if target.id == "2-WINDOWS")
    windows.target_file_source_path = str(source)
    windows.target_file_path = r"C:\Lab\evidence.txt"

    service = GuestFileService(scenario)
    plans = service.build_plans()
    selected = next(plan for plan in plans if plan.machine_id == "2-WINDOWS")

    assert selected.source_path == str(source.resolve())
    assert selected.destination_path == r"C:\Lab\evidence.txt"
    assert len(file_confirmation_token(plans)) == 12
    assert service.execute(plans)[0].mode == "dry-run"


def test_vmrun_snapshot_plan_covers_reserved_and_targets_without_vagrant():
    scenario = _prepared_scenario()
    scenario.lab_control.snapshot_with_memory = False
    for target in scenario.targets:
        target.vmx_path = rf"C:\Lab\{target.id}\{target.id}.vmx"
    service = SnapshotService(
        scenario,
        DeploymentState(scenario_name=scenario.metadata.name),
        vmrun_path=r"C:\VMware\vmrun.exe",
    )

    commands = service.build_commands()

    assert {command.machine_id for command in commands} == {
        machine.id for machine in scenario.infrastructure
    } | {target.id for target in scenario.targets if target.snapshot}
    assert all(command.arguments[3] == "snapshot" for command in commands)
    assert all("vagrant" not in command.display().casefold() for command in commands)
    assert all(result.mode == "dry-run" for result in service.execute(commands))


def test_vmrun_refuses_to_claim_memory_snapshots():
    scenario = _prepared_scenario()
    scenario.lab_control.snapshot_with_memory = True
    service = SnapshotService(
        scenario,
        DeploymentState(scenario_name=scenario.metadata.name),
        vmrun_path=r"C:\VMware\vmrun.exe",
    )

    with pytest.raises(SnapshotSafetyError, match="mémoire"):
        service.build_commands()


def test_windows_network_plan_uses_model_address_and_dns_disable_option():
    scenario = _prepared_scenario()
    windows = next(target for target in scenario.targets if target.id == "2-WINDOWS")
    windows.network_backend = GuestNetworkBackend.WINDOWS_POWERSHELL
    scenario.targets = [windows]
    scenario.infrastructure = []
    windows.guest_access.connection_address = "172.30.40.25"

    plans = GuestNetworkService(scenario).build_plans()

    assert len(plans) == 1
    assert "New-NetIPAddress" in plans[0].remote_command
    assert "10.0.0.2" in plans[0].remote_command
    assert "Set-DnsClient" in plans[0].remote_command


def test_target_uses_bootstrap_lease_without_configuring_vmnet0():
    scenario = _prepared_scenario()
    windows = next(target for target in scenario.targets if target.id == "2-WINDOWS")
    windows.network_backend = GuestNetworkBackend.WINDOWS_POWERSHELL
    windows.guest_access.connection_address = "172.30.40.25"
    scenario.targets = [windows]
    scenario.infrastructure = []

    plan = GuestNetworkService(scenario).build_plans()[0]

    assert plan.address == "172.30.40.25"
    assert "192.168.10.30" not in plan.remote_command
    assert "VMnet0" not in plan.remote_command
    assert "Configurer 1 interface(s)" in plan.description


def test_running_vm_inspection_is_read_only_and_covers_every_snapshot(monkeypatch):
    scenario = _prepared_scenario()
    scenario.lab_control.snapshot_with_memory = False
    for target in scenario.targets:
        target.vmx_path = rf"C:\Lab\{target.id}\{target.id}.vmx"
    running_paths = [
        *(machine.vmx_path for machine in scenario.infrastructure),
        *(target.vmx_path for target in scenario.targets if target.snapshot),
    ]

    def fake_run(arguments, **kwargs):
        assert arguments[-1] == "list"
        return CompletedProcess(arguments, 0, "Total running VMs: 9\n" + "\n".join(running_paths), "")

    monkeypatch.setattr("cygil_builder.snapshot_control.subprocess.run", fake_run)
    service = SnapshotService(
        scenario,
        DeploymentState(scenario_name=scenario.metadata.name),
        vmrun_path=r"C:\VMware\vmrun.exe",
    )

    states = service.inspect_running_vms()

    assert states and all(states.values())


def test_reserved_bootstrap_plan_uses_post_only_and_never_vagrant_or_delete():
    scenario = _prepared_scenario()
    scenario.vagrant.bootstrap_network = "VMnet9"
    for index, machine in enumerate(scenario.infrastructure):
        machine.vmware_id = f"vm-{index}"
        machine.inventory_confirmed = True

    adapter = VmwareReservedAdapter(scenario, "", "")
    plans = adapter.build_bootstrap_plans()

    assert {plan.machine_id for plan in plans} == {
        machine.id for machine in scenario.infrastructure
    }
    assert all(plan.method == "POST" for plan in plans)
    assert all(plan.body == {"type": "custom", "vmnet": "VMnet9"} for plan in plans)
    assert all("delete" not in plan.preview().casefold() for plan in plans)
    assert all("vagrant" not in plan.preview().casefold() for plan in plans)
    assert len(vmrest_confirmation_token(plans)) == 12
    assert all(result.mode == "dry-run" for result in adapter.execute(plans))
