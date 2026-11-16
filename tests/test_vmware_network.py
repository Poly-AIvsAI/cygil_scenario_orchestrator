"""Non-régression de l'inventaire MAC et de la reconstruction VMware sécurisée."""

from pathlib import Path

import pytest

from cygil_builder.compilers.network import compile_network
from cygil_builder.exceptions import CompilationError
from cygil_builder.models import (
    GuestAccessConfig,
    GuestCommunicator,
    InterfacePurpose,
    MacAddressSource,
    VmwareNetworkAdapter,
)
from cygil_builder.vmware_network import (
    NetworkReconstructionPlan,
    NetworkRollbackBundle,
    ReservedVMNetworkPlan,
    StaticMacPolicy,
    VmwareInventorySnapshot,
    VmwareNetworkError,
    VmwareVMInventory,
    VmxNetworkReconstructor,
    associate_bootstrap_leases,
    generate_stable_mac,
    normalize_mac,
    plan_target_interfaces,
    read_vmx_adapters,
    reconcile_applied_adapters,
    validate_requested_macs,
)


def _adapter(index: int, vmnet: str, mac: str) -> VmwareNetworkAdapter:
    """Construit une carte observée minimale pour les instantanés de test."""

    return VmwareNetworkAdapter(
        vmware_adapter_index=index,
        vmnet=vmnet,
        applied_mac=mac,
        mac_source=MacAddressSource.OBSERVED,
        verified=True,
    )


def _inventory(vmx: Path, *, fingerprint_mac: str = "00:50:56:00:00:01") -> VmwareInventorySnapshot:
    """Scelle un inventaire d'une VM sans effectuer d'appel VMware réel."""

    return VmwareInventorySnapshot(
        complete=True,
        vms=[VmwareVMInventory(
            vmware_id="reserved-1",
            name="reserved",
            vmx_path=str(vmx),
            power_state="poweredOff",
            adapters=[_adapter(0, "VMnet0", fingerprint_mac)],
        )],
    ).seal()


def test_mac_normalization_rejects_multicast_and_accepts_separators():
    """Le validateur compare sans casse ni séparateur et refuse le multicast."""

    assert normalize_mac("00-50-56-AA-bb-CC") == "00:50:56:aa:bb:cc"
    with pytest.raises(VmwareNetworkError, match="multicast"):
        normalize_mac("01:00:5e:00:00:01")


def test_static_mac_generation_is_stable_bounded_and_requires_confirmed_policy():
    """Aucun préfixe VMware n'est supposé tant que la politique n'est pas validée."""

    unconfirmed = StaticMacPolicy(
        workstation_version="test",
        first_mac="00:50:56:00:00:00",
        last_mac="00:50:56:00:00:ff",
    )
    with pytest.raises(VmwareNetworkError, match="confirmée"):
        generate_stable_mac(unconfirmed, "scenario", "cygil", 0, set())
    confirmed = unconfirmed.model_copy(update={"validated": True, "validation_source": "essai local"})
    first = generate_stable_mac(confirmed, "scenario", "cygil", 0, set())
    assert first == generate_stable_mac(confirmed, "scenario", "cygil", 0, set())
    second = generate_stable_mac(confirmed, "scenario", "cygil", 0, {first})
    assert second != first


def test_global_collision_with_vm_outside_scenario_is_rejected(scenario, tmp_path):
    """Une ancienne VM hors scénario reste dans l'ensemble global d'exclusion."""

    requested = "00:50:56:00:00:44"
    scenario.targets[0].interfaces[0].mac = requested
    inventory = VmwareInventorySnapshot(
        complete=True,
        vms=[VmwareVMInventory(
            vmware_id="foreign",
            name="old-target",
            vmx_path=str(tmp_path / "old.vmx"),
            adapters=[_adapter(0, "VMnet2", requested)],
        )],
    ).seal()
    with pytest.raises(VmwareNetworkError, match="déjà utilisée"):
        validate_requested_macs(scenario, inventory)


def test_target_interfaces_receive_stable_unique_macs_and_indices(scenario):
    inventory = VmwareInventorySnapshot(complete=True, vms=[]).seal()
    policy = StaticMacPolicy(
        workstation_version="test",
        first_mac="00:50:56:00:00:00",
        last_mac="00:50:56:00:ff:ff",
        validated=True,
        validation_source="test",
    )
    next_vmnet = 2
    for target in scenario.targets:
        for interface in target.interfaces:
            interface.mac = None
            interface.vmware_adapter_index = None
            interface.vmware_network = f"VMnet{next_vmnet}"
            next_vmnet += 1

    plan_target_interfaces(scenario, inventory, policy)
    first = [
        (interface.mac, interface.vmware_adapter_index)
        for target in scenario.targets
        for interface in target.interfaces
    ]
    assert all(mac and index is not None for mac, index in first)
    assert len({mac for mac, _ in first}) == len(first)

    plan_target_interfaces(scenario, inventory, policy)
    assert first == [
        (interface.mac, interface.vmware_adapter_index)
        for target in scenario.targets
        for interface in target.interfaces
    ]


def test_vmx_inventory_and_reconstruction_preserve_disks_and_unselected_vm(tmp_path):
    """La mutation remplace ethernet uniquement et ne touche aucune VM non sélectionnée."""

    selected = tmp_path / "selected.vmx"
    unselected = tmp_path / "unselected.vmx"
    initial = (
        '.encoding = "UTF-8"\n'
        'scsi0:0.fileName = "disk.vmdk"\n'
        'ethernet0.present = "TRUE"\n'
        'ethernet0.connectionType = "custom"\n'
        'ethernet0.vnet = "VMnet9"\n'
        'ethernet0.address = "00:50:56:00:00:01"\n'
    )
    selected.write_text(initial, encoding="utf-8")
    unselected.write_text(initial, encoding="utf-8")
    inventory = _inventory(selected)
    expected = [_adapter(0, "VMnet0", "00:50:56:00:00:02").model_copy(update={
        "requested_mac": "00:50:56:00:00:02",
        "applied_mac": None,
        "verified": False,
    })]
    plan = NetworkReconstructionPlan(
        scenario_name="test",
        inventory_fingerprint=inventory.fingerprint,
        machines=[ReservedVMNetworkPlan(
            machine_id="cygil",
            vmware_id="reserved-1",
            vmx_path=str(selected),
            observed=inventory.vms[0].adapters,
            expected=expected,
        )],
    ).seal()
    reconstructor = VmxNetworkReconstructor(lambda _: "poweredOff", tmp_path / "backup")
    rollback = reconstructor.create_backup(plan)
    reconstructor.apply(plan, inventory, rollback, confirmation_token=plan.confirmation_token)
    content = selected.read_text(encoding="utf-8")
    assert 'scsi0:0.fileName = "disk.vmdk"' in content
    assert 'ethernet0.vnet = "VMnet0"' in content
    assert unselected.read_text(encoding="utf-8") == initial
    assert read_vmx_adapters(selected)[0].applied_mac == "00:50:56:00:00:02"


def test_reconstruction_rejects_running_vm_and_changed_inventory(tmp_path):
    """Une VM active ou une relecture différente invalide le plan avant toute écriture."""

    vmx = tmp_path / "machine.vmx"
    vmx.write_text('ethernet0.vnet = "VMnet0"\n', encoding="utf-8")
    inventory = _inventory(vmx)
    plan = NetworkReconstructionPlan(
        scenario_name="test",
        inventory_fingerprint=inventory.fingerprint,
        machines=[ReservedVMNetworkPlan(
            machine_id="cygil",
            vmware_id="reserved-1",
            vmx_path=str(vmx),
            observed=inventory.vms[0].adapters,
            expected=[_adapter(0, "VMnet0", "00:50:56:00:00:01").model_copy(update={
                "requested_mac": "00:50:56:00:00:01",
            })],
        )],
    ).seal()
    stopped = VmxNetworkReconstructor(lambda _: "poweredOff", tmp_path / "backup")
    rollback = stopped.create_backup(plan)
    running = VmxNetworkReconstructor(lambda _: "poweredOn", tmp_path / "backup-running")
    with pytest.raises(VmwareNetworkError, match="poweredOff"):
        running.apply(plan, inventory, rollback, confirmation_token=plan.confirmation_token)
    changed = _inventory(vmx, fingerprint_mac="00:50:56:00:00:09")
    with pytest.raises(VmwareNetworkError, match="changé"):
        stopped.apply(plan, changed, rollback, confirmation_token=plan.confirmation_token)


def test_restore_requires_separate_confirmation(tmp_path):
    """La restauration possède son propre jeton et remet exactement le VMX initial."""

    vmx = tmp_path / "machine.vmx"
    vmx.write_text('displayName = "before"\n', encoding="utf-8")
    inventory = _inventory(vmx)
    plan = NetworkReconstructionPlan(
        scenario_name="test",
        inventory_fingerprint=inventory.fingerprint,
        machines=[ReservedVMNetworkPlan(
            machine_id="cygil",
            vmware_id="reserved-1",
            vmx_path=str(vmx),
            observed=[],
            expected=[_adapter(0, "VMnet0", "00:50:56:00:00:02").model_copy(update={
                "requested_mac": "00:50:56:00:00:02",
            })],
        )],
    ).seal()
    reconstructor = VmxNetworkReconstructor(lambda _: "poweredOff", tmp_path / "backup")
    rollback = reconstructor.create_backup(plan)
    vmx.write_text('displayName = "after"\n', encoding="utf-8")
    with pytest.raises(VmwareNetworkError, match="restauration"):
        reconstructor.restore(plan, rollback, confirmation_token=plan.confirmation_token)
    reconstructor.restore(
        plan,
        rollback,
        confirmation_token=reconstructor.restore_confirmation_token(plan),
    )
    assert vmx.read_text(encoding="utf-8") == 'displayName = "before"\n'


def test_final_cygil_compile_requires_verified_applied_mac(scenario):
    """Le YAML final refuse une MAC seulement demandée et utilise la valeur relue."""

    with pytest.raises(CompilationError, match="relue"):
        compile_network(scenario, require_verified_macs=True)
    for index, target in enumerate(scenario.targets, start=1):
        interface = next(item for item in target.interfaces if item.purpose == InterfacePurpose.SCENARIO)
        interface.applied_mac = normalize_mac(f"00:50:56:00:00:{index:02x}")
        interface.mac_verified = True
    compiled = compile_network(scenario, require_verified_macs=True)
    first_host = compiled["mininet_instances"][0]["hosts"][0]
    assert first_host["mac"]


def test_reserved_reconciliation_records_bootstrap_identity_automatically(scenario):
    """La carte DHCP relue devient l'identité d'amorçage sans saisie manuelle."""

    machine = scenario.infrastructure[0]
    machine.vmware_id = "reserved-1"
    scenario.vagrant.bootstrap_network = "VMnet19"
    management = _adapter(0, "VMnet0", "00:50:56:00:00:10")
    bootstrap = _adapter(1, "VMnet19", "00:50:56:00:00:19")
    expected = [
        item.model_copy(update={"requested_mac": item.applied_mac, "applied_mac": None})
        for item in (management, bootstrap)
    ]
    plan = NetworkReconstructionPlan(
        scenario_name=scenario.metadata.name,
        inventory_fingerprint="inventory",
        machines=[ReservedVMNetworkPlan(
            machine_id=machine.id,
            vmware_id=machine.vmware_id,
            vmx_path="reserved.vmx",
            observed=[],
            expected=expected,
        )],
    ).seal()
    observed = VmwareInventorySnapshot(
        complete=True,
        vms=[VmwareVMInventory(
            vmware_id=machine.vmware_id,
            name=machine.id,
            vmx_path="reserved.vmx",
            adapters=[management, bootstrap],
        )],
    ).seal()

    reconcile_applied_adapters(scenario, plan, observed)

    identity = next(item for item in machine.isolation_interfaces if item.network == "VMnet19")
    assert identity.mac == "00:50:56:00:00:19"
    assert identity.vmware_adapter_index == 1


def test_bootstrap_lease_is_associated_from_verified_vmware_adapter(scenario):
    """Un bail renseigne automatiquement l'adresse de connexion de la VM réservée."""

    machine = scenario.infrastructure[0]
    scenario.vagrant.bootstrap_network = "VMnet19"
    machine.guest_access = GuestAccessConfig(
        communicator=GuestCommunicator.SSH,
        username="cygil",
    )
    machine.observed_adapters = [_adapter(2, "vmnet19", "00:50:56:00:00:29")]

    matched = associate_bootstrap_leases(
        scenario,
        {"00-50-56-00-00-29": "192.168.81.42"},
    )

    assert matched == {machine.id: "192.168.81.42"}
    assert str(machine.guest_access.connection_address) == "192.168.81.42"
