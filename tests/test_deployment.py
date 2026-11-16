"""Teste l'allocation statique et la reprise persistante sans contacter VMware."""

from cygil_builder.deployment import (
    DeploymentState,
    DeploymentStateStore,
    TargetDeploymentPhase,
    allocate_management_addresses,
    allocate_mininet_internal_addresses,
    allocate_reserved_management_addresses,
    synchronize_deployment_allocations,
)
from cygil_builder.lab_topology import permanent_network_expectations


def test_allocator_uses_target_count_and_excludes_host_and_infrastructure(scenario):
    """Aucune plage fixe n'est nécessaire : seules les cibles actives consomment une IP."""

    for machine in scenario.infrastructure:
        machine.inventory_confirmed = True
        machine.management_ip_confirmed = True
    allocations = allocate_management_addresses(
        scenario,
        "192.168.10.0/24",
        host_addresses={"192.168.10.1"},
        occupied_addresses={"192.168.10.2"},
    )

    assert len(allocations) == len(scenario.targets)
    assert len({item.ip for item in allocations.values()}) == len(scenario.targets)
    excluded = {"192.168.10.1", "192.168.10.2"} | {
        machine.management_ip for machine in scenario.infrastructure if machine.management_ip
    }
    assert not ({str(item.ip) for item in allocations.values()} & excluded)


def test_deployment_state_round_trip_keeps_allocations(scenario, tmp_path):
    """Une relance retrouve les réservations au lieu de créer une seconde identité."""

    allocations = allocate_management_addresses(scenario, "192.168.10.0/24", host_addresses={"192.168.10.1"})
    state = synchronize_deployment_allocations(
        DeploymentState(scenario_name=scenario.metadata.name),
        allocations,
        "192.168.10.0/24",
    )
    store = DeploymentStateStore(tmp_path / "state.json")
    store.save(state)
    loaded = store.load(scenario.metadata.name)

    assert loaded.vmnet_cidr.compressed == "192.168.10.0/24"
    assert set(loaded.targets) == set(allocations)
    assert all(item.phase == TargetDeploymentPhase.ADDRESS_RESERVED for item in loaded.targets.values())


def test_reserved_allocator_shares_vmnet0_pool_and_preserves_confirmed_exception(scenario):
    """Les VM réservées sont automatiques, sauf adresse externe explicitement confirmée."""

    scenario.infrastructure[0].management_ip = "192.168.10.7"
    scenario.infrastructure[0].management_ip_confirmed = True
    for machine in scenario.infrastructure[1:]:
        machine.management_ip_confirmed = False
        machine.management_ip = None
    targets = allocate_management_addresses(
        scenario,
        "192.168.10.0/24",
        host_addresses={"192.168.10.1"},
    )
    reserved = allocate_reserved_management_addresses(
        scenario,
        "192.168.10.0/24",
        host_addresses={"192.168.10.1"},
        target_allocations=targets,
    )
    assert str(reserved[scenario.infrastructure[0].id].ip) == "192.168.10.7"
    assert not ({item.ip for item in reserved.values()} & {item.ip for item in targets.values()})
    assert len({item.ip for item in reserved.values()}) == len(scenario.infrastructure)


def test_reserved_allocator_synchronizes_mininet_external_ip_and_management_card(scenario):
    for machine in scenario.infrastructure:
        machine.management_ip = None
        machine.management_ip_confirmed = False
    allocations = allocate_reserved_management_addresses(
        scenario,
        "192.168.10.0/24",
        host_addresses={"192.168.10.1"},
    )
    instance = scenario.mininet_instances[0]
    host = next(machine for machine in scenario.infrastructure if machine.id == instance.infrastructure_vm_id)
    assert instance.external_ip == str(allocations[host.id].ip)
    assert any(
        interface.vmware_network == "VMnet0"
        and interface.address == str(allocations[host.id])
        for interface in host.interfaces
    )


def test_internal_allocator_is_automatic_coherent_and_stable(scenario):
    for machine in scenario.infrastructure:
        machine.internal_ip = None
    for instance in scenario.mininet_instances:
        instance.internal_ip = None

    first = allocate_mininet_internal_addresses(
        scenario,
        "192.170.20.0/24",
        "VMnet18",
    )
    instance = scenario.mininet_instances[0]
    mininet_host = next(
        machine for machine in scenario.infrastructure if machine.id == instance.infrastructure_vm_id
    )
    cygil = next(machine for machine in scenario.infrastructure if machine.role.value == "cygil")
    assert instance.internal_ip == "192.170.20.1"
    assert cygil.internal_ip is None
    assert cygil.id not in first
    assert all(
        any(
            interface.vmware_network == "VMnet18"
            and interface.address == str(first[machine.id])
            for interface in machine.interfaces
        )
        for machine in (mininet_host,)
    )
    assert permanent_network_expectations(scenario)[cygil.id].required_networks == frozenset({"VMnet0"})

    # Même si les adresses répondent maintenant, une nouvelle préparation doit
    # conserver les réservations persistées plutôt que décaler tout le plan.
    second = allocate_mininet_internal_addresses(
        scenario,
        "192.170.20.0/24",
        "VMnet18",
        is_in_use=lambda _address: True,
    )
    assert second == first
