"""Vérifie que les mutations GUI mettent à jour les artefacts dépendants."""

import pytest

from cygil_builder.coherence import select_compromised_target, synchronize_scenario
from cygil_builder.models import InfrastructureRole, InterfacePurpose, MachineInterface, ObjectiveType, Scenario
from cygil_builder.service import ScenarioService


def test_target_file_creates_reward_objective(scenario):
    """Le chemin choisi sur une VM doit apparaître automatiquement dans les récompenses."""

    synchronize_scenario(scenario)
    objective = next(item for item in scenario.reward.objectives if item.type == ObjectiveType.FILE_EXFILTRATION)
    assert objective.host_name == "server_01"
    assert objective.file_path == "/home/lab/target/secret.txt"
    assert objective.source == "target_file:server_01"


def test_mininet_addresses_and_onos_are_derived_after_every_synchronization(scenario):
    """Une mutation de VM remplace toujours les anciennes copies Mininet."""

    instance = scenario.mininet_instances[0]
    machine = next(
        item for item in scenario.infrastructure if item.id == instance.infrastructure_vm_id
    )
    onos = next(
        item for item in scenario.infrastructure if item.role == InfrastructureRole.ONOS
    )
    instance.external_ip = "203.0.113.10"
    instance.internal_ip = "203.0.113.11"
    instance.onos_controller_id = "ancien-onos"
    machine.management_ip = "192.168.10.44"
    machine.internal_ip = "192.170.20.44"

    synchronize_scenario(scenario)

    assert instance.external_ip == machine.management_ip
    assert instance.internal_ip == machine.internal_ip
    assert instance.onos_controller_id == onos.id


def test_loading_and_saving_replace_stale_mininet_copies(scenario, tmp_path):
    """La dérivation s'applique aux deux frontières de persistance YAML."""

    payload = scenario.model_dump(mode="json")
    payload["mininet_instances"][0]["external_ip"] = "203.0.113.20"
    payload["mininet_instances"][0]["internal_ip"] = "203.0.113.21"
    payload["mininet_instances"][0]["onos_controller_id"] = "onos-obsolete"
    loaded = Scenario.model_validate(payload)
    instance = loaded.mininet_instances[0]
    machine = next(
        item for item in loaded.infrastructure if item.id == instance.infrastructure_vm_id
    )
    onos = next(
        item for item in loaded.infrastructure if item.role == InfrastructureRole.ONOS
    )

    assert instance.external_ip == machine.management_ip
    assert instance.internal_ip == machine.internal_ip
    assert instance.onos_controller_id == onos.id

    instance.external_ip = "198.51.100.20"
    instance.internal_ip = "198.51.100.21"
    instance.onos_controller_id = "encore-obsolete"
    destination = ScenarioService().save(loaded, tmp_path / "scenario.yml")
    reloaded = Scenario.from_yaml(destination)

    assert reloaded.mininet_instances[0].external_ip == machine.management_ip
    assert reloaded.mininet_instances[0].internal_ip == machine.internal_ip
    assert reloaded.mininet_instances[0].onos_controller_id == onos.id


def test_several_targets_can_each_contribute_a_file_objective(scenario):
    """Les dépôts de plusieurs VM doivent produire plusieurs objectifs CyGIL."""

    workstation = next(target for target in scenario.targets if target.id == "workstation_01")
    workstation.target_file_path = r"C:\Lab\evidence.txt"
    workstation.target_file_worth = 75

    synchronize_scenario(scenario)
    derived = [
        objective
        for objective in scenario.reward.objectives
        if objective.source.startswith("target_file:")
    ]

    assert {objective.host_name for objective in derived} == {"workstation_01", "server_01"}
    assert {objective.file_path for objective in derived} == {r"C:\Lab\evidence.txt", "/home/lab/target/secret.txt"}


def test_target_accepts_multiple_interfaces(scenario):
    """Une carte de gestion supplémentaire ne doit pas remplacer la carte de scénario."""

    target = scenario.targets[0]
    target.interfaces.append(
        MachineInterface(name="Ethernet1", address="192.168.50.20/24", purpose=InterfacePurpose.MANAGEMENT)
    )
    assert len(target.interfaces) == 2
    assert {item.purpose for item in target.interfaces} == {InterfacePurpose.SCENARIO, InterfacePurpose.MANAGEMENT}


def test_selecting_compromised_target_is_exclusive_and_moves_caldera_to_same_switch(scenario):
    """Le choix métier doit produire un seul hand et un accès CALDERA dérivé."""

    selected = next(target for target in scenario.targets if target.id == "server_01")
    caldera = next(
        machine
        for machine in scenario.infrastructure
        if machine.role == InfrastructureRole.CALDERA
    )
    previous_interface = next(
        interface
        for interface in caldera.interfaces
        if interface.purpose == InterfacePurpose.SCENARIO
    )
    previous_name = previous_interface.name

    select_compromised_target(scenario, selected.id, "10.10.2.5/24")

    assert [target.id for target in scenario.targets if target.compromised] == [selected.id]
    assert [target.id for target in scenario.targets if target.hand.enabled] == [selected.id]
    assert [target.id for target in scenario.targets if target.initial_red_hand] == [selected.id]
    caldera_interfaces = [
        interface
        for interface in caldera.interfaces
        if interface.purpose == InterfacePurpose.SCENARIO
    ]
    assert len(caldera_interfaces) == 1
    assert caldera_interfaces[0].network == "servers"
    assert caldera_interfaces[0].connected_switch == "s2"
    assert caldera_interfaces[0].mininet_instance == "mininet_primary"
    assert caldera_interfaces[0].address == "10.10.2.5/24"
    assert caldera_interfaces[0].name == previous_name


def test_new_caldera_access_does_not_invent_or_require_guest_interface_name(scenario):
    """La future découverte par MAC doit pouvoir partir d'un nom invité vide."""

    caldera = next(
        machine
        for machine in scenario.infrastructure
        if machine.role == InfrastructureRole.CALDERA
    )
    caldera.interfaces = [
        interface
        for interface in caldera.interfaces
        if interface.purpose != InterfacePurpose.SCENARIO
    ]

    select_compromised_target(scenario, "workstation_01", "10.10.1.5/24")

    derived = next(
        interface
        for interface in caldera.interfaces
        if interface.purpose == InterfacePurpose.SCENARIO
    )
    assert derived.name == ""
    assert derived.connected_switch == "s1"


def test_caldera_access_rejects_an_address_already_used_by_a_target(scenario):
    target = next(target for target in scenario.targets if target.id == "workstation_01")

    with pytest.raises(ValueError, match="déjà utilisée"):
        select_compromised_target(scenario, target.id, target.interfaces[0].address)
