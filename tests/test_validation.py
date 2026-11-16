"""Teste les règles transversales qui protègent la cohérence du scénario."""

import pytest
from pydantic import ValidationError

from cygil_builder.coherence import synchronize_scenario
from cygil_builder.models import InfrastructureRole, InterfacePurpose, MininetInstance, NetworkSwitch, Scenario
from cygil_builder.validation import validate_scenario


def test_example_is_valid_with_expected_warning(scenario):
    result = validate_scenario(scenario)
    assert result.is_valid
    assert any(issue.code == "cygil.no_launch_command" for issue in result.warnings)


def test_new_blank_scenario_loads_no_example_topology_or_targets():
    """Le bouton Nouveau repose sur un canevas neuf, pas sur scenario_two nettoyé."""

    scenario = Scenario.new_blank("scenario_neuf")
    assert scenario.networks == []
    assert scenario.switches == []
    assert scenario.mininet_instances == []
    assert scenario.targets == []
    assert {machine.role for machine in scenario.infrastructure} == set(InfrastructureRole)
    assert all(not machine.interfaces and not machine.vmware_id for machine in scenario.infrastructure)


def test_first_switch_in_blank_scenario_remains_typed_after_synchronization():
    """Reproduit Nouveau scénario → instance Mininet → premier switch."""

    scenario = Scenario.new_blank("scenario_switch")
    scenario.mininet_instances = [
        MininetInstance(name="Mininet", infrastructure_vm_id="mininet")
    ]
    scenario.switches = [
        *scenario.switches,
        NetworkSwitch(name="s1", mininet_instance="Mininet"),
    ]

    synchronize_scenario(scenario)

    assert len(scenario.switches) == 1
    assert isinstance(scenario.switches[0], NetworkSwitch)
    assert scenario.switches[0].name == "s1"


def test_legacy_target_mac_is_discarded_instead_of_becoming_vmware_request(scenario):
    """Une ancienne MAC d'hôte CyGIL ne doit plus piloter une carte VMware."""

    payload = scenario.model_dump(mode="json")
    payload["targets"][0]["mac"] = "00:00:00:00:00:02"
    payload["targets"][0]["interfaces"][0]["mac"] = None
    migrated = Scenario.model_validate(payload)
    assert "mac" not in migrated.targets[0].model_dump()
    assert migrated.targets[0].interfaces[0].mac is None


def test_duplicate_address_is_rejected(scenario):
    scenario.targets[1].interfaces[0].address = scenario.targets[0].interfaces[0].address
    result = validate_scenario(scenario)
    assert any(issue.code == "interface.address_outside" for issue in result.errors)
    assert any(issue.code == "interface.duplicate_address" for issue in result.errors)


def test_reverse_switch_link_is_rejected_as_same_bidirectional_link(scenario):
    """Un lien OVS ou GRE ne peut pas être redéclaré dans le sens inverse."""

    scenario.mininet_instances[0].switch_links["s2"] = ["s1"]
    result = validate_scenario(scenario)
    assert any(issue.code == "switch_link.duplicate" for issue in result.errors)


def test_same_bidirectional_link_cannot_be_declared_twice(scenario):
    scenario.mininet_instances[0].switch_links["s1"].append("s2")
    result = validate_scenario(scenario)
    assert any(issue.code == "switch_link.duplicate" for issue in result.errors)


def test_exactly_one_compromised_target_is_required(scenario):
    """Le schéma CALDERA CyGIL reste non ambigu avec un seul hand initial."""

    scenario.targets[0].compromised = False
    scenario.targets[0].hand.enabled = False
    scenario.targets[0].initial_red_hand = False
    assert any(
        issue.code == "target.compromised_count"
        for issue in validate_scenario(scenario).errors
    )

    scenario.targets[0].compromised = True
    scenario.targets[0].hand.enabled = True
    scenario.targets[0].initial_red_hand = True
    scenario.targets[1].compromised = True
    scenario.targets[1].hand.enabled = True
    scenario.targets[1].initial_red_hand = True
    assert any(
        issue.code == "target.compromised_count"
        for issue in validate_scenario(scenario).errors
    )


def test_caldera_access_must_share_compromised_target_switch(scenario):
    """Un lien CALDERA valide ne peut pas viser un autre switch OVS."""

    caldera = next(machine for machine in scenario.infrastructure if machine.role.value == "caldera")
    caldera_interface = next(
        interface
        for interface in caldera.interfaces
        if interface.purpose == InterfacePurpose.SCENARIO
    )
    caldera_interface.connected_switch = "s2"

    assert any(
        issue.code == "caldera.topology_mismatch"
        for issue in validate_scenario(scenario).errors
    )

def test_target_requires_exactly_one_local_scenario_interface(scenario):
    """Une cible ne peut ni multiplier ses accès ni viser un switch distant."""

    target = scenario.targets[0]
    target.interfaces.append(target.interfaces[0].model_copy(deep=True))
    assert any(
        issue.code == "target.scenario_interface_count"
        for issue in validate_scenario(scenario).errors
    )

    target.interfaces = target.interfaces[:1]
    target.interfaces[0].mininet_instance = "instance_inconnue"
    assert any(
        issue.code == "target.remote_switch_forbidden"
        for issue in validate_scenario(scenario).errors
    )

def test_multiple_mininet_vms_are_allowed_but_other_reserved_roles_remain_unique(scenario):
    """Le nombre de VM Mininet est extensible sans autoriser deux CALDERA."""

    data = scenario.model_dump(mode="json")
    second_mininet = dict(data["infrastructure"][-1])
    second_mininet["id"] = "mininet_secondary_vm"
    second_mininet["interfaces"] = []
    data["infrastructure"].append(second_mininet)
    assert len(Scenario.model_validate(data).infrastructure) == 5

    duplicate_caldera = dict(data["infrastructure"][1])
    duplicate_caldera["id"] = "caldera_duplicate"
    data["infrastructure"].append(duplicate_caldera)
    with pytest.raises(ValidationError):
        Scenario.model_validate(data)


def test_legacy_mininet_instance_is_automatically_associated(scenario):
    """Un ancien YAML à une seule VM Mininet reste chargeable sans nouveau champ."""

    data = scenario.model_dump(mode="json")
    data["mininet_instances"][0].pop("infrastructure_vm_id")
    migrated = Scenario.model_validate(data)
    assert migrated.mininet_instances[0].infrastructure_vm_id == "mininet"


def test_unmapped_mininet_instance_is_rejected(scenario):
    """La validation globale interdit une section YAML sans VM VMware correspondante."""

    scenario.mininet_instances[0].infrastructure_vm_id = None
    result = validate_scenario(scenario)
    assert any(issue.code == "mininet.vm_missing" for issue in result.errors)


def test_missing_onos_has_one_dedicated_validation_error(scenario):
    """Les instances n'ajoutent pas une erreur par ancienne référence ONOS."""

    scenario.infrastructure = [
        machine
        for machine in scenario.infrastructure
        if machine.role != InfrastructureRole.ONOS
    ]
    scenario.mininet_instances[0].onos_controller_id = "ancien-onos"

    synchronize_scenario(scenario)
    result = validate_scenario(scenario)

    assert [issue.code for issue in result.errors].count("infrastructure.onos_count") == 1
    assert not any(issue.code == "mininet.onos_controller_invalid" for issue in result.errors)
    assert scenario.mininet_instances[0].onos_controller_id is None
