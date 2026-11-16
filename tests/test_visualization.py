"""Vérifie la séparation déterministe des vues VMware et SDN."""

import re

from cygil_builder.visualization import render_infrastructure_view, render_sdn_view


def _assert_balanced_subgraphs(diagram: str) -> None:
    """Effectue le contrôle structurel minimal avant envoi à Mermaid."""

    assert len(re.findall(r"^subgraph ", diagram, re.MULTILINE)) == len(
        re.findall(r"^end$", diagram, re.MULTILINE)
    )


def test_sdn_view_contains_only_logical_topology(scenario):
    diagram = render_sdn_view(scenario)
    assert diagram.startswith("flowchart LR")
    assert "workstation_01" in diagram
    assert "ONOS Controller" in diagram
    assert "OF:6653" in diagram
    assert 'n_switch_s1 ---|"OVS local"| n_switch_s2' in diagram
    assert 'n_service_caldera ---|"Access CALDERA"| n_switch_s1' in diagram
    assert "hand via Mininet" not in diagram
    assert "VMnet0" not in diagram
    assert "Provisioning Network" not in diagram
    _assert_balanced_subgraphs(diagram)


def test_infrastructure_view_contains_vm_boundaries_and_networks(scenario):
    scenario.vagrant.bootstrap_network = "VMnet19"
    scenario.vagrant.mininet_internal_network = "VMnet18"
    compromised = next(target for target in scenario.targets if target.compromised)
    compromised.caldera_vmware_network = "VMnet17"
    for index, target in enumerate(scenario.targets, start=2):
        target.interfaces[0].vmware_network = f"VMnet{index}"

    diagram = render_infrastructure_view(scenario)
    assert "Management Network" in diagram
    assert "Orchestration Network" in diagram
    target_block = diagram.split('subgraph n_vm_workstation_01', 1)[1].split("end", 1)[0]
    assert "VMnet0" not in target_block
    assert "VMnet19" in target_block
    assert "Provisioning Network" not in diagram
    assert diagram.count("_orchestration") >= len(scenario.infrastructure) + len(scenario.targets)
    assert "Control-Channel Network" in diagram
    assert "CALDERA-Link" in diagram
    assert "Access-Link workstation_01" in diagram
    assert 'subgraph n_vm_workstation_01["workstation_01 · cible compromise"]' in diagram
    assert "OVS local" not in diagram
    assert "OF:6653" not in diagram
    _assert_balanced_subgraphs(diagram)


def test_views_are_deterministic(scenario):
    assert render_sdn_view(scenario) == render_sdn_view(scenario)
    assert render_infrastructure_view(scenario) == render_infrastructure_view(scenario)


def test_infrastructure_view_reflects_interface_edits_immediately(scenario):
    """Le nom et l'adresse modifiés doivent changer le contenu Mermaid."""

    target = scenario.targets[0]
    target.interfaces[0].vmware_network = "VMnet12"
    before = render_infrastructure_view(scenario)

    target.interfaces[0].name = "Ethernet-Lab"
    target.interfaces[0].address = "10.10.1.99/24"
    after = render_infrastructure_view(scenario)

    assert before != after
    assert "Ethernet-Lab · 10.10.1.99/24" in after
