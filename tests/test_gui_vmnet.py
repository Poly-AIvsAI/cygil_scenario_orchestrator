"""Tests ciblés des règles de sélection des VMnet dans la GUI."""

from ipaddress import ip_network

import pytest

from cygil_builder.gui import _is_vmnet0, _resolve_internal_vmnet_cidr, _same_vmnet_name
from cygil_builder.models import VagrantConfig
from cygil_builder.vagrant_environment import VmnetRecord


@pytest.mark.parametrize("name", ["VMnet0", "vmnet0", "VMNET0", "VmNeT0"])
def test_vmnet0_is_recognized_case_insensitively(name: str) -> None:
    assert _is_vmnet0(name)


@pytest.mark.parametrize("name", [None, "", "VMnet1", "vmnet18"])
def test_other_vmnet_names_are_not_vmnet0(name: str | None) -> None:
    assert not _is_vmnet0(name)


def test_saved_vmnet_names_are_normalized_on_load_and_assignment() -> None:
    """Les anciennes sauvegardes minuscules retrouvent les options de la GUI."""

    config = VagrantConfig(
        bootstrap_network="vmnet19",
        mininet_internal_network="VMNET1",
    )

    assert config.bootstrap_network == "VMnet19"
    assert config.mininet_internal_network == "VMnet1"
    config.bootstrap_network = "VmNeT9"
    assert config.bootstrap_network == "VMnet9"


def test_vmnet_name_comparison_is_case_insensitive() -> None:
    assert _same_vmnet_name("vmnet19", "VMnet19")
    assert not _same_vmnet_name("VMnet1", "VMnet19")


def test_manual_internal_vmnet_keeps_its_saved_cidr_when_vmrest_has_none() -> None:
    """Un VMnet manuel reste utilisable si son CIDR est déjà dans le scénario."""

    record = VmnetRecord("VMnet1", "hostOnly", False, None, "255.255.255.0")
    saved_cidr = ip_network("192.170.20.0/24")

    resolved = _resolve_internal_vmnet_cidr(
        "VMnet1",
        record,
        "vmnet1",
        saved_cidr,
    )

    assert resolved == saved_cidr


def test_unknown_new_internal_vmnet_cannot_reuse_another_saved_cidr() -> None:
    record = VmnetRecord("VMnet2", "hostOnly", False, None, None)

    with pytest.raises(ValueError, match="CIDR valide"):
        _resolve_internal_vmnet_cidr(
            "VMnet2",
            record,
            "VMnet1",
            ip_network("192.170.20.0/24"),
        )
