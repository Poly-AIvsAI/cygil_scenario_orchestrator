"""Garantit l'inventaire sûr et l'exclusion Vagrant des VM réservées."""

import base64
import io
import json
import tarfile

import httpx
import pytest
from pydantic import ValidationError

from cygil_builder.adapters.vagrant import (
    VagrantCommand,
    VagrantSafetyError,
    VagrantTargetAdapter,
    build_vagrant_commands,
    render_vagrantfile,
)
from cygil_builder.models import GuestAccessConfig, GuestCommunicator
from cygil_builder.vagrant_environment import (
    EnvironmentInventoryError,
    VagrantEnvironmentService,
    VmnetRecord,
    VmwareVMRecord,
    _cached_box_provider,
    associate_reserved_vm_roles,
)


def _write_test_box(path, provider="vmware_desktop"):
    """Crée une archive minimale pour tester sa reconnaissance par contenu."""

    metadata = json.dumps({"architecture": "amd64", "provider": provider}).encode("utf-8")
    with tarfile.open(path, "w") as archive:
        member = tarfile.TarInfo("metadata.json")
        member.size = len(metadata)
        archive.addfile(member, io.BytesIO(metadata))


def test_vagrantfile_only_contains_targets(scenario, tmp_path):
    scenario.vagrant.bootstrap_network = "VMnet9"
    path = render_vagrantfile(scenario, tmp_path / "Vagrantfile")
    content = path.read_text(encoding="utf-8")
    assert 'config.vm.define "workstation_01"' in content
    assert 'config.vm.define "server_01"' in content
    assert 'config.vm.define "cygil"' not in content
    assert "vmware_desktop" in content
    assert 'provider.vmx["ethernet0.vnet"] = "VMnet9"' in content
    assert 'provider.vmx["ethernet0.vnet"] = "VMnet0"' not in content


def test_targets_use_bootstrap_and_never_orchestration_vmnet0(scenario):
    """Les cibles utilisent le DHCP d'amorçage et restent hors de VMnet0."""

    scenario.vagrant.bootstrap_network = "VMnet9"
    reloaded = type(scenario).model_validate(scenario.model_dump(mode="json"))
    assert all(target.temporary_management.vmware_network == "VMnet9" for target in reloaded.targets)
    assert all(target.temporary_management.address_mode == "dhcp" for target in reloaded.targets)


def test_vagrantfile_keeps_vmnet_and_mac_mapping_explicit(scenario, tmp_path):
    """La carte temporaire et la carte Mininet ne doivent jamais être confondues."""

    target = scenario.targets[0]
    scenario.vagrant.bootstrap_network = "VMnet9"
    target.interfaces[0].vmware_network = "VMnet2"
    target.interfaces[0].vmware_adapter_index = 2
    target.interfaces[0].mac = "00:50:56:11:22:33"
    target.guest_access = GuestAccessConfig(
        communicator=GuestCommunicator.WINRM,
        username="lab-user",
    )

    content = render_vagrantfile(scenario, tmp_path / "Vagrantfile").read_text(encoding="utf-8")

    assert 'provider.vmx["ethernet0.vnet"] = "VMnet9"' in content
    assert 'provider.vmx["ethernet0.vnet"] = "VMnet0"' not in content
    assert 'provider.vmx["ethernet2.vnet"] = "VMnet2"' in content
    assert 'provider.vmx["ethernet2.address"] = "00:50:56:11:22:33"' in content
    assert 'vm.winrm.username = "lab-user"' in content


def test_vagrantfile_adds_separate_dhcp_bootstrap_without_exporting_it(scenario, tmp_path):
    """Le VMnet DHCP temporaire occupe sa propre carte, distincte de VMnet0."""

    scenario.vagrant.bootstrap_network = "VMnet9"
    scenario.vagrant.bootstrap_dhcp_enabled = True
    scenario.targets[0].interfaces[0].vmware_network = "VMnet2"

    content = render_vagrantfile(scenario, tmp_path / "Vagrantfile").read_text(encoding="utf-8")

    assert 'provider.vmx["ethernet0.vnet"] = "VMnet9"' in content
    assert 'provider.vmx["ethernet0.vnet"] = "VMnet0"' not in content
    assert "temporary DHCP bootstrap" in content
    assert "VMnet9" not in scenario.model_dump_json(exclude={"vagrant"})


def test_command_plan_is_sequential_and_never_contains_destroy(scenario):
    """Chaque cible est inspectée avant up et un échec ne provoque pas de destroy."""

    commands = build_vagrant_commands(scenario)
    actions = [command.action for command in commands]

    assert actions.count("status") == len(scenario.targets)
    assert actions.count("up") == len(scenario.targets)
    assert "destroy" not in actions
    assert all("--no-destroy-on-error" in command.arguments for command in commands if command.action == "up")


def test_adapter_rejects_reserved_vm_even_in_dry_run(scenario, tmp_path):
    """La protection s'applique avant subprocess et ne dépend pas du mode réel."""

    reserved = scenario.infrastructure[0].id
    command = VagrantCommand("status", reserved, ("vagrant", "status", reserved), mutating=False)

    with pytest.raises(VagrantSafetyError):
        VagrantTargetAdapter(scenario, tmp_path, dry_run=True).execute([command])


def test_local_box_is_validated_without_import(scenario, tmp_path, monkeypatch):
    """L'inventaire distingue le fichier choisi du catalogue Vagrant installé."""

    box_path = tmp_path / "generic-ubuntu1804.box"
    _write_test_box(box_path)
    scenario.vagrant.box_paths = {"cygil/ubuntu": str(box_path)}
    service = VagrantEnvironmentService(scenario)
    monkeypatch.setattr(service, "_find_vagrant", lambda: "vagrant.exe")
    monkeypatch.setattr(service, "_windows_service_state", lambda _: "running")

    def read_only_result(arguments):
        """Simule un Vagrant installé dont le catalogue ne contient encore rien."""

        if arguments[-1] == "--version":
            return "Vagrant 2.4.9"
        if arguments[-2:] == ["plugin", "list"]:
            return "vagrant-vmware-desktop (3.0.5, global)"
        return "There are no installed boxes!"

    monkeypatch.setattr(service, "_run_read_only", read_only_result)
    inventory = service.inspect_vagrant()

    assert inventory.boxes == ()
    assert len(inventory.local_boxes) == 1
    assert inventory.local_boxes[0].valid is True
    assert inventory.local_boxes[0].provider == "vmware_desktop"


def test_local_box_requires_box_extension_and_vmware_desktop_provider(scenario, tmp_path):
    """Une archive ambiguë ou destinée à un autre fournisseur reste refusée."""

    extensionless = tmp_path / "ubuntu"
    _write_test_box(extensionless)
    with pytest.raises(EnvironmentInventoryError, match=r"\.box"):
        VagrantEnvironmentService.validate_box_file(extensionless)

    wrong_provider = tmp_path / "ubuntu-workstation.box"
    _write_test_box(wrong_provider, provider="vmware_workstation")
    with pytest.raises(EnvironmentInventoryError, match="pas VMware Desktop"):
        VagrantEnvironmentService.validate_box_file(wrong_provider)


def test_vmnet_inventory_reads_dhcp_and_subnet_without_mutation(scenario, monkeypatch):
    """L'inventaire bootstrap utilise l'endpoint officiel GET /api/vmnet."""

    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "num": 2,
                "vmnets": [
                    {"name": "VMnet0", "type": "hostOnly", "dhcp": "false", "subnet": "192.168.10.0", "mask": "255.255.255.0"},
                    {"name": "VMnet9", "type": "hostOnly", "dhcp": "true", "subnet": "192.168.90.0", "mask": "255.255.255.0"},
                ],
            }

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.get", fake_get)
    records = VagrantEnvironmentService(scenario).inspect_vmnets("api-user", "secret")

    assert [record.name for record in records] == ["VMnet0", "VMnet9"]
    assert records[0].dhcp_enabled is False
    assert records[1].dhcp_enabled is True
    assert calls[0][0].endswith("/api/vmnet")


def test_vmnet_inventory_merges_scenario_isolated_network_omitted_by_vmrest(
    scenario, monkeypatch
):
    """Un VMnet géré reste observable après retrait de DHCP et de l'adaptateur."""

    scenario.targets[0].interfaces[0].vmware_network = "VMnet2"

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vmnets": [
                    {
                        "name": "VMnet0",
                        "type": "hostOnly",
                        "dhcp": "false",
                        "subnet": "192.168.10.0",
                        "mask": "255.255.255.0",
                    }
                ]
            }

    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        VagrantEnvironmentService,
        "inspect_host_connected_vmnets",
        staticmethod(lambda: frozenset({"VMnet0"})),
    )
    monkeypatch.setattr(
        VagrantEnvironmentService,
        "inspect_locally_registered_vmnets",
        staticmethod(
            lambda: (
                VmnetRecord(
                    "VMnet2",
                    "hostOnly",
                    False,
                    "192.168.225.0",
                    None,
                    False,
                ),
                # Une entrée locale valide mais étrangère au scénario ne
                # doit pas modifier son allocation dynamique.
                VmnetRecord(
                    "VMnet8",
                    "hostOnly",
                    False,
                    "192.168.88.0",
                    "255.255.255.0",
                    False,
                ),
            )
        ),
    )

    records = VagrantEnvironmentService(scenario).inspect_vmnets("api-user", "secret")

    assert [record.name for record in records] == ["VMnet0", "VMnet2"]
    assert records[1].dhcp_enabled is False
    assert records[1].host_connected is False


def test_vmrest_dhcp_inventory_uses_singular_vmnet_endpoint(scenario, monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "mactoips": [
                    {"vmnet": "VMnet19", "mac": "00-50-56-AA-BB-CC", "ip": "192.168.190.10"}
                ]
            }

    def fake_get(url, **kwargs):
        calls.append(url)
        return Response()

    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.get", fake_get)
    leases = VagrantEnvironmentService(scenario).inspect_dhcp_leases(
        "VMnet19", "api-user", "secret"
    )

    assert leases == {"00:50:56:aa:bb:cc": "192.168.190.10"}
    assert calls == ["https://127.0.0.1:8697/api/vmnet/vmnet19/mactoip"]


def test_vmrest_dhcp_inventory_normalizes_legacy_lowercase_name(scenario, monkeypatch):
    """Une ancienne sauvegarde minuscule produit le même endpoint vmrest natif."""

    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"mactoips": []}

    monkeypatch.setattr(
        "cygil_builder.vagrant_environment.httpx.get",
        lambda url, **kwargs: calls.append(url) or Response(),
    )

    VagrantEnvironmentService(scenario).inspect_dhcp_leases(
        "vmnet19", "api-user", "secret"
    )

    assert calls == ["https://127.0.0.1:8697/api/vmnet/vmnet19/mactoip"]


def test_vmrest_creates_only_planned_hostonly_vmnets_then_rereads(scenario, monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vmnets": [
                    {"name": "VMnet2", "type": "hostOnly", "dhcp": "false", "subnet": "192.168.52.0", "mask": "255.255.255.0"},
                    {"name": "VMnet3", "type": "hostOnly", "dhcp": "false", "subnet": "192.168.53.0", "mask": "255.255.255.0"},
                ]
            }

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.post", fake_post)
    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.get", lambda *args, **kwargs: Response())
    records = VagrantEnvironmentService(scenario).create_hostonly_vmnets(
        ("VMnet2", "VMnet3"), "api-user", "secret"
    )

    assert [record.name for record in records] == ["VMnet2", "VMnet3"]
    assert [item[1]["json"] for item in calls] == [
        {"name": "vmnet2", "type": "hostOnly"},
        {"name": "vmnet3", "type": "hostOnly"},
    ]
    assert all(item[0].endswith("/api/vmnets") for item in calls)


def test_vmnet_inventory_normalizes_lowercase_vmware_names(scenario, monkeypatch):
    """vmrest peut répondre ``vmnetN`` sans contaminer le modèle interne."""

    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://127.0.0.1:8697/api/vmnet"),
        json={
            "vmnets": [
                {
                    "name": "vmnet2",
                    "type": "hostOnly",
                    "dhcp": "false",
                    "subnet": "192.168.52.0",
                    "mask": "255.255.255.0",
                }
            ]
        },
    )
    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.get", lambda *args, **kwargs: response)
    monkeypatch.setattr(
        VagrantEnvironmentService,
        "inspect_host_connected_vmnets",
        staticmethod(lambda: frozenset({"vmnet2"})),
    )

    records = VagrantEnvironmentService(scenario).inspect_vmnets("api-user", "secret")

    assert records[0].name == "VMnet2"
    assert records[0].host_connected is True


def test_vmnet_creation_surfaces_vmware_error_body(scenario, monkeypatch):
    """Un rejet 400 doit montrer la raison retournée par VMware."""

    response = httpx.Response(
        400,
        request=httpx.Request("POST", "https://127.0.0.1:8697/api/vmnets"),
        json={"code": 400, "message": "invalid vmnet name"},
    )
    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.post", lambda *args, **kwargs: response)

    with pytest.raises(EnvironmentInventoryError, match="invalid vmnet name"):
        VagrantEnvironmentService(scenario).create_hostonly_vmnets(
            ("VMnet2",), "api-user", "secret"
        )


def test_mininet_host_isolation_removes_only_requested_adapters(scenario, monkeypatch):
    service = VagrantEnvironmentService(scenario)
    inventories = iter(
        (
            frozenset({"VMnet0", "VMnet2", "VMnet3", "VMnet19"}),
            frozenset({"VMnet0", "VMnet19"}),
        )
    )
    calls = []

    monkeypatch.setattr(service, "inspect_host_connected_vmnets", lambda: next(inventories))
    monkeypatch.setattr(service, "_find_vnetlib", lambda: r"C:\VMware\vnetlib64.exe")
    monkeypatch.setattr(
        service,
        "_run_vnetlib_elevated",
        lambda executable, operation, names: calls.append((executable, operation, names)),
    )
    remaining = service.disconnect_host_from_vmnets(
        ("VMnet2", "VMnet3"),
        bootstrap_vmnet="VMnet19",
    )

    assert remaining == frozenset({"VMnet0", "VMnet19"})
    assert calls == [
        (r"C:\VMware\vnetlib64.exe", "remove", ("VMnet2", "VMnet3")),
    ]


def test_vnetlib_mutations_share_one_uac_prompt(scenario, monkeypatch):
    """Tous les adaptateurs d'une étape confirmée passent dans une seule UAC."""

    from cygil_builder.host_setup import HostSetupService

    captured: list[tuple[str, str]] = []
    monkeypatch.setattr(
        HostSetupService,
        "_run_elevated_powershell",
        lambda self, script, action: captured.append((script, action)),
    )

    VagrantEnvironmentService(scenario)._run_vnetlib_elevated(
        r"C:\Program Files (x86)\VMware\VMware Workstation\vnetlib64.exe",
        "remove",
        ("VMnet2", "VMnet3"),
    )

    assert len(captured) == 1
    assert "'remove' 'adapter'" in captured[0][0]
    assert base64.b64encode(b"vmnet2").decode("ascii") in captured[0][0]
    assert base64.b64encode(b"vmnet3").decode("ascii") in captured[0][0]
    assert "$null -ne $exitCode -and $exitCode -ne 0" in captured[0][0]
    assert "(code $exitCode)" in captured[0][0]
    assert captured[0][1] == "Retrait des adaptateurs hôte VMware"


def test_disable_dhcp_uses_vnetlib_and_verifies_vmrest(scenario, monkeypatch):
    """Le DHCP des VMnet gérés est retiré sous UAC puis relu via vmrest."""

    service = VagrantEnvironmentService(scenario)
    calls = []
    monkeypatch.setattr(service, "_find_vnetlib", lambda: r"C:\VMware\vnetlib64.exe")
    monkeypatch.setattr(
        service,
        "_run_vnetlib_elevated",
        lambda executable, operation, names, **kwargs: calls.append(
            (executable, operation, names, kwargs)
        ),
    )
    monkeypatch.setattr(
        service,
        "inspect_vmnets",
        lambda username, password: (
            VmnetRecord("VMnet2", "hostOnly", False, "192.168.52.0", "255.255.255.0"),
            VmnetRecord("VMnet3", "hostOnly", False, "192.168.53.0", "255.255.255.0"),
        ),
    )

    records = service.disable_dhcp_on_vmnets(
        ("VMnet2", "VMnet3"), "api-user", "secret"
    )

    assert [record.name for record in records] == ["VMnet2", "VMnet3"]
    assert calls == [
        (
            r"C:\VMware\vnetlib64.exe",
            "remove",
            ("VMnet2", "VMnet3"),
            {"component": "dhcp"},
        )
    ]


@pytest.mark.parametrize("protected", ["VMnet0", "VMnet1"])
def test_disable_dhcp_refuses_manual_protected_vmnets(scenario, protected):
    """Les réseaux manuels explicitement exclus ne sont jamais modifiés."""

    with pytest.raises(EnvironmentInventoryError, match="non géré"):
        VagrantEnvironmentService(scenario).disable_dhcp_on_vmnets(
            (protected,), "api-user", "secret"
        )


@pytest.mark.parametrize("protected", ["VMnet0", "VMnet19"])
def test_mininet_host_isolation_refuses_protected_networks(scenario, protected):
    with pytest.raises(EnvironmentInventoryError, match="protégée"):
        VagrantEnvironmentService(scenario).disconnect_host_from_vmnets(
            (protected,),
            bootstrap_vmnet="VMnet19",
        )


def test_only_vmnet0_and_bootstrap_can_receive_host_adapters(scenario, monkeypatch):
    service = VagrantEnvironmentService(scenario)
    inventories = iter((frozenset(), frozenset({"VMnet0", "VMnet19"})))
    calls = []

    monkeypatch.setattr(service, "inspect_host_connected_vmnets", lambda: next(inventories))
    monkeypatch.setattr(service, "_find_vnetlib", lambda: r"C:\VMware\vnetlib64.exe")
    monkeypatch.setattr(
        service,
        "_run_vnetlib_elevated",
        lambda executable, operation, names: calls.append((executable, operation, names)),
    )

    service.connect_host_to_management_vmnets(
        ("VMnet0", "VMnet19"),
        bootstrap_vmnet="VMnet19",
    )
    assert calls == [
        (r"C:\VMware\vnetlib64.exe", "add", ("VMnet0", "VMnet19")),
    ]

    with pytest.raises(EnvironmentInventoryError, match="uniquement"):
        service.connect_host_to_management_vmnets(
            ("VMnet2",),
            bootstrap_vmnet="VMnet19",
        )


def test_vmware_inventory_uses_vmx_display_name_instead_of_opaque_id(scenario, tmp_path, monkeypatch):
    """La liste d'association affiche le titre humain conservé dans le VMX."""

    vmx = tmp_path / "technical-file-name.vmx"
    vmx.write_text('displayName = "Serveur CALDERA"\n', encoding="utf-8")

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vms": [{
                    "id": "42J3F6H97K2L5M8N-OPAQUE-IDENTIFIER",
                    "name": "42J3F6H97K2L5M8N-OPAQUE-IDENTIFIER",
                    "path": str(vmx),
                }],
            }

    monkeypatch.setattr("cygil_builder.vagrant_environment.httpx.get", lambda *args, **kwargs: Response())
    records = VagrantEnvironmentService(scenario).discover_vmware_vms("api-user", "secret")
    assert records[0].name == "Serveur CALDERA"
    assert records[0].vmware_id.startswith("42J3F6")


def test_unchanged_box_metadata_is_cached_between_inventories(scenario, tmp_path, monkeypatch):
    """Une seconde inspection ne doit pas reparcourir une grosse archive inchangée."""

    box_path = tmp_path / "windows-server.box"
    _write_test_box(box_path)
    _cached_box_provider.cache_clear()
    original_open = tarfile.open
    open_count = 0

    def counted_open(*args, **kwargs):
        """Compte les ouvertures réelles tout en conservant le lecteur tar standard."""

        nonlocal open_count
        open_count += 1
        return original_open(*args, **kwargs)

    monkeypatch.setattr(tarfile, "open", counted_open)
    service = VagrantEnvironmentService(scenario)

    assert service.validate_box_file(box_path) == "vmware_desktop"
    assert VagrantEnvironmentService(scenario).validate_box_file(box_path) == "vmware_desktop"
    assert open_count == 1


def test_reserved_roles_are_associated_from_role_rows_without_duplicate_vm(scenario, tmp_path):
    """L'enregistrement global associe chaque rôle à une identité VMware unique."""

    records = tuple(
        VmwareVMRecord(
            vmware_id=f"vm-{index}",
            name=f"VMware {machine.role.value}",
            vmx_path=str(tmp_path / f"{machine.id}.vmx"),
            raw={"uuid": f"uuid-{index}"},
        )
        for index, machine in enumerate(scenario.infrastructure)
    )
    assignments = {
        machine.id: records[index].vmware_id
        for index, machine in enumerate(scenario.infrastructure)
    }
    associate_reserved_vm_roles(scenario, records, assignments)
    assert [machine.vmware_id for machine in scenario.infrastructure] == [
        record.vmware_id for record in records
    ]
    assert all(machine.inventory_confirmed for machine in scenario.infrastructure)


def test_reserved_role_association_rejects_missing_and_duplicate_choices(scenario):
    """Aucun rôle vide et aucune VM VMware partagée ne peuvent être enregistrés."""

    records = tuple(
        VmwareVMRecord(vmware_id=f"vm-{index}", name=f"VM {index}", vmx_path=f"C:/vm-{index}.vmx")
        for index, _ in enumerate(scenario.infrastructure)
    )
    incomplete = {machine.id: None for machine in scenario.infrastructure}
    with pytest.raises(EnvironmentInventoryError, match="Toutes les VM réservées"):
        associate_reserved_vm_roles(scenario, records, incomplete)

    duplicate = {machine.id: records[0].vmware_id for machine in scenario.infrastructure}
    with pytest.raises(EnvironmentInventoryError, match="plusieurs rôles"):
        associate_reserved_vm_roles(scenario, records, duplicate)
