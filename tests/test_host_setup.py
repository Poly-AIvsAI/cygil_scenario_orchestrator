"""Teste le monitoring hôte et l'orchestration UAC sans modifier le poste Windows."""

import base64
import re
import subprocess
from pathlib import Path

import httpx
import pytest

from cygil_builder.host_setup import (
    FirewallRuntimeStatus,
    HostSetupError,
    HostSetupService,
    SshdRuntimeStatus,
    VmrestRuntimeStatus,
)


def test_host_plan_hides_password_and_legacy_is_opt_in(scenario):
    """Le plan ne doit contenir aucun secret et ssh-rsa doit rester désactivé par défaut."""

    service = HostSetupService(scenario.vmware)
    text = "\n".join(command for plan in service.command_plans() for command in plan.commands)
    assert "PubkeyAcceptedAlgorithms" not in text
    assert "password" not in text.lower()

    scenario.vmware.allow_legacy_ssh_rsa = True
    legacy_text = "\n".join(command for plan in HostSetupService(scenario.vmware).command_plans() for command in plan.commands)
    assert "PubkeyAcceptedAlgorithms +ssh-rsa" in legacy_text


def test_sshd_inspection_reports_real_service_state(monkeypatch, scenario, tmp_path):
    """L'état SSH doit provenir de Get-Service et de l'existence réelle du fichier."""

    config_path = tmp_path / "sshd_config"
    config_path.write_text("Port 22\n", encoding="utf-8")
    scenario.vmware.sshd_config_path = str(config_path)
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(
        service,
        "_powershell_json",
        lambda script: {"installed": True, "status": "Running", "start_type": "Automatic"},
    )

    runtime = service.inspect_sshd()

    assert runtime.installed is True
    assert runtime.running is True
    assert runtime.config_exists is True
    assert runtime.service_status == "Running"


def test_vmrest_running_requires_process_port_and_api(monkeypatch, scenario, tmp_path):
    """Un PID seul ne doit jamais produire le faux état RUNNING de l'ancienne version."""

    executable = tmp_path / "vmrest.exe"
    executable.touch()
    scenario.vmware.workstation_directory = str(tmp_path)
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(service, "_vmrest_process_ids", lambda: (4242,))
    monkeypatch.setattr(service, "_is_local_port_open", lambda port: False)

    runtime = service.inspect_vmrest()

    assert runtime.process_ids == (4242,)
    assert runtime.running is False
    assert scenario.vmware.setup_status.vmrest_running is False


def test_vmrest_accepts_unauthenticated_401_as_reachable(monkeypatch, scenario, tmp_path):
    """HTTP 401 prouve que vmrest répond, tout en conservant authenticated=False."""

    (tmp_path / "vmrest.exe").touch()
    scenario.vmware.workstation_directory = str(tmp_path)
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(service, "_vmrest_process_ids", lambda: (73,))
    monkeypatch.setattr(service, "_is_local_port_open", lambda port: True)
    response = httpx.Response(401, request=httpx.Request("GET", "https://127.0.0.1/api/vms"))
    monkeypatch.setattr("cygil_builder.host_setup.httpx.get", lambda *args, **kwargs: response)

    runtime = service.inspect_vmrest()

    assert runtime.api_reachable is True
    assert runtime.authenticated is False
    assert runtime.running is True
    assert runtime.http_status == 401


def test_vmrest_credentials_use_a_visible_console_without_piping_secrets(monkeypatch, scenario, tmp_path):
    """L'assistant interactif doit hériter d'une nouvelle console et attendre sa fermeture."""

    executable = tmp_path / "vmrest.exe"
    executable.touch()
    scenario.vmware.workstation_directory = str(tmp_path)
    captured: dict = {}

    class FakeProcess:
        """Simule une saisie terminée correctement dans la console enfant."""

        @staticmethod
        def wait():
            return 0

    def fake_popen(arguments, **kwargs):
        """Capture l'appel sans ouvrir de fenêtre pendant le test."""

        captured["arguments"] = arguments
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr("cygil_builder.host_setup.subprocess.Popen", fake_popen)
    message = HostSetupService(scenario.vmware).configure_vmrest_credentials()

    assert captured["arguments"] == [str(executable), "-C"]
    assert captured["kwargs"]["creationflags"] == getattr(subprocess, "CREATE_NEW_CONSOLE", 0)
    assert "input" not in captured["kwargs"]
    assert "configurés" in message
    assert scenario.vmware.setup_status.credentials_configured is True


def test_vmrest_start_always_uses_uac_and_supported_port_flag(monkeypatch, scenario, tmp_path):
    """Chaque démarrage passe par UAC avec -p, sans lancement ordinaire préalable."""

    executable = tmp_path / "vmrest.exe"
    executable.touch()
    certificate = tmp_path / "cert.pem"
    certificate.write_text(
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    private_key = tmp_path / "key.pem"
    private_key.write_text(
        "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    scenario.vmware.workstation_directory = str(tmp_path)
    scenario.vmware.api_port = 8697
    status = scenario.vmware.setup_status
    status.certificate_path = str(certificate)
    status.private_key_path = str(private_key)
    # Un nouveau scénario ne possède aucune preuve historique. Le succès
    # doit venir de l'authentification réelle après démarrage.
    status.credentials_configured = False
    stopped = VmrestRuntimeStatus(True, (), False, False, False, None, False, "arrêté")
    running = VmrestRuntimeStatus(True, (42,), True, True, True, 200, True, "actif")
    runtimes = iter([stopped, running])
    captured: dict = {}

    def fake_elevated_start(arguments):
        """Capture le lancement UAC sans modifier le poste pendant le test."""

        captured["arguments"] = arguments

    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(service, "inspect_vmrest", lambda *args: next(runtimes))
    monkeypatch.setattr(service, "ensure_vmrest_portproxy", lambda: "redirection prête")
    monkeypatch.setattr(service, "_start_vmrest_elevated", fake_elevated_start)
    monkeypatch.setattr(
        "cygil_builder.host_setup.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("vmrest ne doit jamais être lancé sans UAC"),
    )

    service.start_vmrest("api-user", "api-password")

    assert captured["arguments"][-2:] == ["-p", "8697"]
    assert "-i" not in captured["arguments"]
    assert status.credentials_configured is True


def test_elevated_vmrest_start_is_hidden(monkeypatch, scenario):
    """Le serveur administrateur reste un processus d'arrière-plan sans console visible."""

    captured: dict[str, str] = {}
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(
        service,
        "_run_elevated_powershell",
        lambda script, action: captured.update(script=script, action=action),
    )

    service._start_vmrest_elevated([r"C:\VMware\vmrest.exe", "-p", "8697"])

    assert "Start-Process" in captured["script"]
    assert "Stop-Process" in captured["script"]
    assert "-WindowStyle Hidden" in captured["script"]
    assert captured["action"] == "Démarrage de VMware vmrest"


def test_elevated_vmrest_preserves_arguments_with_spaces(monkeypatch, scenario):
    """Les chemins de certificat et de clé restent chacun un argument Windows."""

    captured: dict[str, str] = {}
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(
        service,
        "_run_elevated_powershell",
        lambda script, action: captured.update(script=script),
    )
    arguments = [
        r"C:\Program Files (x86)\VMware\VMware Workstation\vmrest.exe",
        "-c",
        r"F:\Projet avec espaces\certificat.pem",
        "-k",
        r"F:\Projet avec espaces\clé privée.pem",
        "-p",
        "8697",
    ]

    service._start_vmrest_elevated(arguments)

    encoded_values = re.findall(r"FromBase64String\('([^']+)'\)", captured["script"])
    decoded_values = [base64.b64decode(value).decode("utf-8") for value in encoded_values]
    assert decoded_values == [arguments[0], subprocess.list2cmdline(arguments[1:])]
    assert '"F:\\Projet avec espaces\\certificat.pem"' in decoded_values[1]
    assert '"F:\\Projet avec espaces\\clé privée.pem"' in decoded_values[1]


def test_elevated_runner_precreates_user_owned_result_file(monkeypatch, scenario):
    """Le retour UAC existe avant l'élévation et n'est pas relu lors d'un succès."""

    service = HostSetupService(scenario.vmware)

    def fake_runas(script_path: Path) -> int:
        """Valide le fichier préparé sans lancer de véritable processus UAC."""

        script = script_path.read_text(encoding="utf-8-sig")
        marker = "FromBase64String('"
        encoded = script.split(marker, 1)[1].split("')", 1)[0]
        result_path = Path(base64.b64decode(encoded).decode("utf-8"))
        assert result_path.is_file()
        # Un succès ne doit pas dépendre de la relecture de ce contenu.
        result_path.write_text("OK", encoding="utf-8-sig")
        return 0

    monkeypatch.setattr(service, "_shell_execute_runas", fake_runas)

    service._run_elevated_powershell("$null = 1", "Test UAC")


def test_vmrest_start_requires_current_credentials_not_saved_scenario_flag(scenario):
    """Un ancien booléen vrai ne remplace jamais les identifiants courants."""

    scenario.vmware.setup_status.credentials_configured = True
    service = HostSetupService(scenario.vmware)

    with pytest.raises(HostSetupError, match="Saisissez les identifiants"):
        service.start_vmrest("", "")


def test_running_vmrest_is_replaced_by_an_elevated_instance(monkeypatch, scenario, tmp_path):
    """Une ancienne instance joignable ne doit jamais éviter la nouvelle demande UAC."""

    executable = tmp_path / "vmrest.exe"
    executable.touch()
    certificate = tmp_path / "cert.pem"
    certificate.write_text(
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    private_key = tmp_path / "key.pem"
    private_key.write_text(
        "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    scenario.vmware.workstation_directory = str(tmp_path)
    scenario.vmware.setup_status.certificate_path = str(certificate)
    scenario.vmware.setup_status.private_key_path = str(private_key)
    scenario.vmware.setup_status.credentials_configured = False
    runtime = VmrestRuntimeStatus(True, (42,), True, True, True, 200, True, "actif")
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(service, "inspect_vmrest", lambda *args: runtime)
    monkeypatch.setattr(service, "ensure_vmrest_portproxy", lambda: "redirection prête")
    elevated_calls: list[list[str]] = []
    monkeypatch.setattr(service, "_start_vmrest_elevated", lambda args: elevated_calls.append(args))

    assert service.start_vmrest("api-user", "api-password") == "actif"
    assert len(elevated_calls) == 1
    assert scenario.vmware.setup_status.credentials_configured is True


def test_running_vmrest_rejects_wrong_current_credentials(monkeypatch, scenario):
    runtime = VmrestRuntimeStatus(True, (42,), True, True, False, 401, True, "refusé")
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(service, "inspect_vmrest", lambda *args: runtime)

    with pytest.raises(HostSetupError, match="identifiants saisis sont refusés"):
        service.start_vmrest("wrong", "wrong")


def test_existing_vmrest_portproxy_is_reused_without_uac(monkeypatch, scenario):
    """La redirection exacte rend la préparation idempotente."""

    scenario.vmware.external_ip = "192.168.10.3"
    scenario.vmware.api_port = 8697
    service = HostSetupService(scenario.vmware)
    expected = (("192.168.10.3", 8697, "127.0.0.1", 8697),)
    monkeypatch.setattr(service, "inspect_vmrest_portproxy", lambda: expected)
    elevated_calls: list[str] = []
    monkeypatch.setattr(service, "_run_elevated_powershell", lambda script, name: elevated_calls.append(script))

    message = service.ensure_vmrest_portproxy()

    assert "déjà présente" in message
    assert elevated_calls == []


def test_missing_vmrest_portproxy_is_created_and_verified(monkeypatch, scenario):
    """La création emploie l'adresse hôte variable avant de relire la preuve."""

    scenario.vmware.external_ip = "192.168.10.3"
    scenario.vmware.api_port = 8697
    service = HostSetupService(scenario.vmware)
    expected = (("192.168.10.3", 8697, "127.0.0.1", 8697),)
    inventories = iter([(), expected])
    elevated_calls: list[tuple[str, str]] = []
    monkeypatch.setattr(service, "inspect_vmrest_portproxy", lambda: next(inventories))
    monkeypatch.setattr(
        service,
        "_run_elevated_powershell",
        lambda script, name: elevated_calls.append((script, name)),
    )

    message = service.ensure_vmrest_portproxy()

    assert "créée" in message
    assert "listenaddress=192.168.10.3" in elevated_calls[0][0]
    assert "listenport=8697" in elevated_calls[0][0]
    assert "connectaddress=127.0.0.1" in elevated_calls[0][0]
    assert "connectport=8697" in elevated_calls[0][0]


def test_conflicting_vmrest_portproxy_is_never_overwritten(monkeypatch, scenario):
    """Un endpoint occupé exige une décision utilisateur plutôt qu'un remplacement."""

    scenario.vmware.external_ip = "192.168.10.3"
    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(
        service,
        "inspect_vmrest_portproxy",
        lambda: (("192.168.10.3", 8697, "127.0.0.2", 9000),),
    )

    with pytest.raises(HostSetupError, match="autre redirection"):
        service.ensure_vmrest_portproxy()


def test_openssh_installation_uses_elevated_runner(monkeypatch, scenario):
    """L'installation ne doit jamais exécuter Add-WindowsCapability dans le processus normal."""

    service = HostSetupService(scenario.vmware)
    statuses = iter([
        SshdRuntimeStatus(False, False, "Absent", "Inconnu", False, "absent"),
        SshdRuntimeStatus(True, True, "Running", "Automatic", True, "actif"),
    ])
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(service, "inspect_sshd", lambda: next(statuses))
    monkeypatch.setattr(service, "_run_elevated_powershell", lambda script, name: calls.append((script, name)))

    message = service.install_openssh_server()

    assert calls and "Add-WindowsCapability" in calls[0][0]
    assert calls[0][1] == "Installation d'OpenSSH Server"
    assert "installé" in message


def test_openssl_picker_persists_only_an_existing_openssl(monkeypatch, scenario, tmp_path):
    """Le sélecteur natif doit refuser un autre exécutable ou un chemin inexistant."""

    executable = tmp_path / "openssl.exe"
    executable.touch()
    completed = type("Completed", (), {"returncode": 0, "stdout": str(executable), "stderr": ""})()
    monkeypatch.setattr("cygil_builder.host_setup.subprocess.run", lambda *args, **kwargs: completed)

    selected = HostSetupService(scenario.vmware).choose_openssl_executable()

    assert Path(selected) == executable


def test_openssl_config_picker_validates_and_persists_existing_file(monkeypatch, scenario, tmp_path):
    """Le fichier choisi doit exister et contenir une configuration non vide."""

    config_file = tmp_path / "openssl.cnf"
    config_file.write_text("[req]\ndistinguished_name = req_dn\n[req_dn]\n", encoding="utf-8")
    completed = type("Completed", (), {"returncode": 0, "stdout": str(config_file), "stderr": ""})()
    monkeypatch.setattr("cygil_builder.host_setup.subprocess.run", lambda *args, **kwargs: completed)

    selected = HostSetupService(scenario.vmware).choose_openssl_config_file()

    assert selected == str(config_file.resolve())


def test_certificate_command_uses_user_openssl_config(monkeypatch, scenario, tmp_path):
    """La commande réelle et sa sortie restent liées au fichier choisi."""

    executable = tmp_path / "openssl.exe"
    executable.touch()
    config_file = tmp_path / "openssl.cnf"
    config_file.write_text("[req]\ndistinguished_name = req_dn\n[req_dn]\n", encoding="utf-8")
    output_directory = tmp_path / "certificates"
    scenario.vmware.openssl_executable = str(executable)
    scenario.vmware.openssl_config_path = str(config_file)
    scenario.vmware.certificate_directory = str(output_directory)
    captured: list[str] = []

    def fake_run(arguments):
        """Capture la commande et simule uniquement les deux fichiers attendus."""

        captured.extend(arguments)
        output_directory.joinpath("workstationapi-key.pem").write_text("key", encoding="utf-8")
        output_directory.joinpath("workstationapi-cert.pem").write_text("cert", encoding="utf-8")

    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(service, "_run", fake_run)

    service.generate_certificate()

    config_index = captured.index("-config")
    assert captured[config_index + 1] == str(config_file.resolve())
    plan_text = "\n".join(command for plan in service.command_plans() for command in plan.commands)
    assert f'-config "{config_file}"' in plan_text


def test_certificate_generation_requires_openssl_config(scenario, tmp_path):
    """Aucune clé ne doit être créée tant que le fichier manque."""

    executable = tmp_path / "openssl.exe"
    executable.touch()
    scenario.vmware.openssl_executable = str(executable)
    scenario.vmware.openssl_config_path = None

    with pytest.raises(HostSetupError, match="configuration OpenSSL est requis"):
        HostSetupService(scenario.vmware).generate_certificate()


def test_public_key_file_is_extracted_and_validated(scenario, tmp_path):
    """Une clé et son commentaire doivent être lus comme une seule ligne OpenSSH."""

    public_key = tmp_path / "cygil-host.pub"
    payload = base64.b64encode(b"a-valid-public-key-payload").decode("ascii")
    public_key.write_text(f"ssh-ed25519 {payload} cygil@example\n", encoding="utf-8")

    selected = HostSetupService(scenario.vmware).load_public_key_file(str(public_key))

    assert selected.path == str(public_key.resolve())
    assert selected.key.endswith("cygil@example")


def test_public_key_file_rejects_multiple_keys(scenario, tmp_path):
    """Le choix doit rester non ambigu : un fichier ne peut autoriser deux clés implicitement."""

    public_key = tmp_path / "multiple.pub"
    public_key.write_text("ssh-ed25519 AAAAfirst\nssh-rsa AAAAsecond\n", encoding="utf-8")

    with pytest.raises(HostSetupError, match="exactement une clé"):
        HostSetupService(scenario.vmware).load_public_key_file(str(public_key))


def test_public_key_picker_returns_extracted_content(monkeypatch, scenario, tmp_path):
    """Le chemin renvoyé par la fenêtre Windows doit être immédiatement lu par le service."""

    public_key = tmp_path / "selected.pub"
    payload = base64.b64encode(b"another-valid-public-key-payload").decode("ascii")
    public_key.write_text(f"ssh-rsa {payload} operator@example\n", encoding="utf-8")
    completed = type("Completed", (), {"returncode": 0, "stdout": str(public_key), "stderr": ""})()
    monkeypatch.setattr("cygil_builder.host_setup.subprocess.run", lambda *args, **kwargs: completed)

    selected = HostSetupService(scenario.vmware).choose_public_key_file()

    assert selected is not None
    assert selected.path == str(public_key.resolve())
    assert selected.key.startswith("ssh-rsa ")


def test_firewall_inspection_reports_matching_active_rule(monkeypatch, scenario):
    """L'état actif doit exiger une règle entrante Allow/TCP sur le port vmrest courant."""

    service = HostSetupService(scenario.vmware)
    monkeypatch.setattr(
        service,
        "_powershell_json",
        lambda script: {
            "exists": True,
            "enabled": True,
            "direction": "Inbound",
            "action": "Allow",
            "protocol": "TCP",
            "local_port": str(scenario.vmware.api_port),
        },
    )

    runtime = service.inspect_vmrest_firewall()

    assert runtime.exists is True
    assert runtime.enabled is True
    assert runtime.matches_configuration is True


def test_firewall_enable_uses_uac_and_verifies_result(monkeypatch, scenario):
    """L'activation doit exécuter la mutation élevée puis relire la preuve Windows."""

    service = HostSetupService(scenario.vmware)
    elevated_calls: list[tuple[str, str]] = []
    active = FirewallRuntimeStatus(
        True,
        True,
        "Inbound",
        "Allow",
        "TCP",
        str(scenario.vmware.api_port),
        True,
        "règle active",
    )
    monkeypatch.setattr(service, "_run_elevated_powershell", lambda script, name: elevated_calls.append((script, name)))
    monkeypatch.setattr(service, "inspect_vmrest_firewall", lambda: active)

    message = service.enable_vmrest_firewall()

    assert elevated_calls
    assert "New-NetFirewallRule" in elevated_calls[0][0]
    assert str(scenario.vmware.api_port) in elevated_calls[0][0]
    assert "Activation" in elevated_calls[0][1]
    assert message == "règle active"


def test_firewall_disable_does_not_delete_rule(monkeypatch, scenario):
    """La désactivation conserve la règle et utilise exclusivement Set-NetFirewallRule."""

    service = HostSetupService(scenario.vmware)
    active = FirewallRuntimeStatus(True, True, "Inbound", "Allow", "TCP", "8697", True, "active")
    inactive = FirewallRuntimeStatus(True, False, "Inbound", "Allow", "TCP", "8697", True, "inactive")
    statuses = iter([active, inactive])
    elevated_calls: list[str] = []
    monkeypatch.setattr(service, "inspect_vmrest_firewall", lambda: next(statuses))
    monkeypatch.setattr(service, "_run_elevated_powershell", lambda script, name: elevated_calls.append(script))

    service.disable_vmrest_firewall()

    assert "Set-NetFirewallRule" in elevated_calls[0]
    assert "Remove-NetFirewallRule" not in elevated_calls[0]


def test_vmrest_certificate_and_key_files_are_validated(scenario, tmp_path):
    """Les chemins sauvegardés doivent pointer vers un certificat et une clé PEM reconnaissables."""

    certificate = tmp_path / "vmrest-cert.pem"
    private_key = tmp_path / "vmrest-key.pem"
    certificate.write_text(
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    private_key.write_text(
        "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    service = HostSetupService(scenario.vmware)

    assert service.validate_vmrest_certificate_file(str(certificate)) == str(certificate.resolve())
    assert service.validate_vmrest_private_key_file(str(private_key)) == str(private_key.resolve())


def test_vmrest_encrypted_private_key_is_rejected(scenario, tmp_path):
    """Une clé chiffrée est refusée car le serveur détaché ne peut demander de secret."""

    private_key = tmp_path / "encrypted.pem"
    private_key.write_text(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZQ==\n-----END ENCRYPTED PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    with pytest.raises(HostSetupError, match="chiffrée"):
        HostSetupService(scenario.vmware).validate_vmrest_private_key_file(str(private_key))
