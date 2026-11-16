"""Configuration et supervision de l'hôte Windows pour OpenSSH et VMware vmrest.

Le service sépare les inspections sans privilège des mutations administrateur. Lorsqu'une
mutation exige des droits supplémentaires, Windows affiche une demande UAC et seul un script
PowerShell temporaire est exécuté avec élévation. L'état affiché provient toujours d'une
nouvelle inspection de Windows ou de l'API, jamais d'une simple supposition après lancement.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path

import httpx

from .models import HostSetupState, VmwareHostConfig
from .settings import PROJECT_ROOT


class HostSetupError(RuntimeError):
    """Erreur de configuration présentée sans traceback dans l'interface."""


@dataclass(frozen=True)
class HostCommandPlan:
    """Commandes affichées avant leur exécution et leur niveau de privilège."""

    section: str
    commands: list[str]
    requires_admin: bool = True


@dataclass(frozen=True)
class SshdRuntimeStatus:
    """Photographie de l'installation et de l'exécution du service OpenSSH Server."""

    installed: bool
    running: bool
    service_status: str
    start_type: str
    config_exists: bool
    message: str


@dataclass(frozen=True)
class VmrestRuntimeStatus:
    """Photographie recoupée du processus, du port et de l'endpoint VMware REST."""

    executable_exists: bool
    process_ids: tuple[int, ...]
    port_listening: bool
    api_reachable: bool
    authenticated: bool
    http_status: int | None
    running: bool
    message: str


@dataclass(frozen=True)
class FirewallRuntimeStatus:
    """Etat réel de la règle entrante qui expose le port de VMware vmrest."""

    exists: bool
    enabled: bool
    direction: str
    action: str
    protocol: str
    local_port: str
    matches_configuration: bool
    message: str


@dataclass(frozen=True)
class SelectedPublicKey:
    """Fichier public choisi et contenu OpenSSH validé qui en a été extrait."""

    path: str
    key: str


# region API publique de configuration et de supervision
class HostSetupService:
    """Inspecte, configure et pilote OpenSSH et vmrest sur l'hôte Windows."""

    def __init__(self, config: VmwareHostConfig) -> None:
        self.config = config

    @staticmethod
    def is_admin() -> bool:
        """Indique si le processus NiceGUI possède déjà les droits administrateur."""

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def command_plans(self) -> list[HostCommandPlan]:
        """Retourne les opérations lisibles à confirmer avant toute mutation de l'hôte."""

        legacy = []
        if self.config.allow_legacy_ssh_rsa:
            legacy = [
                f'Copy-Item "{self.config.sshd_config_path}" "{self.config.sshd_config_path}.cygil.bak" -Force',
                "Insérer globalement : PubkeyAcceptedAlgorithms +ssh-rsa",
                "Valider la configuration avec sshd.exe -t avant le redémarrage",
            ]
        certificate_directory = self._certificate_directory()
        openssl_config = self.config.openssl_config_path or "<fichier openssl.cnf requis>"
        return [
            HostCommandPlan(
                "Installation OpenSSH Server (si absent)",
                [
                    "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0",
                    "Set-Service -Name sshd -StartupType Automatic",
                    "Start-Service -Name sshd",
                    "Vérifier/créer la règle de pare-feu OpenSSH-Server-In-TCP",
                ],
            ),
            HostCommandPlan(
                "Configuration OpenSSH",
                [
                    "Sélectionner un fichier .pub et en extraire une unique clé OpenSSH valide",
                    "Choisir authorized_keys ou administrators_authorized_keys selon le compte",
                    "Ajouter la clé publique fournie sans créer de doublon",
                    "Appliquer des ACL strictes au fichier de clés",
                    *legacy,
                    "Restart-Service -Name sshd",
                ],
            ),
            HostCommandPlan(
                "Certificat vmrest",
                [
                    f'New-Item -ItemType Directory -Force -Path "{certificate_directory}"',
                    f'"{self.config.openssl_executable}" req -config "{openssl_config}" -x509 -newkey rsa:4096 -keyout "{certificate_directory / "workstationapi-key.pem"}" -out "{certificate_directory / "workstationapi-cert.pem"}" -days 365 -nodes -subj "/CN={self.config.external_ip}"',
                ],
                requires_admin=False,
            ),
            HostCommandPlan(
                "Identifiants et cycle de vie vmrest",
                [
                    f'"{self._vmrest_executable()}" -C  # console Windows visible; saisie interactive requise',
                    f'netsh interface portproxy add v4tov4 listenport={self.config.api_port} listenaddress={self.config.external_ip} connectport={self.config.api_port} connectaddress=127.0.0.1  # seulement si la redirection exacte est absente',
                    f'"{self._vmrest_executable()}" -c "<certificat>" -k "<clé>" -p {self.config.api_port}',
                    "Contrôler le processus, le port et GET /api/vms avant d'afficher RUNNING",
                    "Arrêter uniquement le processus vmrest correspondant à VMware Workstation",
                ],
                requires_admin=False,
            ),
            HostCommandPlan(
                "Règle de pare-feu vmrest",
                [
                    f"Lire Get-NetFirewallRule -Name '{self.config.vmrest_firewall_rule_name}'",
                    f"Créer ou activer une règle entrante TCP sur le port {self.config.api_port}",
                    "Désactiver la règle sans la supprimer lorsque l'accès distant n'est plus requis",
                ],
            ),
        ]

    def inspect_sshd(self) -> SshdRuntimeStatus:
        """Lit l'état réel du service sshd sans modifier Windows ni demander UAC."""

        script = """
$service = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
if ($null -eq $service) {
    [pscustomobject]@{installed=$false; status='Absent'; start_type='Inconnu'} | ConvertTo-Json -Compress
} else {
    [pscustomobject]@{
        installed=$true
        status=[string]$service.Status
        start_type=[string]$service.StartType
    } | ConvertTo-Json -Compress
}
"""
        try:
            data = self._powershell_json(script)
        except HostSetupError as exc:
            return SshdRuntimeStatus(False, False, "Erreur", "Inconnu", False, str(exc))

        installed = bool(data.get("installed"))
        service_status = str(data.get("status", "Inconnu"))
        config_exists = Path(self.config.sshd_config_path).is_file()
        running = installed and service_status.casefold() == "running"
        if not installed:
            message = "OpenSSH Server est absent : une installation administrateur est requise."
        elif running:
            message = "Le service OpenSSH Server est installé et en cours d'exécution."
        else:
            message = f"OpenSSH Server est installé mais son état est {service_status}."
        return SshdRuntimeStatus(
            installed=installed,
            running=running,
            service_status=service_status,
            start_type=str(data.get("start_type", "Inconnu")),
            config_exists=config_exists,
            message=message,
        )

    def inspect_vmrest(self, username: str = "", password: str = "") -> VmrestRuntimeStatus:
        """Recoupe processus, port TCP et réponse HTTP pour éviter un faux RUNNING."""

        executable = self._vmrest_executable()
        process_ids = self._vmrest_process_ids()
        port_listening = self._is_local_port_open(self.config.api_port)
        api_reachable = False
        authenticated = False
        http_status: int | None = None
        if port_listening:
            try:
                auth = (username, password) if username and password else None
                response = httpx.get(
                    f"https://127.0.0.1:{self.config.api_port}/api/vms",
                    auth=auth,
                    verify=False,
                    timeout=2,
                )
                http_status = response.status_code
                # Une réponse 401 prouve que le serveur VMware répond, mais pas les identifiants.
                api_reachable = response.status_code in {200, 401}
                authenticated = response.status_code == 200
            except httpx.HTTPError:
                api_reachable = False

        running = bool(process_ids) and port_listening and api_reachable
        if running and authenticated:
            message = f"vmrest fonctionne et l'API est authentifiée (HTTP {http_status})."
        elif running:
            message = f"vmrest fonctionne, mais les identifiants doivent être vérifiés (HTTP {http_status})."
        elif process_ids and not port_listening:
            message = "Le processus vmrest existe, mais le port API n'écoute pas encore."
        elif port_listening and not api_reachable:
            message = "Le port est ouvert, mais l'endpoint VMware /api/vms ne répond pas correctement."
        elif not executable.is_file():
            message = f"vmrest.exe est introuvable : {executable}"
        else:
            message = "vmrest est arrêté."

        status = self.config.setup_status
        status.vmrest_running = running
        status.vmrest_process_ids = list(process_ids)
        status.vmrest_http_status = http_status
        # Une réponse HTTP 200 avec les identifiants fournis est la preuve
        # réelle que ``vmrest -C`` est déjà configuré sur cet hôte. Cette
        # propriété ne doit pas dépendre du scénario qui a lancé la commande.
        if authenticated:
            status.credentials_configured = True
        if running:
            status.state = HostSetupState.RUNNING
        elif status.state == HostSetupState.RUNNING:
            status.state = HostSetupState.READY if status.credentials_configured else HostSetupState.PARTIAL
        return VmrestRuntimeStatus(
            executable_exists=executable.is_file(),
            process_ids=process_ids,
            port_listening=port_listening,
            api_reachable=api_reachable,
            authenticated=authenticated,
            http_status=http_status,
            running=running,
            message=message,
        )

    def inspect_vmrest_firewall(self) -> FirewallRuntimeStatus:
        """Lit la règle Windows et vérifie qu'elle correspond au port vmrest configuré."""

        rule_name_b64 = self._base64_text(self.config.vmrest_firewall_rule_name)
        script = f"""
$name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{rule_name_b64}'))
$rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $rule) {{
    [pscustomobject]@{{exists=$false; enabled=$false; direction=''; action=''; protocol=''; local_port=''}} | ConvertTo-Json -Compress
}} else {{
    $port = $rule | Get-NetFirewallPortFilter | Select-Object -First 1
    [pscustomobject]@{{
        exists=$true
        enabled=([string]$rule.Enabled -eq 'True')
        direction=[string]$rule.Direction
        action=[string]$rule.Action
        protocol=[string]$port.Protocol
        local_port=[string]$port.LocalPort
    }} | ConvertTo-Json -Compress
}}
"""
        try:
            data = self._powershell_json(script)
        except HostSetupError as exc:
            return FirewallRuntimeStatus(False, False, "", "", "", "", False, str(exc))
        if not isinstance(data, dict):
            return FirewallRuntimeStatus(False, False, "", "", "", "", False, "Etat du pare-feu illisible.")

        exists = bool(data.get("exists"))
        enabled = bool(data.get("enabled"))
        direction = str(data.get("direction", ""))
        action = str(data.get("action", ""))
        protocol = str(data.get("protocol", ""))
        local_port = str(data.get("local_port", ""))
        matches = (
            exists
            and direction.casefold() == "inbound"
            and action.casefold() == "allow"
            and protocol.casefold() in {"tcp", "6"}
            and local_port == str(self.config.api_port)
        )
        if not exists:
            message = f"La règle {self.config.vmrest_firewall_rule_name} n'existe pas."
        elif enabled and matches:
            message = f"La règle autorise le trafic TCP entrant sur le port {self.config.api_port}."
        elif not enabled:
            message = "La règle vmrest existe, mais elle est désactivée."
        else:
            message = "La règle est active, mais ses paramètres ne correspondent pas à la configuration vmrest."
        return FirewallRuntimeStatus(exists, enabled, direction, action, protocol, local_port, matches, message)

    def enable_vmrest_firewall(self) -> str:
        """Crée ou active par UAC la règle entrante du port vmrest, puis la relit."""

        rule_name_b64 = self._base64_text(self.config.vmrest_firewall_rule_name)
        port = self.config.api_port
        script = f"""
$name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{rule_name_b64}'))
$rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
if ($null -eq $rule) {{
    New-NetFirewallRule -Name $name -DisplayName $name -Enabled True -Direction Inbound -Protocol TCP -LocalPort {port} -Action Allow | Out-Null
}} else {{
    Set-NetFirewallRule -Name $name -Enabled True -Direction Inbound -Action Allow -Protocol TCP -LocalPort {port}
}}
"""
        self._run_elevated_powershell(script, "Activation de la règle pare-feu vmrest")
        runtime = self.inspect_vmrest_firewall()
        if not (runtime.exists and runtime.enabled and runtime.matches_configuration):
            raise HostSetupError(f"La règle n'a pas pu être activée correctement : {runtime.message}")
        return self._update_status(runtime.message)

    def disable_vmrest_firewall(self) -> str:
        """Désactive par UAC la règle vmrest sans supprimer sa configuration."""

        current = self.inspect_vmrest_firewall()
        if not current.exists:
            return self._update_status(current.message)
        rule_name_b64 = self._base64_text(self.config.vmrest_firewall_rule_name)
        script = f"""
$name = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{rule_name_b64}'))
Set-NetFirewallRule -Name $name -Enabled False -ErrorAction Stop
"""
        self._run_elevated_powershell(script, "Désactivation de la règle pare-feu vmrest")
        runtime = self.inspect_vmrest_firewall()
        if runtime.exists and runtime.enabled:
            raise HostSetupError("Windows indique encore que la règle pare-feu vmrest est active")
        return self._update_status(runtime.message)

    def choose_openssl_executable(self) -> str | None:
        """Ouvre le sélecteur natif Windows et retourne le chemin choisi, sans téléverser le fichier."""

        script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Localiser openssl.exe'
$dialog.Filter = 'OpenSSL (openssl.exe)|openssl.exe|Exécutables (*.exe)|*.exe|Tous les fichiers (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $dialog.FileName
}
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise HostSetupError(f"Impossible d'ouvrir le sélecteur OpenSSL : {result.stderr.strip()}")
        selected = result.stdout.strip()
        if not selected:
            return None
        path = Path(selected)
        if not path.is_file() or path.name.casefold() != "openssl.exe":
            raise HostSetupError("Le fichier sélectionné doit être un exécutable openssl.exe existant")
        return str(path)

    def choose_openssl_config_file(self) -> str | None:
        """Choisit le fichier de configuration fourni par l'utilisateur."""

        script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Choisir le fichier de configuration OpenSSL'
$dialog.Filter = 'Configuration OpenSSL (*.cnf;*.conf)|*.cnf;*.conf|Tous les fichiers (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $dialog.FileName
}
"""
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
        )
        if result.returncode != 0:
            raise HostSetupError(
                f"Impossible d'ouvrir le sélecteur de configuration OpenSSL : {result.stderr.strip()}"
            )
        selected = result.stdout.strip()
        return self.validate_openssl_config_file(selected) if selected else None

    @staticmethod
    def validate_openssl_config_file(file_path: str) -> str:
        """Refuse un chemin absent, vide ou anormalement volumineux."""

        path = Path(file_path).expanduser()
        if not path.is_file():
            raise HostSetupError(f"Fichier de configuration OpenSSL introuvable : {path}")
        size = path.stat().st_size
        if size == 0:
            raise HostSetupError("Le fichier de configuration OpenSSL est vide")
        if size > 1024 * 1024:
            raise HostSetupError("Le fichier de configuration OpenSSL dépasse 1 Mio")
        return str(path.resolve())

    def choose_public_key_file(self) -> SelectedPublicKey | None:
        """Ouvre le sélecteur Windows puis extrait et valide la clé du fichier ``.pub``."""

        script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Choisir une clé publique OpenSSH'
$dialog.Filter = 'Clés publiques OpenSSH (*.pub)|*.pub'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $dialog.FileName
}
"""
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostSetupError(f"Impossible d'ouvrir le sélecteur de clé publique : {exc}") from exc
        if result.returncode != 0:
            raise HostSetupError(f"Impossible d'ouvrir le sélecteur de clé publique : {result.stderr.strip()}")
        selected = result.stdout.strip()
        return self.load_public_key_file(selected) if selected else None

    @staticmethod
    def load_public_key_file(file_path: str) -> SelectedPublicKey:
        """Lit un petit fichier ``.pub`` et refuse tout contenu ambigu ou non OpenSSH."""

        path = Path(file_path).expanduser()
        if path.suffix.casefold() != ".pub":
            raise HostSetupError("Le fichier de clé publique doit porter l'extension .pub")
        if not path.is_file():
            raise HostSetupError(f"Fichier de clé publique introuvable : {path}")
        if path.stat().st_size > 64 * 1024:
            raise HostSetupError("Le fichier .pub est anormalement volumineux")
        try:
            lines = [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        except (OSError, UnicodeError) as exc:
            raise HostSetupError(f"Impossible de lire la clé publique : {exc}") from exc
        if len(lines) != 1:
            raise HostSetupError("Le fichier .pub doit contenir exactement une clé publique non vide")
        key = lines[0]
        if not key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
            raise HostSetupError("Le fichier ne contient pas une clé publique OpenSSH prise en charge")
        # Une clé comprend au minimum son algorithme et une charge utile Base64 non triviale.
        parts = key.split()
        if len(parts) < 2:
            raise HostSetupError("Le contenu du fichier .pub est incomplet")
        try:
            padding = "=" * (-len(parts[1]) % 4)
            decoded_key = base64.b64decode(parts[1] + padding, validate=True)
        except ValueError as exc:
            raise HostSetupError("La charge utile de la clé publique n'est pas un Base64 valide") from exc
        if len(decoded_key) < 16:
            raise HostSetupError("La charge utile de la clé publique est trop courte")
        return SelectedPublicKey(path=str(path.resolve()), key=key)

    def choose_vmrest_certificate_file(self) -> str | None:
        """Choisit un certificat PEM local et retourne son chemin absolu validé."""

        selected = self._choose_windows_file(
            "Choisir le certificat TLS de vmrest",
            "Certificats (*.pem;*.crt;*.cer)|*.pem;*.crt;*.cer|Tous les fichiers (*.*)|*.*",
        )
        return self.validate_vmrest_certificate_file(selected) if selected else None

    def choose_vmrest_private_key_file(self) -> str | None:
        """Choisit une clé privée PEM locale non chiffrée et retourne son chemin validé."""

        selected = self._choose_windows_file(
            "Choisir la clé privée TLS de vmrest",
            "Clés privées (*.pem;*.key)|*.pem;*.key|Tous les fichiers (*.*)|*.*",
        )
        return self.validate_vmrest_private_key_file(selected) if selected else None

    @staticmethod
    def validate_vmrest_certificate_file(file_path: str) -> str:
        """Refuse un fichier absent, trop grand ou qui n'est pas un certificat PEM."""

        path, content = HostSetupService._read_small_pem_file(file_path, "certificat")
        if "-----BEGIN CERTIFICATE-----" not in content or "-----END CERTIFICATE-----" not in content:
            raise HostSetupError("Le fichier choisi ne contient pas un certificat PEM valide")
        return str(path.resolve())

    @staticmethod
    def validate_vmrest_private_key_file(file_path: str) -> str:
        """Accepte les principaux formats de clé PEM non chiffrés utilisables par vmrest."""

        path, content = HostSetupService._read_small_pem_file(file_path, "clé privée")
        if "-----BEGIN ENCRYPTED PRIVATE KEY-----" in content:
            raise HostSetupError("La clé privée est chiffrée; vmrest ne pourra pas demander sa phrase secrète")
        markers = (
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        )
        if not any(marker in content for marker in markers):
            raise HostSetupError("Le fichier choisi ne contient pas une clé privée PEM prise en charge")
        return str(path.resolve())

    @staticmethod
    def _read_small_pem_file(file_path: str, label: str) -> tuple[Path, str]:
        """Lit de façon bornée un fichier PEM avant de conserver son chemin."""

        path = Path(file_path).expanduser()
        if not path.is_file():
            raise HostSetupError(f"Fichier de {label} introuvable : {path}")
        if path.stat().st_size > 1024 * 1024:
            raise HostSetupError(f"Le fichier de {label} est anormalement volumineux")
        try:
            return path, path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError) as exc:
            raise HostSetupError(f"Impossible de lire le fichier de {label} : {exc}") from exc

    @staticmethod
    def _choose_windows_file(title: str, file_filter: str) -> str | None:
        """Ouvre un explorateur Windows natif avec des libellés encodés sans injection PowerShell."""

        title_b64 = HostSetupService._base64_text(title)
        filter_b64 = HostSetupService._base64_text(file_filter)
        script = f"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{title_b64}'))
$dialog.Filter = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{filter_b64}'))
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    Write-Output $dialog.FileName
}}
"""
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-STA", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=300,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostSetupError(f"Impossible d'ouvrir le sélecteur de fichier : {exc}") from exc
        if result.returncode != 0:
            raise HostSetupError(f"Impossible d'ouvrir le sélecteur de fichier : {result.stderr.strip()}")
        return result.stdout.strip() or None

    def install_openssh_server(self) -> str:
        """Demande UAC, installe OpenSSH Server, active son service et contrôle le pare-feu."""

        if self.inspect_sshd().installed:
            return "OpenSSH Server est déjà installé"
        script = r"""
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
Set-Service -Name 'sshd' -StartupType Automatic
Start-Service -Name 'sshd'
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
}
"""
        self._run_elevated_powershell(script, "Installation d'OpenSSH Server")
        runtime = self.inspect_sshd()
        if not runtime.installed or not runtime.running:
            raise HostSetupError(f"L'installation s'est terminée, mais sshd n'est pas opérationnel : {runtime.message}")
        return self._update_status("OpenSSH Server installé et démarré")

    def configure_ssh(self, public_key: str) -> str:
        """Demande UAC, ajoute la clé, applique les ACL puis valide et redémarre sshd."""

        runtime = self.inspect_sshd()
        if not runtime.installed:
            raise HostSetupError("OpenSSH Server est absent. Utilisez d'abord le bouton Installer OpenSSH Server.")
        normalized_key = public_key.strip()
        if not normalized_key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")) or "\n" in normalized_key:
            raise HostSetupError("Fournissez une clé publique OpenSSH valide sur une seule ligne")
        if not self.config.ssh_user.strip():
            raise HostSetupError("L'utilisateur Windows/SSH est requis")

        key_b64 = self._base64_text(normalized_key)
        user_b64 = self._base64_text(self.config.ssh_user.strip())
        config_b64 = self._base64_text(self.config.sshd_config_path)
        legacy_literal = "$true" if self.config.allow_legacy_ssh_rsa else "$false"
        # Les valeurs utilisateur sont décodées depuis Base64 afin qu'elles ne deviennent jamais du code PowerShell.
        script = rf"""
$publicKey = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{key_b64}'))
$username = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{user_b64}'))
$configPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{config_b64}'))
$allowLegacy = {legacy_literal}
$adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
$isAdministrator = $null -ne (Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue | Where-Object {{ ($_.Name -split '\\')[-1] -ieq $username }})
if ($isAdministrator) {{
    $authorizedKeys = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
}} else {{
    $localUser = Get-LocalUser -Name $username -ErrorAction Stop
    $profileKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $localUser.SID.Value
    $profilePath = (Get-ItemProperty -LiteralPath $profileKey -ErrorAction Stop).ProfileImagePath
    $sshDirectory = Join-Path $profilePath '.ssh'
    New-Item -ItemType Directory -Force -Path $sshDirectory | Out-Null
    $authorizedKeys = Join-Path $sshDirectory 'authorized_keys'
}}
if (-not (Test-Path -LiteralPath $authorizedKeys)) {{ New-Item -ItemType File -Path $authorizedKeys -Force | Out-Null }}
$existingKeys = @(Get-Content -LiteralPath $authorizedKeys -ErrorAction SilentlyContinue)
if ($existingKeys -notcontains $publicKey) {{
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::AppendAllText($authorizedKeys, $publicKey + [Environment]::NewLine, $utf8NoBom)
}}
if ($isAdministrator) {{
    & icacls.exe $authorizedKeys /inheritance:r /grant:r '*S-1-5-32-544:(F)' /grant:r '*S-1-5-18:(F)' | Out-Null
}} else {{
    & icacls.exe $authorizedKeys /inheritance:r /grant:r "$username`:(F)" /grant:r '*S-1-5-18:(F)' | Out-Null
}}
if ($LASTEXITCODE -ne 0) {{ throw "Impossible d'appliquer les ACL au fichier authorized_keys." }}
$backupPath = $null
if ($allowLegacy) {{
    $backupPath = $configPath + '.cygil.bak'
    Copy-Item -LiteralPath $configPath -Destination $backupPath -Force
    $content = Get-Content -LiteralPath $configPath -Raw
    $directive = 'PubkeyAcceptedAlgorithms +ssh-rsa'
    if ($content -notmatch '(?m)^\s*PubkeyAcceptedAlgorithms\s+.*ssh-rsa') {{
        $match = [regex]::Match($content, '(?m)^\s*Match\s+')
        if ($match.Success) {{
            $content = $content.Insert($match.Index, $directive + [Environment]::NewLine)
        }} else {{
            $content = $content.TrimEnd() + [Environment]::NewLine + $directive + [Environment]::NewLine
        }}
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($configPath, $content, $utf8NoBom)
    }}
}}
$sshd = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
& $sshd -t -f $configPath
if ($LASTEXITCODE -ne 0) {{
    if ($null -ne $backupPath) {{
        Copy-Item -LiteralPath $backupPath -Destination $configPath -Force
    }}
    throw 'sshd_config est invalide; aucun redémarrage ne sera effectué.'
}}
Restart-Service -Name 'sshd' -ErrorAction Stop
"""
        self._run_elevated_powershell(script, "Configuration d'OpenSSH Server")
        runtime = self.inspect_sshd()
        if not runtime.running:
            raise HostSetupError(f"La configuration est terminée, mais sshd n'est pas actif : {runtime.message}")
        self.config.setup_status.ssh_configured = True
        return self._update_status("Configuration OpenSSH terminée et service actif")

    def configure_ssh_from_file(self, file_path: str) -> str:
        """Relit le fichier choisi au dernier moment puis configure SSH avec son contenu."""

        selected = self.load_public_key_file(file_path)
        self.config.ssh_authorized_public_key_path = selected.path
        return self.configure_ssh(selected.key)

    def generate_certificate(self) -> str:
        """Génère la clé privée et le certificat auto-signé utilisés par vmrest."""

        openssl = self._resolve_openssl_executable()
        openssl_config = self._resolve_openssl_config_file()
        directory = self._certificate_directory()
        directory.mkdir(parents=True, exist_ok=True)
        key_path = directory / "workstationapi-key.pem"
        certificate_path = directory / "workstationapi-cert.pem"
        self._run([
            str(openssl),
            "req",
            "-config",
            str(openssl_config),
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            str(key_path),
            "-out",
            str(certificate_path),
            "-days",
            "365",
            "-nodes",
            "-subj",
            f"/CN={self.config.external_ip}",
        ])
        if not key_path.is_file() or not certificate_path.is_file():
            raise HostSetupError("OpenSSL s'est terminé sans produire les deux fichiers attendus")
        self.config.setup_status.certificate_generated = True
        self.config.setup_status.private_key_path = str(key_path)
        self.config.setup_status.certificate_path = str(certificate_path)
        return self._update_status("Certificat vmrest généré")

    def configure_vmrest_credentials(self) -> str:
        """Ouvre l'assistant ``vmrest -C`` dans une console Windows temporaire.

        vmrest 1.2.1 lit le mot de passe directement depuis un terminal et ignore
        une entrée standard redirigée. Le processus NiceGUI attend donc la console
        dans son travail d'arrière-plan, sans recevoir ni journaliser le secret.
        """

        vmrest = self._require_vmrest_executable()
        try:
            process = subprocess.Popen(
                [str(vmrest), "-C"],
                # CREATE_NEW_CONSOLE fournit le terminal réel exigé par la
                # lecture masquée du mot de passe dans cette version de vmrest.
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
            returncode = process.wait()
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostSetupError(f"Impossible d'ouvrir la console d'identifiants vmrest : {exc}") from exc
        if returncode != 0:
            raise HostSetupError(
                f"vmrest -C s'est terminé avec le code {returncode}; les identifiants ne sont pas confirmés"
            )
        self.config.setup_status.credentials_configured = True
        return self._update_status("Identifiants vmrest configurés")

    def inspect_vmrest_portproxy(self) -> tuple[tuple[str, int, str, int], ...]:
        """Lit les redirections IPv4 netsh sans modifier la configuration réseau."""

        try:
            result = subprocess.run(
                ["netsh.exe", "interface", "portproxy", "show", "v4tov4"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostSetupError(f"Inspection de la redirection vmrest impossible : {exc}") from exc
        if result.returncode != 0:
            raise HostSetupError(
                f"Inspection de la redirection vmrest impossible : {result.stderr.strip() or result.stdout.strip()}"
            )
        rules: list[tuple[str, int, str, int]] = []
        # Les titres de netsh sont localisés, mais chaque ligne de données garde
        # quatre colonnes adresse/port/adresse/port que l'on valide strictement.
        for line in result.stdout.splitlines():
            columns = line.split()
            if len(columns) != 4:
                continue
            try:
                listen_address = str(IPv4Address(columns[0]))
                listen_port = int(columns[1])
                connect_address = str(IPv4Address(columns[2]))
                connect_port = int(columns[3])
            except (AddressValueError, ValueError):
                continue
            rules.append((listen_address, listen_port, connect_address, connect_port))
        return tuple(rules)

    def ensure_vmrest_portproxy(self) -> str:
        """Crée la redirection vmrest absente sans remplacer un endpoint existant."""

        try:
            listen_address = str(IPv4Address(self.config.external_ip))
        except AddressValueError as exc:
            raise HostSetupError(
                f"L'adresse de l'hôte n'est pas une IPv4 valide pour portproxy : {self.config.external_ip}"
            ) from exc
        port = int(self.config.api_port)
        expected = (listen_address, port, "127.0.0.1", port)
        current = self.inspect_vmrest_portproxy()
        if expected in current:
            return f"Redirection vmrest déjà présente sur {listen_address}:{port}"
        conflict = next(
            (rule for rule in current if rule[0] == listen_address and rule[1] == port),
            None,
        )
        if conflict:
            raise HostSetupError(
                "Une autre redirection utilise déjà "
                f"{listen_address}:{port} vers {conflict[2]}:{conflict[3]}; aucune modification automatique effectuée"
            )
        command = (
            "& netsh.exe interface portproxy add v4tov4 "
            f"listenport={port} listenaddress={listen_address} "
            f"connectport={port} connectaddress=127.0.0.1"
        )
        script = f"""
$output = {command} 2>&1
if ($LASTEXITCODE -ne 0) {{ throw ($output | Out-String) }}
"""
        self._run_elevated_powershell(script, "Création de la redirection vmrest")
        if expected not in self.inspect_vmrest_portproxy():
            raise HostSetupError("netsh s'est terminé sans créer la redirection vmrest attendue")
        return f"Redirection vmrest créée sur {listen_address}:{port}"

    def start_vmrest(self, username: str = "", password: str = "") -> str:
        """Démarre toujours vmrest par UAC, puis vérifie processus, port et HTTP.

        La lecture de l'API fonctionne sans élévation, mais la création des VMnet
        est refusée par VMware avec HTTP 403 lorsque le processus serveur n'est
        pas administrateur. Le bouton de démarrage doit donc produire une demande
        UAC à chaque nouveau lancement, sans tenter d'abord un processus ordinaire.
        """

        if not username or not password:
            raise HostSetupError(
                "Saisissez les identifiants vmrest utilisés sur cet hôte avant le démarrage"
            )
        current = self.inspect_vmrest(username, password)
        if current.running:
            if not current.authenticated:
                raise HostSetupError(
                    "vmrest fonctionne déjà, mais les identifiants saisis sont refusés"
                )
            # Même une instance joignable peut avoir hérité d'un jeton Windows
            # non élevé. Elle sera remplacée sous le même UAC ci-dessous afin
            # que les mutations POST /api/vmnets ne puissent plus recevoir 403.
            self.config.setup_status.credentials_configured = True
        status = self.config.setup_status
        if not (status.certificate_path and status.private_key_path):
            raise HostSetupError(
                "Le certificat et la clé privée vmrest doivent être sélectionnés avant le démarrage"
            )
        certificate = Path(status.certificate_path)
        private_key = Path(status.private_key_path)
        if not certificate.is_file() or not private_key.is_file():
            raise HostSetupError("Le certificat ou la clé privée enregistrée n'existe plus")
        # Un scénario chargé peut contenir des chemins qui n'ont pas été choisis par la GUI.
        self.validate_vmrest_certificate_file(str(certificate))
        self.validate_vmrest_private_key_file(str(private_key))
        vmrest = self._require_vmrest_executable()
        # La redirection doit exister avant le processus API afin que les VM du
        # réseau de gestion puissent joindre son écoute locale 127.0.0.1.
        self.ensure_vmrest_portproxy()
        arguments = [
            str(vmrest),
            "-c",
            str(certificate),
            "-k",
            str(private_key),
            # vmrest 1.2.1 ne propose aucune option -i; sa CLI expose
            # uniquement -p/--port pour configurer l'écoute du serveur.
            "-p",
            str(self.config.api_port),
        ]
        try:
            # Aucun lancement non élevé ne précède cet appel : ShellExecuteEx
            # affiche donc systématiquement UAC quand vmrest est arrêté.
            self._start_vmrest_elevated(arguments)
        except OSError as exc:
            raise HostSetupError(f"Impossible de démarrer vmrest : {exc}") from exc

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            runtime = self.inspect_vmrest(username, password)
            if runtime.running:
                if not runtime.authenticated:
                    raise HostSetupError(
                        "vmrest a démarré, mais les identifiants saisis sont refusés; "
                        "utilisez la console vmrest -C seulement si ces identifiants n'ont jamais été configurés sur l'hôte"
                    )
                status.credentials_configured = True
                return self._update_status(runtime.message)
            time.sleep(0.25)
        raise HostSetupError("vmrest élevé n'est pas devenu opérationnel en 10 secondes")

    def stop_vmrest(self) -> str:
        """Arrête le vmrest de Workstation et demande UAC uniquement en cas d'accès refusé."""

        process_ids = self._vmrest_process_ids()
        if not process_ids:
            self.config.setup_status.vmrest_running = False
            return self._update_status("vmrest est déjà arrêté")
        pid_list = ",".join(str(pid) for pid in process_ids)
        script = f"Stop-Process -Id @({pid_list}) -Force -ErrorAction Stop"
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            # Le clic de l'utilisateur autorise l'action, mais Windows conserve le dernier mot via UAC.
            self._run_elevated_powershell(script, "Arrêt de VMware vmrest")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not self._vmrest_process_ids() and not self._is_local_port_open(self.config.api_port):
                self.config.setup_status.vmrest_running = False
                self.config.setup_status.vmrest_process_ids = []
                return self._update_status("vmrest est arrêté")
            time.sleep(0.2)
        raise HostSetupError("Le processus vmrest n'a pas pu être arrêté")

    def check_vmrest(self, username: str, password: str) -> str:
        """Force une inspection réelle et exige une réponse API authentifiée."""

        runtime = self.inspect_vmrest(username, password)
        if not runtime.running:
            self.config.setup_status.state = HostSetupState.ERROR
            raise HostSetupError(runtime.message)
        if not runtime.authenticated:
            self.config.setup_status.state = HostSetupState.ERROR
            raise HostSetupError("vmrest répond, mais les identifiants saisis sont refusés")
        self.config.setup_status.state = HostSetupState.RUNNING
        return self._update_status(runtime.message)
    # endregion

    # region Résolution des programmes et inspections locales
    def _certificate_directory(self) -> Path:
        """Résout le dossier de certificats relativement au projet si nécessaire."""

        configured = Path(self.config.certificate_directory)
        return configured if configured.is_absolute() else PROJECT_ROOT / configured

    def _vmrest_executable(self) -> Path:
        """Retourne le chemin attendu de vmrest.exe dans VMware Workstation."""

        return Path(self.config.workstation_directory) / "vmrest.exe"

    def _require_vmrest_executable(self) -> Path:
        """Refuse une action vmrest lorsque l'exécutable configuré n'existe pas."""

        executable = self._vmrest_executable()
        if not executable.is_file():
            raise HostSetupError(f"vmrest.exe est introuvable : {executable}")
        return executable

    def _resolve_openssl_executable(self) -> Path:
        """Valide le chemin choisi ou recherche le nom de programme dans PATH."""

        configured = Path(self.config.openssl_executable).expanduser()
        resolved = configured if configured.is_file() else Path(shutil.which(self.config.openssl_executable) or "")
        if not resolved.is_file():
            raise HostSetupError("OpenSSL est introuvable. Utilisez le bouton Parcourir pour localiser openssl.exe.")
        return resolved

    def _resolve_openssl_config_file(self) -> Path:
        """Exige le fichier utilisateur avant toute création de clé ou certificat."""

        configured = self.config.openssl_config_path
        if not configured:
            raise HostSetupError(
                "Le fichier de configuration OpenSSL est requis. Utilisez le bouton Parcourir."
            )
        return Path(self.validate_openssl_config_file(configured))

    def _vmrest_process_ids(self) -> tuple[int, ...]:
        """Retourne uniquement les PID dont le chemin correspond au vmrest configuré."""

        expected_b64 = self._base64_text(str(self._vmrest_executable().resolve()))
        script = f"""
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{expected_b64}'))
$ids = @(Get-Process -Name 'vmrest' -ErrorAction SilentlyContinue | Where-Object {{ $null -eq $_.Path -or $_.Path -ieq $expected }} | Select-Object -ExpandProperty Id)
@($ids) | ConvertTo-Json -Compress
"""
        try:
            data = self._powershell_json(script)
        except HostSetupError:
            return ()
        if data is None:
            return ()
        values = data if isinstance(data, list) else [data]
        return tuple(sorted(int(value) for value in values))

    @staticmethod
    def _is_local_port_open(port: int) -> bool:
        """Teste l'écoute TCP locale sans supposer que le processus a bien démarré."""

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            return False
    # endregion

    # region Exécution PowerShell normale et élevée
    @staticmethod
    def _powershell_json(script: str) -> dict | list | int | None:
        """Exécute une inspection PowerShell et décode sa sortie JSON."""

        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostSetupError(f"Inspection PowerShell impossible : {exc}") from exc
        if result.returncode != 0:
            raise HostSetupError(result.stderr.strip() or "Inspection PowerShell échouée")
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise HostSetupError(f"Réponse PowerShell illisible : {output}") from exc

    def _run_elevated_powershell(self, action_script: str, action_name: str) -> None:
        """Affiche UAC, attend le PowerShell administrateur et remonte son résultat."""

        if os.name != "nt":
            raise HostSetupError("L'élévation UAC n'est disponible que sous Windows")
        with tempfile.TemporaryDirectory(prefix="cygil-uac-") as temporary_directory:
            directory = Path(temporary_directory)
            script_path = directory / "elevated-action.ps1"
            result_path = directory / "result.txt"
            # Le fichier doit appartenir au processus utilisateur avant UAC.
            # Si PowerShell administrateur le crée lui-même, certaines politiques
            # Windows empêchent ensuite NiceGUI de le lire ou de le supprimer.
            result_path.write_text("", encoding="utf-8-sig")
            result_b64 = self._base64_text(str(result_path))
            wrapped_script = f"""
$ErrorActionPreference = 'Stop'
$resultPath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{result_b64}'))
try {{
{action_script}
    'OK' | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 0
}} catch {{
    ($_ | Out-String) | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}}
"""
            script_path.write_text(wrapped_script, encoding="utf-8-sig")
            exit_code = self._shell_execute_runas(script_path)
            # Une action réussie n'a pas besoin de relire le canal d'erreur. Cela
            # évite également qu'une ACL Windows atypique transforme un succès
            # administrateur en faux échec PermissionError côté interface.
            if exit_code == 0:
                return
            try:
                details = result_path.read_text(encoding="utf-8-sig").strip()
            except OSError:
                details = ""
            raise HostSetupError(f"{action_name} a échoué : {details or f'code {exit_code}'}")

    @staticmethod
    def _shell_execute_runas(script_path: Path) -> int:
        """Utilise ShellExecuteEx afin que Windows affiche explicitement sa fenêtre UAC."""

        class ShellExecuteInfo(ctypes.Structure):
            """Structure Win32 minimale nécessaire pour attendre le processus élevé."""

            _fields_ = [
                ("cbSize", ctypes.c_ulong),
                ("fMask", ctypes.c_ulong),
                ("hwnd", ctypes.c_void_p),
                ("lpVerb", ctypes.c_wchar_p),
                ("lpFile", ctypes.c_wchar_p),
                ("lpParameters", ctypes.c_wchar_p),
                ("lpDirectory", ctypes.c_wchar_p),
                ("nShow", ctypes.c_int),
                ("hInstApp", ctypes.c_void_p),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", ctypes.c_wchar_p),
                ("hkeyClass", ctypes.c_void_p),
                ("dwHotKey", ctypes.c_ulong),
                ("hIconOrMonitor", ctypes.c_void_p),
                ("hProcess", ctypes.c_void_p),
            ]

        info = ShellExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS permet d'attendre la fin.
        info.lpVerb = "runas"
        info.lpFile = "powershell.exe"
        info.lpParameters = f'-NoProfile -ExecutionPolicy Bypass -File "{script_path}"'
        info.nShow = 1
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ctypes.set_last_error(0)
        if not shell32.ShellExecuteExW(ctypes.byref(info)):
            error = ctypes.get_last_error()
            if error == 1223:
                raise HostSetupError("L'utilisateur a annulé la demande d'élévation UAC")
            raise HostSetupError(f"Windows n'a pas pu demander l'élévation UAC (erreur {error})")
        try:
            kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
            exit_code = ctypes.c_ulong()
            kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(exit_code))
            return int(exit_code.value)
        finally:
            kernel32.CloseHandle(info.hProcess)

    def _start_vmrest_elevated(self, arguments: list[str]) -> None:
        """Remplace vmrest et le relance en arrière-plan avec le jeton UAC."""

        # Start-Process fusionne son tableau ArgumentList en une chaîne et perd
        # alors les limites des valeurs contenant des espaces. list2cmdline
        # applique ici les règles de citation Windows avant le passage en Base64.
        executable_b64 = self._base64_text(arguments[0])
        command_line_b64 = self._base64_text(subprocess.list2cmdline(arguments[1:]))
        decoded_lines = [
            f"$executable = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{executable_b64}'))",
            f"$commandLine = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{command_line_b64}'))",
        ]
        script = "\n".join(decoded_lines) + (
            "\n# Ne remplace que le vmrest de l'installation Workstation configurée.\n"
            "$existing = @(Get-Process -Name 'vmrest' -ErrorAction SilentlyContinue | "
            "Where-Object { $null -eq $_.Path -or $_.Path -ieq $executable })\n"
            "if ($existing) { $existing | Stop-Process -Force -ErrorAction Stop }\n"
            "Start-Process -FilePath $executable -ArgumentList $commandLine -WindowStyle Hidden"
        )
        self._run_elevated_powershell(script, "Démarrage de VMware vmrest")

    @staticmethod
    def _run(arguments: list[str]) -> None:
        """Exécute un programme sans shell et transforme son échec en erreur métier."""

        try:
            subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            raise HostSetupError(f"Commande échouée : {arguments[0]} — {exc}") from exc
    # endregion

    def _update_status(self, message: str) -> str:
        """Calcule l'état persistant après une étape confirmée ou une inspection."""

        status = self.config.setup_status
        status.last_message = message
        status.last_checked_at = datetime.now(UTC).isoformat()
        if status.vmrest_running:
            status.state = HostSetupState.RUNNING
        elif status.ssh_configured and status.certificate_generated and status.credentials_configured:
            status.state = HostSetupState.READY
        else:
            status.state = HostSetupState.PARTIAL
        return message

    @staticmethod
    def _base64_text(value: str) -> str:
        """Encode une valeur destinée à PowerShell sans ambiguïté de guillemets."""

        return base64.b64encode(value.encode("utf-8")).decode("ascii")
# endregion
