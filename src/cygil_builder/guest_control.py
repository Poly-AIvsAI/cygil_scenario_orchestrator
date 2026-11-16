"""Plans confirmés pour agir dans les VM sans bloquer NiceGUI.

Ce module ne contacte jamais VMware. Il utilise les accès invités explicitement
configurés et ouvre les terminaux dans la session graphique de la VM. Les plans
sont empreintés afin que la commande exécutée soit exactement celle affichée.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
from dataclasses import dataclass
from ipaddress import ip_interface
from pathlib import Path

from .lab_topology import PingRoute, resolve_ping_routes
from .models import (
    GuestAccessConfig,
    GuestCommunicator,
    GuestDesktopConfig,
    InfrastructureVM,
    IsolationInterfaceConfig,
    OSFamily,
    Scenario,
    TargetVM,
)


class GuestControlError(RuntimeError):
    """Refus d'un plan incomplet, ambigu ou non confirmé."""


@dataclass(frozen=True)
class GuestEndpoint:
    """Adresse et propriétés nécessaires pour contacter un OS invité."""

    machine_id: str
    os_family: OSFamily
    address: str
    access: GuestAccessConfig
    desktop: GuestDesktopConfig


@dataclass(frozen=True)
class GuestCommandPlan:
    """Commande distante prévisualisable et liée à une empreinte."""

    action: str
    machine_id: str
    transport: GuestCommunicator
    address: str
    remote_command: str
    description: str
    mutating: bool = True
    expected_disconnect: bool = False

    def preview(self) -> str:
        """Affiche le canal et la charge distante sans jamais inclure un secret."""

        return f"{self.transport.value.upper()} {self.machine_id}@{self.address}\n{self.remote_command}"


@dataclass(frozen=True)
class GuestExecutionResult:
    """Résultat borné d'une commande déclenchée en arrière-plan par la GUI."""

    plan: GuestCommandPlan
    returncode: int | None
    stdout: str
    stderr: str
    mode: str


def guest_confirmation_token(plans: list[GuestCommandPlan]) -> str:
    """Empreinte les commandes exactes affichées avant une mutation invitée."""

    payload = json.dumps(
        [
            {
                "action": plan.action,
                "machine": plan.machine_id,
                "transport": plan.transport.value,
                "address": plan.address,
                "command": plan.remote_command,
            }
            for plan in plans
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12].upper()


def _ps_encoded(command: str) -> str:
    """Encode une commande PowerShell sans la réinterpréter sur l'hôte."""

    return base64.b64encode(command.encode("utf-16-le")).decode("ascii")


def _utf8_encoded(command: str) -> str:
    """Encode une commande Linux afin d'éviter les concaténations shell."""

    return base64.b64encode(command.encode("utf-8")).decode("ascii")


class GuestControlService:
    """Construit et exécute uniquement des plans invités confirmés."""

    def __init__(self, scenario: Scenario, *, dry_run: bool = True) -> None:
        self.scenario = scenario
        self.dry_run = dry_run

    def machine_ids(self) -> list[str]:
        """Présente ensemble les VM réservées et cibles, sans utiliser Vagrant."""

        return [machine.id for machine in self.scenario.infrastructure] + [
            target.id for target in self.scenario.targets
        ]

    def endpoint(self, machine_id: str) -> GuestEndpoint:
        """Résout un accès explicite et refuse toute valeur devinée."""

        infrastructure = next(
            (machine for machine in self.scenario.infrastructure if machine.id == machine_id),
            None,
        )
        if infrastructure:
            return self._infrastructure_endpoint(infrastructure)
        target = next((item for item in self.scenario.targets if item.id == machine_id), None)
        if target:
            return self._target_endpoint(target)
        raise GuestControlError(f"VM inconnue : {machine_id}")

    def ping_routes(self, source_id: str, destination_id: str) -> list[PingRoute]:
        """Expose uniquement les routes explicitement présentes dans le scénario."""

        return resolve_ping_routes(self.scenario, source_id, destination_id)

    def build_visible_command_plan(
        self,
        machine_id: str,
        command: str,
        *,
        elevated: bool = False,
        action: str = "user_command",
        description: str = "Commande choisie par l'utilisateur",
    ) -> GuestCommandPlan:
        """Prépare l'ouverture d'un terminal dans la session graphique invitée."""

        if not command.strip():
            raise GuestControlError("La commande invitée est vide")
        endpoint = self.endpoint(machine_id)
        if not endpoint.desktop.visible_terminal_validated:
            raise GuestControlError(
                f"Le terminal graphique de {machine_id} n'a pas encore été validé"
            )
        remote = (
            self._windows_visible_terminal(endpoint, command, elevated=elevated)
            if endpoint.os_family == OSFamily.WINDOWS
            else self._linux_visible_terminal(endpoint, command, elevated=elevated)
        )
        return GuestCommandPlan(
            action=action,
            machine_id=machine_id,
            transport=endpoint.access.communicator,
            address=endpoint.address,
            remote_command=remote,
            description=description,
        )

    def build_ping_plan(self, route: PingRoute) -> GuestCommandPlan:
        """Ouvre un ping continu visible à l'intérieur de la VM source."""

        endpoint = self.endpoint(route.source_id)
        command = (
            f"ping.exe -t {route.destination_address}"
            if endpoint.os_family == OSFamily.WINDOWS
            else f"ping {route.destination_address}"
        )
        return self.build_visible_command_plan(
            route.source_id,
            command,
            action="continuous_ping",
            description=(
                f"Ping visible {route.source_id} -> {route.destination_id} "
                f"sur {route.network} ({route.destination_address})"
            ),
        )

    def build_isolation_plans(self, network: str) -> list[GuestCommandPlan]:
        """Désactive un réseau donné dans chaque invité, sans retirer de carte."""

        plans: list[GuestCommandPlan] = []
        for machine_id in self.machine_ids():
            machine = self._machine(machine_id)
            matches = [
                item
                for item in machine.isolation_interfaces
                if item.network == network and item.disable_before_snapshot
            ]
            if not matches:
                continue
            if len(matches) > 1:
                raise GuestControlError(
                    f"Plusieurs interfaces d'isolation {network} sont déclarées sur {machine_id}"
                )
            interface = matches[0]
            endpoint = self.endpoint(machine_id)
            command = self._disable_interface_command(endpoint.os_family, interface)
            plans.append(
                GuestCommandPlan(
                    action="disable_isolation_interface",
                    machine_id=machine_id,
                    transport=endpoint.access.communicator,
                    address=endpoint.address,
                    remote_command=command,
                    description=f"Dernière commande distante : désactiver {network}",
                    expected_disconnect=True,
                )
            )
        if not plans:
            raise GuestControlError(f"Aucune interface n'est associée au réseau {network}")
        return plans

    def execute(
        self,
        plans: list[GuestCommandPlan],
        *,
        confirmation_token: str | None = None,
    ) -> list[GuestExecutionResult]:
        """Exécute le plan exact; le dry-run demeure la valeur par défaut."""

        expected = guest_confirmation_token(plans)
        if not self.dry_run and confirmation_token != expected:
            raise GuestControlError("Le plan invité exact n'a pas été confirmé")
        if self.dry_run:
            return [GuestExecutionResult(plan, None, plan.preview(), "", "dry-run") for plan in plans]

        results: list[GuestExecutionResult] = []
        for plan in plans:
            endpoint = self.endpoint(plan.machine_id)
            arguments, environment = self._transport_command(endpoint, plan.remote_command)
            completed = subprocess.run(
                arguments,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=90,
                check=False,
                env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # La connexion peut disparaître avant la fin de la commande
            # d'isolation; ce fait reste explicite dans le résultat au lieu
            # d'être transformé silencieusement en succès.
            results.append(
                GuestExecutionResult(
                    plan,
                    completed.returncode,
                    completed.stdout[-12000:],
                    completed.stderr[-12000:],
                    "real",
                )
            )
        return results

    def verify_management_unreachable(
        self,
        plans: list[GuestCommandPlan],
        *,
        timeout: float = 2.0,
    ) -> dict[str, bool]:
        """Effectue un contrôle ponctuel des ports, sans minuteur global.

        ``True`` signifie que le canal de gestion testé est devenu injoignable.
        Ce contrôle doit être combiné à l'état VMware « powered on » avant de
        constituer la preuve finale d'air gap.
        """

        results: dict[str, bool] = {}
        for plan in plans:
            endpoint = self.endpoint(plan.machine_id)
            default_port = 22 if endpoint.access.communicator == GuestCommunicator.SSH else 5986 if endpoint.access.winrm_use_ssl else 5985
            port = endpoint.access.port or default_port
            try:
                with socket.create_connection((endpoint.address, port), timeout=timeout):
                    results[plan.machine_id] = False
            except OSError:
                results[plan.machine_id] = True
        return results

    def _machine(self, machine_id: str) -> InfrastructureVM | TargetVM:
        """Retourne le modèle sans confondre propriété VMware et Vagrant."""

        for machine in [*self.scenario.infrastructure, *self.scenario.targets]:
            if machine.id == machine_id:
                return machine
        raise GuestControlError(f"VM inconnue : {machine_id}")

    def _access_address(self, target: TargetVM) -> str | None:
        """Préfère le canal d'amorçage encore joignable à VMnet0."""

        if target.guest_access and target.guest_access.connection_address:
            return str(target.guest_access.connection_address)
        if self.scenario.vagrant.bootstrap_network:
            # Utiliser l'adresse VMnet0 avant de l'avoir configurée produirait
            # une tentative trompeuse. Le bail doit d'abord être inventorié.
            return None
        assigned = target.temporary_management.assigned_address
        return str(assigned.ip) if assigned else None

    def _target_endpoint(self, target: TargetVM) -> GuestEndpoint:
        address = self._access_address(target)
        if not address or not target.guest_access:
            raise GuestControlError(f"Accès invité incomplet pour {target.id}")
        return GuestEndpoint(
            target.id,
            target.os_family,
            address,
            target.guest_access,
            target.guest_desktop,
        )

    @staticmethod
    def _infrastructure_endpoint(machine: InfrastructureVM) -> GuestEndpoint:
        access = machine.guest_access
        # Les anciens champs SSH sont convertis en mémoire sans modifier le YAML.
        if access is None and machine.ssh_user:
            access = GuestAccessConfig(
                communicator=GuestCommunicator.SSH,
                username=machine.ssh_user,
                password_secret=machine.ssh_password_secret,
            )
        address = access.connection_address if access else None
        if not address:
            address = machine.management_ip
        if not machine.os_family or not address or not access:
            raise GuestControlError(f"Accès invité incomplet pour {machine.id}")
        return GuestEndpoint(
            machine.id,
            machine.os_family,
            str(ip_interface(address).ip) if "/" in str(address) else str(address),
            access,
            machine.guest_desktop,
        )

    @staticmethod
    def _windows_visible_terminal(
        endpoint: GuestEndpoint,
        command: str,
        *,
        elevated: bool,
    ) -> str:
        user = endpoint.desktop.session_user
        terminal = endpoint.desktop.terminal_executable
        if not user or not terminal:
            raise GuestControlError(
                f"Session utilisateur ou terminal Windows manquant pour {endpoint.machine_id}"
            )
        command_b64 = _ps_encoded(command)
        task_id = hashlib.sha256(
            f"{endpoint.machine_id}:{command}".encode("utf-8")
        ).hexdigest()[:10]
        run_level = "Highest" if elevated else "Limited"
        escaped_terminal = terminal.replace("'", "''")
        escaped_user = user.replace("'", "''")
        # La tâche Interactive ouvre la fenêtre dans la session déjà connectée;
        # aucun mot de passe n'est incorporé dans cette charge distante.
        return (
            f"$action=New-ScheduledTaskAction -Execute '{escaped_terminal}' "
            f"-Argument '-NoExit -NoProfile -EncodedCommand {command_b64}'; "
            f"$principal=New-ScheduledTaskPrincipal -UserId '{escaped_user}' "
            f"-LogonType Interactive -RunLevel {run_level}; "
            f"Register-ScheduledTask -TaskName 'CyGIL-{task_id}' -Action $action "
            f"-Principal $principal -Force | Out-Null; Start-ScheduledTask -TaskName 'CyGIL-{task_id}'"
        )

    @staticmethod
    def _linux_visible_terminal(
        endpoint: GuestEndpoint,
        command: str,
        *,
        elevated: bool,
    ) -> str:
        user = endpoint.desktop.session_user
        terminal = endpoint.desktop.terminal_executable
        display = endpoint.desktop.linux_display
        if not user or not terminal or not display:
            raise GuestControlError(
                f"Session graphique Linux incomplète pour {endpoint.machine_id}"
            )
        payload = command if not elevated else f"sudo -- bash -lc {json.dumps(command)}"
        encoded = _utf8_encoded(payload)
        launcher = (
            f"env DISPLAY={display} XAUTHORITY=/home/{user}/.Xauthority "
            f"nohup {terminal} -- bash -lc 'echo {encoded} | base64 --decode | bash' "
            f">/tmp/cygil-terminal.log 2>&1 &"
        )
        if endpoint.access.username == user:
            return launcher
        return f"sudo -n -u {user} {launcher}"

    @staticmethod
    def _disable_interface_command(
        os_family: OSFamily,
        interface: IsolationInterfaceConfig,
    ) -> str:
        if not interface.guest_name:
            raise GuestControlError(
                f"Nom invité manquant pour l'interface {interface.network}"
            )
        name = interface.guest_name
        if os_family == OSFamily.WINDOWS:
            escaped = name.replace("'", "''")
            delayed = (
                "Start-Sleep -Seconds 2; "
                f"Disable-NetAdapter -Name '{escaped}' -Confirm:$false"
            )
            return (
                "Start-Process powershell.exe -WindowStyle Hidden "
                f"-ArgumentList '-NoProfile','-EncodedCommand','{_ps_encoded(delayed)}'"
            )
        encoded_name = _utf8_encoded(name)
        return (
            "nohup sh -c 'sleep 2; name=$(echo "
            f"{encoded_name} | base64 --decode); sudo ip link set dev \"$name\" down' "
            ">/tmp/cygil-isolation.log 2>&1 &"
        )

    @staticmethod
    def _transport_command(
        endpoint: GuestEndpoint,
        remote_command: str,
    ) -> tuple[list[str], dict[str, str]]:
        """Construit un transport sans shell local ni secret dans les arguments."""

        environment = os.environ.copy()
        access = endpoint.access
        if access.communicator == GuestCommunicator.SSH:
            if access.password_secret and not access.private_key_path:
                raise GuestControlError(
                    "L'exécution SSH non interactive exige une clé ou un agent; "
                    "le mot de passe ne sera pas placé sur la ligne de commande"
                )
            arguments = ["ssh.exe", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
            if access.port:
                arguments.extend(["-p", str(access.port)])
            if access.private_key_path:
                arguments.extend(["-i", str(Path(access.private_key_path))])
            destination = f"{access.username}@{endpoint.address}" if access.username else endpoint.address
            arguments.extend([destination, remote_command])
            return arguments, environment

        if not access.username or not access.password_secret:
            raise GuestControlError("WinRM exige un utilisateur et une référence de secret")
        if access.password_secret not in environment:
            raise GuestControlError(
                f"La variable de secret {access.password_secret} n'est pas définie"
            )
        password_name = access.password_secret.replace("'", "''")
        username = access.username.replace("'", "''")
        address = endpoint.address.replace("'", "''")
        remote_b64 = _ps_encoded(remote_command)
        port_part = f" -Port {access.port}" if access.port else ""
        ssl_part = " -UseSSL" if access.winrm_use_ssl else ""
        local_script = (
            f"$p=[Environment]::GetEnvironmentVariable('{password_name}'); "
            "$s=ConvertTo-SecureString $p -AsPlainText -Force; "
            f"$c=[pscredential]::new('{username}',$s); "
            f"Invoke-Command -ComputerName '{address}'{port_part}{ssl_part} -Credential $c "
            f"-ScriptBlock {{param($e) powershell.exe -NoProfile -EncodedCommand $e}} "
            f"-ArgumentList '{remote_b64}'"
        )
        return [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            _ps_encoded(local_script),
        ], environment
