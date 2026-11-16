"""Transferts confirmés de fichiers vers les VM avant leur isolation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .guest_control import (
    GuestCommandPlan,
    GuestControlError,
    GuestControlService,
    _ps_encoded,
    guest_confirmation_token,
)
from .models import GuestCommunicator, GuestFileDeployment, Scenario


@dataclass(frozen=True)
class GuestFilePlan:
    """Copie source/destination indépendante des fichiers YAML CyGIL."""

    machine_id: str
    source_path: str
    destination_path: str
    transport: GuestCommunicator
    requires_admin: bool

    def preview(self) -> str:
        return (
            f"{self.transport.value.upper()} COPY {self.source_path} -> "
            f"{self.machine_id}:{self.destination_path}"
        )


@dataclass(frozen=True)
class GuestFileResult:
    plan: GuestFilePlan
    returncode: int | None
    stdout: str
    stderr: str
    mode: str


def file_confirmation_token(plans: list[GuestFilePlan]) -> str:
    """Lie la confirmation aux sources et destinations exactes."""

    payload = json.dumps(
        [plan.__dict__ for plan in plans],
        ensure_ascii=False,
        default=str,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12].upper()


class GuestFileService:
    """Prépare et exécute les copies sans jamais exposer de mot de passe."""

    def __init__(self, scenario: Scenario, *, dry_run: bool = True) -> None:
        self.scenario = scenario
        self.dry_run = dry_run
        self.control = GuestControlService(scenario, dry_run=dry_run)

    def build_plans(self) -> list[GuestFilePlan]:
        """Collecte les dépôts explicites et l'ancien fichier cible si complet."""

        plans: list[GuestFilePlan] = []
        for machine in [*self.scenario.infrastructure, *self.scenario.targets]:
            deployments = list(machine.guest_files)
            source = getattr(machine, "target_file_source_path", None)
            destination = getattr(machine, "target_file_path", None)
            if source and destination and not any(
                item.source_path == source and item.destination_path == destination
                for item in deployments
            ):
                deployments.append(
                    GuestFileDeployment(
                        source_path=source,
                        destination_path=destination,
                    )
                )
            if not deployments:
                continue
            endpoint = self.control.endpoint(machine.id)
            for deployment in deployments:
                source_path = Path(deployment.source_path)
                if not source_path.is_file():
                    raise GuestControlError(f"Fichier source introuvable : {source_path}")
                plans.append(
                    GuestFilePlan(
                        machine_id=machine.id,
                        source_path=str(source_path.resolve()),
                        destination_path=deployment.destination_path,
                        transport=endpoint.access.communicator,
                        requires_admin=deployment.requires_admin,
                    )
                )
        return plans

    def execute(
        self,
        plans: list[GuestFilePlan],
        *,
        confirmation_token: str | None = None,
    ) -> list[GuestFileResult]:
        """Copie chaque fichier seulement après confirmation de la liste exacte."""

        expected = file_confirmation_token(plans)
        if not self.dry_run and confirmation_token != expected:
            raise GuestControlError("Le plan de transfert exact n'a pas été confirmé")
        if self.dry_run:
            return [GuestFileResult(plan, None, plan.preview(), "", "dry-run") for plan in plans]

        results: list[GuestFileResult] = []
        for plan in plans:
            endpoint = self.control.endpoint(plan.machine_id)
            if plan.transport == GuestCommunicator.SSH:
                result = self._execute_scp(plan, endpoint)
            else:
                result = self._execute_winrm_copy(plan, endpoint)
            results.append(result)
        return results

    def _execute_scp(self, plan: GuestFilePlan, endpoint) -> GuestFileResult:
        access = endpoint.access
        if access.password_secret and not access.private_key_path:
            raise GuestControlError(
                "SCP automatisé exige une clé ou un agent; aucun mot de passe "
                "ne sera placé dans la ligne de commande"
            )
        destination = plan.destination_path
        temporary = None
        if plan.requires_admin:
            temporary = f"/tmp/cygil-{hashlib.sha256(plan.destination_path.encode()).hexdigest()[:12]}"
            destination = temporary
        arguments = ["scp.exe", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
        if access.port:
            arguments.extend(["-P", str(access.port)])
        if access.private_key_path:
            arguments.extend(["-i", access.private_key_path])
        remote = f"{access.username}@{endpoint.address}" if access.username else endpoint.address
        arguments.extend([plan.source_path, f"{remote}:{destination}"])
        completed = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
        if returncode == 0 and temporary:
            # Le déplacement privilégié est une seconde opération explicitement
            # dérivée du plan confirmé; la source temporaire est déterministe.
            move_command = (
                f"sudo -n install -D {shlex.quote(temporary)} "
                f"{shlex.quote(plan.destination_path)}"
            )
            move_plan = GuestCommandPlan(
                action="finalize_guest_file",
                machine_id=plan.machine_id,
                transport=endpoint.access.communicator,
                address=endpoint.address,
                remote_command=move_command,
                description="Déplacer le fichier vers sa destination privilégiée",
            )
            move_result = self.control.execute(
                [move_plan],
                confirmation_token=guest_confirmation_token([move_plan]),
            )[0]
            stdout += move_result.stdout
            stderr += move_result.stderr
            returncode = move_result.returncode or 0
        return GuestFileResult(plan, returncode, stdout[-12000:], stderr[-12000:], "real")

    @staticmethod
    def _execute_winrm_copy(plan: GuestFilePlan, endpoint) -> GuestFileResult:
        access = endpoint.access
        if not access.username or not access.password_secret:
            raise GuestControlError("WinRM exige un utilisateur et une référence de secret")
        environment = os.environ.copy()
        if access.password_secret not in environment:
            raise GuestControlError(f"La variable {access.password_secret} n'est pas définie")
        source_b64 = base64.b64encode(plan.source_path.encode("utf-8")).decode("ascii")
        destination_b64 = base64.b64encode(plan.destination_path.encode("utf-8")).decode("ascii")
        password_name = access.password_secret.replace("'", "''")
        username = access.username.replace("'", "''")
        address = endpoint.address.replace("'", "''")
        port_part = f" -Port {access.port}" if access.port else ""
        ssl_part = " -UseSSL" if access.winrm_use_ssl else ""
        script = (
            f"$src=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{source_b64}')); "
            f"$dst=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{destination_b64}')); "
            f"$p=[Environment]::GetEnvironmentVariable('{password_name}'); "
            "$s=ConvertTo-SecureString $p -AsPlainText -Force; "
            f"$c=[pscredential]::new('{username}',$s); "
            f"$session=New-PSSession -ComputerName '{address}'{port_part}{ssl_part} -Credential $c; "
            "try { Copy-Item -LiteralPath $src -Destination $dst -ToSession $session -Force } "
            "finally { Remove-PSSession $session }"
        )
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", _ps_encoded(script)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
            check=False,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return GuestFileResult(
            plan,
            completed.returncode,
            completed.stdout[-12000:],
            completed.stderr[-12000:],
            "real",
        )
