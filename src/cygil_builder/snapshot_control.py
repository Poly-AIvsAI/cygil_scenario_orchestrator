"""Planification sûre des snapshots VMware Workstation.

La version vmrun 1.17 installée sait créer un snapshot mais n'expose pas
d'option permettant d'exiger l'inclusion de la mémoire. Le service refuse donc
de présenter cette propriété comme garantie.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .deployment import DeploymentState, refresh_snapshot_authorization
from .models import Scenario


class SnapshotSafetyError(RuntimeError):
    """Refus d'une capture prématurée, ambiguë ou non confirmée."""


@dataclass(frozen=True)
class SnapshotCommand:
    """Commande vmrun exacte, valable pour une VM réservée ou cible."""

    machine_id: str
    vmx_path: str
    snapshot_name: str
    arguments: tuple[str, ...]

    def display(self) -> str:
        return subprocess.list2cmdline(self.arguments)


@dataclass(frozen=True)
class SnapshotResult:
    command: SnapshotCommand
    returncode: int | None
    stdout: str
    stderr: str
    mode: str


def snapshot_confirmation_token(commands: list[SnapshotCommand]) -> str:
    payload = json.dumps(
        [command.arguments for command in commands],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12].upper()


class SnapshotService:
    """Construit un plan global sans jamais déléguer les réservées à Vagrant."""

    def __init__(
        self,
        scenario: Scenario,
        deployment_state: DeploymentState,
        *,
        vmrun_path: str | Path,
        dry_run: bool = True,
    ) -> None:
        self.scenario = scenario
        self.deployment_state = deployment_state
        self.vmrun_path = str(Path(vmrun_path))
        self.dry_run = dry_run

    def build_commands(self) -> list[SnapshotCommand]:
        """Refuse toute promesse de mémoire que vmrun ne peut exprimer."""

        if self.scenario.lab_control.snapshot_with_memory is None:
            raise SnapshotSafetyError(
                "Le choix d'inclure ou non la mémoire des VM doit être confirmé"
            )
        if self.scenario.lab_control.snapshot_with_memory:
            raise SnapshotSafetyError(
                "vmrun 1.17 ne permet pas d'exiger un snapshot avec mémoire; "
                "un mécanisme Workstation compatible doit être validé avant exécution"
            )
        commands: list[SnapshotCommand] = []
        for machine in self.scenario.infrastructure:
            if not machine.vmx_path:
                raise SnapshotSafetyError(f"Chemin VMX manquant pour {machine.id}")
            commands.append(self._command(machine.id, machine.vmx_path))
        for target in self.scenario.targets:
            if not target.snapshot:
                continue
            if not target.vmx_path:
                raise SnapshotSafetyError(f"Chemin VMX manquant pour {target.id}")
            commands.append(self._command(target.id, target.vmx_path))
        return commands

    def inspect_running_vms(self) -> dict[str, bool]:
        """Lit ``vmrun list`` sans changer l'alimentation des VM."""

        completed = subprocess.run(
            [self.vmrun_path, "-T", "ws", "list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise SnapshotSafetyError(
                completed.stderr.strip() or "Impossible de lire les VM démarrées"
            )
        running = {
            str(Path(line.strip())).replace("/", "\\").casefold()
            for line in completed.stdout.splitlines()[1:]
            if line.strip()
        }
        states: dict[str, bool] = {}
        for machine in self.scenario.infrastructure:
            states[machine.id] = bool(
                machine.vmx_path
                and str(Path(machine.vmx_path)).replace("/", "\\").casefold() in running
            )
        for target in self.scenario.targets:
            if target.snapshot:
                states[target.id] = bool(
                    target.vmx_path
                    and str(Path(target.vmx_path)).replace("/", "\\").casefold() in running
                )
        return states

    def execute(
        self,
        commands: list[SnapshotCommand],
        *,
        confirmation_token: str | None = None,
    ) -> list[SnapshotResult]:
        """Exige le verrou persistant et l'empreinte du plan exact."""

        if not self.dry_run and not refresh_snapshot_authorization(self.deployment_state):
            raise SnapshotSafetyError("La séquence de snapshots est encore verrouillée")
        expected = snapshot_confirmation_token(commands)
        if not self.dry_run and confirmation_token != expected:
            raise SnapshotSafetyError("Le plan exact de snapshots n'a pas été confirmé")
        if self.dry_run:
            return [SnapshotResult(command, None, command.display(), "", "dry-run") for command in commands]

        results: list[SnapshotResult] = []
        for command in commands:
            completed = subprocess.run(
                list(command.arguments),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=None,
                check=False,
            )
            results.append(
                SnapshotResult(
                    command,
                    completed.returncode,
                    completed.stdout[-12000:],
                    completed.stderr[-12000:],
                    "real",
                )
            )
            if completed.returncode != 0:
                # Une capture en échec arrête la séquence afin de ne pas produire
                # un ensemble de snapshots présenté à tort comme cohérent.
                break
        return results

    def _command(self, machine_id: str, vmx_path: str) -> SnapshotCommand:
        arguments = (
            self.vmrun_path,
            "-T",
            "ws",
            "snapshot",
            str(Path(vmx_path)),
            self.scenario.vmware.snapshot_name,
        )
        return SnapshotCommand(
            machine_id,
            vmx_path,
            self.scenario.vmware.snapshot_name,
            arguments,
        )
