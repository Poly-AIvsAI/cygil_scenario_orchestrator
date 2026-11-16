"""Adaptateur de simulation qui journalise les actions sans contacter le laboratoire."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..models import InfrastructureVM, Scenario, TargetVM


@dataclass
class DryRunAdapter:
    """Records intended actions without touching VMware, guests or CyGIL."""

    actions: list[dict] = field(default_factory=list)

    def _record(self, action: str, target: str, **details) -> dict:
        event = {"mode": "dry-run", "action": action, "target": target, **details}
        self.actions.append(event)
        return event

    def discover(self, machine: InfrastructureVM) -> dict:
        return self._record("discover", machine.id, role=machine.role.value)

    def create_target(self, target: TargetVM) -> dict:
        return self._record("create_target", target.id, template=target.template)

    def attach_temporary_management(self, target: TargetVM) -> dict:
        """Journalise la NIC d'automatisation qui ne fera pas partie du scénario final."""

        return self._record(
            "attach_temporary_management",
            target.id,
            network=target.temporary_management.vmware_network,
            address_mode=target.temporary_management.address_mode,
        )

    def detach_temporary_management(self, target: TargetVM) -> dict:
        """Journalise la désactivation invitée sans retrait à chaud VMware."""

        return self._record(
            "detach_temporary_management",
            target.id,
            network=target.temporary_management.vmware_network,
            method="guest_interface_disable",
            verify_air_gap=True,
        )

    def snapshot(self, machine_id: str, snapshot_name: str) -> dict:
        return self._record("snapshot", machine_id, snapshot=snapshot_name)

    def configure_network(self, target: TargetVM) -> dict:
        return self._record("configure_network", target.id, interfaces=len(target.interfaces))

    def ping_discovery(self, target: TargetVM) -> dict:
        return self._record("ping_discovery", target.id)

    def upload_bundle(self, scenario: Scenario, directory: Path) -> dict:
        return self._record("upload_bundle", scenario.metadata.name, directory=str(directory))

    def run_commands(self, scenario: Scenario) -> dict:
        return self._record("run_commands", "cygil", commands=scenario.cygil_runtime.launch_commands)

    def register(self, scenario: Scenario) -> dict:
        return self._record("register", scenario.metadata.name)
