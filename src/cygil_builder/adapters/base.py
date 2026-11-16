"""Contrats que devront respecter les futurs adaptateurs VMware, invités et CyGIL."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..models import InfrastructureVM, Scenario, TargetVM


class InfrastructureVirtualizationAdapter(Protocol):
    """Contrat VMware des VM réservées, inaccessible à Vagrant."""

    def discover(self, machine: InfrastructureVM) -> dict: ...
    def snapshot(self, machine_id: str, snapshot_name: str) -> dict: ...


class TargetVirtualizationAdapter(Protocol):
    """Contrat limité aux nouvelles cibles créées par Vagrant."""

    def create_target(self, target: TargetVM) -> dict: ...
    def attach_temporary_management(self, target: TargetVM) -> dict: ...
    def detach_temporary_management(self, target: TargetVM) -> dict: ...
    def snapshot(self, machine_id: str, snapshot_name: str) -> dict: ...


class GuestAdapter(Protocol):
    """Opérations exécutées à l'intérieur des systèmes invités."""

    def configure_network(self, target: TargetVM) -> dict: ...
    def ping_discovery(self, target: TargetVM) -> dict: ...


class CyGILAdapter(Protocol):
    """Transfert, lancement et enregistrement côté VM CyGIL."""
    def upload_bundle(self, scenario: Scenario, directory: Path) -> dict: ...
    def run_commands(self, scenario: Scenario) -> dict: ...
    def register(self, scenario: Scenario) -> dict: ...
