"""Coordination de bout en bout des adaptateurs, actuellement sûre par défaut en dry-run."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .adapters.dry_run import DryRunAdapter
from .compilers import CompilationBundle
from .exceptions import ScenarioValidationError
from .models import Scenario
from .service import ScenarioService


@dataclass(frozen=True)
class PreparationResult:
    """Artefacts produits et journal ordonné des actions simulées."""
    bundle: CompilationBundle
    actions: list[dict]


class ScenarioOrchestrator:
    """Coordinates the workflow through adapters; safe dry-run is the current default."""

    def __init__(
        self,
        adapter: DryRunAdapter | None = None,
        infrastructure_adapter: DryRunAdapter | None = None,
    ) -> None:
        # Deux instances distinctes empêchent qu'un futur adaptateur Vagrant
        # transmis pour les cibles reçoive une VM réservée par accident.
        self.adapter = adapter or DryRunAdapter()
        self.infrastructure_adapter = infrastructure_adapter or DryRunAdapter()
        self.service = ScenarioService()

    def prepare_dry_run(
        self,
        scenario: Scenario,
        output_directory: str | Path,
        *,
        base_dir: str | Path | None = None,
        secret_values: dict[str, str] | None = None,
    ) -> PreparationResult:
        validation = self.service.validate(scenario)
        if validation.errors:
            raise ScenarioValidationError("; ".join(issue.message for issue in validation.errors))
        actions: list[dict] = []
        for machine in scenario.infrastructure:
            actions.append(self.infrastructure_adapter.discover(machine))
        for target in scenario.targets:
            actions.append(self.adapter.create_target(target))
            if target.temporary_management.enabled and target.temporary_management.vmware_network:
                actions.append(self.adapter.attach_temporary_management(target))
            actions.append(self.adapter.configure_network(target))
        bundle = self.service.compile(
            scenario,
            output_directory,
            base_dir=base_dir,
            inject_secrets=bool(secret_values),
            secret_values=secret_values,
        )
        actions.append(self.adapter.upload_bundle(scenario, bundle.output_directory))
        actions.append(self.adapter.run_commands(scenario))
        for target in scenario.targets:
            actions.append(self.adapter.ping_discovery(target))
        for target in scenario.targets:
            management = target.temporary_management
            if management.enabled and management.vmware_network and management.detach_before_snapshot:
                actions.append(self.adapter.detach_temporary_management(target))
        for machine in scenario.infrastructure:
            actions.append(self.infrastructure_adapter.snapshot(machine.id, scenario.vmware.snapshot_name))
        for target in scenario.targets:
            if target.snapshot:
                actions.append(self.adapter.snapshot(target.id, scenario.vmware.snapshot_name))
        actions.append(self.adapter.register(scenario))
        return PreparationResult(bundle, actions)
