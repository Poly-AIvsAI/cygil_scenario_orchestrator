"""Façade applicative qui garantit la synchronisation avant chaque opération globale."""

from __future__ import annotations

from pathlib import Path

from .adapters.vagrant import render_vagrantfile
from .compilers import CompilationBundle, compile_bundle
from .coherence import synchronize_scenario
from .models import Scenario
from .planner import PlanStep, build_plan
from .validation import ValidationResult, validate_scenario
from .visualization import render_infrastructure_view, render_sdn_view


class ScenarioService:
    """Point d'entrée commun de la GUI et de la CLI pour manipuler un scénario."""

    def load(self, source: str | Path) -> Scenario:
        scenario = Scenario.from_yaml(source)
        synchronize_scenario(scenario)
        return scenario

    def save(self, scenario: Scenario, destination: str | Path) -> Path:
        synchronize_scenario(scenario)
        return scenario.to_yaml(destination)

    def validate(self, scenario: Scenario) -> ValidationResult:
        synchronize_scenario(scenario)
        return validate_scenario(scenario)

    def plan(self, scenario: Scenario) -> list[PlanStep]:
        synchronize_scenario(scenario)
        return build_plan(scenario)

    def visualize(self, scenario: Scenario) -> str:
        """Retourne la vue SDN historique utilisée par les appels existants."""

        return render_sdn_view(scenario)

    def visualize_infrastructure(self, scenario: Scenario) -> str:
        """Retourne la vue physique VMware séparée de la logique SDN."""

        return render_infrastructure_view(scenario)

    def visualize_sdn(self, scenario: Scenario) -> str:
        """Retourne la vue logique SDN sans adaptateurs ni VMnet."""

        return render_sdn_view(scenario)

    def compile(
        self,
        scenario: Scenario,
        destination: str | Path,
        *,
        inject_secrets: bool = False,
        base_dir: str | Path | None = None,
        require_verified_macs: bool = False,
        secret_values: dict[str, str] | None = None,
    ) -> CompilationBundle:
        synchronize_scenario(scenario)
        return compile_bundle(
            scenario,
            destination,
            inject_secrets=inject_secrets,
            base_dir=base_dir,
            require_verified_macs=require_verified_macs,
            secret_values=secret_values,
        )

    def vagrantfile(self, scenario: Scenario, destination: str | Path) -> Path:
        return render_vagrantfile(scenario, destination)
