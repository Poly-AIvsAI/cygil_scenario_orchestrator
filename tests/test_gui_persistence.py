"""Non-régression de la persistance des paramètres saisis dans la GUI."""

from types import SimpleNamespace

from cygil_builder.gui import ScenarioWizard
from cygil_builder.models import Scenario
from cygil_builder.service import ScenarioService


def test_active_scenario_persistence_keeps_vagrant_box_paths(scenario: Scenario, tmp_path) -> None:
    """Le bouton Vagrant doit écrire les chemins dans le YAML réellement rechargeable."""

    destination = tmp_path / "saved-scenario.yml"
    scenario.vagrant.box_paths = {
        "cygil/ubuntu": r"C:\boxes\ubuntu.box",
        "cygil/windows": r"C:\boxes\windows.box",
    }
    wizard = object.__new__(ScenarioWizard)
    wizard.state = SimpleNamespace(
        scenario=scenario,
        service=ScenarioService(),
        source=None,
    )
    wizard.scenario_path = SimpleNamespace(value=str(destination))

    written = wizard._persist_active_scenario()
    reloaded = wizard.state.service.load(written)

    assert written == destination
    assert wizard.state.source == destination
    assert reloaded.vagrant.box_paths == scenario.vagrant.box_paths

