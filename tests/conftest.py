"""Fixtures partagées construites depuis le scénario de démonstration documenté."""

from pathlib import Path

import pytest

from cygil_builder.models import Scenario


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def scenario() -> Scenario:
    return Scenario.from_yaml(ROOT / "examples" / "scenario_demo.yml")
