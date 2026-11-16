"""Vérifie la préparation CALDERA sans effectuer de connexion réseau."""

import asyncio

import httpx
import pytest

from cygil_builder.caldera_service import CalderaClient, CalderaConnectionError


def test_preview_uses_target_os_agent_and_group(scenario):
    """La prévisualisation doit refléter les choix dynamiques de la VM."""

    target = scenario.targets[0]
    preview = CalderaClient("http://caldera.lab:8888", "unused").build_preview_command(target)
    assert "sandcat" in preview
    assert "windows" in preview
    assert "groupe=red" in preview


def test_connection_uses_configured_endpoint(monkeypatch):
    """Le test ne doit jamais réintroduire un endpoint agents v2 codé en dur."""

    requested: dict[str, object] = {}

    class FakeClient:
        def __init__(self, **kwargs):
            requested["client_options"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, *, headers):
            requested["url"] = url
            requested["headers"] = headers
            return httpx.Response(200, request=httpx.Request("GET", url))

    monkeypatch.setattr("cygil_builder.caldera_service.httpx.AsyncClient", FakeClient)

    result = asyncio.run(
        CalderaClient("http://caldera.lab:8888", "red-key").check_connection("/api/rest")
    )

    assert result == "CALDERA répond correctement (200)"
    assert requested["url"] == "http://caldera.lab:8888/api/rest"
    assert requested["headers"] == {"KEY": "red-key", "Content-Type": "application/json"}


def test_connection_requires_configured_endpoint():
    with pytest.raises(CalderaConnectionError, match="endpoint API CALDERA"):
        asyncio.run(CalderaClient("http://caldera.lab:8888", "red-key").check_connection("  "))
