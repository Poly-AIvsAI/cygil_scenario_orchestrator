"""Vérifie que le coffre ne place jamais le mot de passe dans un fichier local."""

from cygil_builder.secret_store import VmrestSecretStore


def test_vmrest_store_uses_windows_credential_manager_metadata(monkeypatch, tmp_path):
    saved = {}

    def fake_write(target, username, password):
        saved[target] = {"username": username, "password": password}

    def fake_read(target):
        return saved.get(target, {})

    monkeypatch.setattr("cygil_builder.secret_store._credential_write", fake_write)
    monkeypatch.setattr("cygil_builder.secret_store._credential_read", fake_read)
    store = VmrestSecretStore(tmp_path)
    marker = store.save("scenario_test", "vmrest-user", "vmrest-password")

    assert store.load("scenario_test") == {
        "username": "vmrest-user",
        "password": "vmrest-password",
    }
    assert "vmrest-password" not in marker.read_text(encoding="utf-8")
