"""Coffre VMREST fondé sur le Gestionnaire d'identification Windows."""

from __future__ import annotations

import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path


class SecretStoreError(RuntimeError):
    """Signale qu'un secret ne peut pas être protégé ou relu."""


class _Credential(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


def _credential_target(scenario_name: str) -> str:
    return f"CyGIL/vmrest/{scenario_name}"


def _credential_write(target: str, username: str, password: str) -> None:
    if os.name != "nt":
        raise SecretStoreError("Le coffre VMREST requiert le Gestionnaire d'identification Windows")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.CredWriteW.argtypes = [ctypes.POINTER(_Credential), wintypes.DWORD]
    advapi32.CredWriteW.restype = wintypes.BOOL
    encoded = password.encode("utf-16-le")
    blob = ctypes.create_string_buffer(encoded)
    credential = _Credential(
        0,
        1,  # CRED_TYPE_GENERIC
        target,
        "CyGIL VMREST",
        wintypes.FILETIME(),
        len(encoded),
        ctypes.cast(blob, ctypes.POINTER(ctypes.c_byte)),
        2,  # CRED_PERSIST_LOCAL_MACHINE
        0,
        None,
        None,
        username,
    )
    if not advapi32.CredWriteW(ctypes.byref(credential), 0):
        raise SecretStoreError(
            f"Windows n'a pas pu enregistrer les identifiants VMREST (code {ctypes.get_last_error()})"
        )


def _credential_read(target: str) -> dict[str, str]:
    if os.name != "nt":
        raise SecretStoreError("Le coffre VMREST requiert le Gestionnaire d'identification Windows")
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.POINTER(_Credential)()
    advapi32.CredReadW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(_Credential)),
    ]
    advapi32.CredReadW.restype = wintypes.BOOL
    advapi32.CredFree.argtypes = [ctypes.c_void_p]
    if not advapi32.CredReadW(target, 1, 0, ctypes.byref(pointer)):
        if ctypes.get_last_error() == 1168:  # ERROR_NOT_FOUND
            return {}
        raise SecretStoreError(
            f"Windows n'a pas pu relire les identifiants VMREST (code {ctypes.get_last_error()})"
        )
    try:
        credential = pointer.contents
        raw = ctypes.string_at(credential.CredentialBlob, credential.CredentialBlobSize)
        return {
            "username": credential.UserName or "",
            "password": raw.decode("utf-16-le"),
        }
    finally:
        advapi32.CredFree(pointer)


class VmrestSecretStore:
    """Enregistre les secrets dans le Gestionnaire d'identification Windows."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def _path(self, scenario_name: str) -> Path:
        safe = "".join(character for character in scenario_name if character.isalnum() or character in "_-")
        if not safe or safe != scenario_name:
            raise SecretStoreError("Nom de scénario invalide pour le coffre VMREST")
        return self.directory / f"{safe}.vmrest.json"

    def save(self, scenario_name: str, username: str, password: str) -> Path:
        if not username or not password:
            raise SecretStoreError("L'utilisateur et le mot de passe VMREST sont requis")
        _credential_write(_credential_target(scenario_name), username, password)
        destination = self._path(scenario_name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "provider": "Windows Credential Manager",
                    "target": _credential_target(scenario_name),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        temporary.replace(destination)
        return destination

    def load(self, scenario_name: str) -> dict[str, str]:
        return _credential_read(_credential_target(scenario_name))
