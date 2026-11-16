"""Plans VMware REST limités aux VM réservées et dépourvus de suppression NIC."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import httpx

from .models import Scenario


class VmwareControlError(RuntimeError):
    """Refus d'une mutation VMware ambiguë ou non confirmée."""


@dataclass(frozen=True)
class VmrestPlan:
    """Requête exacte affichable sans identifiants vmrest."""

    action: str
    machine_id: str
    method: str
    path: str
    body: dict | None = None

    def preview(self) -> str:
        suffix = f" {json.dumps(self.body, ensure_ascii=False)}" if self.body else ""
        return f"{self.method} {self.path}{suffix}"


@dataclass(frozen=True)
class VmrestResult:
    plan: VmrestPlan
    status_code: int | None
    payload: object
    mode: str


def vmrest_confirmation_token(plans: list[VmrestPlan]) -> str:
    payload = json.dumps(
        [plan.__dict__ for plan in plans],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12].upper()


class VmwareReservedAdapter:
    """Gère seulement les VM existantes associées manuellement à un rôle."""

    def __init__(
        self,
        scenario: Scenario,
        username: str,
        password: str,
        *,
        dry_run: bool = True,
    ) -> None:
        self.scenario = scenario
        self.username = username
        self.password = password
        self.dry_run = dry_run

    def build_bootstrap_plans(self) -> list[VmrestPlan]:
        """Ajoute le VMnet DHCP aux réservées; aucune route DELETE n'existe ici."""

        vmnet = self.scenario.vagrant.bootstrap_network
        if not vmnet or vmnet == "VMnet0":
            raise VmwareControlError("Le VMnet d'amorçage distinct de VMnet0 n'est pas choisi")
        plans = []
        for machine in self.scenario.infrastructure:
            if not machine.inventory_confirmed or not machine.vmware_id:
                raise VmwareControlError(
                    f"L'identité VMware réservée de {machine.id} n'est pas confirmée"
                )
            plans.append(
                VmrestPlan(
                    action="attach_bootstrap_nic",
                    machine_id=machine.id,
                    method="POST",
                    path=f"/api/vms/{machine.vmware_id}/nic",
                    body={"type": "custom", "vmnet": vmnet},
                )
            )
        return plans

    def execute(
        self,
        plans: list[VmrestPlan],
        *,
        confirmation_token: str | None = None,
    ) -> list[VmrestResult]:
        """Exécute seulement POST NIC après empreinte; DELETE reste impossible."""

        for plan in plans:
            if plan.method != "POST" or not plan.path.endswith("/nic"):
                raise VmwareControlError(f"Opération vmrest interdite : {plan.preview()}")
        expected = vmrest_confirmation_token(plans)
        if not self.dry_run and confirmation_token != expected:
            raise VmwareControlError("Le plan vmrest exact n'a pas été confirmé")
        if self.dry_run:
            return [VmrestResult(plan, None, plan.preview(), "dry-run") for plan in plans]
        if not self.username or not self.password:
            raise VmwareControlError("Les identifiants vmrest sont requis")
        base = f"https://127.0.0.1:{self.scenario.vmware.api_port}"
        results = []
        with httpx.Client(
            auth=(self.username, self.password),
            verify=False,
            timeout=30,
        ) as client:
            for plan in plans:
                # L'inventaire juste avant mutation rend la relance idempotente
                # et évite de créer une deuxième carte sur le même VMnet.
                inventory = client.get(base + plan.path)
                inventory.raise_for_status()
                existing = inventory.json().get("nics", [])
                if any(
                    str(item.get("vmnet")) == str(plan.body.get("vmnet"))
                    for item in existing
                    if isinstance(item, dict)
                ):
                    results.append(VmrestResult(plan, 200, {"existing": True}, "real-existing"))
                    continue
                response = client.request(plan.method, base + plan.path, json=plan.body)
                payload = response.json() if response.content else None
                results.append(VmrestResult(plan, response.status_code, payload, "real"))
                if response.status_code >= 400:
                    break
        return results

    def powered_on_states(self) -> dict[str, bool]:
        """Vérifie ponctuellement l'alimentation des VM associées, sans mutation."""

        if not self.username or not self.password:
            raise VmwareControlError("Les identifiants vmrest sont requis")
        base = f"https://127.0.0.1:{self.scenario.vmware.api_port}"
        states: dict[str, bool] = {}
        with httpx.Client(auth=(self.username, self.password), verify=False, timeout=10) as client:
            for machine in self.scenario.infrastructure:
                if not machine.vmware_id:
                    states[machine.id] = False
                    continue
                response = client.get(f"{base}/api/vms/{machine.vmware_id}/power")
                response.raise_for_status()
                states[machine.id] = response.json().get("power_state") == "poweredOn"
        return states

    def power_states(self) -> dict[str, str]:
        """Retourne l'état VMware exact; une valeur absente n'est jamais assimilée à l'arrêt."""

        if not self.username or not self.password:
            raise VmwareControlError("Les identifiants vmrest sont requis")
        base = f"https://127.0.0.1:{self.scenario.vmware.api_port}"
        states: dict[str, str] = {}
        with httpx.Client(auth=(self.username, self.password), verify=False, timeout=10) as client:
            for machine in self.scenario.infrastructure:
                if not machine.vmware_id:
                    states[machine.id] = "unknown"
                    continue
                response = client.get(f"{base}/api/vms/{machine.vmware_id}/power")
                response.raise_for_status()
                states[machine.id] = str(response.json().get("power_state") or "unknown")
        return states
