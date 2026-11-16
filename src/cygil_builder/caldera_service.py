"""Client CALDERA limité à la vérification API et à la génération de commandes de hand.

Ce module ne lance jamais la commande sur la VM cible. Il récupère une commande depuis
l'API configurée et la conserve dans le scénario pour l'étape de déploiement ultérieure.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from .models import HandAgentType, OSFamily, TargetVM


class CalderaConnectionError(RuntimeError):
    """Erreur lisible par la GUI lorsqu'une requête CALDERA échoue."""


class CalderaClient:
    """Client asynchrone minimal dont les chemins API restent configurables par version."""

    def __init__(self, base_url: str, api_key: str, *, verify_tls: bool = True) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {"KEY": api_key, "Content-Type": "application/json"}
        self.verify_tls = verify_tls

    async def check_connection(self, endpoint: str) -> str:
        """Vérifie l'accès à l'endpoint explicitement choisi dans la GUI."""

        normalized_endpoint = endpoint.strip()
        if not normalized_endpoint:
            raise CalderaConnectionError("Un endpoint API CALDERA est requis pour le test")
        url = f"{self.base_url}/{normalized_endpoint.lstrip('/')}"
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=10) as client:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()
            return f"CALDERA répond correctement ({response.status_code})"
        except httpx.HTTPError as exc:
            raise CalderaConnectionError(f"Connexion CALDERA impossible sur {url} : {exc}") from exc

    async def request_hand_command(self, target: TargetVM, endpoint: str) -> str:
        """Demande une commande de déploiement à l'endpoint configuré du banc.

        CALDERA ne garantit pas un endpoint de génération identique entre toutes les versions.
        L'utilisateur peut donc adapter ``endpoint`` sans modifier le client.
        """

        payload = {
            "agent": target.hand.agent_type.value,
            "platform": target.os_family.value,
            "group": target.hand.group,
            "c2": target.hand.c2_protocol,
        }
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=20) as client:
                response = await client.post(
                    f"{self.base_url}/{endpoint.lstrip('/')}",
                    headers=self.headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CalderaConnectionError(f"Génération du hand impossible : {exc}") from exc

        command = data.get("command") or data.get("deploy_command")
        if not command:
            raise CalderaConnectionError("La réponse CALDERA ne contient ni 'command' ni 'deploy_command'")
        target.hand.generated_command = str(command)
        target.hand.generated_at = datetime.now(UTC).isoformat()
        return target.hand.generated_command

    def build_preview_command(self, target: TargetVM) -> str:
        """Produit une prévisualisation non secrète lorsque l'API n'est pas encore disponible."""

        if target.hand.agent_type == HandAgentType.CUSTOM:
            return "Commande personnalisée à fournir"
        platform = "windows" if target.os_family == OSFamily.WINDOWS else "linux"
        return (
            f"CALDERA[{self.base_url}] -> générer {target.hand.agent_type.value} "
            f"pour {platform}, groupe={target.hand.group}, c2={target.hand.c2_protocol}"
        )
