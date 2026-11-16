"""Interface en ligne de commande pour valider, planifier et compiler un scénario."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .exceptions import ScenarioError
from .orchestrator import ScenarioOrchestrator
from .secret_store import SecretStoreError, VmrestSecretStore
from .service import ScenarioService
from .settings import PROJECT_ROOT


def _parser() -> argparse.ArgumentParser:
    """Déclare les sous-commandes sans exécuter d'action sur le banc."""
    parser = argparse.ArgumentParser(prog="cygil-scenario", description="Préparer un scénario CyGIL")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan", "mermaid"):
        command = commands.add_parser(name)
        command.add_argument("scenario", type=Path)
    compile_command = commands.add_parser("compile")
    compile_command.add_argument("scenario", type=Path)
    compile_command.add_argument("--out", type=Path, required=True)
    compile_command.add_argument("--inject-secrets", action="store_true")
    vagrant = commands.add_parser("vagrantfile")
    vagrant.add_argument("scenario", type=Path)
    vagrant.add_argument("--out", type=Path, required=True)
    dry_run = commands.add_parser("dry-run")
    dry_run.add_argument("scenario", type=Path)
    dry_run.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Charge le scénario puis route la commande en retournant un code système explicite."""
    args = _parser().parse_args(argv)
    service = ScenarioService()
    try:
        scenario = service.load(args.scenario)
        if args.command == "validate":
            result = service.validate(scenario)
            for issue in result.issues:
                print(f"{issue.level.upper():7} {issue.code}: {issue.message}")
            print("VALIDE" if result.is_valid else "INVALIDE")
            return 0 if result.is_valid else 2
        if args.command == "plan":
            print(json.dumps([step.to_dict() for step in service.plan(scenario)], ensure_ascii=False, indent=2))
        elif args.command == "mermaid":
            print(service.visualize(scenario))
        elif args.command == "compile":
            bundle = service.compile(
                scenario,
                args.out,
                inject_secrets=args.inject_secrets,
                base_dir=args.scenario.parent,
            )
            print(bundle.output_directory.resolve())
        elif args.command == "vagrantfile":
            print(service.vagrantfile(scenario, args.out).resolve())
        elif args.command == "dry-run":
            credentials = VmrestSecretStore(PROJECT_ROOT / "work" / "secrets").load(
                scenario.metadata.name
            )
            secret_values = (
                {
                    scenario.vmware.api_username_secret: credentials["username"],
                    scenario.vmware.api_password_secret: credentials["password"],
                }
                if credentials
                else None
            )
            result = ScenarioOrchestrator().prepare_dry_run(
                scenario,
                args.out,
                base_dir=args.scenario.parent,
                secret_values=secret_values,
            )
            print(json.dumps(result.actions, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValidationError, ScenarioError, SecretStoreError, ValueError) as exc:
        print(f"ERREUR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
