"""Interface NiceGUI progressive et réactive du constructeur de scénarios CyGIL.

L'écran est organisé en cinq étapes. Toutes utilisent le même ``GuiState`` : lorsqu'un
réseau, une VM ou une interface change, les panneaux abonnés sont reconstruits afin que
la topologie, les récompenses, CALDERA, le YAML et la validation restent cohérents.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
from collections.abc import Callable
from ipaddress import ip_network
from pathlib import Path

import yaml
import httpx
from nicegui import run, ui
from pydantic import ValidationError

from .caldera_service import CalderaClient, CalderaConnectionError
from .coherence import select_compromised_target, synchronize_scenario
from .deployment import (
    DeploymentStateStore,
    PingSessionState,
    TargetDeploymentPhase,
    TargetDeploymentState,
    allocate_management_addresses,
    allocate_mininet_internal_addresses,
    allocate_reserved_management_addresses,
    refresh_snapshot_authorization,
    synchronize_deployment_allocations,
)
from .guest_control import (
    GuestCommandPlan,
    GuestControlError,
    GuestControlService,
    guest_confirmation_token,
)
from .guest_files import GuestFileService, file_confirmation_token
from .guest_network import GuestNetworkService
from .host_setup import HostSetupError, HostSetupService
from .models import (
    HandAgentType,
    GuestAccessConfig,
    GuestCommunicator,
    GuestDesktopConfig,
    GuestNetworkBackend,
    InfrastructureRole,
    InfrastructureVM,
    IsolationInterfaceConfig,
    InterfacePurpose,
    LinkScope,
    MachineInterface,
    MininetInstance,
    Network,
    NetworkSwitch,
    OSFamily,
    Scenario,
    TargetVM,
)
from .service import ScenarioService
from .secret_store import SecretStoreError, VmrestSecretStore
from .settings import PROJECT_ROOT
from .snapshot_control import (
    SnapshotSafetyError,
    SnapshotService,
    snapshot_confirmation_token,
)
from .topology import add_switch_link, remove_switch_link, remove_switch_references, switch_owners, unique_switch_links
from .adapters.vagrant import (
    VagrantSafetyError,
    VagrantTargetAdapter,
    build_vagrant_commands,
    command_confirmation_token,
    render_vagrantfile,
)
from .vagrant_environment import (
    EnvironmentInventoryError,
    VagrantEnvironmentService,
    associate_reserved_vm_roles,
)
from .vmware_control import (
    VmwareReservedAdapter,
)
from .vmware_network import (
    NetworkReconstructionPlan,
    NetworkRollbackBundle,
    StaticMacPolicy,
    VmwareInventorySnapshot,
    VmwareNetworkError,
    VmwareNetworkInventoryService,
    VmxNetworkReconstructor,
    build_reconstruction_plan,
    associate_bootstrap_leases,
    apply_verified_target_macs,
    plan_target_interfaces,
    reconcile_applied_adapters,
)
from .vmnet_topology import ScenarioVmnetPlan, plan_scenario_vmnets
from .compilers.reward import load_reward_document


def _is_vmnet0(name: str | None) -> bool:
    """Reconnaît le réseau de gestion quelle que soit la casse de VMware."""

    return (name or "").casefold() == "vmnet0"


def _same_vmnet_name(first: str | None, second: str | None) -> bool:
    """Compare deux identifiants VMware sans dépendre de leur casse d'origine."""

    return bool(first and second and first.casefold() == second.casefold())


def _resolve_internal_vmnet_cidr(
    selected: str,
    record,
    previous_name: str | None,
    previous_cidr,
):
    """Préfère le CIDR observé, sinon conserve celui du même VMnet manuel."""

    if record is not None and record.cidr is not None:
        return record.cidr
    if _same_vmnet_name(selected, previous_name) and previous_cidr is not None:
        return previous_cidr
    raise ValueError(f"VMware n'a pas fourni de CIDR valide pour {selected}")


EXAMPLE = PROJECT_ROOT / "examples" / "scenario_two.yml"
GENERATED = PROJECT_ROOT / "generated"
REWARD_REFERENCE = PROJECT_ROOT.parent / "scenario_two" / "scenario_two_reward_config.yml"


def _default_reward_document() -> dict:
    """Relit la référence officielle sans la modifier."""

    if not REWARD_REFERENCE.is_file():
        raise ValueError(f"Fichier de récompenses de référence introuvable : {REWARD_REFERENCE}")
    document = yaml.safe_load(REWARD_REFERENCE.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Le fichier de récompenses scenario2 doit contenir un objet YAML")
    return document


class GuiState:
    """État partagé et bus de rafraîchissement de tous les composants dynamiques."""

    def __init__(self) -> None:
        self.service = ScenarioService()
        self.source = EXAMPLE
        self.scenario = self.service.load(self.source)
        if not self.scenario.reward.raw_config:
            load_reward_document(self.scenario.reward, _default_reward_document())
        synchronize_scenario(self.scenario)
        self.yaml_text = self._as_yaml()
        self._observers: list[Callable[[], None]] = []

    def subscribe(self, callback: Callable[[], None]) -> None:
        """Enregistre un panneau qui devra être reconstruit après une mutation."""

        self._observers.append(callback)

    def changed(self) -> None:
        """Synchronise les données dérivées puis rafraîchit chaque vue abonnée."""

        synchronize_scenario(self.scenario)
        self.yaml_text = self._as_yaml()
        for callback in self._observers:
            callback()

    def set_target_file(self, target_id: str, source_path: str, file_path: str, worth: int) -> None:
        """Configure le dépôt et la récompense d'une VM sans effacer les autres."""

        for target in self.scenario.targets:
            if target.id == target_id:
                target.target_file_source_path = source_path
                target.target_file_path = file_path
                target.target_file_worth = worth
        self.changed()

    def _as_yaml(self) -> str:
        """Sérialise l'état courant pour l'éditeur avancé de la dernière étape."""

        return yaml.safe_dump(
            self.scenario.model_dump(mode="json"),
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        )


class ScenarioWizard:
    """Construit l'assistant et centralise ses dialogues et mutations métier."""

    def __init__(self, state: GuiState) -> None:
        self.state = state
        self._secret_store = VmrestSecretStore(PROJECT_ROOT / "work" / "secrets")
        self.stepper = None
        self.yaml_editor = None
        # Les inspections Windows sont lentes : les cartes affichent ces caches et
        # ne lancent jamais directement PowerShell pendant un rendu NiceGUI.
        self._sshd_runtime = None
        self._vmrest_runtime = None
        self._firewall_runtime = None
        self._host_refresh_in_progress = False
        # Les inventaires Vagrant/VMware/VMnet sont coûteux et restent donc en
        # cache jusqu'à une action explicite, comme les inspections hôte existantes.
        self._vagrant_inventory = None
        self._vmnet_inventory = None
        self._vmnet_records = ()
        self._scenario_vmnet_plan: ScenarioVmnetPlan | None = None
        self._bootstrap_leases: dict[str, str] = {}
        self._vmware_vms = ()
        self._reserved_vm_selects = {}
        self._vmware_network_inventory: VmwareInventorySnapshot | None = None
        self._network_reconstruction_plan: NetworkReconstructionPlan | None = None
        self._network_rollback: NetworkRollbackBundle | None = None
        self._allocation_preview = {}
        self._allocation_context = None
        self._deployment_results = []
        self._vagrant_commands = []
        self._vagrant_token = ""
        self._vagrantfile_text = ""
        self._vagrant_plan_context = ""
        self._vagrant_box_hashes = {}
        self._vagrant_refresh_in_progress = False
        self.vagrant_box_inputs = {}
        self.vagrant_box_status_labels = {}
        self._vagrant_box_templates: tuple[str, ...] = ()
        # Le panneau de topologie est recréé après chaque mutation. Conserver
        # l'onglet choisi évite de renvoyer l'utilisateur vers la vue SDN.
        self._topology_tab = "sdn"
        # Le centre de contrôle conserve uniquement des plans prévisualisés et
        # leur empreinte; aucune commande n'est exécutée pendant un rendu.
        self._guest_plans: list[GuestCommandPlan] = []
        self._guest_token = ""
        self._guest_results = []
        self._ping_routes = []
        self._file_plans = []
        self._snapshot_commands = []
        self._snapshot_token = ""
        self._snapshot_results = []
        self._lab_state_store = DeploymentStateStore(
            PROJECT_ROOT / "work" / "deployments" / f"{self.state.scenario.metadata.name}.json"
        )
        self._lab_state = self._lab_state_store.load(self.state.scenario.metadata.name)
        self._build_page()

    # region Infrastructure visuelle commune
    def _build_page(self) -> None:
        """Crée l'en-tête, le résumé et les cinq étapes de travail."""

        ui.colors(primary="#245680", secondary="#4f8531", accent="#c68b00")
        with ui.header().classes("items-center gap-3"):
            ui.icon("hub").classes("text-2xl")
            ui.label("CyGIL Scenario Orchestrator").classes("text-xl font-semibold")
            ui.space()
            ui.badge("MODE PRÉPARATION", color="secondary")

        with ui.column().classes("w-full max-w-[1700px] mx-auto p-5 gap-4"):
            ui.label("Assistant de construction d'un scénario").classes("text-2xl font-semibold")
            ui.label("Chaque étape utilise le même scénario : les listes et fichiers dérivés se mettent à jour automatiquement.").classes("text-grey-7")
            with ui.card().classes("w-full"):
                ui.label("Fichier de scénario").classes("font-semibold")
                with ui.row().classes("w-full items-center"):
                    self.scenario_path = ui.input("Sauvegarde active", value=str(self.state.source)).props("readonly").classes("flex-1")
                    ui.button("Nouveau scénario", icon="note_add", on_click=self.open_new_scenario_dialog).props("outline")
                    ui.button("Charger un scénario", icon="folder_open", on_click=self.choose_and_load_scenario).props("outline")
                    ui.button("Enregistrer sous", icon="save", on_click=self.save_scenario).props("outline")
            self.summary_panel()

            with ui.stepper().props("vertical header-nav").classes("w-full") as self.stepper:
                with ui.step("1. Conception du réseau", icon="account_tree"):
                    self._build_network_step()
                with ui.step("2. Configuration des VM", icon="computer"):
                    self._build_vm_step()
                with ui.step("3. Déploiement des hands", icon="security"):
                    self._build_hand_step()
                with ui.step("4. Configuration de l'hôte", icon="dns"):
                    self._build_host_step()
                with ui.step("5. Contrôle du banc", icon="terminal"):
                    self._build_lab_control_step()
                with ui.step("6. Validation et génération", icon="fact_check"):
                    self._build_validation_step()

        # Tous les composants ci-dessous sont @refreshable et utilisent ce bus unique.
        for panel in (
            self.summary_panel,
            self.mininet_instance_panel,
            self.switch_panel,
            self.network_panel,
            self.switch_link_panel,
            self.machine_topology_panel,
            self.topology_panel,
            self.vm_configuration_panel,
            self.target_file_panel,
            self.hand_target_panel,
            self.host_status_panel,
            self.host_plan_panel,
            self.vagrant_status_panel,
            self.vmnet_mapping_panel,
            self.vmware_inventory_panel,
            self.management_allocation_panel,
            self.vagrant_plan_panel,
            self.lab_control_status_panel,
            self.validation_panel,
            self.plan_panel,
        ):
            self.state.subscribe(panel.refresh)
        self.state.subscribe(self._refresh_lab_control_step)
        self.state.subscribe(self._refresh_vagrant_box_paths_if_templates_changed)
        self.state.subscribe(self._refresh_yaml_editor)

    @ui.refreshable
    def summary_panel(self) -> None:
        """Affiche les compteurs globaux et l'état de validation courant."""

        result = self.state.service.validate(self.state.scenario)
        color = "positive" if result.is_valid else "negative"
        with ui.row().classes("w-full gap-3"):
            ui.badge(f"{len(self.state.scenario.networks)} sous-réseaux", color="primary")
            ui.badge(f"{len(self.state.scenario.switches)} switches", color="primary")
            ui.badge(f"{len(self.state.scenario.mininet_instances)} instance(s) Mininet", color="primary")
            ui.badge(f"{len(self.state.scenario.targets)} VM cibles", color="secondary")
            interface_count = sum(len(machine.interfaces) for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets])
            ui.badge(f"{interface_count} interfaces", color="accent")
            ui.badge(f"{len(result.errors)} erreurs · {len(result.warnings)} avertissements", color=color)

    def _navigation(self, *, previous: bool = True, next_callback: Callable | None = None) -> None:
        """Ajoute des boutons homogènes au bas d'une étape."""

        with ui.stepper_navigation():
            if previous:
                ui.button("Précédent", icon="arrow_back", on_click=self.stepper.previous).props("flat")
            ui.button("Suivant", icon="arrow_forward", on_click=next_callback or self.stepper.next)
    # endregion

    # region Étape 1 — conception dynamique du réseau
    def _build_network_step(self) -> None:
        """Permet de déclarer instances Mininet, réseaux, machines et interfaces."""

        ui.label("Déclarez d'abord les sous-réseaux et les VM présentes dans la topologie.").classes("text-grey-7")
        with ui.row().classes("w-full items-start gap-4"):
            with ui.column().classes("w-full xl:w-[650px]"):
                with ui.row().classes("w-full items-center"):
                    ui.label("Instances Mininet").classes("text-lg font-semibold")
                    ui.space()
                    ui.button("Ajouter une instance", icon="add", on_click=self.open_mininet_instance_dialog).props("outline")
                self.mininet_instance_panel()
                with ui.row().classes("w-full items-center mt-3"):
                    ui.label("Switches").classes("text-lg font-semibold")
                    ui.space()
                    ui.button("Ajouter un switch", icon="add", on_click=self.open_switch_dialog).props("outline")
                self.switch_panel()
                with ui.row().classes("w-full items-center"):
                    ui.label("Sous-réseaux").classes("text-lg font-semibold")
                    ui.space()
                    ui.button("Ajouter un réseau", icon="add", on_click=self.open_network_dialog).props("outline")
                self.network_panel()
                with ui.row().classes("w-full items-center mt-3"):
                    ui.label("Connexions entre switches").classes("text-lg font-semibold")
                    ui.space()
                    ui.button("Relier deux switches", icon="device_hub", on_click=self.open_switch_link_dialog).props("outline")
                self.switch_link_panel()
                with ui.row().classes("w-full items-center mt-3"):
                    ui.label("Machines et interfaces").classes("text-lg font-semibold")
                    ui.space()
                    ui.button("Déclarer une VM cible", icon="add", on_click=self.open_target_identity_dialog).props("outline")
                self.machine_topology_panel()
            with ui.column().classes("flex-1 min-w-0"):
                ui.label("Topologie générée automatiquement").classes("text-lg font-semibold")
                self.topology_panel()
        self._navigation(previous=False, next_callback=self.advance_from_network)

    @ui.refreshable
    def mininet_instance_panel(self) -> None:
        """Affiche chaque instance CyGIL avec la VM VMware qui l'héberge."""

        if not self.state.scenario.mininet_instances:
            ui.label("Aucune instance Mininet déclarée").classes("text-grey")
            return

        infrastructure_by_id = {machine.id: machine for machine in self.state.scenario.infrastructure}
        for instance in self.state.scenario.mininet_instances:
            machine = infrastructure_by_id.get(instance.infrastructure_vm_id or "")
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("dns")
                    with ui.column().classes("gap-0"):
                        ui.label(instance.name).classes("font-semibold")
                        ui.label(
                            f"VM {machine.id if machine else 'non associée'} · "
                            f"ONOS {instance.onos_controller_id or 'non associé'} · "
                            f"gestion {instance.external_ip or 'à allouer'} · "
                            f"interne {instance.internal_ip or 'à allouer'}"
                        ).classes("text-grey-7 text-sm")
                    ui.space()
                    ui.button(
                        icon="edit",
                        on_click=lambda _, item=instance: self.open_mininet_instance_dialog(item),
                    ).props("flat round")
                    ui.button(
                        icon="delete",
                        on_click=lambda _, item=instance: self.remove_mininet_instance(item),
                    ).props("flat round color=negative")

    @ui.refreshable
    def network_panel(self) -> None:
        """Liste réactive des sous-réseaux avec suppression cohérente."""

        if not self.state.scenario.networks:
            ui.label("Aucun sous-réseau déclaré").classes("text-grey")
        for network in self.state.scenario.networks:
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("lan")
                    ui.label(network.id).classes("font-semibold")
                    ui.label(network.subnet_label or network.cidr or "segment non configuré").classes("text-grey-7")
                    ui.space()
                    ui.button(icon="delete", on_click=lambda _, item=network: self.remove_network(item)).props("flat round color=negative")

    @ui.refreshable
    def switch_panel(self) -> None:
        """Liste les switches indépendants et leur instance Mininet propriétaire."""

        if not self.state.scenario.switches:
            ui.label("Aucun switch déclaré").classes("text-grey")
            return
        for switch in self.state.scenario.switches:
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("device_hub")
                    ui.label(switch.name).classes("font-semibold")
                    ui.badge(switch.mininet_instance, color="secondary")
                    ui.space()
                    ui.button(icon="delete", on_click=lambda _, item=switch: self.remove_switch(item)).props("flat round color=negative")

    @ui.refreshable
    def switch_link_panel(self) -> None:
        """Liste chaque lien physique une seule fois, quelle que soit sa direction YAML."""

        links = unique_switch_links(self.state.scenario)
        if not links:
            ui.label("Aucune connexion inter-switch déclarée").classes("text-grey")
            return

        owners = switch_owners(self.state.scenario)
        for _, source, destination in links:
            scope = "local" if owners.get(source) == owners.get(destination) else "distant"
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("device_hub")
                    ui.label(f"{source} — {destination}").classes("font-semibold")
                    ui.badge(scope, color="primary" if scope == "local" else "accent")
                    ui.space()
                    ui.button(
                        icon="delete",
                        on_click=lambda _, left=source, right=destination: self.remove_switch_connection(left, right),
                    ).props("flat round color=negative")

    @ui.refreshable
    def machine_topology_panel(self) -> None:
        """Affiche les VM réservées et cibles avec toutes leurs cartes réseau."""

        machines = [*self.state.scenario.infrastructure, *self.state.scenario.targets]
        for machine in machines:
            reserved = isinstance(machine, InfrastructureVM)
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("dns" if reserved else "computer")
                    with ui.column().classes("gap-0"):
                        label = f"{machine.id} — réservée ({machine.role.value})" if reserved else f"{machine.id} — cible"
                        ui.label(label).classes("font-semibold")
                        ui.label(f"{len(machine.interfaces)} interface(s)").classes("text-grey-7 text-sm")
                    ui.space()
                    ui.button("Interface", icon="add_link", on_click=lambda _, item=machine: self.open_interface_dialog(item)).props("outline dense")
                    if reserved:
                        ui.button("Accès", icon="terminal", on_click=lambda _, item=machine: self.open_infrastructure_access_dialog(item)).props("outline dense")
                    else:
                        ui.button(icon="delete", on_click=lambda _, item=machine: self.remove_target(item)).props("flat round color=negative")
                for interface in machine.interfaces:
                    network_label = interface.network or interface.purpose.value
                    with ui.row().classes("w-full items-center pl-8"):
                        ui.icon("settings_ethernet", size="sm")
                        ui.label(f"{interface.name} · {interface.address} · {network_label}").classes("text-sm")
                        ui.space()
                        ui.button(icon="edit", on_click=lambda _, owner=machine, item=interface: self.open_interface_dialog(owner, item)).props("flat round dense")
                        ui.button(icon="close", on_click=lambda _, owner=machine, item=interface: self.remove_interface(owner, item)).props("flat round dense color=negative")

    @ui.refreshable
    def topology_panel(self) -> None:
        """Sépare les couches VMware et SDN dans deux panneaux Mermaid."""

        def remember_tab(event) -> None:
            """Mémorise la vue active avant le prochain rafraîchissement."""

            self._topology_tab = str(event.value)

        with ui.tabs(value=self._topology_tab, on_change=remember_tab) as tabs:
            ui.tab("sdn", label="Topologie SDN", icon="account_tree")
            ui.tab("infrastructure", label="Infrastructure VMware", icon="dns")
        with ui.tab_panels(tabs, value=self._topology_tab).classes("w-full"):
            with ui.tab_panel("sdn"):
                ui.button(
                    "Télécharger l'image SVG",
                    icon="download",
                    on_click=lambda: self.download_diagram("cygil-sdn-diagram", "topologie-sdn"),
                ).props("outline")
                with ui.scroll_area().classes("w-full h-[680px] border rounded bg-white"):
                    ui.mermaid(
                        self.state.service.visualize_sdn(self.state.scenario)
                    ).props("id=cygil-sdn-diagram").classes("min-w-[1050px] p-6")
            with ui.tab_panel("infrastructure"):
                ui.button(
                    "Télécharger l'image SVG",
                    icon="download",
                    on_click=lambda: self.download_diagram("cygil-infrastructure-diagram", "infrastructure-vmware"),
                ).props("outline")
                with ui.scroll_area().classes("w-full h-[680px] border rounded bg-white"):
                    ui.mermaid(
                        self.state.service.visualize_infrastructure(self.state.scenario)
                    ).props("id=cygil-infrastructure-diagram").classes("min-w-[1050px] p-6")

    async def download_diagram(self, element_id: str, suffix: str) -> None:
        """Télécharge le SVG Mermaid effectivement rendu dans le navigateur."""

        filename = f"{self.state.scenario.metadata.name}-{suffix}.svg"
        await ui.run_javascript(
            f"""
            (() => {{
              const root = document.getElementById('{element_id}');
              const svg = root ? root.querySelector('svg') : null;
              if (!svg) {{ throw new Error("Le diagramme Mermaid n'est pas encore rendu"); }}
              const clone = svg.cloneNode(true);
              clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
              const source = new XMLSerializer().serializeToString(clone);
              const href = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(source);
              const link = document.createElement('a');
              link.href = href;
              link.download = '{filename}';
              link.style.display = 'none';
              document.body.appendChild(link);
              link.click();
              link.remove();
            }})()
            """,
            timeout=5.0,
        )

    def open_network_dialog(self) -> None:
        """Ajoute un sous-réseau IP sans lui inventer de switch propriétaire."""

        with ui.dialog() as dialog, ui.card().classes("w-[540px]"):
            ui.label("Ajouter un sous-réseau").classes("text-lg font-semibold")
            network_id = ui.input("Identifiant", value=f"network_{len(self.state.scenario.networks) + 1}").classes("w-full")
            cidr = ui.input("CIDR du réseau", placeholder="10.10.1.0/24").classes("w-full")
            ui.label("L'étiquette CyGIL sera déduite de l'adresse réseau; aucune passerelle n'est inventée.").classes("text-grey-7 text-sm")

            def save() -> None:
                try:
                    parsed = ip_network((cidr.value or "").strip(), strict=True)
                    self.state.scenario.networks.append(
                        Network(
                            id=network_id.value,
                            subnet_label=str(parsed.network_address),
                            cidr=str(parsed),
                            gateway=None,
                        )
                    )
                    dialog.close()
                    self.state.changed()
                except (ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Ajouter", on_click=save)
        dialog.open()

    def open_switch_dialog(self) -> None:
        """Crée un switch et demande explicitement l'instance qui l'héberge."""

        instances = [item.name for item in self.state.scenario.mininet_instances]
        if not instances:
            ui.notify("Ajoutez d'abord une instance Mininet.", type="warning")
            return
        with ui.dialog() as dialog, ui.card().classes("w-[520px]"):
            ui.label("Ajouter un switch").classes("text-lg font-semibold")
            name = ui.input("Nom", value=f"s{len(self.state.scenario.switches) + 1}").classes("w-full")
            instance = ui.select(instances, label="Instance Mininet", value=instances[0]).classes("w-full")

            def save() -> None:
                """Ajoute le switch seulement si son nom est globalement unique."""

                try:
                    # Valider la liste complète avant de publier le changement
                    # empêche tout état partiellement typé dans les panneaux.
                    if any(item.name == name.value for item in self.state.scenario.switches):
                        raise ValueError(f"Le switch {name.value} existe déjà")
                    new_switch = NetworkSwitch(
                        name=name.value,
                        mininet_instance=instance.value,
                    )
                    self.state.scenario.switches = [
                        *self.state.scenario.switches,
                        new_switch,
                    ]
                    dialog.close()
                    self.state.changed()
                except (ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Ajouter", on_click=save)
        dialog.open()

    def open_mininet_instance_dialog(self, instance: MininetInstance | None = None) -> None:
        """Crée ou modifie conjointement une instance Mininet et sa VM réservée."""

        editing = instance is not None
        position = len(self.state.scenario.mininet_instances) + 1
        mapped_machine = next(
            (
                machine
                for machine in self.state.scenario.infrastructure
                if instance and machine.id == instance.infrastructure_vm_id
            ),
            None,
        )
        used_machine_ids = {
            item.infrastructure_vm_id
            for item in self.state.scenario.mininet_instances
            if item is not instance and item.infrastructure_vm_id
        }
        eligible = [
            machine
            for machine in self.state.scenario.infrastructure
            if machine.role in {InfrastructureRole.ONOS, InfrastructureRole.MININET}
            and machine.id not in used_machine_ids
        ]
        machine_options = {
            machine.id: f"{machine.id} — {machine.role.value}"
            for machine in eligible
        }
        machine_options["__new__"] = "Créer une VM Mininet réservée supplémentaire"
        default_machine = (
            mapped_machine.id
            if mapped_machine
            else (eligible[0].id if eligible else "__new__")
        )
        with ui.dialog() as dialog, ui.card().classes("w-[620px]"):
            ui.label("Modifier l'instance Mininet" if editing else "Ajouter une instance Mininet").classes("text-lg font-semibold")
            ui.label("Choisissez la VM ONOS/Mininet existante ou créez un rôle Mininet supplémentaire.").classes("text-grey-7")
            name = ui.input("Nom de l'instance", value=instance.name if instance else f"mininet_{position}").classes("w-full")
            host_machine = ui.select(
                machine_options,
                label="VM réservée hébergeant cette instance",
                value=default_machine,
            ).classes("w-full")
            vm_id = ui.input(
                "Identifiant de la nouvelle VM (seulement si création)",
                value=f"mininet_vm_{position}",
            ).classes("w-full")
            if editing:
                host_machine.props("disable")
                vm_id.props("disable")
            ui.label(
                "Le contrôleur ONOS et les adresses sont dérivés des VM réservées; "
                "ils ne sont pas saisis dans ce dialogue."
            ).classes("text-positive text-sm")
            preview_machine = mapped_machine or next(
                (item for item in eligible if item.id == default_machine),
                None,
            )
            missing_addresses = []
            if preview_machine is None or not preview_machine.management_ip:
                missing_addresses.append("adresse de gestion")
            if preview_machine is None or not preview_machine.internal_ip:
                missing_addresses.append("adresse interne")
            if missing_addresses:
                ui.label(
                    "Adresses de la VM associée non encore allouées : "
                    + ", ".join(missing_addresses)
                    + "."
                ).classes("text-warning text-sm")

            def save() -> None:
                """Maintient les références réseau lors d'un renommage d'instance."""

                try:
                    new_name = (name.value or "").strip()
                    selected_machine_id = host_machine.value
                    new_vm_id = (
                        (vm_id.value or "").strip()
                        if selected_machine_id == "__new__"
                        else selected_machine_id
                    )
                    if not new_name or not new_vm_id:
                        raise ValueError("Le nom et la VM hôte sont obligatoires")
                    if any(item.name == new_name and item is not instance for item in self.state.scenario.mininet_instances):
                        raise ValueError(f"L'instance {new_name} existe déjà")

                    if instance is None:
                        machine = next(
                            (item for item in self.state.scenario.infrastructure if item.id == new_vm_id),
                            None,
                        )
                        if selected_machine_id == "__new__":
                            if machine is not None:
                                raise ValueError(f"La VM {new_vm_id} existe déjà")
                            machine = InfrastructureVM(id=new_vm_id, role=InfrastructureRole.MININET)
                            self.state.scenario.infrastructure.append(machine)
                        if machine is None:
                            raise ValueError("La VM réservée choisie est introuvable")
                        machine.mininet_instance = new_name
                        self.state.scenario.mininet_instances.append(
                            MininetInstance(
                                name=new_name,
                                infrastructure_vm_id=new_vm_id,
                                onos_controller_id=next(
                                    (
                                        item.id
                                        for item in self.state.scenario.infrastructure
                                        if item.role == InfrastructureRole.ONOS
                                    ),
                                    None,
                                ),
                            )
                        )
                    else:
                        if mapped_machine is None:
                            raise ValueError("La VM associée à cette instance est introuvable")
                        old_name = instance.name
                        instance.name = new_name
                        mapped_machine.mininet_instance = new_name
                        for switch in self.state.scenario.switches:
                            if switch.mininet_instance == old_name:
                                switch.mininet_instance = new_name
                        for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets]:
                            if isinstance(machine, InfrastructureVM) and machine.mininet_instance == old_name:
                                machine.mininet_instance = new_name
                            for interface in machine.interfaces:
                                if interface.mininet_instance == old_name:
                                    interface.mininet_instance = new_name

                    dialog.close()
                    self.state.changed()
                except (ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Enregistrer", on_click=save)
        dialog.open()

    def open_switch_link_dialog(self) -> None:
        """Ajoute un arc entre switches; le type local ou distant est déduit automatiquement."""

        options = {
            switch.name: f"{switch.name} — {switch.mininet_instance}"
            for switch in self.state.scenario.switches
        }
        with ui.dialog() as dialog, ui.card().classes("w-[580px]"):
            ui.label("Relier deux switches").classes("text-lg font-semibold")
            ui.label("Le lien est bidirectionnel : OVS local ou GRE selon les instances.").classes("text-grey-7")
            source = ui.select(options, label="Premier switch").classes("w-full")
            destination = ui.select(options, label="Second switch").classes("w-full")

            def save() -> None:
                """Valide les deux extrémités puis ajoute exactement l'arc demandé."""

                try:
                    if not source.value or not destination.value:
                        raise ValueError("Choisissez les deux switches à relier")
                    add_switch_link(self.state.scenario, source.value, destination.value)
                    dialog.close()
                    self.state.changed()
                except ValueError as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Créer le lien", on_click=save)
        dialog.open()

    def open_target_identity_dialog(self) -> None:
        """Déclare seulement l'identité d'une VM ; ses ressources sont choisies à l'étape 2."""

        with ui.dialog() as dialog, ui.card().classes("w-[520px]"):
            ui.label("Déclarer une VM cible").classes("text-lg font-semibold")
            target_id = ui.input("Identifiant", value=f"target_{len(self.state.scenario.targets) + 1}").classes("w-full")
            hostname = ui.input("Nom d'hôte", value=f"target-{len(self.state.scenario.targets) + 1}").classes("w-full")
            os_family = ui.select([item.value for item in OSFamily], label="Système", value=OSFamily.LINUX.value).classes("w-full")

            def save() -> None:
                try:
                    self.state.scenario.targets.append(TargetVM(id=target_id.value, hostname=hostname.value, os_family=OSFamily(os_family.value)))
                    dialog.close()
                    self.state.changed()
                except (ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Déclarer", on_click=save)
        dialog.open()

    def open_interface_dialog(
        self,
        machine: InfrastructureVM | TargetVM,
        existing: MachineInterface | None = None,
    ) -> None:
        """Ajoute ou modifie une carte tout en conservant les autres interfaces."""

        networks = self.state.scenario.networks
        network_options = {
            network.id: f"{network.id} — {network.subnet_label or network.cidr}"
            for network in networks
        }
        switch_options = {
            switch.name: f"{switch.name} — {switch.mininet_instance}"
            for switch in self.state.scenario.switches
        }
        owners = switch_owners(self.state.scenario)
        with ui.dialog() as dialog, ui.card().classes("w-[620px]"):
            ui.label(f"{'Modifier' if existing else 'Ajouter'} une interface à {machine.id}").classes("text-lg font-semibold")
            name = ui.input("Nom dans l'OS", value=existing.name if existing else f"eth{len(machine.interfaces)}").classes("w-full")
            address = ui.input("Adresse avec préfixe", value=existing.address if existing else "", placeholder="10.10.1.20/24").classes("w-full")
            purpose = ui.select([item.value for item in InterfacePurpose], label="Fonction", value=existing.purpose.value if existing else InterfacePurpose.SCENARIO.value).classes("w-full")
            network_select = ui.select(network_options, label="Sous-réseau (laisser vide pour la gestion)", value=existing.network if existing else None, clearable=True).classes("w-full")
            switch_select = ui.select(switch_options, label="Switch cible", value=existing.connected_switch if existing else None, clearable=True).classes("w-full")
            ui.label(
                "L'instance Mininet est déduite du switch : une cible ne peut pas utiliser un switch distant."
            ).classes("text-grey-7 text-sm")
            ui.label(
                "Le VMnet dédié à ce raccordement sera calculé automatiquement depuis l'inventaire VMware."
            ).classes("text-grey-7 text-sm")
            disable_dns = ui.checkbox(
                "Désactiver le DNS sur cette interface dans l'invité",
                value=existing.disable_dns if existing else True,
            )

            def save() -> None:
                try:
                    network = next((item for item in networks if item.id == network_select.value), None)
                    chosen_purpose = InterfacePurpose(purpose.value)
                    selected_switch = switch_select.value
                    selected_instance = owners.get(selected_switch) if selected_switch else None
                    if chosen_purpose == InterfacePurpose.SCENARIO and (
                        network is None or not selected_switch or not selected_instance
                    ):
                        raise ValueError("Une interface de scénario exige un sous-réseau, un switch et une instance Mininet")
                    if (
                        isinstance(machine, TargetVM)
                        and chosen_purpose == InterfacePurpose.SCENARIO
                        and any(
                            item is not existing and item.purpose == InterfacePurpose.SCENARIO
                            for item in machine.interfaces
                        )
                    ):
                        raise ValueError("Une cible ne peut posséder qu'une seule interface d'accès au switch")
                    derived_scope = LinkScope.LOCAL
                    updated = MachineInterface(
                            name=name.value,
                            address=address.value,
                            purpose=chosen_purpose,
                            network=network.id if network else None,
                            mininet_instance=selected_instance if network else None,
                            connected_switch=selected_switch if network else None,
                            scope=derived_scope,
                            mac=existing.mac if existing else None,
                            applied_mac=existing.applied_mac if existing else None,
                            mac_source=existing.mac_source if existing else None,
                            mac_verified=existing.mac_verified if existing else False,
                            vmware_network=existing.vmware_network if existing else None,
                            vmware_adapter_index=existing.vmware_adapter_index if existing else None,
                            gateway=network.gateway if network else None,
                            disable_dns=bool(disable_dns.value),
                        )
                    if existing:
                        machine.interfaces[machine.interfaces.index(existing)] = updated
                    else:
                        machine.interfaces.append(updated)
                    dialog.close()
                    self.state.changed()
                except (ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Enregistrer" if existing else "Ajouter sans remplacer", on_click=save)
        dialog.open()

    def remove_network(self, network: Network) -> None:
        """Interdit la suppression d'un réseau encore référencé par une interface."""

        machines = [*self.state.scenario.infrastructure, *self.state.scenario.targets]
        if any(interface.network == network.id for machine in machines for interface in machine.interfaces):
            ui.notify("Ce sous-réseau est encore utilisé par une interface.", type="warning")
            return
        self.state.scenario.networks.remove(network)
        self.state.changed()

    def remove_switch(self, switch: NetworkSwitch) -> None:
        """Supprime un switch uniquement lorsqu'aucune interface ne le cible encore."""

        machines = [*self.state.scenario.infrastructure, *self.state.scenario.targets]
        if any(interface.connected_switch == switch.name for machine in machines for interface in machine.interfaces):
            ui.notify("Ce switch est encore utilisé par une interface.", type="warning")
            return
        remove_switch_references(self.state.scenario, switch.name)
        self.state.scenario.switches.remove(switch)
        self.state.changed()

    def remove_mininet_instance(self, instance: MininetInstance) -> None:
        """Supprime une instance vide et sa VM associée sans laisser de référence."""

        machines = [*self.state.scenario.infrastructure, *self.state.scenario.targets]
        if any(switch.mininet_instance == instance.name for switch in self.state.scenario.switches):
            ui.notify("Supprimez d'abord les switches de cette instance.", type="warning")
            return
        if any(interface.mininet_instance == instance.name for machine in machines for interface in machine.interfaces):
            ui.notify("Cette instance est encore utilisée par une interface.", type="warning")
            return
        if any(
            isinstance(machine, InfrastructureVM) and machine.mininet_instance == instance.name
            for machine in machines
            if machine.id != instance.infrastructure_vm_id
        ):
            ui.notify("Cette instance est encore référencée par une VM d'infrastructure.", type="warning")
            return
        mapped_machine = next(
            (machine for machine in self.state.scenario.infrastructure if machine.id == instance.infrastructure_vm_id),
            None,
        )
        if mapped_machine and mapped_machine.interfaces:
            ui.notify("Retirez d'abord les interfaces de la VM Mininet associée.", type="warning")
            return
        self.state.scenario.mininet_instances.remove(instance)
        if mapped_machine:
            self.state.scenario.infrastructure.remove(mapped_machine)
        self.state.changed()

    def remove_switch_connection(self, source: str, destination: str) -> None:
        """Supprime la connexion choisie puis resynchronise le graphe et le YAML."""

        remove_switch_link(self.state.scenario, source, destination)
        self.state.changed()

    def remove_target(self, target: TargetVM) -> None:
        """Supprime une cible et laisse le synchroniseur nettoyer ses références dérivées."""

        self.state.scenario.targets.remove(target)
        self.state.changed()

    def remove_interface(self, machine: InfrastructureVM | TargetVM, interface: MachineInterface) -> None:
        """Retire uniquement l'interface choisie de la VM propriétaire."""

        machine.interfaces.remove(interface)
        self.state.changed()

    def advance_from_network(self) -> None:
        """Bloque l'étape suivante si la conception minimale n'est pas terminée."""

        if not self.state.scenario.mininet_instances:
            ui.notify("Ajoutez au moins une instance Mininet.", type="warning")
            return
        if not self.state.scenario.switches:
            ui.notify("Ajoutez au moins un switch.", type="warning")
            return
        if not self.state.scenario.networks or not self.state.scenario.targets:
            ui.notify("Ajoutez au moins un réseau et une VM cible.", type="warning")
            return
        if any(not target.interfaces for target in self.state.scenario.targets):
            ui.notify("Chaque VM cible doit avoir au moins une interface.", type="warning")
            return
        if any(not machine.interfaces for machine in self.state.scenario.infrastructure):
            ui.notify("Chaque VM réservée doit déclarer ses interfaces permanentes.", type="warning")
            return
        self.stepper.next()
    # endregion

    # region Étape 2 — configuration des VM et du fichier cible
    def _build_vm_step(self) -> None:
        """Configure les ressources uniquement pour les VM déclarées à l'étape précédente."""

        ui.label("Cette liste provient automatiquement de la conception du réseau.").classes("text-grey-7")
        self.vm_configuration_panel()
        ui.separator().classes("my-3")
        self.vagrant_box_paths_panel()
        ui.separator().classes("my-3")
        ui.label("Fichier cible et récompense").classes("text-lg font-semibold")
        self.target_file_panel()
        self._navigation()

    @ui.refreshable
    def vm_configuration_panel(self) -> None:
        """Liste réactive des spécifications de chaque VM cible."""

        if not self.state.scenario.targets:
            ui.label("Retournez à l'étape 1 pour déclarer une VM.").classes("text-warning")
        for target in self.state.scenario.targets:
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("desktop_windows" if target.os_family == OSFamily.WINDOWS else "terminal")
                    with ui.column().classes("gap-0"):
                        ui.label(f"{target.id} · {target.hostname}").classes("font-semibold")
                        ui.label(f"{target.os_family.value} · {target.cpus} CPU · {target.memory_mb} Mo · modèle {target.template}").classes("text-grey-7")
                        ui.label(f"VMX : {target.vmx_path or 'à résoudre après création'}").classes("text-grey-7 text-sm")
                        management = target.temporary_management
                        ui.label(
                            f"Amorçage temporaire : {management.vmware_network or 'à choisir'} · désactivation invitée avant snapshot={management.detach_before_snapshot}"
                        ).classes("text-grey-7 text-sm")
                    ui.space()
                    ui.button("Configurer", icon="edit", on_click=lambda _, item=target: self.open_vm_config_dialog(item)).props("outline")

    @ui.refreshable
    def target_file_panel(self) -> None:
        """Présente la cible choisie et la récompense dérivée correspondante."""

        selected = [target for target in self.state.scenario.targets if target.target_file_path]
        if selected:
            for target in selected:
                ui.label(
                    f"Cible : {target.id} · source : {target.target_file_source_path or 'à choisir'} · "
                    f"destination : {target.target_file_path} · valeur : {target.target_file_worth}"
                ).classes("text-positive font-semibold")
        else:
            ui.label("Aucun fichier cible sélectionné.").classes("text-warning")
        with ui.row().classes("w-full gap-2"):
            for target in self.state.scenario.targets:
                ui.button(f"Choisir {target.id}", icon="target", on_click=lambda _, item=target: self.open_target_file_dialog(item)).props("outline")

    def open_vm_config_dialog(self, target: TargetVM) -> None:
        """Modifie les ressources sans recréer la VM ni perdre ses interfaces."""

        with ui.dialog() as dialog, ui.card().classes("w-[620px]"):
            ui.label(f"Configurer {target.id}").classes("text-lg font-semibold")
            hostname = ui.input("Nom d'hôte", value=target.hostname).classes("w-full")
            os_family = ui.select([item.value for item in OSFamily], label="Système", value=target.os_family.value).classes("w-full")
            template = ui.input("Modèle Vagrant/VMware", value=target.template).classes("w-full")
            with ui.row().classes("w-full"):
                cpus = ui.number("CPU", value=target.cpus, min=1, max=64).classes("flex-1")
                memory = ui.number("Mémoire (Mo)", value=target.memory_mb, min=512).classes("flex-1")
            snapshot = ui.checkbox("Créer un snapshot", value=target.snapshot)
            critical = ui.checkbox("Inclure dans les réinitialisations critiques", value=target.critical_reset)
            ui.separator()
            ui.label("Réseau d'orchestration et d'amorçage temporaire").classes("font-semibold")
            ui.label("Les cibles ne sont jamais connectées à VMnet0.").classes("text-grey-7 text-sm")
            bootstrap_network = ui.input(
                "VMnet d'orchestration choisi dans la configuration hôte",
                value=self.state.scenario.vagrant.bootstrap_network or "",
            ).props("readonly").classes("w-full")
            detach_management = ui.checkbox(
                "Désactiver dans l’OS invité avant les snapshots pour assurer l’air gap",
                value=target.temporary_management.detach_before_snapshot,
            )
            ui.separator()
            ui.label("Accès technique fourni par la box").classes("font-semibold")
            default_communicator = (
                target.guest_access.communicator.value
                if target.guest_access
                else (GuestCommunicator.WINRM.value if target.os_family == OSFamily.WINDOWS else GuestCommunicator.SSH.value)
            )
            communicator = ui.select(
                [item.value for item in GuestCommunicator],
                label="Communicateur",
                value=default_communicator,
            ).classes("w-full")
            ui.label("L'adresse joignable sera reprise automatiquement du bail DHCP d'amorçage.").classes("text-grey-7 text-sm")
            network_backend = ui.select(
                [item.value for item in GuestNetworkBackend],
                label="Backend de configuration réseau invité",
                value=target.network_backend.value if target.network_backend else None,
                clearable=True,
            ).classes("w-full")
            guest_username = ui.input(
                "Utilisateur de la box",
                value=target.guest_access.username if target.guest_access else "",
            ).classes("w-full")
            password_secret = ui.input(
                "Nom de variable d'environnement du mot de passe",
                value=target.guest_access.password_secret if target.guest_access else "",
            ).classes("w-full")
            private_key_path = ui.input(
                "Chemin de clé privée SSH (optionnel)",
                value=target.guest_access.private_key_path if target.guest_access else "",
            ).classes("w-full")
            guest_port = ui.number(
                "Port personnalisé (optionnel)",
                value=target.guest_access.port if target.guest_access else None,
                min=1,
                max=65535,
            ).classes("w-full")
            ui.separator()
            ui.label("Terminal visible dans la session graphique invitée").classes("font-semibold")
            desktop_user = ui.input(
                "Utilisateur de la session graphique",
                value=target.guest_desktop.session_user or "",
            ).classes("w-full")
            terminal_executable = ui.input(
                "Exécutable du terminal dans la VM",
                value=target.guest_desktop.terminal_executable or "",
                placeholder="powershell.exe ou gnome-terminal",
            ).classes("w-full")
            linux_display = ui.input(
                "DISPLAY Linux (si applicable)",
                value=target.guest_desktop.linux_display or "",
                placeholder=":0",
            ).classes("w-full")
            visible_terminal_validated = ui.checkbox(
                "Terminal visible validé sur cette VM",
                value=target.guest_desktop.visible_terminal_validated,
            )
            ui.separator()
            ui.label("Interfaces d'isolation").classes("font-semibold")
            ui.label(
                "Les MAC et indices d'amorçage seront relus dans VMware après la création; aucune saisie manuelle n'est requise."
            ).classes("text-grey-7 text-sm")

            def save() -> None:
                target.hostname = hostname.value
                target.os_family = OSFamily(os_family.value)
                target.template = template.value
                target.cpus = int(cpus.value)
                target.memory_mb = int(memory.value)
                target.snapshot = bool(snapshot.value)
                target.critical_reset = bool(critical.value)
                target.temporary_management.enabled = True
                target.temporary_management.vmware_network = bootstrap_network.value or ""
                target.temporary_management.detach_before_snapshot = bool(detach_management.value)
                target.guest_access = GuestAccessConfig(
                    communicator=GuestCommunicator(communicator.value),
                    connection_address=(
                        target.guest_access.connection_address
                        if target.guest_access
                        else None
                    ),
                    username=guest_username.value or None,
                    password_secret=password_secret.value or None,
                    private_key_path=private_key_path.value or None,
                    port=int(guest_port.value) if guest_port.value is not None else None,
                )
                target.network_backend = (
                    GuestNetworkBackend(network_backend.value)
                    if network_backend.value
                    else None
                )
                if self._bootstrap_leases:
                    associate_bootstrap_leases(self.state.scenario, self._bootstrap_leases)
                target.guest_desktop = GuestDesktopConfig(
                    session_user=desktop_user.value or None,
                    terminal_executable=terminal_executable.value or None,
                    linux_display=linux_display.value or None,
                    visible_terminal_validated=bool(visible_terminal_validated.value),
                )
                dialog.close()
                self.state.changed()

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Enregistrer", on_click=save)
        dialog.open()

    def open_infrastructure_access_dialog(self, machine: InfrastructureVM) -> None:
        """Configure l'accès invité d'une VM réservée sans l'envoyer à Vagrant."""

        access = machine.guest_access
        desktop = machine.guest_desktop
        networks = sorted(
            {
                *(
                    [self.state.scenario.vagrant.bootstrap_network]
                    if self.state.scenario.vagrant.bootstrap_network
                    else []
                ),
            }
        )
        with ui.dialog() as dialog, ui.card().classes("w-[680px]"):
            ui.label(f"Accès invité de {machine.id}").classes("text-lg font-semibold")
            ui.label("Cette configuration ne transfère jamais la VM à Vagrant.").classes("text-grey-7")
            os_family = ui.select(
                [item.value for item in OSFamily],
                label="Système invité",
                value=machine.os_family.value if machine.os_family else None,
            ).classes("w-full")
            communicator = ui.select(
                [item.value for item in GuestCommunicator],
                label="Canal",
                value=access.communicator.value if access else GuestCommunicator.SSH.value,
            ).classes("w-full")
            connection_address = ui.input(
                "Adresse actuellement joignable sur le réseau temporaire",
                value=str(access.connection_address) if access and access.connection_address else "",
            ).classes("w-full")
            network_backend = ui.select(
                [item.value for item in GuestNetworkBackend],
                label="Backend de configuration réseau invité",
                value=machine.network_backend.value if machine.network_backend else None,
                clearable=True,
            ).classes("w-full")
            username = ui.input(
                "Utilisateur",
                value=access.username if access else machine.ssh_user or "",
            ).classes("w-full")
            password_secret = ui.input(
                "Variable d'environnement du mot de passe",
                value=access.password_secret if access else machine.ssh_password_secret or "",
            ).classes("w-full")
            private_key = ui.input(
                "Clé privée SSH",
                value=access.private_key_path if access else "",
            ).classes("w-full")
            port = ui.number(
                "Port personnalisé",
                value=access.port if access else None,
                min=1,
                max=65535,
            ).classes("w-full")
            ui.separator()
            session_user = ui.input("Utilisateur graphique", value=desktop.session_user or "").classes("w-full")
            terminal = ui.input(
                "Terminal dans la VM",
                value=desktop.terminal_executable or "",
                placeholder="powershell.exe ou gnome-terminal",
            ).classes("w-full")
            display = ui.input("DISPLAY Linux", value=desktop.linux_display or "").classes("w-full")
            terminal_validated = ui.checkbox(
                "Ouverture du terminal visible validée",
                value=desktop.visible_terminal_validated,
            )
            ui.separator()
            isolation_network = ui.select(
                networks,
                label="Interface DHCP d'amorçage à identifier",
                value=networks[0] if networks else None,
            ).classes("w-full")
            isolation_name = ui.input("Nom dans l'OS").classes("w-full")
            isolation_mac = ui.input("MAC").classes("w-full")
            isolation_index = ui.number("Indice VMware", min=0).classes("w-full")

            def save() -> None:
                if not os_family.value:
                    ui.notify("Le système invité est requis.", type="negative")
                    return
                machine.os_family = OSFamily(os_family.value)
                machine.guest_access = GuestAccessConfig(
                    communicator=GuestCommunicator(communicator.value),
                    connection_address=connection_address.value or None,
                    username=username.value or None,
                    password_secret=password_secret.value or None,
                    private_key_path=private_key.value or None,
                    port=int(port.value) if port.value is not None else None,
                )
                machine.network_backend = (
                    GuestNetworkBackend(network_backend.value)
                    if network_backend.value
                    else None
                )
                machine.guest_desktop = GuestDesktopConfig(
                    session_user=session_user.value or None,
                    terminal_executable=terminal.value or None,
                    linux_display=display.value or None,
                    visible_terminal_validated=bool(terminal_validated.value),
                )
                if isolation_network.value and (isolation_name.value or isolation_mac.value):
                    machine.isolation_interfaces = [
                        item
                        for item in machine.isolation_interfaces
                        if item.network != isolation_network.value
                    ]
                    machine.isolation_interfaces.append(
                        IsolationInterfaceConfig(
                            network=isolation_network.value,
                            guest_name=isolation_name.value or None,
                            mac=isolation_mac.value or None,
                            vmware_adapter_index=(
                                int(isolation_index.value)
                                if isolation_index.value is not None
                                else None
                            ),
                        )
                    )
                if self._bootstrap_leases:
                    associate_bootstrap_leases(self.state.scenario, self._bootstrap_leases)
                dialog.close()
                self.state.changed()

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Enregistrer", on_click=save)
        dialog.open()

    def open_target_file_dialog(self, target: TargetVM) -> None:
        """Choisit le chemin du fichier cible et crée automatiquement file_exfiltration."""

        with ui.dialog() as dialog, ui.card().classes("w-[580px]"):
            ui.label(f"Fichier cible sur {target.id}").classes("text-lg font-semibold")
            with ui.row().classes("w-full items-end"):
                source = ui.input(
                    "Fichier source local",
                    value=target.target_file_source_path or "",
                ).props("readonly").classes("flex-1")

                async def browse_source() -> None:
                    selected = await run.io_bound(VagrantEnvironmentService.choose_guest_file)
                    if selected:
                        source.value = selected

                ui.button("Parcourir…", icon="folder_open", on_click=browse_source).props("outline")
            path = ui.input("Chemin dans la VM", value=target.target_file_path or "").classes("w-full")
            worth = ui.number("Valeur de récompense", value=target.target_file_worth, min=0).classes("w-full")

            def save() -> None:
                if not source.value:
                    ui.notify("Le fichier source local est requis.", type="negative")
                    return
                if not path.value:
                    ui.notify("Le chemin du fichier est requis.", type="negative")
                    return
                self.state.set_target_file(target.id, source.value, path.value, int(worth.value))
                dialog.close()
                ui.notify("Le fichier et la récompense ont été synchronisés.", type="positive")

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Choisir cette cible", on_click=save)
        dialog.open()
    # endregion

    # region Étape 3 — CALDERA et hands
    def _build_hand_step(self) -> None:
        """Configure la connexion CALDERA et les agents pour la liste courante de VM."""

        caldera = next(machine for machine in self.state.scenario.infrastructure if machine.role.value == "caldera")
        default_url = f"http://{caldera.management_ip}:8888"
        with ui.card().classes("w-full"):
            ui.label("Connexion à l'API CALDERA").classes("text-lg font-semibold")
            self.caldera_url = ui.input("URL CALDERA", value=default_url).classes("w-full")
            self.caldera_api_key = ui.input("Clé API (conservée uniquement en mémoire)", password=True, password_toggle_button=True).classes("w-full")
            self.caldera_endpoint = ui.input(
                "Endpoint API CALDERA (test et génération)",
                value="/api/v2/deployments",
            ).classes("w-full")
            self.caldera_verify_tls = ui.checkbox("Vérifier le certificat TLS", value=True)
            ui.button("Tester la connexion", icon="wifi", on_click=self.check_caldera_connection).props("outline")
        self.hand_target_panel()
        self._navigation(next_callback=self.advance_from_hand)

    def advance_from_hand(self) -> None:
        """N'autorise la suite qu'avec une unique cible compromise cohérente."""

        compromised = [target for target in self.state.scenario.targets if target.compromised]
        if len(compromised) != 1:
            ui.notify(
                "Sélectionnez exactement une cible compromise avant de continuer.",
                type="negative",
            )
            return
        caldera = next(
            (
                machine
                for machine in self.state.scenario.infrastructure
                if machine.role == InfrastructureRole.CALDERA
            ),
            None,
        )
        if caldera is None or len(
            [item for item in caldera.interfaces if item.purpose == InterfacePurpose.SCENARIO]
        ) != 1:
            ui.notify(
                "Le raccordement CALDERA vers le switch de la cible compromise est incomplet.",
                type="negative",
            )
            return
        self.stepper.next()

    @ui.refreshable
    def hand_target_panel(self) -> None:
        """Liste les mêmes VM que les étapes précédentes et leur état de génération."""

        for target in self.state.scenario.targets:
            with ui.card().classes("w-full"):
                with ui.row().classes("w-full items-center"):
                    ui.icon("smart_toy")
                    with ui.column().classes("gap-0"):
                        ui.label(target.id).classes("font-semibold")
                        ui.label(f"{target.hand.agent_type.value} · groupe {target.hand.group} · C2 {target.hand.c2_protocol}").classes("text-grey-7")
                        ui.label(target.hand.generated_command or "Commande non générée").classes("text-xs font-mono break-all")
                    ui.space()
                    ui.button("Options", icon="tune", on_click=lambda _, item=target: self.open_hand_dialog(item)).props("outline")
                    ui.button("Prévisualiser", on_click=lambda _, item=target: self.preview_hand(item)).props("flat")
                    ui.button("Générer via API", on_click=lambda _, item=target: self.generate_hand_via_api(item))

    def open_hand_dialog(self, target: TargetVM) -> None:
        """Configure le hand et le lien invité CALDERA vers la VM Mininet."""

        caldera = next(
            (machine for machine in self.state.scenario.infrastructure if machine.role == InfrastructureRole.CALDERA),
            None,
        )
        caldera_interface = next(
            (item for item in (caldera.interfaces if caldera else []) if item.purpose == InterfacePurpose.SCENARIO),
            None,
        )

        with ui.dialog() as dialog, ui.card().classes("w-[520px]"):
            ui.label(f"Hand de {target.id}").classes("text-lg font-semibold")
            enabled = ui.checkbox("Cible compromise (hand CALDERA initial)", value=target.compromised)
            agent = ui.select([item.value for item in HandAgentType], label="Type d'agent", value=target.hand.agent_type.value).classes("w-full")
            group = ui.input("Groupe CALDERA", value=target.hand.group).classes("w-full")
            c2 = ui.select(["http", "tcp", "gist"], label="Canal C2", value=target.hand.c2_protocol).classes("w-full")
            ui.separator()
            ui.label("Lien CALDERA ↔ Mininet").classes("font-semibold")
            ui.label(
                "Cette carte rejoint la VM Mininet qui héberge le switch de la cible; elle ne relie jamais CALDERA directement à la cible."
            ).classes("text-grey-7 text-sm")
            ui.label(
                "Le nom de la carte CALDERA n'est pas demandé ici. Il devra être résolu par la future étape de découverte par MAC avant la compilation finale."
            ).classes("text-grey-7 text-sm")
            caldera_address = ui.input(
                "Adresse CALDERA avec préfixe",
                value=caldera_interface.address if caldera_interface else "",
                placeholder="10.0.0.5/24",
            ).classes("w-full")

            def save() -> None:
                compromised = bool(enabled.value)
                target_interface = next(
                    (item for item in target.interfaces if item.purpose == InterfacePurpose.SCENARIO),
                    None,
                )
                if compromised and target_interface is None:
                    ui.notify("Ajoutez d'abord l'unique interface d'accès de cette cible.", type="negative")
                    return
                if not compromised and target.compromised:
                    ui.notify(
                        "Le scénario doit conserver exactement une cible compromise. Sélectionnez-en une autre pour transférer ce rôle.",
                        type="negative",
                    )
                    return
                target.hand.agent_type = HandAgentType(agent.value)
                target.hand.group = group.value
                target.hand.c2_protocol = c2.value
                target.hand.generated_command = None
                if compromised:
                    if not (caldera_address.value or "").strip():
                        ui.notify("L'adresse CALDERA avec préfixe est obligatoire.", type="negative")
                        return
                    try:
                        select_compromised_target(
                            self.state.scenario,
                            target.id,
                            (caldera_address.value or "").strip(),
                        )
                    except ValueError as exc:
                        ui.notify(str(exc), type="negative", multi_line=True)
                        return
                dialog.close()
                self.state.changed()

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Enregistrer", on_click=save)
        dialog.open()

    async def check_caldera_connection(self) -> None:
        """Teste CALDERA sans sauvegarder la clé API saisie."""

        try:
            client = CalderaClient(self.caldera_url.value, self.caldera_api_key.value, verify_tls=self.caldera_verify_tls.value)
            ui.notify(await client.check_connection(self.caldera_endpoint.value), type="positive")
        except CalderaConnectionError as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def preview_hand(self, target: TargetVM) -> None:
        """Affiche le choix qui sera envoyé à CALDERA sans effectuer de requête."""

        client = CalderaClient(self.caldera_url.value, "preview", verify_tls=self.caldera_verify_tls.value)
        ui.notify(client.build_preview_command(target), type="info", multi_line=True)

    async def generate_hand_via_api(self, target: TargetVM) -> None:
        """Récupère et sauvegarde la commande générée par l'API pour la VM choisie."""

        if not target.hand.enabled:
            ui.notify("Activez d'abord le hand dans les options de cette VM.", type="warning")
            return
        try:
            client = CalderaClient(self.caldera_url.value, self.caldera_api_key.value, verify_tls=self.caldera_verify_tls.value)
            await client.request_hand_command(target, self.caldera_endpoint.value)
            self.state.changed()
            ui.notify("Commande de hand générée et sauvegardée.", type="positive")
        except CalderaConnectionError as exc:
            ui.notify(str(exc), type="negative", multi_line=True)
    # endregion

    # region Étape 4 — centre de contrôle de l'hôte Windows
    def _build_host_step(self) -> None:
        """Construit les onglets hôte, VMware et déploiement Vagrant."""

        config = self.state.scenario.vmware
        try:
            stored_vmrest = self._secret_store.load(self.state.scenario.metadata.name)
        except SecretStoreError:
            stored_vmrest = {}
        ui.label("Centre interactif de configuration et de surveillance OpenSSH / VMware REST API").classes("text-xl font-semibold")
        ui.label("Les identifiants VMREST sont chiffrés par Windows pour cet utilisateur et ne sont jamais placés dans la sauvegarde YAML.").classes("text-grey-7")
        self.host_confirmation = ui.checkbox("Je confirme l'exécution des commandes affichées sur cet hôte")

        with ui.tabs().classes("w-full") as host_tabs:
            monitoring_tab = ui.tab("Surveillance", icon="monitor_heart")
            ssh_tab = ui.tab("OpenSSH", icon="terminal")
            vmrest_tab = ui.tab("VMREST", icon="dns")
            vagrant_tab = ui.tab("Vagrant", icon="deployed_code")
            settings_tab = ui.tab("Paramètres", icon="settings")
            plan_tab = ui.tab("Plan des commandes", icon="fact_check")

        with ui.tab_panels(host_tabs, value=monitoring_tab).classes("w-full"):
            with ui.tab_panel(monitoring_tab):
                with ui.row().classes("w-full items-center"):
                    ui.label("État courant de l'hôte").classes("text-lg font-semibold")
                    ui.space()
                    ui.button("Actualiser maintenant", icon="refresh", on_click=self.refresh_host_runtime_panels).props("outline")
                self.host_status_panel()
                self.ssh_runtime_panel()
                self.vmrest_runtime_panel()
                self.vmrest_firewall_panel()

            with ui.tab_panel(ssh_tab):
                ui.label("OpenSSH Server").classes("text-lg font-semibold")
                ui.label("Si le service est absent, l'installation sera proposée puis Windows demandera l'autorisation administrateur.").classes("text-grey-7")
                self.host_ssh_user = ui.input("Utilisateur Windows/SSH", value=config.ssh_user).classes("w-full")
                with ui.row().classes("w-full items-end"):
                    self.host_public_key_path = ui.input(
                        "Fichier de clé publique (.pub)",
                        value=config.ssh_authorized_public_key_path or "",
                    ).props("readonly").classes("flex-1")
                    ui.button("Parcourir…", icon="folder_open", on_click=self.browse_public_key).props("outline")
                self.host_public_key_preview = ui.textarea(
                    "Clé extraite automatiquement",
                    placeholder="Choisissez un fichier .pub pour afficher sa clé.",
                ).props("readonly autogrow").classes("w-full font-mono")
                self.host_legacy_rsa = ui.checkbox("Autoriser temporairement ssh-rsa ancien (risque de sécurité)", value=config.allow_legacy_ssh_rsa)
                with ui.row().classes("gap-2"):
                    ui.button("Installer OpenSSH Server", icon="download", on_click=self.open_openssh_install_dialog).props("outline")
                    ui.button("Configurer SSH", icon="admin_panel_settings", on_click=self.execute_ssh_setup)
                    ui.button("Relire l'état SSH", icon="refresh", on_click=self.refresh_host_runtime_panels).props("flat")

            with ui.tab_panel(vmrest_tab):
                ui.label("Cycle de vie VMware REST API").classes("text-lg font-semibold")
                self.host_api_user = ui.input(
                    "Utilisateur API vmrest",
                    value=stored_vmrest.get("username", ""),
                ).classes("w-full")
                self.host_api_password = ui.input(
                    "Mot de passe API vmrest",
                    value=stored_vmrest.get("password", ""),
                    password=True,
                    password_toggle_button=True,
                ).classes("w-full")
                with ui.row().classes("gap-2"):
                    ui.button("Enregistrer les identifiants", icon="encrypted", on_click=self.save_vmrest_credentials).props("outline")
                    ui.button("1. Générer le certificat", icon="workspace_premium", on_click=self.execute_certificate_setup).props("outline")
                    ui.button("2. Ouvrir la console d'identifiants", icon="password", on_click=self.execute_vmrest_credentials).props("outline")
                    ui.button("3. Démarrer vmrest", icon="play_arrow", on_click=self.execute_vmrest_start, color="positive")
                    ui.button("Arrêter vmrest", icon="stop", on_click=self.execute_vmrest_stop, color="negative").props("outline")
                    ui.button("Vérifier l'API", icon="health_and_safety", on_click=self.check_vmrest_status).props("flat")
                ui.label("Le démarrage n'est confirmé qu'après détection du processus, du port et de /api/vms.").classes("text-grey-7")
                ui.label(
                    "La console vmrest demande le nom, le mot de passe et sa confirmation. "
                    "Saisissez ensuite les mêmes valeurs ci-dessus pour les contrôles API. "
                    "Sur un hôte déjà configuré, un nouveau scénario peut démarrer directement : "
                    "l'authentification HTTP sert de preuve et la console -C n'est pas à refaire."
                ).classes("text-grey-7 text-sm")
                ui.separator().classes("my-3")
                self.vmrest_firewall_panel()

            with ui.tab_panel(vagrant_tab):
                self._build_vagrant_tab()

            with ui.tab_panel(settings_tab):
                ui.label("Paramètres de l'hôte").classes("text-lg font-semibold")
                with ui.row().classes("w-full"):
                    self.host_ip = ui.input("Adresse de l'hôte", value=config.external_ip).classes("flex-1")
                    self.host_port = ui.number("Port vmrest", value=config.api_port, min=1, max=65535).classes("w-40")
                self.host_workstation = ui.input("Dossier VMware Workstation", value=config.workstation_directory).classes("w-full")
                with ui.row().classes("w-full items-end"):
                    self.host_openssl = ui.input("Exécutable OpenSSL", value=config.openssl_executable).classes("flex-1")
                    ui.button("Parcourir…", icon="folder_open", on_click=self.browse_openssl).props("outline")
                with ui.row().classes("w-full items-end"):
                    self.host_openssl_config = ui.input(
                        "Fichier de configuration OpenSSL",
                        value=config.openssl_config_path or "",
                    ).props("readonly").classes("flex-1")
                    ui.button(
                        "Parcourir…",
                        icon="description",
                        on_click=self.browse_openssl_config,
                    ).props("outline")
                self.host_certificate_directory = ui.input("Dossier des certificats", value=config.certificate_directory).classes("w-full")
                with ui.row().classes("w-full items-end"):
                    self.host_vmrest_certificate = ui.input(
                        "Certificat TLS utilisé par vmrest",
                        value=config.setup_status.certificate_path or "",
                    ).props("readonly").classes("flex-1")
                    ui.button("Parcourir…", icon="folder_open", on_click=self.browse_vmrest_certificate).props("outline")
                with ui.row().classes("w-full items-end"):
                    self.host_vmrest_private_key = ui.input(
                        "Clé privée TLS utilisée par vmrest",
                        value=config.setup_status.private_key_path or "",
                    ).props("readonly").classes("flex-1")
                    ui.button("Parcourir…", icon="folder_open", on_click=self.browse_vmrest_private_key).props("outline")
                with ui.expansion("Politique MAC statique VMware validée", icon="fingerprint").classes("w-full"):
                    ui.label(
                        "Ces valeurs doivent provenir de la version Workstation installée; aucune plage par défaut n'est supposée."
                    ).classes("text-grey-7")
                    self.host_mac_version = ui.input(
                        "Version VMware Workstation",
                        value=config.static_mac_workstation_version or "",
                    ).classes("w-full")
                    with ui.row().classes("w-full"):
                        self.host_mac_first = ui.input("Première MAC autorisée", value=config.static_mac_first or "").classes("flex-1")
                        self.host_mac_last = ui.input("Dernière MAC autorisée", value=config.static_mac_last or "").classes("flex-1")
                    self.host_mac_source = ui.input(
                        "Source locale de validation (document/version/essai)",
                        value=config.static_mac_validation_source or "",
                    ).classes("w-full")
                    self.host_mac_validated = ui.checkbox(
                        "Je confirme que cette plage a été validée sur cette version",
                        value=config.static_mac_policy_validated,
                    )
                ui.button("Appliquer les paramètres", icon="save", on_click=self.apply_host_fields).props("outline")

            with ui.tab_panel(plan_tab):
                self.host_plan_panel()

        self._navigation()

    # region Vagrant, VM réservées et allocation VMnet0
    def _build_vagrant_tab(self) -> None:
        """Affiche la préparation Vagrant sans inspection pendant le rendu."""

        config = self.state.scenario.vagrant
        ui.label("Déploiement des nouvelles VM cibles").classes("text-lg font-semibold")
        ui.label(
            "Vagrant ne recevra jamais les VM CyGIL, CALDERA, ONOS ou Mininet. "
            "Toute commande réelle reste liée au plan exact affiché."
        ).classes("text-grey-7")
        if not config.bootstrap_validated:
            ui.label(
                "Exécution réelle bloquée : le VMnet d'amorçage DHCP séparé doit être validé avec les boxes choisies."
            ).classes("text-negative font-semibold")
        with ui.row().classes("w-full items-end"):
            self.vagrant_executable = ui.input(
                "Exécutable Vagrant",
                value=config.executable_path or "",
                placeholder="Détection automatique après installation",
            ).classes("flex-1")
            ui.button("Inventorier", icon="refresh", on_click=self.refresh_vagrant_inventory).props("outline")
        with ui.row().classes("w-full items-end"):
            self.vagrant_clone_directory = ui.input(
                "Répertoire des nouvelles VM",
                value=config.clone_directory or "",
            ).props("readonly").classes("flex-1")
            ui.button("Parcourir…", icon="folder_open", on_click=self.browse_clone_directory).props("outline")
        with ui.card().classes("w-full"):
            ui.label("Réseau host-only d'orchestration / amorçage").classes("font-semibold")
            ui.label(
                "Ce réseau unique relie temporairement toutes les VM, est distinct de VMnet0, peut fournir le DHCP et n'est jamais exporté vers CyGIL."
            ).classes("text-grey-7")
            # La liste est alimentée uniquement par l'inventaire VMREST. VMnet0
            # en est exclu car il constitue le réseau de gestion statique.
            initial_bootstrap_options = (
                [config.bootstrap_network] if config.bootstrap_network else []
            )
            self.bootstrap_network = ui.select(
                initial_bootstrap_options,
                label="VMnet d'orchestration / amorçage choisi",
                value=config.bootstrap_network,
                with_input=False,
                clearable=True,
            ).props("hint='Inventoriez les VMnet, puis choisissez un host-only distinct de VMnet0'").classes("w-full")
            self.bootstrap_dhcp = ui.checkbox(
                "DHCP VMware activé sur ce VMnet temporaire",
                value=config.bootstrap_dhcp_enabled,
            )
            self.bootstrap_validated = ui.checkbox(
                "Accès d'amorçage validé avec les VM et boxes réelles",
                value=config.bootstrap_validated,
            )
            ui.separator()
            ui.label("Réseau interne CyGIL / Mininet / ONOS").classes("font-semibold")
            ui.label(
                "Choisissez le VMnet physique. Le CIDR observé est prioritaire; "
                "le CIDR déjà enregistré est conservé pour un VMnet manuel que vmrest ne décrit pas."
            ).classes("text-grey-7")
            initial_internal_options = (
                [config.mininet_internal_network]
                if config.mininet_internal_network
                else []
            )
            self.mininet_internal_network = ui.select(
                initial_internal_options,
                label="VMnet interne choisi",
                value=config.mininet_internal_network,
                with_input=False,
                clearable=True,
            ).classes("w-full")
            self.mininet_internal_cidr_label = ui.label(
                f"CIDR observé : {config.mininet_internal_cidr or 'non inventorié'}"
            ).classes("text-grey-7 text-sm")
            ui.button(
                "Inventorier les VMnet via VMREST",
                icon="refresh",
                on_click=self.refresh_vmnet_records,
            ).props("outline")
            ui.button(
                "Lire les baux DHCP du VMnet choisi",
                icon="manage_search",
                on_click=self.refresh_bootstrap_leases,
            ).props("outline")
            self.vmnet_inventory_panel()
            self.vmnet_mapping_panel()

        self.vagrant_status_panel()
        with ui.expansion("Installation contrôlée de Vagrant", icon="download").classes("w-full"):
            environment_service = VagrantEnvironmentService(self.state.scenario)
            staging = PROJECT_ROOT / "work" / "installers"
            utility_msi = staging / (
                f"vagrant-vmware-utility_{environment_service.UTILITY_VERSION}_windows_amd64.msi"
            )
            utility_url = (
                "https://releases.hashicorp.com/vagrant-vmware-utility/"
                f"{environment_service.UTILITY_VERSION}/{utility_msi.name}"
            )
            ui.label(f"Téléchargement : {utility_url}").classes("font-mono text-sm")
            ui.label(f"SHA-256 exigé : {environment_service.UTILITY_SHA256}").classes("font-mono text-sm")
            for command in environment_service.installation_commands(str(utility_msi.resolve())):
                ui.code(subprocess.list2cmdline(command), language="powershell").classes("w-full")
            self.vagrant_install_token_value = environment_service.installation_confirmation_token(
                str(utility_msi.resolve())
            )
            ui.label(f"Jeton d'installation : {self.vagrant_install_token_value}").classes("font-mono font-semibold")
            self.vagrant_install_token = ui.input("Retaper le jeton d'installation").classes("w-full")
            self.vagrant_install_confirmation = ui.checkbox(
                "Je confirme l'installation de Vagrant, de l'Utility VMware et du plugin officiel"
            )
            ui.button(
                "Installer la pile Vagrant",
                icon="admin_panel_settings",
                on_click=self.execute_vagrant_installation,
                color="warning",
            )

        ui.separator().classes("my-3")
        with ui.row().classes("w-full items-center"):
            ui.label("VM VMware réservées").classes("text-lg font-semibold")
            ui.space()
            ui.button("Lire les VM enregistrées", icon="view_list", on_click=self.refresh_vmware_inventory).props("outline")
        ui.label("L'association utilise vmrest et ne démarre aucune VM.").classes("text-grey-7")
        self.vmware_inventory_panel()

        with ui.card().classes("w-full mt-3"):
            ui.label("Reconstruction réseau des VM réservées").classes("text-lg font-semibold")
            ui.label(
                "L'inventaire global, le diff et la sauvegarde sont obligatoires. "
                "L'application refuse toute VM active ou tout inventaire modifié."
            ).classes("text-grey-7")
            with ui.row().classes("w-full"):
                ui.button(
                    "1. Inventorier toutes les cartes",
                    icon="manage_search",
                    on_click=self.refresh_vmware_network_inventory,
                ).props("outline")
                ui.button(
                    "2. Préparer le diff",
                    icon="difference",
                    on_click=self.preview_reserved_reconstruction,
                ).props("outline")
            self.vmware_reconstruction_panel()
            self.network_reconstruction_stop_confirm = ui.checkbox(
                "Je confirme que l'arrêt des seules VM réservées associées est autorisé"
            )
            self.network_reconstruction_destructive_confirm = ui.checkbox(
                "Je confirme la suppression et recréation des cartes affichées"
            )
            self.network_reconstruction_token = ui.input(
                "Recopier l'empreinte du plan destructif"
            ).classes("w-full")
            ui.button(
                "Sauvegarder puis appliquer hors tension",
                icon="published_with_changes",
                on_click=self.execute_reserved_reconstruction,
                color="negative",
            )
            self.network_restore_token = ui.input(
                "Jeton distinct de restauration (affiché après sauvegarde)"
            ).classes("w-full")
            ui.button(
                "Restaurer les VMX sauvegardés",
                icon="restore",
                on_click=self.restore_reserved_networks,
                color="warning",
            ).props("outline")

        ui.separator().classes("my-3")
        with ui.row().classes("w-full items-center"):
            ui.label("Adresses de management VMnet0 (VM réservées)").classes("text-lg font-semibold")
            ui.space()
            ui.button("Calculer une proposition", icon="lan", on_click=self.preview_management_allocation).props("outline")
        self.management_allocation_panel()

        ui.separator().classes("my-3")
        with ui.row().classes("w-full items-center"):
            ui.label("Plan Vagrant exact").classes("text-lg font-semibold")
            ui.space()
            ui.button("Préparer le plan", icon="fact_check", on_click=self.prepare_vagrant_plan).props("outline")
        self.vagrant_plan_panel()

    @ui.refreshable
    def vagrant_box_paths_panel(self) -> None:
        """Reconstruit les champs box depuis les modèles et chemins du scénario courant."""

        config = self.state.scenario.vagrant
        templates = tuple(sorted({target.template for target in self.state.scenario.targets}))
        self._vagrant_box_templates = templates
        self.vagrant_box_inputs = {}
        self.vagrant_box_status_labels = {}
        ui.label("Boxes locales Vagrant").classes("text-lg font-semibold")
        ui.label(
            "Choisissez uniquement les archives .box des modèles utilisés. "
            "La sélection valide les métadonnées VMware Desktop sans importer la box ni démarrer Vagrant."
        ).classes("text-grey-7")
        if not templates:
            ui.label("Aucune cible ne requiert encore de box locale.").classes("text-grey-7")
        for template in templates:
            with ui.column().classes("w-full gap-0"):
                with ui.row().classes("w-full items-end"):
                    box_input = ui.input(
                        f"Box locale — {template}",
                        value=config.box_paths.get(template, ""),
                    ).props("readonly").classes("flex-1")
                    self.vagrant_box_inputs[template] = box_input
                    ui.button(
                        "Parcourir…",
                        icon="inventory_2",
                        on_click=lambda _, item=template: self.browse_box(item),
                    ).props("outline")
                initial_status = (
                    "Chemin chargé depuis le scénario; cliquez sur Inventorier pour le revérifier."
                    if config.box_paths.get(template)
                    else "Aucun fichier choisi."
                )
                self.vagrant_box_status_labels[template] = ui.label(initial_status).classes(
                    "text-grey-7 text-sm"
                )
        ui.button(
            "Enregistrer les chemins",
            icon="save",
            on_click=self.save_vagrant_settings,
        ).props("outline")

    def _refresh_vagrant_box_paths_if_templates_changed(self) -> None:
        """Actualise la liste seulement lorsque les modèles requis ont changé."""

        templates = tuple(sorted({target.template for target in self.state.scenario.targets}))
        if templates != self._vagrant_box_templates:
            self.vagrant_box_paths_panel.refresh()

    @ui.refreshable
    def vagrant_status_panel(self) -> None:
        """Affiche uniquement le dernier inventaire explicitement demandé."""

        inventory = self._vagrant_inventory
        with ui.card().classes("w-full mt-2"):
            if inventory is None:
                ui.label("Inventaire Vagrant non exécuté.").classes("text-warning")
                for command in VagrantEnvironmentService(self.state.scenario).installation_commands():
                    ui.code(subprocess.list2cmdline(command), language="powershell").classes("w-full")
                ui.label("Ces commandes sont une prévisualisation; aucun bouton ne les exécute automatiquement.").classes("text-grey-7 text-sm")
                return
            color = "positive" if inventory.provider_available else "warning"
            ui.label(f"Vagrant : {inventory.version or 'absent'}").classes(f"text-{color} font-semibold")
            ui.label(f"Exécutable : {inventory.executable or 'introuvable'}")
            ui.label(f"Vagrant VMware Utility : {inventory.vmware_utility_service}")
            ui.label("Plugins : " + ("; ".join(inventory.plugins) or "aucun"))
            ui.label(
                "Boxes déjà installées dans Vagrant : "
                + ("; ".join(inventory.boxes) or "aucune")
            )
            ui.label(
                "Les fichiers choisis ci-dessous restent locaux jusqu'à l'exécution d'un plan explicitement confirmé."
            ).classes("text-grey-7 text-sm")
            if not inventory.local_boxes:
                ui.label("Fichiers box locaux sélectionnés : aucun").classes("text-warning")
            for box in inventory.local_boxes:
                box_color = "positive" if box.valid else "negative"
                size = f"{box.size_bytes / (1024 ** 3):.2f} Gio" if box.size_bytes is not None else "taille inconnue"
                ui.label(
                    f"{box.template} : {'valide' if box.valid else 'invalide'} · "
                    f"{box.provider or 'fournisseur inconnu'} · {size}"
                ).classes(f"text-{box_color} font-semibold")
                ui.label(box.path).classes("font-mono text-sm")
                ui.label(box.message).classes("text-grey-7 text-sm")

    @ui.refreshable
    def vmnet_inventory_panel(self) -> None:
        """Affiche l'inventaire explicitement demandé et les baux sans mutation."""

        if not self._vmnet_records:
            ui.label("Aucun inventaire VMnet chargé.").classes("text-warning")
        for record in self._vmnet_records:
            host_connection = (
                "Yes" if record.host_connected is True
                else "No" if record.host_connected is False
                else "inconnu"
            )
            ui.label(
                f"{record.name} · {record.network_type} · DHCP={record.dhcp_enabled} · "
                f"Host Connection={host_connection} · {record.subnet or '?'} / {record.mask or '?'}"
            ).classes("text-sm font-mono")
        if self._bootstrap_leases:
            ui.label("Baux DHCP observés (MAC → IPv4)").classes("font-semibold")
            for mac, address in sorted(self._bootstrap_leases.items()):
                ui.label(f"{mac} → {address}").classes("text-sm font-mono")

    @ui.refreshable
    def vmnet_mapping_panel(self) -> None:
        """Affiche un VMnet physique par raccordement cible/Mininet."""

        with ui.card().classes("w-full mt-2"):
            ui.label("Raccordements physiques cible ↔ Mininet").classes("font-semibold")
            ui.label(
                "Chaque interface de cible reçoit un VMnet dédié et une carte correspondante sur sa VM Mininet, même lorsque plusieurs cibles partagent le même sous-réseau logique."
            ).classes("text-grey-7 text-sm")
            if not self._vmnet_records:
                ui.label("Inventoriez les VMnet avant de calculer les raccordements.").classes("text-warning")
                return
            ui.button(
                "Calculer les raccordements",
                icon="account_tree",
                on_click=self.prepare_scenario_vmnet_plan,
            ).props("outline")
            plan = self._scenario_vmnet_plan
            if plan is None:
                return
            for attachment in plan.attachments:
                status = "à créer" if attachment.create_required else "existant"
                ui.label(
                    f"{attachment.target_id}/{attachment.interface_name or attachment.interface_index} "
                    f"↔ {attachment.mininet_instance} : {attachment.vmnet} ({status})"
                ).classes("font-mono text-sm")
            ui.separator()
            ui.label(
                "Isolation hôte obligatoire : " + ", ".join(plan.isolated_vmnets)
            ).classes("text-sm font-semibold")
            ui.label(
                "Host Connection = Yes requis uniquement pour : "
                + ", ".join(plan.required_host_vmnets)
            ).classes("text-grey-7 text-sm")
            if plan.host_connected_vmnets:
                ui.label(
                    "Host Connection doit passer à No : "
                    + ", ".join(plan.host_connected_vmnets)
                ).classes("text-negative font-semibold")
            if plan.host_connection_unknown:
                ui.label(
                    "Host Connection non vérifié : "
                    + ", ".join(plan.host_connection_unknown)
                ).classes("text-warning font-semibold")
            if plan.dhcp_disable_vmnets:
                ui.label(
                    "DHCP VMware doit être désactivé sur les VMnet d'accès gérés : "
                    + ", ".join(plan.dhcp_disable_vmnets)
                ).classes("text-negative font-semibold")
            if plan.required_host_disconnected:
                ui.label(
                    "Host Connection doit passer à Yes : "
                    + ", ".join(plan.required_host_disconnected)
                ).classes("text-negative font-semibold")
            if plan.required_host_unknown:
                ui.label(
                    "Connexion hôte de gestion non vérifiée : "
                    + ", ".join(plan.required_host_unknown)
                ).classes("text-warning font-semibold")
            if plan.host_isolation_confirmed:
                ui.label("Politique confirmée : No sur Mininet; Yes sur VMnet0 et l'amorçage.").classes(
                    "text-positive font-semibold"
                )
            if plan.dhcp_policy_confirmed:
                ui.label("DHCP confirmé désactivé sur tous les VMnet d'accès gérés.").classes(
                    "text-positive font-semibold"
                )
            if plan.changes_required:
                ui.label(f"Jeton d'exécution : {plan.confirmation_token}").classes("font-mono font-semibold")
                self.scenario_vmnet_creation_confirmation = ui.checkbox(
                    "Je confirme la création affichée, No sur les VMnet Mininet et Yes uniquement sur VMnet0/amorcçage"
                )
                self.scenario_vmnet_creation_token = ui.input(
                    "Recopier le jeton d'exécution"
                ).classes("w-full")
                ui.button(
                    "Créer et isoler les VMnet Mininet",
                    icon="add_to_queue",
                    on_click=self.create_scenario_vmnets,
                    color="warning",
                )

    def prepare_scenario_vmnet_plan(self) -> None:
        """Calcule et persiste les raccordements sans modifier VMware."""

        try:
            self._scenario_vmnet_plan = plan_scenario_vmnets(
                self.state.scenario,
                tuple(self._vmnet_records),
            )
            self.state.changed()
            self.vmnet_mapping_panel.refresh()
            ui.notify("Plan des raccordements calculé; aucun VMnet n'a encore été créé.", type="positive")
        except ValueError as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    async def create_scenario_vmnets(self) -> None:
        """Crée les VMnet, retire leurs cartes hôte, puis relit les deux états."""

        plan = self._scenario_vmnet_plan
        if plan is None or not plan.changes_required:
            ui.notify("Aucune création ou isolation VMnet n'est requise.", type="warning")
            return
        if not self.scenario_vmnet_creation_confirmation.value:
            ui.notify("La confirmation explicite est requise.", type="negative")
            return
        if (self.scenario_vmnet_creation_token.value or "").strip().upper() != plan.confirmation_token:
            ui.notify("Le jeton ne correspond pas au plan affiché.", type="negative")
            return
        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        try:
            service = VagrantEnvironmentService(self.state.scenario)
            if plan.missing_vmnets:
                await run.io_bound(
                    service.create_hostonly_vmnets,
                    plan.missing_vmnets,
                    username,
                    password,
                )
            if plan.dhcp_disable_vmnets:
                await run.io_bound(
                    service.disable_dhcp_on_vmnets,
                    plan.dhcp_disable_vmnets,
                    username,
                    password,
                )
            await run.io_bound(
                service.disconnect_host_from_vmnets,
                plan.isolated_vmnets,
                bootstrap_vmnet=self.state.scenario.vagrant.bootstrap_network,
            )
            await run.io_bound(
                service.connect_host_to_management_vmnets,
                plan.required_host_vmnets,
                bootstrap_vmnet=self.state.scenario.vagrant.bootstrap_network,
            )
            self._vmnet_records = await run.io_bound(service.inspect_vmnets, username, password)
            self._scenario_vmnet_plan = plan_scenario_vmnets(
                self.state.scenario,
                tuple(self._vmnet_records),
            )
            self.vmnet_inventory_panel.refresh()
            self.vmnet_mapping_panel.refresh()
            self.state.changed()
            if not self._scenario_vmnet_plan.host_isolation_confirmed:
                details = (
                    self._scenario_vmnet_plan.host_connected_vmnets
                    or self._scenario_vmnet_plan.host_connection_unknown
                    or self._scenario_vmnet_plan.required_host_disconnected
                    or self._scenario_vmnet_plan.required_host_unknown
                )
                raise EnvironmentInventoryError(
                    "La relecture ne confirme pas la politique Host Connection complète : "
                    + ", ".join(details)
                )
            if not self._scenario_vmnet_plan.dhcp_policy_confirmed:
                raise EnvironmentInventoryError(
                    "La relecture indique que le DHCP VMware reste actif sur : "
                    + ", ".join(self._scenario_vmnet_plan.dhcp_disable_vmnets)
                )
            ui.notify(
                "VMnet relus : No sur Mininet; Yes uniquement sur VMnet0 et l'amorçage.",
                type="positive",
            )
        except (EnvironmentInventoryError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    @ui.refreshable
    def vmware_inventory_panel(self) -> None:
        """Affiche une ligne compacte par rôle réservé à associer."""

        if not self._vmware_vms:
            ui.label(
                "Cliquez sur « Lire les VM enregistrées » pour charger les titres depuis VMware."
            ).classes("text-warning")
            return
        vm_options = {
            record.vmware_id: (
                f"{record.name if record.name != record.vmware_id else 'VM sans titre'} "
                f"— {record.vmware_id[:12]}{'…' if len(record.vmware_id) > 12 else ''}"
            )
            for record in sorted(self._vmware_vms, key=lambda item: item.name.casefold())
        }
        self._reserved_vm_selects = {}
        with ui.card().classes("w-full"):
            ui.label("Associer chaque rôle à sa VM VMware existante").classes("font-semibold")
            ui.label(
                "Les adresses VMnet0 seront calculées plus tard. Une VM VMware ne peut servir qu'à un seul rôle."
            ).classes("text-grey-7 text-sm")
            for machine in self.state.scenario.infrastructure:
                current = machine.vmware_id if machine.vmware_id in vm_options else None
                with ui.row().classes("w-full items-center"):
                    with ui.column().classes("w-52 gap-0"):
                        ui.label(machine.id).classes("font-semibold")
                        ui.label(machine.role.value.upper()).classes("text-grey-7 text-xs")
                    selector = ui.select(
                        vm_options,
                        label="VM VMware correspondante",
                        value=current,
                        with_input=True,
                        clearable=True,
                    ).classes("flex-1")
                    self._reserved_vm_selects[machine.id] = selector
            associated = sum(
                1 for machine in self.state.scenario.infrastructure if machine.vmware_id in vm_options
            )
            ui.label(
                f"{associated}/{len(self.state.scenario.infrastructure)} rôles actuellement associés"
            ).classes("text-grey-7")
            ui.button(
                "Enregistrer toutes les associations",
                icon="link",
                on_click=self.save_reserved_vm_associations,
            ).props("outline")

    @ui.refreshable
    def management_allocation_panel(self) -> None:
        """Sépare clairement la proposition de son approbation persistante."""

        inventory = self._vmnet_inventory
        if inventory:
            color = "negative" if inventory.dhcp_enabled else "positive"
            ui.label(
                f"{inventory.adapter_name} · {inventory.cidr} · hôte {', '.join(sorted(inventory.host_addresses))}"
            ).classes("font-semibold")
            ui.label(
                f"Adressage DHCP de l'adaptateur Windows VMnet0 : "
                f"{'ACTIVÉ' if inventory.dhcp_enabled else 'désactivé'}"
            ).classes(f"text-{color}")
        if not self._allocation_preview:
            ui.label("Aucune proposition calculée.").classes("text-warning")
            return
        for machine_id, assigned in self._allocation_preview.items():
            ui.label(f"{machine_id} → {assigned}").classes("font-mono")
        ui.button("Approuver et enregistrer ces adresses", icon="verified", on_click=self.approve_management_allocation)

    @ui.refreshable
    def vagrant_plan_panel(self) -> None:
        """Affiche le Vagrantfile, les commandes, l'empreinte et les résultats."""

        if not self._vagrant_commands:
            ui.label("Le plan n'est pas encore prêt.").classes("text-warning")
            return
        if self._vagrantfile_text:
            with ui.expansion("Vagrantfile généré", icon="description").classes("w-full"):
                ui.code(self._vagrantfile_text, language="ruby").classes("w-full")
        for command in self._vagrant_commands:
            ui.code(command.display(), language="powershell").classes("w-full")
        for template, digest in self._vagrant_box_hashes.items():
            ui.label(f"SHA-256 {template} : {digest}").classes("font-mono text-sm")
        ui.label(f"Jeton du plan : {self._vagrant_token}").classes("font-semibold font-mono")
        self.vagrant_execution_token = ui.input("Retaper le jeton pour autoriser ce plan exact").classes("w-full")
        self.vagrant_execution_confirmation = ui.checkbox(
            "Je confirme l'import des boxes et la création des seules VM cibles affichées"
        )
        ui.button("Exécuter le plan confirmé", icon="play_arrow", on_click=self.execute_vagrant_plan, color="warning")
        for result in self._deployment_results:
            color = "positive" if result.returncode == 0 else "negative"
            ui.label(
                f"{result.command.action} {result.command.target_id or ''} : code {result.returncode}"
            ).classes(f"text-{color} font-semibold")
            if result.stdout:
                ui.code(result.stdout[-8000:], language="text").classes("w-full")
            if result.stderr:
                ui.code(result.stderr[-8000:], language="text").classes("w-full text-negative")

    async def browse_box(self, template: str) -> None:
        """Valide une archive locale avant de l'enregistrer dans le scénario."""

        try:
            service = VagrantEnvironmentService(self.state.scenario)
            selected = await run.io_bound(service.choose_box_file, template)
            if selected:
                # Une archive peut être volumineuse. Le statut rend l'attente
                # visible, mais le modèle n'est modifié qu'après validation.
                self.vagrant_box_status_labels[template].text = "Validation de l'archive en cours…"
                ui.notify("Validation de la box en arrière-plan.", type="info")
                await asyncio.sleep(0)
                try:
                    provider = await run.io_bound(service.validate_box_file, selected)
                    size_gib = Path(selected).stat().st_size / (1024 ** 3)
                    self.vagrant_box_inputs[template].value = selected
                    self.state.scenario.vagrant.box_paths[template] = selected
                    self.vagrant_box_status_labels[template].text = (
                        f"✓ Box valide · {provider} · {size_gib:.2f} Gio"
                    )
                    self.state.changed()
                    ui.notify(f"Box {template} validée pour {provider}.", type="positive")
                except (EnvironmentInventoryError, OSError) as exc:
                    # Une sélection invalide ne remplace jamais un chemin déjà
                    # validé et persisté dans le scénario.
                    self.vagrant_box_status_labels[template].text = f"✗ Box invalide : {exc}"
                    ui.notify(str(exc), type="negative", multi_line=True)
        except (EnvironmentInventoryError, VmwareNetworkError, ValidationError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    async def browse_clone_directory(self) -> None:
        """Choisit le dossier des clones sans bloquer les autres clients GUI."""

        try:
            selected = await run.io_bound(VagrantEnvironmentService(self.state.scenario).choose_clone_directory)
            if selected:
                self.vagrant_clone_directory.value = selected
                self.state.scenario.vagrant.clone_directory = selected
                self.state.changed()
        except (EnvironmentInventoryError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def apply_vagrant_paths(self, *, notify: bool = True) -> None:
        """Applique les chemins à l'état mémoire; la persistance reste explicite."""

        config = self.state.scenario.vagrant
        config.executable_path = self.vagrant_executable.value or None
        config.clone_directory = self.vagrant_clone_directory.value or None
        config.bootstrap_network = self.bootstrap_network.value or None
        config.bootstrap_dhcp_enabled = bool(self.bootstrap_dhcp.value)
        config.bootstrap_validated = bool(self.bootstrap_validated.value)
        for target in self.state.scenario.targets:
            target.temporary_management.enabled = True
            target.temporary_management.vmware_network = config.bootstrap_network or ""
            target.temporary_management.assigned_address = None
        self._synchronize_mininet_internal_selection()
        if self._vmnet_records and config.bootstrap_network and config.mininet_internal_network:
            self._scenario_vmnet_plan = plan_scenario_vmnets(
                self.state.scenario,
                tuple(self._vmnet_records),
            )
        for template, field in self.vagrant_box_inputs.items():
            if field.value:
                self.state.scenario.vagrant.box_paths[template] = field.value
        self.state.changed()
        if notify:
            ui.notify("Paramètres Vagrant appliqués au scénario courant.", type="positive")

    def save_vagrant_settings(self) -> None:
        """Applique les chemins puis écrit immédiatement le scénario actif sur disque."""

        try:
            self.apply_vagrant_paths(notify=False)
            destination = self._persist_active_scenario()
            ui.notify(
                f"Chemins Vagrant enregistrés dans {destination}",
                type="positive",
                multi_line=True,
            )
        except (OSError, ValidationError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def _synchronize_mininet_internal_selection(self) -> None:
        """Persiste le VMnet et seulement le CIDR observé dans VMware."""

        config = self.state.scenario.vagrant
        selected = self.mininet_internal_network.value or None
        if _is_vmnet0(selected) or _same_vmnet_name(selected, self.bootstrap_network.value):
            raise ValueError("Le VMnet interne doit être distinct de VMnet0 et de l'amorçage")
        previous_name = config.mininet_internal_network
        previous_cidr = config.mininet_internal_cidr
        config.mininet_internal_network = selected
        record = next((item for item in self._vmnet_records if item.name == selected), None)
        if selected:
            config.mininet_internal_cidr = _resolve_internal_vmnet_cidr(
                selected,
                record,
                previous_name,
                previous_cidr,
            )
        elif not selected:
            config.mininet_internal_cidr = None
        if getattr(self, "mininet_internal_cidr_label", None) is not None:
            self.mininet_internal_cidr_label.text = (
                f"CIDR observé : {config.mininet_internal_cidr or 'non inventorié'}"
            )

    async def refresh_vagrant_inventory(self) -> None:
        """Détecte Vagrant, ses plugins et boxes dans un travail d'arrière-plan."""

        if self._vagrant_refresh_in_progress:
            return
        self._vagrant_refresh_in_progress = True
        try:
            self.apply_vagrant_paths()
            self._vagrant_inventory = await run.io_bound(VagrantEnvironmentService(self.state.scenario).inspect_vagrant)
            if self._vagrant_inventory.executable:
                self.state.scenario.vagrant.executable_path = self._vagrant_inventory.executable
            self.vagrant_status_panel.refresh()
        except (EnvironmentInventoryError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)
        finally:
            self._vagrant_refresh_in_progress = False

    async def execute_vagrant_installation(self) -> None:
        """Installe les composants officiels après jeton et laisse Windows afficher UAC."""

        if not self.vagrant_install_confirmation.value:
            ui.notify("Cochez la confirmation d'installation.", type="warning")
            return
        token = self.vagrant_install_token.value.strip().upper()
        if token != self.vagrant_install_token_value:
            ui.notify("Le jeton d'installation est incorrect.", type="negative")
            return
        ui.notify(
            "Installation Vagrant en cours; une demande UAC Windows peut apparaître.",
            type="info",
            timeout=0,
            close_button="×",
        )
        service = VagrantEnvironmentService(self.state.scenario)
        try:
            results = await run.io_bound(
                service.install_vagrant_stack,
                PROJECT_ROOT / "work" / "installers",
                token,
            )
            failures = [item for item in results if item.returncode != 0]
            if failures:
                raise EnvironmentInventoryError(
                    failures[-1].stderr.strip() or failures[-1].stdout.strip() or "Installation incomplète"
                )
            self._vagrant_inventory = await run.io_bound(service.inspect_vagrant)
            self.vagrant_status_panel.refresh()
            ui.notify("Pile Vagrant installée et réinventoriée.", type="positive")
        except EnvironmentInventoryError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def refresh_vmware_inventory(self) -> None:
        """Charge les VM enregistrées via vmrest avec les secrets conservés en mémoire."""

        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        try:
            self._vmware_vms = await run.io_bound(
                VagrantEnvironmentService(self.state.scenario).discover_vmware_vms,
                username,
                password,
            )
            self.vmware_inventory_panel.refresh()
        except EnvironmentInventoryError as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    @ui.refreshable
    def vmware_reconstruction_panel(self) -> None:
        """Affiche l'instantané global et le diff scellé sans lancer d'inspection."""

        inventory = self._vmware_network_inventory
        plan = self._network_reconstruction_plan
        if inventory is None:
            ui.label("Inventaire global des cartes non exécuté.").classes("text-warning")
            return
        ui.label(
            f"Inventaire : {len(inventory.vms)} VM · "
            f"empreinte {inventory.fingerprint[:12].upper()} · "
            f"{'complet' if inventory.complete else 'incomplet'}"
        ).classes("font-mono")
        for error in inventory.errors:
            ui.label(error).classes("text-negative")
        if plan is None:
            return
        ui.label(f"Empreinte du plan : {plan.confirmation_token}").classes("font-mono font-semibold")
        for machine in plan.machines:
            with ui.expansion(machine.machine_id, icon="lan").classes("w-full"):
                ui.label("Cartes observées qui seront retirées").classes("font-semibold")
                for adapter in machine.observed:
                    ui.code(
                        f"ethernet{adapter.vmware_adapter_index} · {adapter.vmnet} · "
                        f"{adapter.applied_mac or '<MAC absente>'}",
                        language="text",
                    ).classes("w-full")
                ui.label("Cartes attendues qui seront créées").classes("font-semibold")
                for adapter in machine.expected:
                    nature = "permanente" if adapter.permanent else "amorçage temporaire"
                    ui.code(
                        f"ethernet{adapter.vmware_adapter_index} · {adapter.vmnet} · "
                        f"{adapter.requested_mac} · {nature} · {adapter.address or 'DHCP/aucune IP statique'}",
                        language="text",
                    ).classes("w-full")
                ui.label(
                    "Restauration : copie exacte du VMX sauvegardé, uniquement VM éteinte."
                ).classes("text-grey-7")

    async def refresh_vmware_network_inventory(self) -> None:
        """Inventorie explicitement toutes les VM et persiste l'instantané normalisé."""

        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        try:
            service = VmwareNetworkInventoryService(self.state.scenario, username, password)
            snapshot = await run.io_bound(service.inspect_all)
            await run.io_bound(
                service.persist,
                snapshot,
                PROJECT_ROOT / "work" / "vmware-inventory" / f"{self.state.scenario.metadata.name}.json",
            )
            self._vmware_network_inventory = snapshot
            # Une nouvelle lecture invalide toujours le plan précédent, même
            # si l'empreinte se révèle identique après l'affichage.
            self._network_reconstruction_plan = None
            self._network_rollback = None
            self.vmware_reconstruction_panel.refresh()
            ui.notify("Inventaire global des cartes enregistré.", type="positive")
        except (VmwareNetworkError, OSError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def _static_mac_policy(self) -> StaticMacPolicy:
        """Construit la politique seulement depuis les valeurs validées du banc."""

        host = self.state.scenario.vmware
        if not host.static_mac_workstation_version or not host.static_mac_first or not host.static_mac_last:
            raise VmwareNetworkError(
                "La version VMware et la plage MAC statique validée doivent être renseignées avant le plan"
            )
        return StaticMacPolicy(
            workstation_version=host.static_mac_workstation_version,
            first_mac=host.static_mac_first,
            last_mac=host.static_mac_last,
            validated=host.static_mac_policy_validated,
            validation_source=host.static_mac_validation_source,
        )

    def preview_reserved_reconstruction(self) -> None:
        """Dérive et affiche le diff sans arrêter ni modifier une VM."""

        try:
            self.apply_vagrant_paths()
            if self._vmware_network_inventory is None:
                raise VmwareNetworkError("Inventoriez d'abord toutes les VM et toutes leurs cartes")
            if self._vmnet_inventory is None:
                raise VmwareNetworkError("Inventoriez VMnet0 avant de calculer ses adresses")
            reserved_allocations = allocate_reserved_management_addresses(
                self.state.scenario,
                self._vmnet_inventory.cidr,
                host_addresses=set(self._vmnet_inventory.host_addresses),
                occupied_addresses=set(self._vmnet_inventory.occupied_addresses),
                target_allocations={},
            )
            internal_vmnet = self.state.scenario.vagrant.mininet_internal_network
            internal_cidr = self.state.scenario.vagrant.mininet_internal_cidr
            if not internal_vmnet or internal_cidr is None:
                raise VmwareNetworkError(
                    "Inventoriez puis choisissez le VMnet interne Mininet/ONOS avant le plan"
                )
            allocate_mininet_internal_addresses(
                self.state.scenario,
                internal_cidr,
                internal_vmnet,
                is_in_use=VagrantEnvironmentService(
                    self.state.scenario
                ).address_responds_to_arp,
            )
            self._scenario_vmnet_plan = plan_scenario_vmnets(
                self.state.scenario,
                tuple(self._vmnet_records),
            )
            if self._scenario_vmnet_plan.missing_vmnets:
                raise VmwareNetworkError(
                    "Créez et relisez d'abord les VMnet dédiés manquants : "
                    + ", ".join(self._scenario_vmnet_plan.missing_vmnets)
                )
            if not self._scenario_vmnet_plan.dhcp_policy_confirmed:
                raise VmwareNetworkError(
                    "Désactivez d'abord le DHCP VMware des VMnet d'accès gérés : "
                    + ", ".join(self._scenario_vmnet_plan.dhcp_disable_vmnets)
                )
            if not self._scenario_vmnet_plan.host_isolation_confirmed:
                details = (
                    self._scenario_vmnet_plan.host_connected_vmnets
                    or self._scenario_vmnet_plan.host_connection_unknown
                    or self._scenario_vmnet_plan.required_host_disconnected
                    or self._scenario_vmnet_plan.required_host_unknown
                )
                raise VmwareNetworkError(
                    "Appliquez d'abord la politique Host Connection (No sur Mininet, Yes sur gestion) : "
                    + ", ".join(details)
                )
            policy = self._static_mac_policy()
            plan_target_interfaces(
                self.state.scenario,
                self._vmware_network_inventory,
                policy,
            )
            self._network_reconstruction_plan = build_reconstruction_plan(
                self.state.scenario,
                self._vmware_network_inventory,
                policy,
                management_addresses=reserved_allocations,
            )
            self._network_rollback = None
            self.state.changed()
            self.vmware_reconstruction_panel.refresh()
            ui.notify("Diff réseau prêt; aucune VM n'a été modifiée.", type="positive")
        except (VmwareNetworkError, ValueError) as exc:
            self._network_reconstruction_plan = None
            self.vmware_reconstruction_panel.refresh()
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def execute_reserved_reconstruction(self) -> None:
        """Sauvegarde et applique en arrière-plan après deux confirmations distinctes."""

        plan = self._network_reconstruction_plan
        inventory = self._vmware_network_inventory
        if plan is None or inventory is None:
            ui.notify("Préparez d'abord un plan depuis l'inventaire global.", type="warning")
            return
        if not self.network_reconstruction_stop_confirm.value:
            ui.notify("La confirmation d'arrêt des VM réservées manque.", type="warning")
            return
        if not self.network_reconstruction_destructive_confirm.value:
            ui.notify("La confirmation destructive dédiée manque.", type="warning")
            return
        if (self.network_reconstruction_token.value or "").strip().upper() != plan.confirmation_token:
            ui.notify("L'empreinte saisie ne correspond pas au diff affiché.", type="negative")
            return
        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        adapter = VmwareReservedAdapter(self.state.scenario, username, password, dry_run=False)

        def state_reader(vmware_id: str) -> str:
            """Relit ponctuellement l'état via vmrest sans inspection périodique."""

            machine = next(item for item in self.state.scenario.infrastructure if item.vmware_id == vmware_id)
            return adapter.power_states().get(machine.id, "unknown")

        reconstructor = VmxNetworkReconstructor(
            state_reader,
            PROJECT_ROOT / "work" / "vmware-rollback" / plan.fingerprint[:12],
        )
        try:
            # Cette action n'arrête pas implicitement les VM : elle exige qu'elles
            # aient été arrêtées par le workflow explicitement confirmé.
            rollback = await run.io_bound(reconstructor.create_backup, plan)
            self._network_rollback = rollback
            restore_token = reconstructor.restore_confirmation_token(plan)
            ui.notify(
                f"Sauvegarde créée. Jeton de restauration : {restore_token}",
                type="warning",
                timeout=0,
                close_button="×",
            )
            await run.io_bound(
                reconstructor.apply,
                plan,
                inventory,
                rollback,
                confirmation_token=plan.confirmation_token,
            )
            refreshed = await run.io_bound(
                VmwareNetworkInventoryService(self.state.scenario, username, password).inspect_all
            )
            reconcile_applied_adapters(self.state.scenario, plan, refreshed)
            if self._bootstrap_leases:
                associate_bootstrap_leases(self.state.scenario, self._bootstrap_leases)
            self._vmware_network_inventory = refreshed
            self.state.changed()
            self.vmware_reconstruction_panel.refresh()
            ui.notify("Cartes reconstruites et relues conformément au plan.", type="positive")
        except (VmwareNetworkError, httpx.HTTPError, OSError) as exc:
            ui.notify(
                f"Échec explicite : {exc}. La sauvegarde de retour est conservée.",
                type="negative",
                multi_line=True,
                timeout=0,
                close_button="×",
            )

    async def restore_reserved_networks(self) -> None:
        """Restaure seulement les VMX sauvegardés après une confirmation distincte."""

        plan = self._network_reconstruction_plan
        rollback = self._network_rollback
        if plan is None or rollback is None:
            ui.notify("Aucune sauvegarde de retour active pour ce plan.", type="warning")
            return
        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        adapter = VmwareReservedAdapter(self.state.scenario, username, password, dry_run=False)

        def state_reader(vmware_id: str) -> str:
            """Exige de nouveau poweredOff avant chaque restauration de VMX."""

            machine = next(item for item in self.state.scenario.infrastructure if item.vmware_id == vmware_id)
            return adapter.power_states().get(machine.id, "unknown")

        reconstructor = VmxNetworkReconstructor(
            state_reader,
            PROJECT_ROOT / "work" / "vmware-rollback" / plan.fingerprint[:12],
        )
        try:
            await run.io_bound(
                reconstructor.restore,
                plan,
                rollback,
                confirmation_token=(self.network_restore_token.value or "").strip().upper(),
            )
            ui.notify("Configuration réseau VMX restaurée depuis la sauvegarde.", type="positive")
        except (VmwareNetworkError, httpx.HTTPError, OSError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def refresh_vmnet_records(self) -> None:
        """Inventorie les VMnet sans créer de réseau ni modifier leur DHCP."""

        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        try:
            self._vmnet_records = await run.io_bound(
                VagrantEnvironmentService(self.state.scenario).inspect_vmnets,
                username,
                password,
            )
            self._scenario_vmnet_plan = None
            self.vmnet_inventory_panel.refresh()
            scenario_used = {
                interface.vmware_network.casefold()
                for target in self.state.scenario.targets
                for interface in target.interfaces
                if interface.purpose == InterfacePurpose.SCENARIO and interface.vmware_network
            }
            choices = [
                record.name
                for record in self._vmnet_records
                if not _is_vmnet0(record.name) and record.network_type.casefold() == "hostonly"
                and record.name.casefold() not in scenario_used
            ]
            # Actualiser explicitement le composant évite de reconstruire tout
            # l'onglet et conserve les autres saisies déjà effectuées.
            self.bootstrap_network.options = choices
            if self.bootstrap_network.value not in choices:
                self.bootstrap_network.value = None
            self.bootstrap_network.update()
            internal_choices = [
                record.name
                for record in self._vmnet_records
                if not _is_vmnet0(record.name)
                and not _same_vmnet_name(record.name, self.bootstrap_network.value)
                and record.network_type.casefold() == "hostonly"
                and (
                    record.cidr is not None
                    or (
                        _same_vmnet_name(
                            record.name,
                            self.state.scenario.vagrant.mininet_internal_network,
                        )
                        and self.state.scenario.vagrant.mininet_internal_cidr is not None
                    )
                )
            ]
            self.mininet_internal_network.options = internal_choices
            if self.mininet_internal_network.value not in internal_choices:
                # Un choix implicite peut réutiliser l'amorçage après une
                # actualisation. L'utilisateur doit sélectionner explicitement
                # un autre VMnet si la valeur enregistrée n'est plus admissible.
                self.mininet_internal_network.value = None
            self.mininet_internal_network.update()
            self._synchronize_mininet_internal_selection()
            if self.bootstrap_network.value and self.mininet_internal_network.value:
                self._scenario_vmnet_plan = plan_scenario_vmnets(
                    self.state.scenario,
                    tuple(self._vmnet_records),
                )
            self.vmnet_mapping_panel.refresh()
            ui.notify(
                "VMnet host-only disponibles : " + (", ".join(choices) if choices else "aucun"),
                type="positive" if choices else "warning",
            )
        except (EnvironmentInventoryError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    async def refresh_bootstrap_leases(self) -> None:
        """Lit les baux et associe seulement les MAC déjà confirmées aux VM."""

        self.apply_vagrant_paths()
        vmnet = self.state.scenario.vagrant.bootstrap_network
        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        try:
            self._bootstrap_leases = await run.io_bound(
                VagrantEnvironmentService(self.state.scenario).inspect_dhcp_leases,
                vmnet,
                username,
                password,
            )
            associations = associate_bootstrap_leases(
                self.state.scenario,
                self._bootstrap_leases,
            )
            matched = [f"{machine_id}={address}" for machine_id, address in associations.items()]
            self.state.changed()
            self.vmnet_inventory_panel.refresh()
            ui.notify(
                "Adresses associées : "
                + (", ".join(matched) if matched else "aucune association complète (MAC, bail et accès invité)"),
                type="positive" if matched else "warning",
            )
        except (EnvironmentInventoryError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def save_reserved_vm_associations(self) -> None:
        """Enregistre en une fois toutes les associations choisies par rôle."""

        assignments = {
            machine_id: selector.value
            for machine_id, selector in self._reserved_vm_selects.items()
        }
        try:
            associate_reserved_vm_roles(
                self.state.scenario,
                tuple(self._vmware_vms),
                assignments,
            )
            # Un changement d'identité invalide l'inventaire de cartes et tout
            # plan destructif préparé avec les anciennes associations.
            self._vmware_network_inventory = None
            self._network_reconstruction_plan = None
            self._network_rollback = None
            self.state.changed()
            self.vmware_inventory_panel.refresh()
            self.vmware_reconstruction_panel.refresh()
            ui.notify("Toutes les VM réservées sont associées de façon unique.", type="positive")
        except EnvironmentInventoryError as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    async def preview_management_allocation(self) -> None:
        """Calcule sur une copie afin que l'utilisateur puisse refuser la proposition."""

        try:
            service = VagrantEnvironmentService(self.state.scenario)
            inventory = await run.io_bound(service.inspect_vmnet0)
            if inventory.dhcp_enabled:
                raise EnvironmentInventoryError("L'adaptateur Windows VMnet0 ne doit pas utiliser DHCP")
            scenario_copy = self.state.scenario.model_copy(deep=True)
            allocations = await run.io_bound(
                allocate_reserved_management_addresses,
                scenario_copy,
                inventory.cidr,
                host_addresses=set(inventory.host_addresses),
                occupied_addresses=set(inventory.occupied_addresses),
                target_allocations={},
                is_in_use=service.address_responds_to_arp,
            )
            self._vmnet_inventory = inventory
            self._allocation_preview = {machine_id: str(value) for machine_id, value in allocations.items()}
            self._allocation_context = self._current_allocation_context(str(inventory.cidr))
            self.management_allocation_panel.refresh()
        except (EnvironmentInventoryError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def approve_management_allocation(self) -> None:
        """Applique la proposition inchangée au scénario et au journal local."""

        if not self._vmnet_inventory or not self._allocation_preview:
            ui.notify("Calculez d'abord une proposition.", type="warning")
            return
        if self._allocation_context != self._current_allocation_context(str(self._vmnet_inventory.cidr)):
            ui.notify("Le scénario a changé; recalculez la proposition d'adresses.", type="warning")
            return
        from ipaddress import ip_interface  # Import local pour garder le haut du fichier centré sur l'UI.

        allocations = {machine_id: ip_interface(value) for machine_id, value in self._allocation_preview.items()}
        for machine in self.state.scenario.infrastructure:
            if machine.id in allocations:
                machine.management_ip = str(allocations[machine.id].ip)
                machine.management_ip_confirmed = True
        state_path = PROJECT_ROOT / "work" / f"{self.state.scenario.metadata.name}.yml"
        self.state.changed()
        ui.notify("Adresses de management appliquées au scénario; enregistrez le YAML pour les conserver.", type="positive", multi_line=True)

    def _current_allocation_context(self, cidr: str) -> tuple:
        """Lie une proposition aux cibles et réservations qui l'ont produite."""

        targets = ()
        infrastructure = tuple(
            sorted(
                machine.management_ip
                for machine in self.state.scenario.infrastructure
                if machine.management_ip_confirmed and machine.management_ip
            )
        )
        reservations = tuple(
            sorted(str(address) for address in self.state.scenario.vagrant.reserved_management_addresses)
        )
        return cidr, targets, infrastructure, reservations

    async def prepare_vagrant_plan(self) -> None:
        """Génère le fichier et l'empreinte seulement après les prérequis locaux."""

        try:
            self.apply_vagrant_paths()
            errors = await run.io_bound(self._vagrant_preflight_errors)
            if errors:
                raise VagrantSafetyError("\n".join(errors))
            workspace = self._vagrant_workspace()
            vagrantfile = render_vagrantfile(self.state.scenario, workspace / "Vagrantfile")
            executable = self.state.scenario.vagrant.executable_path or "vagrant"
            installed_boxes = {
                line.split(" ", 1)[0]
                for line in (self._vagrant_inventory.boxes if self._vagrant_inventory else ())
            }
            self._vagrant_commands = build_vagrant_commands(
                self.state.scenario,
                executable,
                installed_boxes=installed_boxes,
            )
            self._vagrant_token = command_confirmation_token(self._vagrant_commands)
            self._vagrantfile_text = vagrantfile.read_text(encoding="utf-8")
            self._vagrant_plan_context = self.state.scenario.model_dump_json()
            self._vagrant_box_hashes = await run.io_bound(self._current_box_hashes)
            self._deployment_results = []
            self.vagrant_plan_panel.refresh()
        except (OSError, VagrantSafetyError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def execute_vagrant_plan(self) -> None:
        """Exécute en arrière-plan uniquement le plan dont le jeton a été retapé."""

        if not getattr(self, "vagrant_execution_confirmation", None) or not self.vagrant_execution_confirmation.value:
            ui.notify("Cochez la confirmation après lecture du plan.", type="warning")
            return
        if self.vagrant_execution_token.value.strip().upper() != self._vagrant_token:
            ui.notify("Le jeton ne correspond pas au plan affiché.", type="negative")
            return
        if self._vagrant_plan_context != self.state.scenario.model_dump_json():
            ui.notify("Le scénario a changé; préparez et relisez un nouveau plan.", type="warning")
            return
        current_hashes = await run.io_bound(self._current_box_hashes)
        if current_hashes != self._vagrant_box_hashes:
            ui.notify("Au moins une box a changé depuis la préparation du plan.", type="negative")
            return
        errors = await run.io_bound(self._vagrant_preflight_errors, require_inventory=True)
        if errors:
            ui.notify(
                "\n".join(errors),
                type="negative",
                multi_line=True,
                timeout=0,
                close_button="×",
            )
            return
        workspace = self._vagrant_workspace()
        adapter = VagrantTargetAdapter(self.state.scenario, workspace, dry_run=False)
        try:
            queue: asyncio.Queue = asyncio.Queue()
            loop = asyncio.get_running_loop()

            def report(result) -> None:
                """Transfère un résultat du thread Vagrant vers la boucle NiceGUI."""

                loop.call_soon_threadsafe(queue.put_nowait, result)

            execution = asyncio.create_task(
                run.io_bound(
                    adapter.execute,
                    self._vagrant_commands,
                    confirmation_token=self._vagrant_token,
                    progress_callback=report,
                )
            )
            self._deployment_results = []
            while not execution.done() or not queue.empty():
                try:
                    result = await asyncio.wait_for(queue.get(), timeout=0.5)
                    self._deployment_results.append(result)
                    self.vagrant_plan_panel.refresh()
                except TimeoutError:
                    # Ce court timeout ne lance aucune inspection : il permet
                    # seulement à la page de rester réactive pendant la commande.
                    continue
            completed_results = await execution
            if len(self._deployment_results) != len(completed_results):
                self._deployment_results = completed_results
            self._persist_vagrant_results(workspace)
            await self._reread_target_macs()
            self.vagrant_plan_panel.refresh()
        except (
            OSError,
            subprocess.SubprocessError,
            SecretStoreError,
            VagrantSafetyError,
            VmwareNetworkError,
        ) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def _persist_vagrant_results(self, workspace: Path) -> None:
        """Conserve l'état de chaque cible et l'identifiant réel retourné par Vagrant."""

        state_path = PROJECT_ROOT / "work" / "deployments" / self.state.scenario.metadata.name / "state.json"
        store = DeploymentStateStore(state_path)
        deployment = store.load(self.state.scenario.metadata.name)
        deployment.vagrant_working_directory = str(workspace.resolve())
        for result in self._deployment_results:
            target_id = result.command.target_id
            if not target_id:
                continue
            target_state = deployment.targets.setdefault(
                target_id,
                TargetDeploymentState(target_id=target_id),
            )
            if result.returncode not in {None, 0}:
                target_state.phase = TargetDeploymentPhase.FAILED
                target_state.last_error = (result.stderr or result.stdout)[-8000:]
                continue
            if result.command.action == "up":
                target_state.phase = TargetDeploymentPhase.RUNNING
                identity_path = workspace / ".vagrant" / "machines" / target_id / "vmware_desktop" / "id"
                if identity_path.is_file():
                    identity = identity_path.read_text(encoding="utf-8").strip()
                    target_state.vagrant_machine_id = identity
                    if identity.casefold().endswith(".vmx"):
                        target_state.vmx_path = identity
                        target = next(item for item in self.state.scenario.targets if item.id == target_id)
                        target.vmx_path = identity
        store.save(deployment)
        self.state.changed()

    async def _reread_target_macs(self) -> None:
        """Relit VMware après Vagrant et rattache chaque MAC à son VMX réel."""

        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        if not username or not password:
            credentials = self._secret_store.load(self.state.scenario.metadata.name)
            username = credentials.get("username", "")
            password = credentials.get("password", "")
        if not username or not password:
            raise VmwareNetworkError("Les identifiants VMREST sont requis pour relire les MAC finales")
        snapshot = await run.io_bound(
            VmwareNetworkInventoryService(self.state.scenario, username, password).inspect_all
        )
        observed_by_vmx = {record.vmx_path: record.adapters for record in snapshot.vms}
        apply_verified_target_macs(self.state.scenario, observed_by_vmx)
        self._vmware_network_inventory = snapshot
        self.state.changed()

    def _vagrant_preflight_errors(self, *, require_inventory: bool = False) -> list[str]:
        """Bloque le réel sans box, mapping réseau, accès invité ou fournisseur."""

        scenario = self.state.scenario
        errors: list[str] = []
        checked_templates: set[str] = set()
        if require_inventory and not scenario.vagrant.bootstrap_validated:
            errors.append(
                "L'amorçage par le VMnet host-only DHCP temporaire n'a pas encore été validé avec les boxes réelles."
            )
        if require_inventory and not scenario.vagrant.guest_network_commands_validated:
            errors.append("Les commandes invitées IP/MAC/routes et de désactivation DNS ne sont pas encore validées.")
        if scenario.mininet_instances:
            if self._scenario_vmnet_plan is None:
                errors.append(
                    "Calculez et appliquez le plan VMnet avant l'exécution : les connexions hôte Mininet ne sont pas vérifiées."
                )
            elif not self._scenario_vmnet_plan.host_isolation_confirmed:
                errors.append(
                    "La politique Host Connection n'est pas confirmée : No sur les VMnet Mininet, Yes uniquement sur VMnet0 et l'amorçage."
                )
            elif not self._scenario_vmnet_plan.dhcp_policy_confirmed:
                errors.append(
                    "Le DHCP VMware reste actif sur des VMnet d'accès gérés : "
                    + ", ".join(self._scenario_vmnet_plan.dhcp_disable_vmnets)
                )
        if not scenario.vagrant.clone_directory or not Path(scenario.vagrant.clone_directory).is_dir():
            errors.append("Choisissez un répertoire existant pour les nouvelles VM.")
        for target in scenario.targets:
            box_path = scenario.vagrant.box_paths.get(target.template)
            if not box_path or not Path(box_path).is_file():
                errors.append(f"Box absente pour {target.template}.")
            elif target.template not in checked_templates:
                try:
                    VagrantEnvironmentService.validate_box_file(box_path)
                except EnvironmentInventoryError as exc:
                    errors.append(f"{target.template} : {exc}")
            checked_templates.add(target.template)
            if not scenario.vagrant.bootstrap_network:
                errors.append(f"VMnet d'amorçage non choisi pour {target.id}.")
            if not target.guest_access:
                errors.append(f"Accès SSH/WinRM non configuré pour {target.id}.")
            for interface in target.interfaces:
                if interface.purpose == InterfacePurpose.SCENARIO and not interface.vmware_network:
                    errors.append(f"VMnet Mininet non choisi pour {target.id}/{interface.name}.")
        for machine in scenario.infrastructure:
            if not machine.vmware_id:
                errors.append(f"VM VMware réservée non associée : {machine.id}.")
            if not machine.management_ip:
                errors.append(f"IPv4 VMnet0 non allouée pour la VM réservée {machine.id}.")
        if require_inventory and (not self._vagrant_inventory or not self._vagrant_inventory.provider_available):
            errors.append("Vagrant, Vagrant VMware Utility et vmware_desktop doivent être vérifiés avant l'exécution.")
        if self._vmnet_inventory and self._vmnet_inventory.dhcp_enabled:
            errors.append("L'adaptateur Windows VMnet0 utilise encore DHCP.")
        return list(dict.fromkeys(errors))

    def _vagrant_workspace(self) -> Path:
        """Refuse qu'un chemin YAML fasse écrire le Vagrantfile hors du projet."""

        workspace = (
            PROJECT_ROOT
            / self.state.scenario.vagrant.workspace_directory
            / self.state.scenario.metadata.name
        ).resolve()
        if not workspace.is_relative_to(PROJECT_ROOT.resolve()):
            raise VagrantSafetyError("Le répertoire de travail Vagrant doit rester dans le projet")
        return workspace

    @staticmethod
    def _sha256_file(path: Path) -> str:
        """Lie le plan au contenu réel de chaque archive sans la charger en mémoire."""

        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _current_box_hashes(self) -> dict[str, str]:
        """Calcule hors UI les empreintes des seules boxes utilisées par les cibles."""

        templates = {target.template for target in self.state.scenario.targets}
        return {
            template: self._sha256_file(Path(path))
            for template, path in self.state.scenario.vagrant.box_paths.items()
            if template in templates
        }
    # endregion

    @ui.refreshable
    def host_status_panel(self) -> None:
        """Affiche l'historique persistant, distinct des inspections temps réel ci-dessous."""

        status = self.state.scenario.vmware.setup_status
        color = "positive" if status.state.value in {"ready", "running"} else "warning"
        with ui.card().classes("w-full"):
            ui.label(f"État : {status.state.value}").classes(f"text-{color} font-semibold")
            ui.label(status.last_message)
            ui.label(f"SSH={status.ssh_configured} · certificat={status.certificate_generated} · identifiants={status.credentials_configured} · vmrest={status.vmrest_running}").classes("text-grey-7")
            if status.last_checked_at:
                ui.label(f"Dernière mise à jour : {status.last_checked_at}").classes("text-grey-7 text-sm")
            if status.certificate_path:
                ui.label(f"Certificat : {status.certificate_path}").classes("text-sm font-mono")

    @ui.refreshable
    def ssh_runtime_panel(self) -> None:
        """Affiche le dernier état SSH collecté hors de la boucle graphique."""

        runtime = self._sshd_runtime
        if runtime is None:
            with ui.card().classes("w-full"):
                ui.label("Service OpenSSH Server (sshd)").classes("font-semibold")
                ui.label("Etat non encore vérifié. Cliquez sur Actualiser maintenant.").classes("text-grey-7")
            return
        color = "positive" if runtime.running else "negative" if not runtime.installed else "warning"
        icon = "check_circle" if runtime.running else "error"
        with ui.card().classes("w-full"):
            with ui.row().classes("w-full items-center"):
                ui.icon(icon, color=color).classes("text-2xl")
                with ui.column().classes("gap-0"):
                    ui.label("Service OpenSSH Server (sshd)").classes("font-semibold")
                    ui.label(runtime.message).classes(f"text-{color}")
                ui.space()
                ui.badge("INSTALLÉ" if runtime.installed else "ABSENT", color=color)
                ui.badge(runtime.service_status.upper(), color=color)
            ui.label(f"Démarrage : {runtime.start_type} · sshd_config : {'présent' if runtime.config_exists else 'absent'}").classes("text-grey-7")
            if not runtime.installed:
                ui.button("Installer OpenSSH Server", icon="download", on_click=self.open_openssh_install_dialog, color="warning")

    @ui.refreshable
    def vmrest_runtime_panel(self) -> None:
        """Affiche le dernier état vmrest collecté hors de la boucle graphique."""

        runtime = self._vmrest_runtime
        if runtime is None:
            with ui.card().classes("w-full"):
                ui.label("VMware REST API (vmrest)").classes("font-semibold")
                ui.label("Etat non encore vérifié. Cliquez sur Actualiser maintenant.").classes("text-grey-7")
            return
        color = "positive" if runtime.running else "negative"
        with ui.card().classes("w-full"):
            with ui.row().classes("w-full items-center"):
                ui.icon("play_circle" if runtime.running else "stop_circle", color=color).classes("text-2xl")
                with ui.column().classes("gap-0"):
                    ui.label("VMware REST API (vmrest)").classes("font-semibold")
                    ui.label(runtime.message).classes(f"text-{color}")
                ui.space()
                ui.badge("RUNNING" if runtime.running else "STOPPED", color=color)
            with ui.row().classes("gap-2"):
                ui.badge(f"EXE {'OK' if runtime.executable_exists else 'ABSENT'}", color="positive" if runtime.executable_exists else "negative")
                ui.badge(f"PROCESSUS {','.join(map(str, runtime.process_ids)) or 'ABSENT'}", color="positive" if runtime.process_ids else "negative")
                ui.badge(f"PORT {self.state.scenario.vmware.api_port} {'OUVERT' if runtime.port_listening else 'FERMÉ'}", color="positive" if runtime.port_listening else "negative")
                ui.badge(f"HTTP {runtime.http_status or '—'}", color="positive" if runtime.api_reachable else "negative")

    @ui.refreshable
    def vmrest_firewall_panel(self) -> None:
        """Affiche le dernier état du pare-feu collecté hors de la boucle graphique."""

        runtime = self._firewall_runtime
        if runtime is None:
            with ui.card().classes("w-full"):
                ui.label(f"Pare-feu Windows — {self.state.scenario.vmware.vmrest_firewall_rule_name}").classes("font-semibold")
                ui.label("Etat non encore vérifié. Cliquez sur Actualiser.").classes("text-grey-7")
                ui.button("Actualiser", icon="refresh", on_click=self.refresh_host_runtime_panels).props("outline")
            return
        color = "positive" if runtime.enabled and runtime.matches_configuration else "warning" if runtime.exists else "negative"
        with ui.card().classes("w-full"):
            with ui.row().classes("w-full items-center"):
                ui.icon("shield" if runtime.enabled else "gpp_maybe", color=color).classes("text-2xl")
                with ui.column().classes("gap-0"):
                    ui.label(f"Pare-feu Windows — {self.state.scenario.vmware.vmrest_firewall_rule_name}").classes("font-semibold")
                    ui.label(runtime.message).classes(f"text-{color}")
                ui.space()
                ui.badge("ACTIVE" if runtime.enabled else "INACTIVE", color=color)
            if runtime.exists:
                ui.label(
                    f"Direction={runtime.direction or '—'} · action={runtime.action or '—'} · "
                    f"protocole={runtime.protocol or '—'} · port={runtime.local_port or '—'}"
                ).classes("text-grey-7")
            with ui.row().classes("gap-2"):
                ui.button("Activer / corriger la règle", icon="lock_open", on_click=self.execute_vmrest_firewall_enable, color="positive")
                ui.button("Désactiver la règle", icon="block", on_click=self.execute_vmrest_firewall_disable, color="negative").props("outline")
                ui.button("Actualiser", icon="refresh", on_click=self.refresh_host_runtime_panels).props("flat")

    @ui.refreshable
    def host_plan_panel(self) -> None:
        """Rend les commandes exactes à relire avant de cocher la confirmation."""

        service = HostSetupService(self.state.scenario.vmware)
        with ui.expansion("Prévisualiser toutes les commandes", icon="terminal").classes("w-full"):
            for plan in service.command_plans():
                ui.label(f"{plan.section}{' — administrateur requis' if plan.requires_admin else ''}").classes("font-semibold")
                ui.code("\n".join(plan.commands), language="powershell").classes("w-full")
        if self.state.scenario.vmware.allow_legacy_ssh_rsa:
            ui.label("Attention : ssh-rsa/SHA-1 est ancien. Ne l'activez que pour le client Ubuntu hérité et retirez-le après migration.").classes("text-negative font-semibold")

    def apply_host_fields(self) -> None:
        """Copie les champs non secrets vers le modèle et actualise le plan."""

        config = self.state.scenario.vmware
        config.external_ip = self.host_ip.value
        config.api_port = int(self.host_port.value)
        config.ssh_user = self.host_ssh_user.value
        config.ssh_authorized_public_key_path = self.host_public_key_path.value or None
        config.workstation_directory = self.host_workstation.value
        config.openssl_executable = self.host_openssl.value
        config.openssl_config_path = self.host_openssl_config.value or None
        config.certificate_directory = self.host_certificate_directory.value
        config.setup_status.certificate_path = self.host_vmrest_certificate.value or None
        config.setup_status.private_key_path = self.host_vmrest_private_key.value or None
        self._update_vmrest_file_readiness()
        config.allow_legacy_ssh_rsa = bool(self.host_legacy_rsa.value)
        config.static_mac_workstation_version = self.host_mac_version.value or None
        config.static_mac_first = self.host_mac_first.value or None
        config.static_mac_last = self.host_mac_last.value or None
        config.static_mac_validation_source = self.host_mac_source.value or None
        config.static_mac_policy_validated = bool(self.host_mac_validated.value)
        if self.host_api_user.value and self.host_api_password.value:
            try:
                self._secret_store.save(
                    self.state.scenario.metadata.name,
                    self.host_api_user.value,
                    self.host_api_password.value,
                )
            except (OSError, SecretStoreError) as exc:
                ui.notify(str(exc), type="negative", multi_line=True)
                return
        self.state.changed()
        ui.notify("Paramètres de l'hôte appliqués.", type="positive")

    def save_vmrest_credentials(self) -> None:
        """Protège les identifiants avec DPAPI, hors du fichier de scénario."""

        try:
            destination = self._secret_store.save(
                self.state.scenario.metadata.name,
                self.host_api_user.value or "",
                self.host_api_password.value or "",
            )
            ui.notify(f"Identifiants VMREST chiffrés dans {destination}", type="positive", multi_line=True)
        except (OSError, SecretStoreError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    async def browse_openssl(self) -> None:
        """Ouvre la fenêtre native Windows sans bloquer les autres clients NiceGUI."""

        try:
            selected = await run.io_bound(HostSetupService(self.state.scenario.vmware).choose_openssl_executable)
            if selected:
                self.host_openssl.value = selected
                self.state.scenario.vmware.openssl_executable = selected
                self.state.changed()
                ui.notify(f"OpenSSL sélectionné : {selected}", type="positive", multi_line=True)
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def browse_openssl_config(self) -> None:
        """Choisit et enregistre le fichier openssl.cnf fourni par l'utilisateur."""

        service = HostSetupService(self.state.scenario.vmware)
        try:
            selected = await run.io_bound(service.choose_openssl_config_file)
            if selected:
                self.host_openssl_config.value = selected
                self.state.scenario.vmware.openssl_config_path = selected
                self.state.changed()
                ui.notify(
                    f"Configuration OpenSSL sélectionnée : {selected}",
                    type="positive",
                    multi_line=True,
                )
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def browse_public_key(self) -> None:
        """Choisit un fichier .pub, en extrait la clé et en affiche un aperçu non modifiable."""

        service = HostSetupService(self.state.scenario.vmware)
        try:
            selected = await run.io_bound(service.choose_public_key_file)
            if selected:
                self.host_public_key_path.value = selected.path
                self.host_public_key_preview.value = selected.key
                self.state.scenario.vmware.ssh_authorized_public_key_path = selected.path
                self.state.changed()
                ui.notify(f"Clé publique chargée depuis {selected.path}", type="positive", multi_line=True)
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def browse_vmrest_certificate(self) -> None:
        """Choisit, valide et enregistre immédiatement le certificat TLS de vmrest."""

        service = HostSetupService(self.state.scenario.vmware)
        try:
            selected = await run.io_bound(service.choose_vmrest_certificate_file)
            if selected:
                self.host_vmrest_certificate.value = selected
                self.state.scenario.vmware.setup_status.certificate_path = selected
                self._update_vmrest_file_readiness()
                self.state.changed()
                ui.notify(f"Certificat vmrest enregistré : {selected}", type="positive", multi_line=True)
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def browse_vmrest_private_key(self) -> None:
        """Choisit, valide et enregistre immédiatement la clé privée TLS de vmrest."""

        service = HostSetupService(self.state.scenario.vmware)
        try:
            selected = await run.io_bound(service.choose_vmrest_private_key_file)
            if selected:
                self.host_vmrest_private_key.value = selected
                self.state.scenario.vmware.setup_status.private_key_path = selected
                self._update_vmrest_file_readiness()
                self.state.changed()
                ui.notify(f"Clé privée vmrest enregistrée : {selected}", type="positive", multi_line=True)
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def _update_vmrest_file_readiness(self) -> None:
        """Marque les fichiers TLS prêts seulement lorsque les deux chemins existent."""

        status = self.state.scenario.vmware.setup_status
        status.certificate_generated = bool(
            status.certificate_path
            and status.private_key_path
            and Path(status.certificate_path).is_file()
            and Path(status.private_key_path).is_file()
        )

    def _confirmed_host_service(self) -> HostSetupService | None:
        """Retourne le service uniquement après confirmation explicite de l'utilisateur."""

        if not self.host_confirmation.value:
            ui.notify("Relisez le plan puis cochez la confirmation.", type="warning")
            return None
        self.apply_host_fields()
        return HostSetupService(self.state.scenario.vmware)

    async def _run_host_action(
        self,
        action: Callable[[HostSetupService], str],
        *,
        uac_expected: bool = False,
        interactive_console_expected: bool = False,
    ) -> None:
        """Exécute hors de la boucle UI, annonce UAC et actualise les preuves réelles."""

        service = self._confirmed_host_service()
        if service is None:
            return
        if uac_expected:
            ui.notify(
                "Windows va demander l'autorisation administrateur (UAC).",
                type="info",
                timeout=0,
                close_button="×",
            )
        if interactive_console_expected:
            ui.notify(
                "Une console Windows temporaire va s'ouvrir. Terminez la saisie dans cette fenêtre.",
                type="info",
                timeout=0,
                close_button="×",
            )
        try:
            message = await run.io_bound(action, service)
            ui.notify(message, type="positive", multi_line=True)
            self.state.changed()
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")
        finally:
            await self.refresh_host_runtime_panels()

    async def open_openssh_install_dialog(self) -> None:
        """Inspecte SSH hors de l'UI puis demande confirmation avant installation et UAC."""

        runtime = await run.io_bound(HostSetupService(self.state.scenario.vmware).inspect_sshd)
        if runtime.installed:
            ui.notify(runtime.message, type="info")
            return
        with ui.dialog() as dialog, ui.card().classes("w-[620px]"):
            ui.label("Installer OpenSSH Server ?").classes("text-lg font-semibold")
            ui.label("Windows installera la fonctionnalité OpenSSH Server, placera sshd en démarrage automatique et vérifiera la règle de pare-feu du port 22.")
            ui.label("Une fenêtre UAC apparaîtra après votre confirmation.").classes("text-warning font-semibold")

            async def confirm_installation() -> None:
                dialog.close()
                await self._run_host_action(lambda service: service.install_openssh_server(), uac_expected=True)

            with ui.row().classes("w-full justify-end"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Confirmer et demander UAC", icon="admin_panel_settings", on_click=confirm_installation, color="warning")
        dialog.open()

    async def execute_ssh_setup(self) -> None:
        """Relit le fichier .pub choisi puis déclenche la configuration OpenSSH confirmée."""

        await self._run_host_action(
            lambda service: service.configure_ssh_from_file(self.host_public_key_path.value),
            uac_expected=True,
        )

    async def execute_certificate_setup(self) -> None:
        """Déclenche la génération OpenSSL confirmée."""

        await self._run_host_action(lambda service: service.generate_certificate())
        # La génération modifie le modèle; les champs sont remis en phase sans reconstruire l'onglet.
        status = self.state.scenario.vmware.setup_status
        self.host_vmrest_certificate.value = status.certificate_path or ""
        self.host_vmrest_private_key.value = status.private_key_path or ""

    async def execute_vmrest_firewall_enable(self) -> None:
        """Demande confirmation puis UAC avant de créer, activer ou corriger la règle."""

        await self._run_host_action(lambda service: service.enable_vmrest_firewall(), uac_expected=True)

    async def execute_vmrest_firewall_disable(self) -> None:
        """Demande confirmation puis UAC avant de désactiver la règle sans la supprimer."""

        await self._run_host_action(lambda service: service.disable_vmrest_firewall(), uac_expected=True)

    async def execute_vmrest_credentials(self) -> None:
        """Ouvre la saisie interactive exigée par vmrest sans bloquer NiceGUI."""

        await self._run_host_action(
            lambda service: service.configure_vmrest_credentials(),
            interactive_console_expected=True,
        )

    async def execute_vmrest_start(self) -> None:
        """Démarre le serveur vmrest après ses prérequis."""

        ui.notify(
            "Windows demandera maintenant UAC pour démarrer vmrest en administrateur.",
            type="info",
        )
        await self._run_host_action(lambda service: service.start_vmrest(self.host_api_user.value, self.host_api_password.value))

    async def execute_vmrest_stop(self) -> None:
        """Arrête vmrest et laisse le service demander UAC uniquement si Windows l'exige."""

        await self._run_host_action(lambda service: service.stop_vmrest())

    async def check_vmrest_status(self) -> None:
        """Teste l'API avec les identifiants actuellement saisis."""

        service = HostSetupService(self.state.scenario.vmware)
        try:
            message = await run.io_bound(service.check_vmrest, self.host_api_user.value, self.host_api_password.value)
            ui.notify(message, type="positive")
            self.state.changed()
        except HostSetupError as exc:
            ui.notify(str(exc), type="negative", multi_line=True)
        finally:
            await self.refresh_host_runtime_panels()

    async def refresh_host_runtime_panels(self) -> None:
        """Inspecte Windows dans un thread puis redessine rapidement les cartes en cache."""

        # Empêche un double-clic de lancer plusieurs PowerShell concurrents.
        if self._host_refresh_in_progress:
            return
        self._host_refresh_in_progress = True
        service = HostSetupService(self.state.scenario.vmware)
        username = getattr(getattr(self, "host_api_user", None), "value", "") or ""
        password = getattr(getattr(self, "host_api_password", None), "value", "") or ""
        try:
            ui.notify("Actualisation de l'état de l'hôte…", type="info")

            def inspect_all() -> tuple:
                """Regroupe les trois inspections lentes dans un unique travail d'arrière-plan."""

                return (
                    service.inspect_sshd(),
                    service.inspect_vmrest(username, password),
                    service.inspect_vmrest_firewall(),
                )

            self._sshd_runtime, self._vmrest_runtime, self._firewall_runtime = await run.io_bound(inspect_all)
        finally:
            self._host_refresh_in_progress = False

        self.host_status_panel.refresh()
        self.ssh_runtime_panel.refresh()
        self.vmrest_runtime_panel.refresh()
        self.vmrest_firewall_panel.refresh()
    # endregion

    # region Étape 5 — contrôle manuel du banc
    @ui.refreshable
    def _build_lab_control_step(self) -> None:
        """Ajoute les commandes, pings, transferts et barrières de snapshot."""

        ui.label("Contrôle manuel après déploiement").classes("text-xl font-semibold")
        ui.label(
            "Les terminaux sont ouverts dans la session graphique des VM. "
            "Chaque mutation doit être prévisualisée et confirmée."
        ).classes("text-grey-7")
        machine_ids = [
            machine.id
            for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets]
        ]
        with ui.tabs().classes("w-full") as tabs:
            command_tab = ui.tab("Commandes", icon="terminal")
            ping_tab = ui.tab("Pings", icon="network_ping")
            files_tab = ui.tab("Fichiers", icon="upload_file")
            isolation_tab = ui.tab("Isolation et snapshots", icon="security")

        with ui.tab_panels(tabs, value=command_tab).classes("w-full"):
            with ui.tab_panel(command_tab):
                self.lab_machine = ui.select(machine_ids, label="VM", value=machine_ids[0] if machine_ids else None).classes("w-full")
                self.lab_command = ui.textarea("Commande à exécuter dans la VM").props("autogrow").classes("w-full font-mono")
                self.lab_elevated = ui.checkbox("Exécuter en mode administrateur si la VM le permet")
                with ui.row().classes("gap-2"):
                    ui.button("Prévisualiser la commande", icon="preview", on_click=self.preview_guest_command).props("outline")
                    ui.button("Prévisualiser toute la configuration réseau", icon="lan", on_click=self.preview_guest_network).props("outline")

            with ui.tab_panel(ping_tab):
                with ui.row().classes("w-full"):
                    self.ping_source = ui.select(machine_ids, label="VM source").classes("flex-1")
                    self.ping_destination = ui.select(machine_ids, label="VM destination").classes("flex-1")
                ui.button("Choisir le chemin et prévisualiser", icon="network_ping", on_click=self.preview_ping).props("outline")
                ui.label("Le ping continu apparaîtra dans un terminal de la VM source.").classes("text-grey-7")

            with ui.tab_panel(files_tab):
                ui.label(
                    "Les sources locales et destinations invitées sont définies dans la configuration des VM."
                ).classes("text-grey-7")
                ui.button("Prévisualiser tous les transferts", icon="preview", on_click=self.preview_guest_files).props("outline")

            with ui.tab_panel(isolation_tab):
                isolation_networks = sorted(
                    {
                        item.network
                        for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets]
                        for item in machine.isolation_interfaces
                        if item.disable_before_snapshot
                    }
                )
                self.isolation_network = ui.select(
                    isolation_networks,
                    label="Interface temporaire à désactiver sur toutes les VM concernées",
                ).classes("w-full")
                ui.button("Prévisualiser l'isolation", icon="preview", on_click=self.preview_isolation).props("outline")
                ui.button("Vérifier maintenant l'injoignabilité", icon="verified_user", on_click=self.verify_air_gap_now).props("outline")
                self.bench_ready = ui.checkbox("Je confirme que l'état du banc est satisfaisant")
                self.pings_active = ui.checkbox("Je confirme que les terminaux de ping attendus sont actifs")
                ui.button("Enregistrer ces confirmations", icon="fact_check", on_click=self.confirm_lab_state).props("outline")
                ui.button(
                    "Vérifier les VM démarrées",
                    icon="power",
                    on_click=self.verify_snapshot_vms_running,
                ).props("outline")
                ui.separator()
                memory_value = (
                    "include"
                    if self.state.scenario.lab_control.snapshot_with_memory is True
                    else "exclude"
                    if self.state.scenario.lab_control.snapshot_with_memory is False
                    else "unknown"
                )
                self.snapshot_memory = ui.select(
                    {
                        "unknown": "À confirmer",
                        "include": "Inclure la mémoire — mécanisme compatible requis",
                        "exclude": "Ne pas inclure la mémoire — vmrun disponible",
                    },
                    label="Mémoire des snapshots",
                    value=memory_value,
                ).classes("w-full")
                self.vmrun_path = ui.input(
                    "Exécutable vmrun",
                    value=str(Path(self.state.scenario.vmware.workstation_directory) / "vmrun.exe"),
                ).classes("w-full")
                ui.button("Prévisualiser les snapshots", icon="preview", on_click=self.preview_snapshots).props("outline")
                self.snapshot_confirm = ui.checkbox("Je confirme le plan exact de snapshots")
                self.snapshot_token_input = ui.input("Recopier l'empreinte des snapshots").classes("w-full")
                self.snapshot_dry_run = ui.checkbox("Snapshots en dry-run", value=True)
                ui.button("Démarrer la séquence de snapshots", icon="camera", on_click=self.execute_snapshots, color="negative")

        with ui.card().classes("w-full"):
            ui.label("Exécution du plan prévisualisé").classes("text-lg font-semibold")
            self.lab_dry_run = ui.checkbox("Mode dry-run", value=True)
            self.lab_confirm = ui.checkbox("Je confirme l'exécution du plan exact affiché")
            self.lab_token = ui.input("Recopier l'empreinte du plan pour une exécution réelle").classes("w-full")
            ui.button("Exécuter le plan affiché", icon="play_arrow", on_click=self.execute_guest_plan, color="negative")
        self.lab_control_status_panel()
        self._navigation()

    def _refresh_lab_control_step(self) -> None:
        """Reconstruit les contrôles depuis le scénario courant et invalide les anciens plans."""

        machine_ids = {
            machine.id
            for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets]
        }
        network_ids = {
            network.id for network in self.state.scenario.networks
        } | {
            interface.network
            for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets]
            for interface in machine.interfaces
            if interface.network
        }
        isolation_networks = {
            item.network
            for machine in [*self.state.scenario.infrastructure, *self.state.scenario.targets]
            for item in machine.isolation_interfaces
        }
        control = self._lab_state.lab_control
        control.ping_sessions = [
            session
            for session in control.ping_sessions
            if session.source_id in machine_ids
            and session.destination_id in machine_ids
            and session.network in network_ids
        ]
        control.disabled_networks = [
            network for network in control.disabled_networks if network in isolation_networks
        ]
        self._guest_plans = []
        self._guest_results = []
        self._guest_token = ""
        self._ping_routes = []
        self._file_plans = []
        self._snapshot_commands = []
        self._snapshot_results = []
        self._snapshot_token = ""
        refresh_snapshot_authorization(self._lab_state)
        self._build_lab_control_step.refresh()

    @ui.refreshable
    def lab_control_status_panel(self) -> None:
        """Affiche plans, résultats et verrou persistant sans inspection lente."""

        with ui.card().classes("w-full"):
            ui.label("Plan invité actuel").classes("text-lg font-semibold")
            if not self._guest_plans and not self._file_plans:
                ui.label("Aucun plan prévisualisé.").classes("text-grey-7")
            for plan in self._guest_plans:
                ui.code(plan.preview(), language="powershell").classes("w-full")
            for plan in self._file_plans:
                ui.code(plan.preview(), language="powershell").classes("w-full")
            if self._guest_token:
                ui.label(f"Empreinte : {self._guest_token}").classes("font-mono font-semibold")
            for result in self._guest_results:
                code = "dry-run" if result.returncode is None else str(result.returncode)
                action = getattr(result.plan, "action", "guest_file_copy")
                ui.label(f"{result.plan.machine_id} · {action} · résultat {code}")

        refresh_snapshot_authorization(self._lab_state)
        lock_color = "positive" if self._lab_state.lab_control.snapshots_authorized else "negative"
        with ui.card().classes("w-full"):
            ui.label("Barrière de snapshots").classes("text-lg font-semibold")
            ui.badge(
                "AUTORISÉS" if self._lab_state.lab_control.snapshots_authorized else "VERROUILLÉS",
                color=lock_color,
            )
            ui.label(
                f"Banc confirmé={self._lab_state.lab_control.bench_confirmed} · "
                f"pings={len(self._lab_state.lab_control.ping_sessions)} · "
                f"air gap={self._lab_state.lab_control.air_gap_verified} · "
                f"VM démarrées={self._lab_state.lab_control.all_vms_running}"
            ).classes("text-grey-7")
            for command in self._snapshot_commands:
                ui.code(command.display(), language="powershell").classes("w-full")
            if self._snapshot_token:
                ui.label(f"Empreinte snapshots : {self._snapshot_token}").classes("font-mono font-semibold")
            for result in self._snapshot_results:
                code = "dry-run" if result.returncode is None else str(result.returncode)
                ui.label(f"{result.command.machine_id} · snapshot · résultat {code}")

    def _set_guest_plans(self, plans: list[GuestCommandPlan]) -> None:
        """Remplace atomiquement la prévisualisation et son empreinte."""

        self._file_plans = []
        self._guest_plans = plans
        self._guest_token = guest_confirmation_token(plans)
        self._guest_results = []
        self.lab_control_status_panel.refresh()

    def preview_guest_command(self) -> None:
        """Prépare une commande libre sans la transmettre à la VM."""

        try:
            plan = GuestControlService(self.state.scenario).build_visible_command_plan(
                self.lab_machine.value,
                self.lab_command.value or "",
                elevated=bool(self.lab_elevated.value),
            )
            self._set_guest_plans([plan])
        except (GuestControlError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def preview_guest_network(self) -> None:
        """Produit les scripts réseau de toutes les VM depuis le même modèle."""

        try:
            plans = GuestNetworkService(self.state.scenario).build_plans()
            if not plans:
                raise GuestControlError("Aucune interface de scénario n'est configurée")
            self._set_guest_plans(plans)
        except (GuestControlError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def preview_ping(self) -> None:
        """Demande un choix lorsqu'une paire possède plusieurs chemins explicites."""

        try:
            if not self.ping_source.value or not self.ping_destination.value:
                raise GuestControlError("Choisissez la VM source et la VM destination")
            service = GuestControlService(self.state.scenario)
            routes = service.ping_routes(self.ping_source.value, self.ping_destination.value)
            if not routes:
                raise GuestControlError("Aucun réseau de scénario commun ne relie cette paire")
            if len(routes) == 1:
                self._set_guest_plans([service.build_ping_plan(routes[0])])
                return
            with ui.dialog() as dialog, ui.card().classes("w-[680px]"):
                ui.label("Plusieurs chemins sont possibles").classes("text-lg font-semibold")
                for route in routes:
                    label = (
                        f"{route.network} · {route.source_interface} -> "
                        f"{route.destination_interface} ({route.destination_address})"
                    )
                    ui.button(
                        label,
                        on_click=lambda _, item=route: self._select_ping_route(dialog, item),
                    ).props("outline").classes("w-full")
            dialog.open()
        except (GuestControlError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def _select_ping_route(self, dialog, route) -> None:
        """Conserve le chemin explicitement choisi dans le dialogue."""

        dialog.close()
        self._set_guest_plans([GuestControlService(self.state.scenario).build_ping_plan(route)])

    def preview_guest_files(self) -> None:
        """Prévisualise les transferts sans ouvrir de connexion invitée."""

        try:
            self._guest_plans = []
            self._file_plans = GuestFileService(self.state.scenario).build_plans()
            if not self._file_plans:
                raise GuestControlError("Aucun fichier complet n'est configuré")
            self._guest_token = file_confirmation_token(self._file_plans)
            self._guest_results = []
            self.lab_control_status_panel.refresh()
        except (GuestControlError, OSError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    def preview_isolation(self) -> None:
        """Affiche chaque dernière commande avant la coupure des sessions."""

        try:
            if not self.isolation_network.value:
                raise GuestControlError("Choisissez le réseau temporaire à désactiver")
            plans = GuestControlService(self.state.scenario).build_isolation_plans(
                self.isolation_network.value
            )
            self._set_guest_plans(plans)
        except (GuestControlError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True)

    async def execute_guest_plan(self) -> None:
        """Exécute en arrière-plan uniquement l'empreinte affichée et confirmée."""

        if not self.lab_confirm.value:
            ui.notify("Confirmez d'abord le plan affiché.", type="warning")
            return
        dry_run = bool(self.lab_dry_run.value)
        if not dry_run and (self.lab_token.value or "").strip().upper() != self._guest_token:
            ui.notify("L'empreinte saisie ne correspond pas au plan affiché.", type="negative")
            return
        try:
            if self._file_plans:
                service = GuestFileService(self.state.scenario, dry_run=dry_run)
                results = await run.io_bound(
                    service.execute,
                    self._file_plans,
                    confirmation_token=self._guest_token,
                )
            elif self._guest_plans:
                service = GuestControlService(self.state.scenario, dry_run=dry_run)
                results = await run.io_bound(
                    service.execute,
                    self._guest_plans,
                    confirmation_token=self._guest_token,
                )
            else:
                raise GuestControlError("Aucun plan n'est prévisualisé")
            self._guest_results = results
            if not dry_run:
                for plan in self._guest_plans:
                    if plan.action == "continuous_ping":
                        route = next(
                            route
                            for route in GuestControlService(self.state.scenario).ping_routes(
                                self.ping_source.value,
                                self.ping_destination.value,
                            )
                            if route.destination_address in plan.description
                        )
                        self._lab_state.lab_control.ping_sessions.append(
                            PingSessionState(
                                source_id=route.source_id,
                                destination_id=route.destination_id,
                                destination_address=route.destination_address,
                                network=route.network,
                            )
                        )
                self._lab_state_store.save(self._lab_state)
            self.lab_control_status_panel.refresh()
            ui.notify("Plan terminé." if not dry_run else "Simulation terminée.", type="positive")
        except (GuestControlError, OSError, subprocess.SubprocessError, StopIteration) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    async def verify_air_gap_now(self) -> None:
        """Teste ponctuellement les ports de gestion des interfaces isolées."""

        isolation_plans = [
            plan for plan in self._guest_plans if plan.action == "disable_isolation_interface"
        ]
        if not isolation_plans:
            ui.notify("Prévisualisez d'abord le plan d'isolation concerné.", type="warning")
            return
        service = GuestControlService(self.state.scenario)
        results = await run.io_bound(service.verify_management_unreachable, isolation_plans)
        self._lab_state.lab_control.air_gap_verified = bool(results) and all(results.values())
        if self._lab_state.lab_control.air_gap_verified and self.isolation_network.value:
            if self.isolation_network.value not in self._lab_state.lab_control.disabled_networks:
                self._lab_state.lab_control.disabled_networks.append(self.isolation_network.value)
        self._lab_state_store.save(self._lab_state)
        self.lab_control_status_panel.refresh()
        failures = [machine_id for machine_id, unreachable in results.items() if not unreachable]
        if failures:
            ui.notify(f"Canal encore joignable : {', '.join(failures)}", type="negative")
        else:
            ui.notify("Les canaux de gestion testés sont injoignables.", type="positive")

    def confirm_lab_state(self) -> None:
        """Enregistre les confirmations humaines séparément des contrôles réseau."""

        self._lab_state.lab_control.bench_confirmed = bool(self.bench_ready.value)
        for session in self._lab_state.lab_control.ping_sessions:
            session.active_confirmed_by_user = bool(self.pings_active.value)
        refresh_snapshot_authorization(self._lab_state)
        self._lab_state_store.save(self._lab_state)
        self.lab_control_status_panel.refresh()
        ui.notify("État du banc enregistré.", type="positive")

    async def verify_snapshot_vms_running(self) -> None:
        """Lit la liste VMware courante sans démarrer ni arrêter aucune VM."""

        try:
            service = SnapshotService(
                self.state.scenario,
                self._lab_state,
                vmrun_path=self.vmrun_path.value,
            )
            states = await run.io_bound(service.inspect_running_vms)
            self._lab_state.lab_control.all_vms_running = bool(states) and all(states.values())
            refresh_snapshot_authorization(self._lab_state)
            self._lab_state_store.save(self._lab_state)
            self.lab_control_status_panel.refresh()
            stopped = [machine_id for machine_id, running in states.items() if not running]
            if stopped:
                ui.notify(
                    f"VM non démarrées : {', '.join(stopped)}",
                    type="negative",
                    multi_line=True,
                )
            else:
                ui.notify("Toutes les VM à capturer sont démarrées.", type="positive")
        except (SnapshotSafetyError, OSError, subprocess.SubprocessError) as exc:
            self._lab_state.lab_control.all_vms_running = False
            self._lab_state_store.save(self._lab_state)
            self.lab_control_status_panel.refresh()
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def preview_snapshots(self) -> None:
        """Construit les commandes vmrun sans les exécuter ni promettre la mémoire."""

        try:
            choice = self.snapshot_memory.value
            vmrun_path = self.vmrun_path.value
            self.state.scenario.lab_control.snapshot_with_memory = (
                True if choice == "include" else False if choice == "exclude" else None
            )
            # La mutation reconstruit maintenant tout le contrôle du banc. Elle
            # doit donc précéder la création du plan qui sera présenté ensuite.
            self.state.changed()
            service = SnapshotService(
                self.state.scenario,
                self._lab_state,
                vmrun_path=vmrun_path,
            )
            self._snapshot_commands = service.build_commands()
            self._snapshot_token = snapshot_confirmation_token(self._snapshot_commands)
            self._snapshot_results = []
            self.lab_control_status_panel.refresh()
        except (SnapshotSafetyError, OSError, ValueError) as exc:
            self._snapshot_commands = []
            self._snapshot_token = ""
            self.lab_control_status_panel.refresh()
            ui.notify(str(exc), type="negative", multi_line=True)

    async def execute_snapshots(self) -> None:
        """Exécute le plan global seulement après toutes les barrières."""

        if not self.snapshot_confirm.value:
            ui.notify("Confirmez le plan de snapshots.", type="warning")
            return
        dry_run = bool(self.snapshot_dry_run.value)
        if not dry_run and (self.snapshot_token_input.value or "").strip().upper() != self._snapshot_token:
            ui.notify("L'empreinte de snapshots ne correspond pas au plan affiché.", type="negative")
            return
        try:
            service = SnapshotService(
                self.state.scenario,
                self._lab_state,
                vmrun_path=self.vmrun_path.value,
                dry_run=dry_run,
            )
            self._snapshot_results = await run.io_bound(
                service.execute,
                self._snapshot_commands,
                confirmation_token=self._snapshot_token,
            )
            self.lab_control_status_panel.refresh()
            ui.notify("Séquence de snapshots terminée.", type="positive")
        except (SnapshotSafetyError, OSError, subprocess.SubprocessError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")
    # endregion

    # region Étape 6 — validation, YAML et compilation
    def open_reward_editor_dialog(self) -> None:
        """Ouvre le document de référence complet sans perdre ses extensions."""

        document = self.state.scenario.reward.raw_config or _default_reward_document()
        with ui.dialog() as dialog, ui.card().classes("w-[1100px] max-w-[95vw]"):
            ui.label("Fichier de récompenses CyGIL").classes("text-lg font-semibold")
            ui.label(
                "Le document scenario2 sert de base. Les champs inconnus de l'application sont conservés tels quels."
            ).classes("text-grey-7")
            editor = ui.textarea(
                value=yaml.safe_dump(document, sort_keys=False, allow_unicode=True),
            ).props("outlined input-style='font-family: monospace; min-height: 680px'").classes("w-full")

            def reload_reference() -> None:
                editor.value = yaml.safe_dump(
                    _default_reward_document(),
                    sort_keys=False,
                    allow_unicode=True,
                )

            def save() -> None:
                try:
                    parsed = yaml.safe_load(editor.value)
                    if not isinstance(parsed, dict):
                        raise ValueError("Le fichier de récompenses doit contenir un objet YAML")
                    load_reward_document(self.state.scenario.reward, parsed)
                    self.state.changed()
                    dialog.close()
                    ui.notify("Fichier de récompenses enregistré dans le scénario.", type="positive")
                except (yaml.YAMLError, ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

            with ui.row().classes("justify-between w-full"):
                ui.button("Recharger scenario2", icon="restart_alt", on_click=reload_reference).props("outline")
                with ui.row():
                    ui.button("Annuler", on_click=dialog.close).props("flat")
                    ui.button("Enregistrer", icon="save", on_click=save)
        dialog.open()

    def _build_validation_step(self) -> None:
        """Regroupe les contrôles finaux, le plan et l'accès avancé au YAML."""

        with ui.row().classes("gap-2"):
            ui.button("Enregistrer le scénario", icon="save", on_click=self.save_scenario).props("outline")
            ui.button("Modifier les récompenses", icon="emoji_events", on_click=self.open_reward_editor_dialog).props("outline")
            ui.button("Générer un brouillon", icon="description", on_click=self.compile_configs).props("outline")
            ui.button("Générer les YAML finaux", icon="verified", on_click=self.compile_final_configs)
        ui.label("Problèmes détectés").classes("text-lg font-semibold mt-4")
        self.validation_panel()
        ui.separator().classes("my-3")
        ui.label("Plan d'exécution").classes("text-lg font-semibold")
        self.plan_panel()
        with ui.expansion("Éditeur YAML avancé", icon="data_object").classes("w-full"):
            self.yaml_editor = ui.textarea(value=self.state.yaml_text).props("outlined input-style='font-family: monospace; min-height: 620px'").classes("w-full")
            ui.button("Appliquer le YAML", on_click=self.apply_yaml).props("outline")
        self._navigation(previous=True, next_callback=lambda: ui.notify("Assistant terminé : vous pouvez générer les fichiers."))

    @ui.refreshable
    def validation_panel(self) -> None:
        """Affiche immédiatement les erreurs et avertissements du scénario courant."""

        result = self.state.service.validate(self.state.scenario)
        if not result.issues:
            ui.label("Le scénario est valide.").classes("text-positive font-semibold")
        for issue in result.issues:
            icon = "error" if issue.level == "error" else "warning"
            color = "negative" if issue.level == "error" else "warning"
            with ui.row().classes("items-start gap-2"):
                ui.icon(icon, color=color)
                ui.label(f"{issue.code} — {issue.message}").classes("max-w-[1100px]")

    @ui.refreshable
    def plan_panel(self) -> None:
        """Présente le plan sans effet de bord produit depuis le même état."""

        columns = [
            {"name": "order", "label": "#", "field": "order", "align": "left"},
            {"name": "phase", "label": "Phase", "field": "phase", "align": "left"},
            {"name": "action", "label": "Action", "field": "action", "align": "left"},
            {"name": "target", "label": "Cible", "field": "target", "align": "left"},
            {"name": "description", "label": "Description", "field": "description", "align": "left"},
        ]
        ui.table(columns=columns, rows=[step.to_dict() for step in self.state.service.plan(self.state.scenario)], row_key="order").classes("w-full")

    def _refresh_yaml_editor(self) -> None:
        """Met à jour l'éditeur sans le recréer lorsqu'un composant change."""

        if self.yaml_editor is not None:
            self.yaml_editor.value = self.state.yaml_text

    def apply_yaml(self) -> None:
        """Remplace l'état partagé par un YAML valide puis actualise tous les écrans."""

        try:
            self.state.scenario = Scenario.model_validate(yaml.safe_load(self.yaml_editor.value))
            self.state.changed()
            self.vagrant_box_paths_panel.refresh()
            ui.notify("YAML appliqué à tous les composants.", type="positive")
        except (yaml.YAMLError, ValidationError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def open_new_scenario_dialog(self) -> None:
        """Demande uniquement l'identité du nouveau canevas avant de repartir de zéro."""

        with ui.dialog() as dialog, ui.card().classes("w-[560px]"):
            ui.label("Nouveau scénario vide").classes("text-lg font-semibold")
            ui.label(
                "Aucun réseau, switch, cible, adresse ou fichier d'exemple ne sera chargé. "
                "Les quatre rôles CyGIL réservés resteront comme emplacements non configurés."
            ).classes("text-grey-7")
            name = ui.input("Nom du scénario", value="nouveau_scenario").classes("w-full")
            description = ui.input("Description (optionnelle)").classes("w-full")

            def create() -> None:
                """Remplace l'état courant seulement après validation du nom."""

                try:
                    scenario = Scenario.new_blank(
                        name=(name.value or "").strip(),
                        description=(description.value or "").strip(),
                    )
                    self._activate_scenario(scenario, None)
                    dialog.close()
                    ui.notify("Nouveau scénario vide créé.", type="positive")
                except (ValidationError, ValueError) as exc:
                    ui.notify(str(exc), type="negative", multi_line=True)

            with ui.row().classes("justify-end w-full"):
                ui.button("Annuler", on_click=dialog.close).props("flat")
                ui.button("Créer", icon="note_add", on_click=create)
        dialog.open()

    async def choose_and_load_scenario(self) -> None:
        """Ouvre le sélecteur natif puis charge la sauvegarde choisie."""

        try:
            selected = await run.io_bound(VagrantEnvironmentService.choose_scenario_file)
            if not selected:
                return
            self.load_scenario(Path(selected))
        except (OSError, ValidationError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def _activate_scenario(self, scenario: Scenario, source: Path | None) -> None:
        """Remplace le scénario et invalide tout plan lié à l'ancien état."""

        self.state.scenario = scenario
        self.state.source = source
        self._lab_state_store = DeploymentStateStore(
            PROJECT_ROOT / "work" / "deployments" / f"{scenario.metadata.name}.json"
        )
        self._lab_state = self._lab_state_store.load(scenario.metadata.name)
        self._guest_plans = []
        self._guest_results = []
        self._file_plans = []
        self._snapshot_commands = []
        self._snapshot_results = []
        self._vmware_vms = ()
        self._reserved_vm_selects = {}
        self._vmnet_inventory = None
        self._vmnet_records = ()
        self._scenario_vmnet_plan = None
        self._bootstrap_leases = {}
        self._vmware_network_inventory = None
        self._network_reconstruction_plan = None
        self._network_rollback = None
        self._allocation_preview = {}
        self._allocation_context = None
        self._deployment_results = []
        self._vagrant_commands = []
        self._vagrant_token = ""
        self._vagrantfile_text = ""
        self._vagrant_plan_context = ""
        self._vagrant_box_hashes = {}
        self.scenario_path.value = str(source) if source else ""
        self._sync_static_scenario_fields()
        self.state.changed()
        self.vagrant_box_paths_panel.refresh()
        self.vmware_reconstruction_panel.refresh()

    def _sync_static_scenario_fields(self) -> None:
        """Réaligne les champs non rafraîchissables après nouveau/chargement."""

        host = self.state.scenario.vmware
        values = {
            "host_ssh_user": host.ssh_user,
            "host_public_key_path": host.ssh_authorized_public_key_path or "",
            "host_legacy_rsa": host.allow_legacy_ssh_rsa,
            "host_ip": host.external_ip,
            "host_port": host.api_port,
            "host_workstation": host.workstation_directory,
            "host_openssl": host.openssl_executable,
            "host_openssl_config": host.openssl_config_path or "",
            "host_certificate_directory": host.certificate_directory,
            "host_vmrest_certificate": host.setup_status.certificate_path or "",
            "host_vmrest_private_key": host.setup_status.private_key_path or "",
            "host_mac_version": host.static_mac_workstation_version or "",
            "host_mac_first": host.static_mac_first or "",
            "host_mac_last": host.static_mac_last or "",
            "host_mac_source": host.static_mac_validation_source or "",
            "host_mac_validated": host.static_mac_policy_validated,
        }
        for attribute, value in values.items():
            widget = getattr(self, attribute, None)
            if widget is not None:
                widget.value = value
        vagrant = self.state.scenario.vagrant
        vagrant_values = {
            "vagrant_executable": vagrant.executable_path or "",
            "vagrant_clone_directory": vagrant.clone_directory or "",
            "bootstrap_network": vagrant.bootstrap_network,
            "bootstrap_dhcp": vagrant.bootstrap_dhcp_enabled,
            "bootstrap_validated": vagrant.bootstrap_validated,
            "mininet_internal_network": vagrant.mininet_internal_network,
        }
        for attribute, value in vagrant_values.items():
            widget = getattr(self, attribute, None)
            if widget is not None:
                widget.value = value
        if getattr(self, "mininet_internal_cidr_label", None) is not None:
            self.mininet_internal_cidr_label.text = (
                f"CIDR observé : {vagrant.mininet_internal_cidr or 'non inventorié'}"
            )
        try:
            credentials = self._secret_store.load(self.state.scenario.metadata.name)
        except SecretStoreError as exc:
            credentials = {}
            ui.notify(str(exc), type="negative", multi_line=True)
        if getattr(self, "host_api_user", None) is not None:
            self.host_api_user.value = credentials.get("username", "")
        if getattr(self, "host_api_password", None) is not None:
            self.host_api_password.value = credentials.get("password", "")
        caldera = next(
            (machine for machine in self.state.scenario.infrastructure if machine.role == InfrastructureRole.CALDERA),
            None,
        )
        if getattr(self, "caldera_url", None) is not None:
            self.caldera_url.value = f"http://{caldera.management_ip}:8888" if caldera and caldera.management_ip else ""

    def load_scenario(self, selected_path: Path | None = None) -> None:
        """Charge un fichier canonique choisi par l'utilisateur et rafraîchit toute la GUI."""

        try:
            raw = selected_path or (Path(self.scenario_path.value).expanduser() if self.scenario_path.value else None)
            if raw is None:
                raise ValueError("Choisissez une sauvegarde YAML à charger")
            source = Path(raw).expanduser()
            if not source.is_file():
                raise ValueError(f"Fichier introuvable : {source}")
            self._activate_scenario(self.state.service.load(source), source)
            ui.notify(f"Scénario chargé : {source}", type="positive", multi_line=True)
        except (OSError, ValidationError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def save_scenario(self) -> None:
        """Enregistre le modèle canonique dans le chemin choisi par l'utilisateur."""

        try:
            destination = self._persist_active_scenario()
            ui.notify(f"Scénario enregistré dans {destination}", type="positive", multi_line=True)
        except (OSError, ValidationError, ValueError) as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def _persist_active_scenario(self) -> Path:
        """Écrit la sauvegarde active et retourne le chemin réellement utilisé."""

        raw_path = self.scenario_path.value.strip() if self.scenario_path.value else ""
        destination = (
            Path(raw_path)
            if raw_path
            else PROJECT_ROOT / "work" / f"{self.state.scenario.metadata.name}.yml"
        )
        if destination.suffix.lower() not in {".yml", ".yaml"}:
            destination = destination.with_suffix(".yml")
        self.state.service.save(self.state.scenario, destination)
        self.state.source = destination
        self.scenario_path.value = str(destination)
        return destination

    def compile_configs(self) -> None:
        """Génère un brouillon sans marqueurs de variables secrètes."""

        try:
            bundle = self.state.service.compile(
                self.state.scenario,
                GENERATED,
                base_dir=PROJECT_ROOT,
                inject_secrets=True,
                secret_values=self._compiled_secret_values(),
            )
            ui.notify(
                f"Brouillon des 4 YAML généré dans {bundle.output_directory}",
                type="positive",
                multi_line=True,
            )
        except Exception as exc:  # Frontière GUI : l'utilisateur doit toujours voir une erreur lisible.
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def compile_final_configs(self) -> None:
        """Bloque la copie finale tant que les MAC VMware n'ont pas été relues."""

        try:
            bundle = self.state.service.compile(
                self.state.scenario,
                GENERATED,
                base_dir=PROJECT_ROOT,
                inject_secrets=True,
                require_verified_macs=True,
                secret_values=self._compiled_secret_values(require=True),
            )
            ui.notify(
                f"4 YAML finaux vérifiés générés dans {bundle.output_directory}",
                type="positive",
                multi_line=True,
            )
        except Exception as exc:
            ui.notify(str(exc), type="negative", multi_line=True, timeout=0, close_button="×")

    def _compiled_secret_values(self, *, require: bool = False) -> dict[str, str]:
        """Associe les deux références VMREST au coffre du scénario actif."""

        credentials = self._secret_store.load(self.state.scenario.metadata.name)
        if not credentials:
            if require:
                raise SecretStoreError(
                    "Enregistrez les identifiants VMREST avant de produire les YAML finaux"
                )
            return {}
        host = self.state.scenario.vmware
        return {
            host.api_username_secret: credentials["username"],
            host.api_password_secret: credentials["password"],
        }
    # endregion


def create_app() -> None:
    """Crée un état isolé par page et construit l'assistant associé."""

    ScenarioWizard(GuiState())


def main() -> None:
    """Démarre le serveur Web local avec une fonction racine compatible aux lanceurs pip."""

    # La variable optionnelle permet de lancer une instance de test sans interrompre
    # l'instance de travail qui utilise normalement le port 8080.
    port = int(os.environ.get("CYGIL_GUI_PORT", "8080"))
    ui.run(root=create_app, title="CyGIL Scenario Orchestrator", host="127.0.0.1", port=port, reload=False)


if __name__ in {"__main__", "__mp_main__"}:
    main()
