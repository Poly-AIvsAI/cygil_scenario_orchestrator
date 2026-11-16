"""Construction d'un plan lisible avant tout effet de bord sur le laboratoire."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .models import Scenario


@dataclass(frozen=True)
class PlanStep:
    """Étape ordonnée précisant sa cible et si elle modifie le banc."""
    order: int
    phase: str
    action: str
    target: str
    description: str
    mutating: bool

    def to_dict(self) -> dict:
        """Convertit l'étape pour la table GUI et la sortie JSON de la CLI."""
        return asdict(self)


def build_plan(scenario: Scenario) -> list[PlanStep]:
    """Déroule le scénario dans l'ordre opérationnel convenu avec CyGIL."""
    steps: list[PlanStep] = []

    def add(phase: str, action: str, target: str, description: str, mutating: bool) -> None:
        steps.append(PlanStep(len(steps) + 1, phase, action, target, description, mutating))

    add("validation", "validate", scenario.metadata.name, "Valider le modèle canonique et les références croisées", False)
    add("locking", "acquire_lock", "laboratoire", "Acquérir le verrou du scénario actif", True)

    add("inventory", "inspect_vagrant", "hôte", "Détecter Vagrant, vmware_desktop, Utility, plugins et boxes", False)
    add("inventory", "inspect_vmnet0", "VMnet0", "Détecter le CIDR, l'hôte, le DHCP et les adresses occupées", False)
    add("inventory", "inspect_bootstrap_vmnet", "VMnet d'amorçage", "Confirmer un host-only distinct de VMnet0 et son DHCP temporaire", False)

    for machine in scenario.infrastructure:
        add("infrastructure", "discover", machine.id, f"Découvrir la VM réservée {machine.role.value}", False)
        add("infrastructure", "start_if_needed_vmrest", machine.id, "Démarrer par vmrest seulement si une action confirmée l'exige; Vagrant est interdit", True)
        if scenario.vagrant.bootstrap_network:
            add("bootstrap", "attach_bootstrap", machine.id, f"Connecter provisoirement {scenario.vagrant.bootstrap_network} sans Vagrant", True)

    for target in scenario.targets:
        if target.temporary_management.enabled and target.temporary_management.vmware_network:
            assigned = target.temporary_management.assigned_address or "à allouer après inspection"
            add("management", "reserve_static_address", target.id, f"Réserver sans conflit {assigned} sur VMnet0", True)
        add("targets", "create_or_clone", target.id, f"Créer depuis le modèle {target.template}", True)
        add("targets", "configure_hardware", target.id, f"Appliquer {target.cpus} CPU et {target.memory_mb} Mo", True)
        if scenario.vagrant.bootstrap_network:
            add("bootstrap", "attach_bootstrap", target.id, f"Connecter provisoirement {scenario.vagrant.bootstrap_network} avec DHCP", True)
        if target.temporary_management.enabled and target.temporary_management.vmware_network:
            add(
                "management",
                "attach_temporary_management",
                target.id,
                f"Connecter provisoirement à {target.temporary_management.vmware_network} pour l'automatisation",
                True,
            )
        for interface in target.interfaces:
            add("network", "configure_interface", target.id, f"Configurer {interface.name} avec {interface.address} sur {interface.network}", True)

    add("resolution", "discover_runtime_values", "VM cibles", "Résoudre chemins VMX, MAC, interfaces et adresses appliquées", False)
    add("network", "configure_all_guests", "VM du scénario", "Appliquer les réseaux permanents par backend invité explicitement validé", True)
    add("compilation", "compile", "CyGIL", "Générer network, command_center, reward et obs", True)
    add("compilation", "cross_validate", "4 YAML", "Valider la syntaxe et les références entre les quatre fichiers", False)
    add("transfer", "upload", scenario.cygil_runtime.destination_directory, "Transférer ensemble les quatre YAML vers la VM CyGIL", True)

    for command in scenario.cygil_runtime.launch_commands:
        add("launch", "run", "VM CyGIL", command, True)

    for target in scenario.targets:
        if target.deploy_hand:
            add("caldera", "deploy_hand", target.id, "Générer et démarrer le hand CALDERA", True)
        if target.target_file_path:
            add("guest_files", "confirm_target_file", target.id, f"Vérifier le dépôt du fichier cible vers {target.target_file_path}", False)
        for deployment_file in target.guest_files:
            add("guest_files", "upload_guest_file", target.id, f"Copier après confirmation vers {deployment_file.destination_path}", True)
    for machine in scenario.infrastructure:
        for deployment_file in machine.guest_files:
            add("guest_files", "upload_guest_file", machine.id, f"Copier après confirmation vers {deployment_file.destination_path}", True)

    add("verification", "wait_services", "Mininet/ONOS/CALDERA", "Attendre des états explicites plutôt qu’un délai fixe", False)
    add("verification", "ping_matrix", "réseau", "Exécuter et enregistrer la matrice initiale de pings", False)
    add("manual_control", "run_user_commands", "VM du scénario", "Laisser l'utilisateur exécuter des commandes confirmées dans des terminaux SSH/WinRM visibles", True)
    add("manual_control", "start_continuous_pings", "paires choisies", "Laisser l'utilisateur démarrer les pings continus visibles pour les paires de VM choisies", True)
    add("manual_control", "confirm_bench_ready", "utilisateur", "Attendre la confirmation explicite que l'état du banc et les pings visibles sont satisfaisants", False)
    if scenario.vagrant.bootstrap_network:
        add("isolation", "disable_bootstrap_all_guests", scenario.vagrant.bootstrap_network, "Dernière commande SSH/WinRM : désactiver l'interface d'amorçage dans chaque OS invité", True)

    # Le nom d'action historique « detach » est conservé pour la compatibilité,
    # mais l'opération désactive uniquement l'interface dans l'OS invité. Le
    # retrait à chaud de l'adaptateur VMware est interdit sur ce banc.
    for target in scenario.targets:
        management = target.temporary_management
        if management.enabled and management.vmware_network and management.detach_before_snapshot:
            add(
                "isolation",
                "detach_temporary_management",
                target.id,
                f"Après confirmation globale, dernière commande SSH/WinRM : désactiver {management.vmware_network} dans l'OS invité, puis vérifier l'absence de trafic",
                True,
            )

    # Le banc exige un snapshot à chaud sans redémarrage : les pings sont déjà
    # actifs lorsque les interfaces de gestion sont désactivées dans les invités.
    add(
        "verification",
        "prepare_live_snapshot",
        "VM du scénario",
        "Garantir que toutes les VM sont restées démarrées après la désactivation des interfaces temporaires",
        False,
    )
    add(
        "verification",
        "verify_continuous_pings",
        "réseau",
        "Vérifier que les pings continus sont toujours actifs et que les interfaces de gestion ne transportent aucun trafic",
        False,
    )

    for machine in scenario.infrastructure:
        add("snapshot", "create_snapshot", machine.id, f"Snapshot à chaud par VMware, pings actifs : {scenario.vmware.snapshot_name}", True)
    for target in scenario.targets:
        if target.snapshot:
            add("snapshot", "create_snapshot", target.id, f"Snapshot à chaud de la cible, pings actifs : {scenario.vmware.snapshot_name}", True)

    add("registration", "write_manifest", scenario.metadata.name, "Enregistrer artefacts, contrôles et identifiants de snapshot", True)
    add("registration", "register_cygil", scenario.metadata.name, "Enregistrer le scénario dans CyGIL", True)
    add("locking", "release_lock", "laboratoire", "Libérer le verrou global", True)
    return steps
