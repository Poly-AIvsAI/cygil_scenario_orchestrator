"""Modèle canonique du scénario partagé par l'interface, les validateurs et les compilateurs.

Toutes les informations saisies par l'utilisateur passent par ces modèles Pydantic. Cette
source unique évite qu'une modification de la topologie soit visible dans un écran mais
oubliée dans les fichiers CyGIL générés.
"""

from __future__ import annotations

from enum import StrEnum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    """Classe de base qui interdit  les champs YAML inconnus."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# region Enumerations partagées
class InfrastructureRole(StrEnum):
    """Rôles des VM réservées; seul Mininet peut avoir plusieurs VM."""

    CYGIL = "cygil"
    CALDERA = "caldera"
    ONOS = "onos"
    MININET = "mininet"


class OSFamily(StrEnum):
    """Familles de systèmes prises en charge pour le provisionnement et les hands."""

    LINUX = "linux"
    WINDOWS = "windows"


class GuestCommunicator(StrEnum):
    """Canal utilisé après l'amorçage pour configurer une VM cible."""

    SSH = "ssh"
    WINRM = "winrm"


class LinkScope(StrEnum):
    """Indique si une interface rejoint un switch Mininet local ou distant."""

    LOCAL = "local"
    REMOTE = "remote"


class InterfacePurpose(StrEnum):
    """Rôle fonctionnel d'une carte réseau dans une VM."""

    MANAGEMENT = "management"
    SCENARIO = "scenario"
    OTHER = "other"


class ProviderType(StrEnum):
    """Versions de fournisseur CALDERA reconnues par les fichiers CyGIL actuels."""

    CALDERA_THREE = "caldera_three"
    CALDERA_FOUR = "caldera_four"


class ObjectiveType(StrEnum):
    """Types d'objectifs actuellement compilés vers le fichier de récompense."""

    HAND_ON_HOST = "hand_on_host"
    TRAIT_VALUE_PAIR = "trait_value_pair"
    FILE_EXFILTRATION = "file_exfiltration"


class HandAgentType(StrEnum):
    """Agents proposés par l'onglet de déploiement CALDERA."""

    SANDCAT = "sandcat"
    MANX = "manx"
    CUSTOM = "custom"


class HostSetupState(StrEnum):
    """État persistant de préparation du serveur hôte."""

    NOT_CONFIGURED = "not_configured"
    PARTIAL = "partial"
    READY = "ready"
    RUNNING = "running"
    ERROR = "error"


class GuestFilePurpose(StrEnum):
    """Rôle d'un fichier copié dans une VM avant l'isolation du banc."""

    SUPPORT = "support"
    CYGIL_TARGET = "cygil_target"


class GuestNetworkBackend(StrEnum):
    """Mécanisme explicitement validé pour rendre la configuration persistante."""

    WINDOWS_POWERSHELL = "windows_powershell"
    LINUX_NMCLI = "linux_nmcli"
    LINUX_NETPLAN = "linux_netplan"


class MacAddressSource(StrEnum):
    """Provenance d'une MAC afin de distinguer demande, calcul et observation."""

    REQUESTED = "requested"
    GENERATED = "generated"
    VMWARE = "vmware"
    OBSERVED = "observed"


class NetworkReconstructionState(StrEnum):
    """État transactionnel de la reconstruction des cartes d'une VM réservée."""

    NOT_PLANNED = "not_planned"
    PLANNED = "planned"
    BACKED_UP = "backed_up"
    APPLYING = "applying"
    VERIFIED = "verified"
    FAILED = "failed"
    RESTORED = "restored"
# endregion


# region Topologie et machines
class ScenarioMetadata(StrictModel):
    """Métadonnées stables utilisées pour nommer les artefacts du scénario."""

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")
    description: str = ""
    version: str = "1.0"


class Network(StrictModel):
    """Segment logique CyGIL, avec CIDR optionnel distinct de son étiquette subnet."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    subnet_label: str | None = None
    cidr: str | None = None
    gateway: str | None = None
    # Champ historique conservé pour charger les anciennes sauvegardes. Les
    # nouveaux scénarios portent le VMnet sur chaque MachineInterface cible.
    vmware_network: str | None = None


class NetworkSwitch(StrictModel):
    """Switch Mininet explicitement rattaché à une instance d'exécution."""

    name: str = Field(pattern=r"^s[0-9]+$")
    mininet_instance: str


class MachineInterface(StrictModel):
    """Carte réseau d'une VM, y compris les interfaces de gestion hors Mininet.

    Les trois références réseau sont optionnelles pour une interface de gestion. Elles sont
    obligatoires pour une interface de scénario, ce que le validateur métier contrôle.
    """

    name: str
    address: str
    purpose: InterfacePurpose = InterfacePurpose.SCENARIO
    network: str | None = None
    mininet_instance: str | None = None
    connected_switch: str | None = Field(default=None, pattern=r"^s[0-9]+$")
    scope: LinkScope = LinkScope.LOCAL
    mac: str | None = None
    # ``mac`` demeure la demande de l'utilisateur. Seule la valeur relue dans
    # VMware peut devenir la source d'un artefact CyGIL final.
    applied_mac: str | None = None
    mac_source: MacAddressSource | None = None
    mac_verified: bool = False
    # Le lien logique Mininet et le VMnet VMware sont deux notions distinctes.
    # Ce champ rend leur correspondance explicite avant tout branchement réel.
    vmware_network: str | None = None
    gateway: str | None = None
    # Le banc ne fournit pas de serveurs DNS aux cartes Mininet : l'option
    # attendue demande au provisionneur de désactiver le DNS dans l'invité.
    disable_dns: bool = True
    vmware_adapter_index: int | None = Field(default=None, ge=0)

    @model_validator(mode="before")
    @classmethod
    def migrate_misinterpreted_dns_servers(cls, data):
        """Charge les sauvegardes transitoires sans conserver la fausse liste DNS.

        Une version de prédéploiement a brièvement compris le besoin comme une
        liste de serveurs. Le champ est retiré et devient l'option correcte de
        désactivation, sans exporter de nouvelle clé vers CyGIL.
        """

        if not isinstance(data, dict) or "dns_servers" not in data:
            return data
        migrated = dict(data)
        migrated.pop("dns_servers", None)
        migrated.setdefault("disable_dns", True)
        return migrated


class GuestAccessConfig(StrictModel):
    """Accès technique sans secret en clair, commun aux VM réservées et cibles."""

    communicator: GuestCommunicator
    # Adresse actuellement joignable pour SSH/WinRM. Pour une nouvelle cible,
    # il s'agit d'abord du bail du VMnet d'amorçage, et non de l'adresse VMnet0
    # qui n'est utilisable qu'après sa configuration dans l'invité.
    connection_address: IPv4Address | None = None
    username: str | None = None
    password_secret: str | None = None
    private_key_path: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    winrm_use_ssl: bool = False


class GuestDesktopConfig(StrictModel):
    """Session graphique dans laquelle les terminaux doivent devenir visibles."""

    session_user: str | None = None
    terminal_executable: str | None = None
    linux_display: str | None = None
    visible_terminal_validated: bool = False


class IsolationInterfaceConfig(StrictModel):
    """Identité stable d'une interface à désactiver sans hot-remove VMware."""

    network: str
    guest_name: str | None = None
    mac: str | None = None
    vmware_adapter_index: int | None = Field(default=None, ge=0)
    disable_before_snapshot: bool = True


class GuestFileDeployment(StrictModel):
    """Transfert local vers invité, éventuellement compilé comme cible CyGIL."""

    source_path: str
    destination_path: str
    purpose: GuestFilePurpose = GuestFilePurpose.SUPPORT
    requires_admin: bool = False
    worth: int = Field(default=100, ge=0)


class VmwareNetworkAdapter(StrictModel):
    """Carte VMware attendue ou observée, indépendante du nom dans l'invité."""

    vmware_adapter_index: int = Field(ge=0)
    vmnet: str
    connection_type: str = "custom"
    requested_mac: str | None = None
    applied_mac: str | None = None
    mac_source: MacAddressSource | None = None
    guest_name: str | None = None
    address: str | None = None
    permanent: bool = True
    verified: bool = False


class InfrastructureVM(StrictModel):
    """VM réservée qui existe avant la création d'un nouveau scénario."""

    id: str
    role: InfrastructureRole
    # Ces identifiants proviennent de VMware et protègent la VM même si son
    # nom d'affichage ou son chemin change après son association dans la GUI.
    vmware_id: str | None = None
    vmware_uuid: str | None = None
    inventory_confirmed: bool = False
    management_ip_confirmed: bool = False
    vmx_path: str | None = None
    management_ip: str | None = None
    internal_ip: str | None = None
    mac: str | None = None
    interface_name: str | None = None
    mininet_instance: str | None = None
    connected_switch: str | None = None
    subnet_label: str | None = None
    scenario_ip: str | None = None
    interfaces: list[MachineInterface] = Field(default_factory=list)
    os_family: OSFamily | None = None
    guest_access: GuestAccessConfig | None = None
    network_backend: GuestNetworkBackend | None = None
    guest_desktop: GuestDesktopConfig = Field(default_factory=GuestDesktopConfig)
    isolation_interfaces: list[IsolationInterfaceConfig] = Field(default_factory=list)
    guest_files: list[GuestFileDeployment] = Field(default_factory=list)
    observed_adapters: list[VmwareNetworkAdapter] = Field(default_factory=list)
    expected_adapters: list[VmwareNetworkAdapter] = Field(default_factory=list)
    network_reconstruction_state: NetworkReconstructionState = NetworkReconstructionState.NOT_PLANNED
    ssh_user: str | None = None
    ssh_password_secret: str | None = None
    api_username_secret: str | None = None
    api_password_secret: str | None = None
    red_api_key_secret: str | None = None
    blue_api_key_secret: str | None = None


class HandConfig(StrictModel):
    """Choix CALDERA associés à une VM cible sans conserver de clé API en clair."""

    enabled: bool = False
    agent_type: HandAgentType = HandAgentType.SANDCAT
    group: str = "red"
    c2_protocol: str = "http"
    generated_command: str | None = None
    generated_at: str | None = None


class TemporaryManagementConfig(StrictModel):
    """Carte d'amorçage provisoire utilisée uniquement pendant l'automatisation.

    Cette carte n'est jamais exportée vers le fichier network de CyGIL. Elle est
    désactivée dans l'OS invité avant les snapshots afin d'obtenir l'air gap
    fonctionnel. L'adaptateur VMware reste attaché, car son retrait à chaud est
    explicitement interdit sur ce banc.
    """

    enabled: bool = True
    # Compatibilité de sauvegarde : ce champ historique désigne désormais le
    # VMnet DHCP d'amorçage. Une cible ne rejoint jamais VMnet0, qui appartient
    # exclusivement à l'orchestration des VM réservées.
    vmware_network: str = ""
    address_mode: str = Field(default="dhcp", pattern=r"^dhcp$")
    assigned_address: IPv4Interface | None = None
    detach_before_snapshot: bool = True


class VagrantConfig(StrictModel):
    """Paramètres locaux de Vagrant et des boxes choisies par l'utilisateur.

    Les chemins sont volontairement configurables : les noms de modèles du
    scénario ne prouvent ni qu'une box existe ni qu'elle prend en charge VMware.
    """

    enabled: bool = True
    executable_path: str | None = None
    clone_directory: str | None = None
    workspace_directory: str = "work/vagrant"
    box_paths: dict[str, str] = Field(default_factory=dict)
    # Une liste explicite complète les adresses découvertes automatiquement.
    # L'application n'invente jamais une plage DHCP ou une passerelle.
    reserved_management_addresses: list[IPv4Address] = Field(default_factory=list)
    management_gateway: IPv4Address | None = None
    # Le premier accès peut passer par un VMnet host-only DHCP distinct de
    # VMnet0. Cette barrière ne sera levée qu'après un essai documenté qui inclut
    # aussi la désactivation finale de cette carte dans l'OS invité.
    bootstrap_method: str | None = None
    bootstrap_network: str | None = None
    bootstrap_dhcp_enabled: bool = False
    bootstrap_validated: bool = False
    guest_network_commands_validated: bool = False
    # Le réseau de contrôle CyGIL/Mininet est choisi dans l'inventaire VMREST.
    # Son CIDR est observé depuis VMware; l'utilisateur ne saisit aucune adresse.
    mininet_internal_network: str | None = None
    mininet_internal_cidr: IPv4Network | None = None

    @field_validator("bootstrap_network", "mininet_internal_network", mode="before")
    @classmethod
    def normalize_vmnet_names(cls, value):
        """Normalise les sauvegardes vmrest historiques sans changer leur numéro."""

        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if stripped.casefold().startswith("vmnet") and stripped[5:].isdigit():
            return f"VMnet{int(stripped[5:])}"
        return stripped

    @model_validator(mode="before")
    @classmethod
    def remove_misinterpreted_management_dns(cls, data):
        """Ignore le champ DNS transitoire lors du chargement d'une sauvegarde.

        Le réseau de gestion VMnet0 n'a pas de liste DNS à configurer; cette
        migration préserve uniquement la compatibilité des fichiers déjà sauvés.
        """

        if not isinstance(data, dict) or "management_dns" not in data:
            return data
        migrated = dict(data)
        migrated.pop("management_dns", None)
        return migrated


class TargetVM(StrictModel):
    """VM cible reliée à un unique port d'accès Mininet pour le MVP."""

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
    hostname: str
    os_family: OSFamily
    template: str = "à_configurer"
    cpus: int = Field(default=2, ge=1, le=64)
    memory_mb: int = Field(default=2048, ge=512)
    vmx_path: str | None = None
    interfaces: list[MachineInterface] = Field(default_factory=list)
    temporary_management: TemporaryManagementConfig = Field(default_factory=TemporaryManagementConfig)
    guest_access: GuestAccessConfig | None = None
    network_backend: GuestNetworkBackend | None = None
    guest_desktop: GuestDesktopConfig = Field(default_factory=GuestDesktopConfig)
    isolation_interfaces: list[IsolationInterfaceConfig] = Field(default_factory=list)
    guest_files: list[GuestFileDeployment] = Field(default_factory=list)
    # Une cible compromise porte le seul hand CALDERA initial du scénario. Les
    # deux anciens booléens restent sérialisés pour le format CyGIL, mais sont
    # synchronisés avec cette source métier unique.
    compromised: bool = False
    hand: HandConfig = Field(default_factory=HandConfig)
    initial_red_hand: bool = False
    # VMnet point-à-point CALDERA ↔ VM Mininet. Il est distinct du VMnet
    # d'accès cible ↔ Mininet afin que CALDERA ne rejoigne jamais directement
    # la cible au niveau VMware.
    caldera_vmware_network: str | None = None
    critical_reset: bool = True
    snapshot: bool = True
    # Le chemin local sert uniquement au transfert vers l'invité et n'est
    # jamais exporté dans les fichiers CyGIL.
    target_file_source_path: str | None = None
    target_file_path: str | None = None
    target_file_worth: int = Field(default=100, ge=0)

    @model_validator(mode="before")
    @classmethod
    def discard_legacy_machine_mac(cls, data):
        """Retire l'ancienne MAC ambiguë placée au niveau de la cible.

        Les anciens exemples utilisaient notamment ``00:00:00:00:00:02`` comme
        identifiant CyGIL. Une demande matérielle appartient désormais à une
        interface précise; sinon elle sera générée après inventaire VMware.
        """

        if not isinstance(data, dict):
            return data
        migrated = dict(data)
        migrated.pop("mac", None)
        hand = migrated.get("hand") or {}
        compromised = bool(
            migrated.get("compromised", False)
            or migrated.get("initial_red_hand", False)
            or (isinstance(hand, dict) and hand.get("enabled", False))
        )
        migrated["compromised"] = compromised
        migrated["initial_red_hand"] = compromised
        if isinstance(hand, dict):
            migrated["hand"] = {**hand, "enabled": compromised}
        return migrated

    @property
    def deploy_hand(self) -> bool:
        """Conserve une lecture simple pour le planificateur et les anciens composants."""

        return self.hand.enabled


class MininetInstance(StrictModel):
    """Instance Mininet contrôlée par l'unique VM ONOS du scénario.

    Chaque paire de ``switch_links`` représente un lien bidirectionnel. Une
    instance est combinée Mininet-ONOS lorsque ``infrastructure_vm_id`` et
    ``onos_controller_id`` désignent la même VM réservée.
    """

    name: str
    infrastructure_vm_id: str | None = None
    onos_controller_id: str | None = None
    # Ces copies persistées appartiennent au format canonique historique, mais
    # elles sont toujours dérivées de la VM réservée associée. Elles ne sont
    # jamais une seconde source de vérité ni des valeurs saisies dans la GUI.
    external_ip: str | None = None
    internal_ip: str | None = None
    switch_links: dict[str, list[str]] = Field(default_factory=dict)


class OnosIntent(StrictModel):
    """Intention de connectivité ONOS entre deux identifiants d'hôtes."""

    host_one: str
    host_two: str
# endregion


# region Configuration de l'hôte VMware
class HostProvisioningStatus(StrictModel):
    """Résultats persistants des étapes exécutées dans l'onglet hôte."""

    state: HostSetupState = HostSetupState.NOT_CONFIGURED
    ssh_configured: bool = False
    certificate_generated: bool = False
    credentials_configured: bool = False
    vmrest_running: bool = False
    # Les PID et le code HTTP sont informatifs : ils sont recalculés à chaque supervision.
    vmrest_process_ids: list[int] = Field(default_factory=list)
    vmrest_http_status: int | None = None
    certificate_path: str | None = None
    private_key_path: str | None = None
    last_message: str = "Aucune configuration exécutée"
    last_checked_at: str | None = None


class VmwareHostConfig(StrictModel):
    """Paramètres du poste VMware et options de préparation SSH/vmrest."""

    host_type: str = "windows"
    external_ip: str
    ssh_user: str
    ssh_private_key_path: str
    # Clé publique Windows choisie dans l'onglet hôte; distincte de la clé privée CyGIL ci-dessus.
    ssh_authorized_public_key_path: str | None = None
    workstation_directory: str
    api_port: int = 8697
    api_username_secret: str
    api_password_secret: str
    snapshot_name: str
    caldera_reset_interval: int = Field(default=100, ge=1)
    openssl_executable: str = "openssl.exe"
    # Le binaire VMware ne fournit pas nécessairement openssl.cnf; le chemin
    # choisi par l'utilisateur est donc explicite et persistant dans le scénario.
    openssl_config_path: str | None = None
    certificate_directory: str = "work/host-certificates"
    # Champ historique conservé pour charger les scénarios existants. vmrest
    # 1.2.1 ne fournit pas d'option d'adresse; seule son option -p est utilisée.
    vmrest_bind_address: str = "0.0.0.0"
    # Nom stable de la règle Windows pilotée depuis l'onglet VMREST.
    vmrest_firewall_rule_name: str = "CyGIL-vmrest"
    sshd_config_path: str = r"C:\ProgramData\ssh\sshd_config"
    allow_legacy_ssh_rsa: bool = False
    # La plage reste vide tant qu'elle n'a pas été validée contre la version
    # installée; aucune valeur générique n'est inventée par l'application.
    static_mac_workstation_version: str | None = None
    static_mac_first: str | None = None
    static_mac_last: str | None = None
    static_mac_validation_source: str | None = None
    static_mac_policy_validated: bool = False
    setup_status: HostProvisioningStatus = Field(default_factory=HostProvisioningStatus)
# endregion


# region CALDERA, récompenses et exécution CyGIL
class CalderaAbility(StrictModel):
    """Association entre une action du simulateur et une ability CALDERA."""

    action_id: int = Field(ge=0)
    ability_id: str
    description: str = ""


class Fact(StrictModel):
    """Fait initial injecté au fournisseur CALDERA."""

    trait: str
    value: str
    score: int = 1
    technique_id: str = ""
    collected_by: str = ""


class Rule(StrictModel):
    """Règle de filtrage initiale transmise à CALDERA."""

    trait: str
    match: str
    action: str = "DENY"


class CommandCenterConfig(StrictModel):
    """Configuration du fournisseur de commandement et de ses actions rouges."""

    provider: ProviderType = ProviderType.CALDERA_THREE
    abilities: list[CalderaAbility] = Field(default_factory=list)
    initial_facts: list[Fact] = Field(default_factory=list)
    rules: list[Rule] = Field(default_factory=list)


class RewardObjective(StrictModel):
    """Objectif de fin et valeur de récompense compilés pour CyGIL."""

    type: ObjectiveType
    enabled: bool = True
    worth: int = 100
    host_name: str | None = None
    privilege: str | None = None
    trait: str | None = None
    value: str | None = None
    count: int = 1
    operator: str = "=="
    file_path: str | None = None
    source: str = "manual"


class RewardConfig(StrictModel):
    """Coûts, durée et objectifs du scénario."""

    action_cost: int = 1
    no_action_dispatched_cost: int = 8
    max_steps: int = Field(default=80, ge=1)
    objectives: list[RewardObjective] = Field(default_factory=list)
    # Document CyGIL complet servant de base à l'éditeur avancé. Les champs
    # que l'application ne modélise pas encore (trait_pairs, trait_worth, etc.)
    # sont ainsi conservés à l'identique lors d'un chargement/enregistrement.
    raw_config: dict = Field(default_factory=dict)


class ObservationConfig(StrictModel):
    """Référence vers le profil de construction des observations."""

    profile_path: str = "profiles/obs_standard.yml"


class CyGILRuntime(StrictModel):
    """Destination et commandes confirmées pour lancer le scénario sur CyGIL."""

    destination_directory: str
    launch_commands: list[str] = Field(default_factory=list)


class LabControlConfig(StrictModel):
    """Garde-fous du contrôle manuel précédant les snapshots à chaud."""

    visible_terminals_required: bool = True
    explicit_bench_confirmation: bool = True
    verify_air_gap: bool = True
    # vmrun 1.17 n'expose aucun indicateur « include memory »; ce choix doit
    # rester explicite jusqu'à validation d'un mécanisme compatible Workstation.
    snapshot_with_memory: bool | None = None
# endregion


class Scenario(StrictModel):
    """Agrégat racine sauvegardé en YAML et partagé par toute l'application."""

    metadata: ScenarioMetadata
    vmware: VmwareHostConfig
    vagrant: VagrantConfig = Field(default_factory=VagrantConfig)
    networks: list[Network] = Field(default_factory=list)
    switches: list[NetworkSwitch] = Field(default_factory=list)
    infrastructure: list[InfrastructureVM] = Field(default_factory=list)
    targets: list[TargetVM] = Field(default_factory=list)
    mininet_instances: list[MininetInstance] = Field(default_factory=list)
    onos_intents: list[OnosIntent] = Field(default_factory=list)
    command_center: CommandCenterConfig = Field(default_factory=CommandCenterConfig)
    reward: RewardConfig = Field(default_factory=RewardConfig)
    observation: ObservationConfig = Field(default_factory=ObservationConfig)
    cygil_runtime: CyGILRuntime
    lab_control: LabControlConfig = Field(default_factory=LabControlConfig)

    @classmethod
    def new_blank(cls, name: str = "nouveau_scenario", description: str = "") -> "Scenario":
        """Crée un canevas neuf sans charger d'exemple ni inventer le banc.

        Les quatre rôles réservés sont seulement les emplacements structurels
        requis par le format. Ils n'ont encore ni VM associée, ni adresse, ni NIC.
        """

        return cls(
            metadata=ScenarioMetadata(name=name, description=description),
            vmware=VmwareHostConfig(
                external_ip="",
                ssh_user="",
                ssh_private_key_path="",
                workstation_directory="",
                api_username_secret="VMWARE_API_USERNAME",
                api_password_secret="VMWARE_API_PASSWORD",
                snapshot_name=f"{name}_ready",
            ),
            infrastructure=[
                InfrastructureVM(id="cygil", role=InfrastructureRole.CYGIL),
                InfrastructureVM(id="caldera", role=InfrastructureRole.CALDERA),
                InfrastructureVM(id="onos", role=InfrastructureRole.ONOS),
                InfrastructureVM(id="mininet", role=InfrastructureRole.MININET),
            ],
            cygil_runtime=CyGILRuntime(destination_directory=f"/opt/cygil/scenarios/{name}"),
        )

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_network_switches(cls, data):
        """Sépare les switches encore imbriqués dans les anciens sous-réseaux.

        Avant la refonte, chaque réseau contenait ``switch`` et
        ``mininet_instance``. La migration les déplace vers la liste explicite
        ``switches`` avant que Pydantic n'applique ``extra='forbid'``.
        """

        if not isinstance(data, dict):
            return data
        # Les sauvegardes antérieures branchaient temporairement les cibles à
        # VMnet0. VMnet0 est maintenant le réseau d'orchestration des seules VM
        # réservées; l'accès initial des cibles passe par l'amorçage DHCP.
        migrated_input = dict(data)
        raw_vagrant = migrated_input.get("vagrant")
        if isinstance(raw_vagrant, dict):
            bootstrap = raw_vagrant.get("bootstrap_network")
            raw_targets = []
            for target in migrated_input.get("targets", []):
                if not isinstance(target, dict):
                    raw_targets.append(target)
                    continue
                migrated_target = dict(target)
                temporary = dict(migrated_target.get("temporary_management") or {})
                if temporary.get("vmware_network") in {None, "", "VMnet0"}:
                    temporary["vmware_network"] = bootstrap or ""
                if temporary.get("address_mode") in {None, "static"}:
                    temporary["address_mode"] = "dhcp"
                    temporary["assigned_address"] = None
                migrated_target["temporary_management"] = temporary
                raw_targets.append(migrated_target)
            migrated_input["targets"] = raw_targets
        data = migrated_input
        # Lors d'une validation d'affectation, Pydantic transmet le modèle déjà
        # construit. Le test doit couvrir les deux collections indépendamment :
        # un nouveau scénario peut avoir un switch avant son premier sous-réseau.
        # Ne tester que ``networks`` transformait alors les ``NetworkSwitch`` en
        # dictionnaires bruts lors de l'affectation suivante.
        existing_networks = data.get("networks", [])
        existing_switches = data.get("switches", [])
        if (
            existing_networks and isinstance(existing_networks[0], Network)
        ) or (
            existing_switches and isinstance(existing_switches[0], NetworkSwitch)
        ):
            return data
        migrated = dict(data)
        raw_networks = [dict(network) for network in migrated.get("networks", [])]
        raw_switches = [dict(switch) for switch in migrated.get("switches", [])]
        known_switches = {switch.get("name") for switch in raw_switches}
        for network in raw_networks:
            switch_name = network.pop("switch", None)
            instance_name = network.pop("mininet_instance", None)
            if switch_name and instance_name and switch_name not in known_switches:
                raw_switches.append({"name": switch_name, "mininet_instance": instance_name})
                known_switches.add(switch_name)
        migrated["networks"] = raw_networks
        migrated["switches"] = raw_switches
        return migrated

    @field_validator("infrastructure")
    @classmethod
    def unique_infrastructure_roles(cls, value: list[InfrastructureVM]) -> list[InfrastructureVM]:
        """Garde CYGIL, CALDERA et ONOS uniques tout en autorisant plusieurs Mininet."""

        roles = [machine.role for machine in value if machine.role != InfrastructureRole.MININET]
        if len(roles) != len(set(roles)):
            raise ValueError("Les rôles cygil, caldera et onos ne peuvent apparaître qu'une fois")
        return value

    @model_validator(mode="after")
    def associate_legacy_mininet_instances(self) -> "Scenario":
        """Associe les anciens YAML à leur VM Mininet lorsque le choix est non ambigu.

        Les versions précédentes ne stockaient pas ``infrastructure_vm_id``. Une
        correspondance par IP ou par ancien champ ``mininet_instance`` permet de les
        charger sans obliger l'utilisateur à modifier manuellement ses fichiers.
        """

        mininet_vms = [machine for machine in self.infrastructure if machine.role == InfrastructureRole.MININET]
        # Les anciens exemples plaçaient CyGIL sur le réseau interne Mininet.
        # La décision actuelle l'isole sur VMnet0; cette migration retire donc
        # toute ancienne carte permanente non dédiée à la gestion.
        cygil = next(
            (machine for machine in self.infrastructure if machine.role == InfrastructureRole.CYGIL),
            None,
        )
        if cygil is not None:
            cygil.internal_ip = None
            cygil.interfaces = [
                interface
                for interface in cygil.interfaces
                if interface.purpose == InterfacePurpose.MANAGEMENT
            ]
        for target in self.targets:
            # La valeur reste persistée afin que les modules Vagrant, invité et
            # snapshot consomment tous le même réseau temporaire.
            target.temporary_management.vmware_network = self.vagrant.bootstrap_network or ""
            target.temporary_management.assigned_address = None
        claimed_ids = {instance.infrastructure_vm_id for instance in self.mininet_instances if instance.infrastructure_vm_id}
        for instance in self.mininet_instances:
            if instance.infrastructure_vm_id:
                continue
            candidates = [
                machine
                for machine in mininet_vms
                if machine.id not in claimed_ids
                and (
                    machine.mininet_instance == instance.name
                    or machine.management_ip == instance.external_ip
                    or machine.internal_ip == instance.internal_ip
                )
            ]
            if not candidates and len(self.mininet_instances) == 1 and len(mininet_vms) == 1:
                candidates = mininet_vms
            if len(candidates) == 1:
                instance.infrastructure_vm_id = candidates[0].id
                claimed_ids.add(candidates[0].id)
        # Les anciennes valeurs ont servi uniquement à retrouver une association
        # absente. Une fois l'association connue, la VM réservée redevient
        # immédiatement l'unique source des adresses et du contrôleur ONOS.
        self.synchronize_mininet_bindings()
        return self

    def synchronize_mininet_bindings(self) -> None:
        """Dérive les adresses Mininet et l'unique référence ONOS.

        Une association de VM absente ou inconnue efface les anciennes adresses
        plutôt que de conserver silencieusement une valeur devenue obsolète. De
        même, l'ID ONOS reste vide tant que l'architecture ne contient pas
        exactement une VM ONOS; la validation globale explique alors l'erreur.
        """

        infrastructure_by_id = {machine.id: machine for machine in self.infrastructure}
        onos_vms = [
            machine
            for machine in self.infrastructure
            if machine.role == InfrastructureRole.ONOS
        ]
        onos_id = onos_vms[0].id if len(onos_vms) == 1 else None
        for instance in self.mininet_instances:
            machine = infrastructure_by_id.get(instance.infrastructure_vm_id or "")
            instance.onos_controller_id = onos_id
            instance.external_ip = machine.management_ip if machine is not None else None
            instance.internal_ip = machine.internal_ip if machine is not None else None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Scenario":
        """Charge et valide un scénario depuis un fichier YAML."""

        source = Path(path)
        with source.open("r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        return cls.model_validate(data)

    def to_yaml(self, path: str | Path) -> Path:
        """Sauvegarde le scénario avec un ordre stable et un encodage UTF-8."""

        # La méthode peut être appelée sans passer par ScenarioService. Elle
        # garantit donc elle-même que les copies historiques restent dérivées.
        self.synchronize_mininet_bindings()
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as stream:
            yaml.safe_dump(
                self.model_dump(mode="json"),
                stream,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
            )
        return destination
