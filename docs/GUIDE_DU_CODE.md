# Guide de lecture du code

Ce document donne un ordre de lecture pratique pour modifier l'application sans devoir comprendre tous les fichiers en même temps.

## 1. Le modèle canonique

Commencer par `src/cygil_builder/models.py`. Ce fichier décrit les objets manipulés : scénario, réseaux, VM, interfaces, hands, récompenses et configuration de l'hôte.

Une interface réseau est un objet `MachineInterface`. Une VM réservée peut être multi-interface, mais une cible possède exactement une interface permanente de scénario, locale à la VM Mininet qui héberge son switch. Le réseau de gestion et le réseau DHCP d'amorçage restent hors de cette interface canonique.

Chaque `MininetInstance` référence aussi l'unique VM ONOS avec `onos_controller_id`. Les liens de switches sont bidirectionnels : intra-instance ils représentent un lien OVS local; inter-instance ils représentent un tunnel GRE. Une seule cible porte `compromised: true`; ce champ synchronise `hand.enabled` et `initial_red_hand`. Son `caldera_vmware_network` relie CALDERA à la VM Mininet concernée sans raccorder directement CALDERA à la cible.

`visualization.py` produit deux documents indépendants : `render_infrastructure_view()` pour les VM, adaptateurs et VMnet, et `render_sdn_view()` pour ONOS, OpenFlow, switches, hôtes et GRE.

## 2. La cohérence globale

`src/cygil_builder/coherence.py` contient les règles qui relient plusieurs écrans. Par exemple, le choix d'un fichier cible sur une VM produit automatiquement un objectif `file_exfiltration` dans les récompenses.

Dans la GUI, `GuiState.changed()` appelle ce synchroniseur puis rafraîchit tous les panneaux abonnés.

## 3. L'interface progressive

`src/cygil_builder/gui.py` contient la classe `ScenarioWizard`. Le fichier est séparé en régions correspondant aux six étapes de l'assistant, dont le contrôle du banc avant snapshots.

Pour ajouter un champ à une étape :

1. ajouter d'abord le champ au modèle approprié dans `models.py` ;
2. l'ajouter au dialogue ou au panneau de `gui.py` ;
3. appeler `self.state.changed()` après la modification ;
4. compléter la validation et les tests si ce champ influence les fichiers CyGIL.

## 4. Les opérations particulières

- `caldera_service.py` communique avec l'API CALDERA et ne lance rien dans la VM cible.
- `host_setup.py` prépare OpenSSH, OpenSSL et vmrest après confirmation explicite.
- `planner.py` décrit l'ordre prévu sans exécuter les opérations.
- `adapters/dry_run.py` simule les opérations réelles.
- `adapters/vagrant.py` limite le Vagrantfile et les commandes préparées aux nouvelles VM cibles. Cette chaîne n'a pas encore été qualifiée de bout en bout sur le banc.
- `vmware_control.py` attache le VMnet d'amorçage aux VM réservées confirmées, sans suppression.
- `guest_network.py` produit les commandes réseau selon le moteur choisi pour chaque OS.
- `guest_control.py` prépare commandes, pings visibles et isolation dans les invités.
- `guest_files.py` sépare les sources locales des destinations invitées.
- `lab_topology.py` calcule la topologie permanente et les chemins de ping explicites.
- `snapshot_control.py` maintient le verrou de capture et pilote `vmrun`.

## 5. Les fichiers CyGIL

Chaque fichier de sortie possède son compilateur dans `src/cygil_builder/compilers` :

- `network.py` pour la topologie et les interfaces ;
- `command_center.py` pour CALDERA et les actions ;
- `reward.py` pour les coûts et objectifs ;
- `observation.py` pour le profil d'observation ;
- `bundle.py` pour générer les quatre fichiers ensemble et créer le manifeste.

## 6. Vérification

Les tests se trouvent dans `tests`. Après une modification :

```powershell
.venv\Scripts\python -m pytest
```

Les commentaires décrivent les responsabilités et les contraintes importantes. Ils ne commentent pas chaque ligne afin de garder le code lisible.
`vmware_network.py` contient la frontière transactionnelle de la reconstruction des VM réservées. La lecture globale produit un `VmwareInventorySnapshot` scellé. `build_reconstruction_plan` dérive les cartes attendues et lie le diff à cet instantané. `VmxNetworkReconstructor` sauvegarde chaque VMX, refuse toute VM autre que `poweredOff`, remplace seulement les clés `ethernetN.*`, puis permet une restauration par un jeton distinct. `reconcile_applied_adapters` compare la relecture exacte avant de marquer les MAC comme vérifiées.

La plage MAC n'est pas une constante du code. `StaticMacPolicy` exige la version VMware, les bornes et une source de validation confirmée. La génération est stable pour un scénario et résout les collisions de manière bornée contre l'inventaire complet.

Le compilateur réseau conserve un mode de préparation compatible avec les exemples historiques. Pour produire un artefact final après déploiement, appeler `compile_bundle(..., require_verified_macs=True)`: chaque cible doit alors fournir une `applied_mac` relue dans VMware et marquée `mac_verified`. Une valeur seulement saisie ou calculée est refusée.
`Scenario.new_blank()` est le seul point de création d'un scénario neuf. Il ne copie aucun exemple : les listes de réseaux, switches, instances Mininet et cibles sont vides. Les quatre entrées d'infrastructure ne sont que les rôles structurels requis et restent sans identité VMware ni configuration.

Depuis ce canevas, la GUI peut ajouter un nombre variable de cibles. Le dialogue du hand sélectionne une cible compromise de façon exclusive et ne demande que l'adresse CALDERA avec préfixe. `select_compromised_target` dérive l'unique interface CALDERA–Mininet vers le même switch OVS, le même réseau logique et la même instance Mininet que la cible. Le nom invité reste vide jusqu'à sa découverte par la MAC. `plan_scenario_vmnets` attribue ensuite un VMnet dédié distinct du lien cible–Mininet. Le compilateur, la reconstruction VMware et la sauvegarde consomment donc la même `MachineInterface` canonique.

VMnet0 est le **Management Network**. Il appartient à toutes les VM réservées et à aucune cible. Le VMnet DHCP temporaire est simultanément le **réseau d'orchestration** et le **réseau d'amorçage**; il est prévu pour toutes les VM. Le Vagrantfile préparé pour les cibles contient cette carte temporaire et les cartes d'accès Mininet, mais le provisionnement réel des cibles reste à qualifier. Les deux diagrammes Mermaid peuvent être téléchargés depuis la GUI comme images SVG.

`plan_scenario_vmnets` inclut dans son jeton les VMnet d'accès gérés dont le DHCP doit être retiré. Après leur création par vmrest, `VagrantEnvironmentService.disable_dhcp_on_vmnets` exécute `vnetlib64.exe -- remove dhcp vmnetN` sous UAC et exige une relecture `DHCP=False`. Les VMnet manuels hors raccordements d'accès ne sont pas concernés.

`TargetVM.discard_legacy_machine_mac` absorbe la clé historique `target.mac` sans la propager. Les consommateurs Vagrant, VMware et CyGIL utilisent exclusivement la MAC de l'interface concernée, puis sa valeur appliquée et vérifiée après déploiement.
