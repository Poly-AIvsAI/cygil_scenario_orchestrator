# Guide d'utilisation du CyGIL Scenario Orchestrator

> Dernière mise à jour : 15 novembre 2026  
> Portée : fonctions implémentées, limites observées et opérations restant à qualifier dans `cygil_scenario_orchestrator`.  
> Maintenance : mettre ce guide à jour dès qu'un bouton, une validation, un réseau, un ordre d'exécution ou une automatisation change.

## 1. Objet du guide

Ce document décrit la chronologie recommandée pour construire un scénario et préparer son déploiement sur le banc VMware Workstation. Il est destiné à une personne qui ne connaît pas le projet.

Le déploiement comprend quatre opérations distinctes qu'il ne faut pas confondre :

1. décrire la topologie logique du scénario ;
2. créer et raccorder les adaptateurs virtuels dans VMware ;
3. préparer la création des nouvelles VM cibles avec Vagrant ;
4. démarrer les VM et écrire la configuration IP dans leurs systèmes d'exploitation après qualification des accès invités.

Une carte visible dans VMware ne signifie donc pas encore que son adresse IP est configurée dans Linux ou Windows.

Le prototype n'a pas réalisé un déploiement complet de `nouveau_20` jusqu'à son exécution dans CyGIL. La conception, les inventaires, les calculs de raccordement, la proposition d'adresses, le différentiel VMware et la compilation de brouillons ont été démontrés. En revanche, le provisionnement effectif des cibles avec Vagrant, la configuration invitée, CALDERA, les snapshots, le transfert final et le lancement CyGIL restent à qualifier de bout en bout. Les sections correspondantes décrivent donc le parcours prévu et les contrôles disponibles, pas la preuve d'un déploiement déjà réussi.

## 2. Architecture réseau actuellement appliquée

L'application distingue les réseaux suivants.

| Réseau | Rôle actuel | Machines connectées | DHCP VMware | Connexion à l'hôte |
|---|---|---|---|---|
| `VMnet0` | Management statique | VM réservées seulement | Désactivé | Requise |
| VMnet d'orchestration/amorçage | Accès technique temporaire | Toutes les VM | Activé | Requise |
| VMnet interne Mininet/ONOS | Contrôle interne | ONOS et VM Mininet concernées | Configuration manuelle du banc | Interdite par le plan d'isolation actuel |
| VMnet d'accès cible–Mininet | Un segment dédié par cible | Une cible et sa VM Mininet | Désactivé automatiquement | Interdite |
| VMnet CALDERA–Mininet | Segment dédié au hand initial | CALDERA et la VM Mininet de la cible compromise | Désactivé automatiquement | Interdite |

Points importants :

- les VM réservées sont CyGIL, CALDERA, ONOS et les VM Mininet déjà présentes ;
- Vagrant ne possède et ne crée que les VM cibles ;
- chaque cible possède exactement une interface permanente d'accès à un switch Mininet ;
- exactement une cible doit être compromise ;
- CALDERA n'est jamais reliée directement à la cible compromise : elle rejoint la même VM Mininet par un autre VMnet dédié ;
- les adaptateurs temporaires restent attachés dans VMware et sont désactivés dans les OS avant les snapshots ;
- l'application ne retire jamais une carte à chaud.

## 3. Informations à réunir avant de commencer

### 3.1 Pour l'hôte Windows

- chemin d'installation de VMware Workstation ;
- chemin de `vmrun.exe` ;
- chemin de `openssl.exe` et de `openssl.cnf` ;
- compte choisi pour VMREST ;
- version exacte de VMware Workstation ;
- plage de MAC statiques autorisée et source qui la valide pour cette version ;
- répertoire dans lequel les nouvelles VM cibles peuvent être créées.

### 3.2 Pour chaque VM réservée

- rôle exact : CyGIL, CALDERA, ONOS ou Mininet ;
- VM correspondante dans l'inventaire VMware ;
- famille d'OS : Linux ou Windows ;
- canal d'accès : SSH ou WinRM ;
- utilisateur et méthode d'authentification ;
- backend réseau : Netplan, NetworkManager (`nmcli`) ou PowerShell ;
- si des terminaux visibles sont exigés : utilisateur graphique, programme de terminal et `DISPLAY` Linux ;
- noms des interfaces dans l'OS, à relever après le premier démarrage si nécessaire.

### 3.3 Pour chaque modèle de cible

- box déjà importée manuellement dans le catalogue Vagrant local ;
- nom et version affichés par `vagrant box list` ;
- nom de modèle utilisé par le scénario, par exemple `cygil/ubuntu` ;
- fournisseur VMware Desktop réellement disponible pour cette box ;
- SSH ou WinRM déjà opérationnel dans la box ;
- utilisateur, clé privée ou variable d'environnement contenant le mot de passe ;
- backend réseau réellement utilisé par l'image.

L'import des boxes est une opération manuelle préalable. Le prototype peut inventorier le catalogue Vagrant et préparer un plan, mais l'association automatique entre les modèles du scénario et les boxes installées n'a pas été rendue opérationnelle pour `nouveau_20`. La présence d'une archive `.box` ou d'un chemin enregistré ne prouve donc pas que la cible peut être créée et configurée avec succès.

### 3.4 Origine des informations réseau

| Information | Source |
|---|---|
| Adresse de scénario d'une cible | Plan logique choisi par le concepteur, toujours avec préfixe |
| Adresse de CALDERA sur le réseau du hand | Adresse libre du même sous-réseau logique, avec préfixe |
| Adresse de management d'une VM réservée | Proposition calculée par l'application dans `VMnet0` |
| Adresse temporaire d'amorçage | Bail DHCP lu automatiquement à partir de la MAC VMware |
| MAC des cartes | Inventaire/relecture VMware ; ne pas la deviner |
| Nom d'une interface dans Linux/Windows | Observation dans l'OS invité |
| VMnet cible–Mininet | Calcul automatique depuis les emplacements VMware libres |

## 4. Préparer les éléments VMware fondamentaux

Avant d'utiliser les plans automatiques, créer ou vérifier manuellement dans VMware Virtual Network Editor :

1. `VMnet0`, réseau de management des VM réservées ;
2. un VMnet host-only d'orchestration/amorçage, distinct de `VMnet0`, avec DHCP ;
3. un VMnet interne Mininet/ONOS, distinct des deux précédents.

L'application crée ensuite les VMnet dédiés aux cibles et à CALDERA. Elle ne doit pas être utilisée pour recréer arbitrairement les VMnet fondamentaux déjà administrés manuellement.

### Contrôles sur `VMnet0`

- le DHCP VMware doit être désactivé ;
- l'adaptateur Windows `VMnet0` doit utiliser une adresse statique, pas « Obtenir une adresse automatiquement » ;
- la connexion de l'hôte doit être présente ;
- le sous-réseau ne doit chevaucher aucun autre VMnet.

Attention : « DHCP VMware désactivé » et « l'adaptateur Windows n'utilise pas DHCP » sont deux vérifications différentes.

### Contrôles sur le VMnet d'amorçage

- il doit être distinct de `VMnet0` et du VMnet interne ;
- il doit fournir le DHCP ;
- il doit posséder une connexion à l'hôte ;
- il doit réellement fournir un bail aux systèmes des boxes et aux VM réservées.

Ne cochez « Accès d'amorçage validé avec les VM et boxes réelles » qu'après un essai réel.

## 5. Installer et démarrer l'application

Dans PowerShell :

```powershell
cd "<dossier-du-projet>\cygil_scenario_orchestrator"
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\cygil-scenario-gui
```

Ouvrir ensuite `http://127.0.0.1:8080`.

Notes :

- l'installation `-e` permet d'utiliser le code modifié au prochain démarrage sans réinstallation ;
- après une mise à jour du programme, arrêter l'ancienne instance avec `Ctrl+C`, puis la relancer ;
- les modifications du scénario dans l'interface ne sont pas automatiquement enregistrées sur disque.

## 6. Créer ou charger le scénario

Dans la barre « Fichier de scénario » :

- choisir « Nouveau scénario » pour partir d'un canevas vide ;
- choisir « Charger un scénario » pour reprendre un fichier `.yml` ou `.yaml` ;
- utiliser régulièrement « Enregistrer sous ».

Un nouveau scénario contient seulement les quatre rôles d'infrastructure. Ceux-ci ne sont pas encore associés aux VM VMware réelles.

Bonne pratique : enregistrer immédiatement le nouveau scénario sous un nom unique. Le nom sert aussi à séparer certains journaux de déploiement.

## 7. Préparer tôt l'hôte et VMREST

Bien que l'interface place cette partie à l'étape 4, elle doit être préparée tôt, car les inventaires VMware en dépendent.

### 7.1 Onglet « Paramètres »

Renseigner :

- adresse de l'hôte ;
- port VMREST ;
- dossier VMware Workstation ;
- OpenSSL et son fichier de configuration ;
- dossier, certificat et clé privée TLS.

Déplier « Politique MAC statique VMware validée » et renseigner :

- version VMware Workstation ;
- première et dernière MAC autorisées ;
- source locale de validation.

Cocher « Je confirme que cette plage a été validée sur cette version », puis cliquer sur « Appliquer les paramètres ».

Ne cochez pas cette confirmation seulement pour contourner le blocage. Une mauvaise plage peut créer des collisions ou des VMX non pris en charge.

### 7.2 Onglet « VMREST »

1. renseigner l'utilisateur et le mot de passe VMREST ;
2. cliquer sur « Enregistrer les identifiants » ;
3. cocher la confirmation générale de l'hôte lorsqu'une action sensible la demande ;
4. utiliser « 1. Générer le certificat » si nécessaire ;
5. utiliser « 2. Ouvrir la console d'identifiants » lors de la première configuration ;
6. saisir dans la console les mêmes identifiants ;
7. cliquer sur « 3. Démarrer vmrest » et accepter l'UAC ;
8. cliquer sur « Vérifier l'API ».

VMREST n'est considéré opérationnel que si le processus existe, si le port écoute et si `/api/vms` répond correctement.

Sur un hôte déjà configuré, il n'est normalement pas nécessaire de rouvrir la console `vmrest -C` pour chaque scénario. Les identifiants saisis doivent toutefois authentifier réellement l'appel API.

## 8. Concevoir la topologie logique — étape 1

Suivre cet ordre :

1. ajouter les sous-réseaux logiques avec leur CIDR ;
2. ajouter les instances Mininet et associer chacune à sa VM réservée Mininet ;
3. vérifier que l'architecture contient exactement une VM ONOS ; toutes les instances l'utilisent automatiquement ;
4. ajouter les switches dans leur instance Mininet ;
5. ajouter les liens entre switches ;
6. déclarer les VM cibles ;
7. ajouter exactement une interface de scénario à chaque cible.

Les adresses d'une instance Mininet ne sont jamais saisies dans son dialogue. Son
adresse externe est toujours recopiée depuis `management_ip` de la VM réservée
associée et son adresse interne depuis `internal_ip` de cette même VM. Si ces
adresses n'ont pas encore été allouées, l'interface l'indique explicitement. Le
chargement, chaque modification et la sauvegarde remplacent aussi toute ancienne
référence `onos_controller_id` par l'identifiant de l'unique VM ONOS.

### Interface d'une cible

Dans « Interface », renseigner :

- « Nom dans l'OS » : nom prévu ou nom que la configuration devra imposer ;
- « Adresse avec préfixe » : par exemple `10.10.1.20/24`, jamais une adresse sans préfixe ;
- « Fonction » : `scenario` ;
- sous-réseau logique ;
- switch cible.

L'instance Mininet est déduite du switch. Le VMnet physique sera calculé plus tard.

Erreurs à éviter :

- ajouter deux interfaces de scénario à une même cible ;
- choisir un switch d'une autre instance Mininet ;
- fournir une adresse hors du CIDR sélectionné ;
- réutiliser une adresse déjà attribuée ;
- choisir manuellement `VMnet0`, le VMnet d'amorçage ou le VMnet interne comme lien d'une cible.

### Interfaces des VM réservées

- ne pas créer manuellement les cartes VMware qui seront dérivées du rôle ;
- CyGIL reste uniquement sur le management ;
- les interfaces de management `VMnet0` et du réseau interne Mininet/ONOS seront créées ou complétées automatiquement lors du calcul des adresses ; une adresse manuelle valide déjà déclarée peut être conservée ;
- l'interface CALDERA vers Mininet sera dérivée du choix de la cible compromise.

## 9. Configurer les VM — étape 2

### 9.1 VM cibles

Pour chaque cible, cliquer sur « Configurer » et renseigner :

- nom d'hôte, OS, modèle de box, CPU et mémoire ;
- création de snapshot et réinitialisation critique ;
- VMnet d'amorçage temporaire ;
- « Désactiver dans l'OS invité avant les snapshots » ;
- SSH ou WinRM ;
- backend réseau ;
- utilisateur ;
- clé SSH ou nom de variable d'environnement du mot de passe ;
- port personnalisé seulement si nécessaire.

Backend à choisir :

- `linux_netplan` si l'image utilise Netplan ;
- `linux_nmcli` si elle utilise NetworkManager ;
- `windows_powershell` pour Windows.

Pour SSH réel, utiliser une clé privée ou un agent SSH. Le programme refuse de placer un mot de passe SSH dans une ligne de commande. Pour WinRM, fournir le nom d'une variable d'environnement contenant le mot de passe, jamais le mot de passe dans le YAML.

Exemple avant le démarrage de l'application :

```powershell
$env:CYGIL_WINDOWS_PASSWORD = "<mot-de-passe>"
```

Dans l'interface, saisir seulement `CYGIL_WINDOWS_PASSWORD` comme référence de secret.

### 9.2 État actuel de la sélection des boxes

L'interface contient encore une section « Boxes locales Vagrant » qui permet de sélectionner une archive `.box`, de lire son `metadata.json` et d'enregistrer son chemin dans `scenario.vagrant.box_paths`. Cette sélection ne lance ni `vagrant box add`, ni `vagrant up`, ni une VM.

Ce mécanisme n'a pas permis d'opérationnaliser le provisionnement des cibles de `nouveau_20`. Pour préparer un déploiement réel :

1. importer manuellement les boxes avec Vagrant ;
2. vérifier leur nom, leur version et leur fournisseur avec `vagrant box list` ;
3. inventorier le catalogue depuis l'application ;
4. considérer les chemins `.box` affichés dans l'interface comme un mécanisme transitoire, et non comme une preuve que la box est installée ou exploitable.

La prochaine évolution doit associer les modèles du scénario aux boxes déjà présentes dans le catalogue Vagrant, sans réimporter automatiquement les archives.

### 9.3 VM réservées

Dans la liste des machines, cliquer sur « Accès » pour chaque VM réservée et renseigner :

- OS ;
- SSH ou WinRM ;
- backend réseau ;
- utilisateur et authentification ;
- informations du terminal graphique si les commandes et pings doivent être visibles.

Laisser « Adresse actuellement joignable sur le réseau temporaire » vide si la VM n'est pas encore démarrée. Après la reconstruction et le démarrage, l'application l'associera automatiquement au bail DHCP grâce à la MAC VMware.

Pour l'isolation finale, le nom réel de la carte d'amorçage dans l'OS reste nécessaire. Il pourra être complété après le démarrage.

### 9.4 Fichiers cibles

Pour chaque fichier de récompense :

- choisir une source locale existante ;
- indiquer le chemin de destination dans la VM ;
- saisir sa valeur.

La source sert au transfert. Seule la destination invitée apparaît dans la récompense CyGIL.

## 10. Choisir la cible compromise — étape 3

1. ouvrir « Options » sur la cible choisie ;
2. cocher « Cible compromise (hand CALDERA initial) » ;
3. choisir l'agent, le groupe et le canal C2 ;
4. fournir une adresse CALDERA libre avec préfixe dans le même sous-réseau logique ;
5. enregistrer.

Le programme impose une seule cible compromise. Les états « compromise », « hand activé » et « hand initial » représentent le même choix.

Le choix crée logiquement l'accès CALDERA vers la même VM Mininet et le même switch que la cible. Le VMnet physique CALDERA–Mininet restera distinct du VMnet cible–Mininet.

La génération du hand via l'API CALDERA peut être faite plus tard, lorsque CALDERA sera démarrée et joignable. Le bouton « Prévisualiser » n'exécute pas la commande dans la cible.

## 11. Préparer Vagrant et les VMnet — étape 4, onglet « Vagrant »

### 11.1 Inventorier Vagrant

1. choisir le répertoire des nouvelles VM ;
2. cliquer sur « Inventorier » ;
3. vérifier Vagrant, VMware Utility et le plugin `vmware_desktop` ;
4. vérifier les boxes déjà installées qui apparaissent dans l'inventaire ;
5. cliquer sur « Enregistrer les chemins » pour les autres paramètres Vagrant.

Ce bouton applique les paramètres de l'onglet Vagrant et écrit immédiatement le
scénario YAML indiqué dans « Sauvegarde active ». Les éventuels chemins d'archives
issus du mécanisme transitoire sont aussi conservés, mais ils ne remplacent pas
l'import manuel dans le catalogue Vagrant.

L'installation contrôlée de Vagrant est protégée par une case et un jeton. Elle n'a pas été qualifiée dans l'évaluation finale : privilégier une installation manuelle vérifiée et utiliser l'inventaire comme contrôle en lecture seule.

### 11.2 Inventorier et choisir les VMnet

1. cliquer sur « Inventorier les VMnet via VMREST » ;
2. choisir le VMnet d'orchestration/amorçage ;
3. cocher « DHCP VMware activé » seulement si l'inventaire le confirme ;
4. cocher la validation de l'amorçage seulement après essai réel ;
5. choisir le VMnet interne Mininet/ONOS ;
6. cliquer sur « Enregistrer les chemins ».

Les trois VMnet fondamentaux doivent être distincts.

### 11.3 Calculer les raccordements dédiés

Dans « Raccordements physiques cible ↔ Mininet » :

1. cliquer sur « Calculer les raccordements » ;
2. vérifier un VMnet dédié par cible et un autre pour CALDERA ;
3. vérifier la liste « à créer » ;
4. lire le jeton ;
5. cocher la confirmation ;
6. recopier exactement le jeton ;
7. cliquer sur « Créer et isoler les VMnet Mininet » ;
8. accepter l'UAC si Windows la demande ;
9. attendre la relecture.

Le résultat attendu est :

- connexion hôte `No` sur le VMnet interne et les VMnet dédiés ;
- connexion hôte `Yes` sur `VMnet0` et l'amorçage ;
- DHCP désactivé sur les VMnet dédiés créés pour les accès.

Ne pas confondre une VM avec un VMnet : voir une VM Mininet dans VMware ne prouve pas que son VMnet dédié existe dans l'inventaire.

## 12. Associer les VM réservées et calculer leurs adresses

### 12.1 Association VMware

1. cliquer sur « Lire les VM enregistrées » ;
2. pour chacun des quatre rôles, choisir une VM VMware différente ;
3. vérifier attentivement le nom et l'identifiant ;
4. cliquer sur « Enregistrer toutes les associations ».

Cette opération ne démarre aucune VM.

### 12.2 Adresses de management `VMnet0`

1. cliquer sur « Calculer une proposition » ;
2. vérifier le CIDR observé et les adresses proposées ;
3. vérifier que l'adaptateur Windows `VMnet0` n'utilise pas DHCP ;
4. cliquer sur « Approuver et enregistrer ces adresses » ;
5. enregistrer le scénario YAML.

L'allocation vérifie les adresses de l'hôte, les adresses occupées observées et les réponses ARP. Elle ne peut toutefois pas garantir l'absence d'une machine éteinte possédant déjà une adresse statique non documentée.

## 13. Reconstruire les cartes des VM réservées, VM éteintes

Toutes les VM réservées associées doivent être `poweredOff`. Ne pas les suspendre.

1. cliquer sur « 1. Inventorier toutes les cartes » ;
2. cliquer sur « 2. Préparer le diff » ;
3. lire pour chaque VM les cartes retirées et les cartes attendues ;
4. vérifier VMnet, indice, MAC, adresse prévue et nature temporaire/permanente ;
5. cocher les deux confirmations :
   - arrêt autorisé des VM réservées associées ;
   - suppression et recréation des cartes affichées ;
6. recopier l'empreinte du plan destructif ;
7. cliquer sur « Sauvegarder puis appliquer hors tension » ;
8. noter le jeton de restauration affiché ;
9. attendre « Cartes reconstruites et relues conformément au plan ».

L'application :

- sauvegarde chaque VMX ;
- modifie uniquement les blocs `ethernetN.*` ;
- refuse une VM démarrée ;
- relit les cartes après écriture ;
- enregistre les MAC réellement appliquées ;
- conserve une possibilité de restauration tant que les VM restent éteintes.

Ne préparez pas un diff puis ne modifiez pas VMware avant de l'appliquer. Tout inventaire changé invalide le plan.

## 14. Démarrer les VM

### 14.1 VM réservées

Démarrer manuellement dans VMware :

- CyGIL ;
- CALDERA ;
- ONOS ;
- chaque VM Mininet.

L'application ne les démarre actuellement pas.

### 14.2 VM cibles Vagrant

Le prototype peut générer un Vagrantfile, afficher les commandes prévues et calculer une empreinte du plan. Cette préparation ne constitue pas une validation du provisionnement réel. Dans `nouveau_20`, les boxes Ubuntu et Windows n'ont pas été reconnues comme sélectionnées et aucune cible n'a été créée de bout en bout par cette chaîne.

La valeur suivante ne peut être activée qu'après qualification manuelle des commandes réseau sur les images réellement importées :

```yaml
vagrant:
  guest_network_commands_validated: true
```

Cette confirmation n'a pas encore de case dédiée. Ne pas la passer à `true` pour contourner les avertissements. Après import manuel des boxes et qualification sur une copie contrôlée, l'onglet Vagrant peut servir à préparer le plan, à vérifier que seules les cibles sont mentionnées et à examiner les commandes prévues. L'exécution réelle demeure un travail futur tant que la chaîne Linux et Windows n'a pas été validée sans ambiguïté.

Les sections suivantes décrivent les opérations prévues après la présence effective des cibles. Elles n'ont pas été parcourues de bout en bout avec `nouveau_20`.

## 15. Lire les baux DHCP et compléter les noms d'interfaces

Lorsque les VM réservées sont démarrées et, à terme, lorsque les cibles ont réellement été créées :

1. revenir à « Étape 4 → Vagrant » ;
2. cliquer sur « Lire les baux DHCP du VMnet choisi » ;
3. vérifier la liste `MAC → IPv4` ;
4. vérifier le message « Adresses associées ».

L'application associe automatiquement un bail à une VM lorsque :

- la MAC d'amorçage a été relue ;
- un bail existe pour cette MAC ;
- l'accès SSH/WinRM de la VM est configuré.

Si le message indique « aucune association complète », vérifier ces trois éléments et le DHCP du bon VMnet. Ne recopiez pas au hasard une adresse observée sur une autre VM.

### Relever les noms réels dans les invités

Sous Linux :

```bash
ip -br link
nmcli device status
```

Sous Windows :

```powershell
Get-NetAdapter | Format-Table Name, InterfaceIndex, MacAddress, Status
```

Comparer les MAC pour identifier la carte d'amorçage. Dans « Accès » de chaque VM réservée, sélectionner le VMnet d'amorçage puis renseigner le nom dans l'OS, la MAC relue et l'indice VMware affiché par le diff.

Limitation actuelle : le dialogue « Configurer » d'une cible n'expose pas encore l'identité de sa carte d'isolation. Pour une cible dont le nom n'a pas été découvert automatiquement, utiliser l'éditeur YAML avancé et compléter l'entrée déjà créée, sans inventer la MAC :

```yaml
targets:
  - id: <identifiant-cible>
    # autres champs conservés
    isolation_interfaces:
      - network: VMnet19       # mettre le VMnet d'amorçage réellement choisi
        guest_name: <nom relevé dans l'OS>
        mac: <MAC relue dans VMware>
        vmware_adapter_index: 0
        disable_before_snapshot: true
```

Après « Appliquer le YAML », enregistrer le scénario. L'application invalide volontairement les anciens plans : il faut les prévisualiser de nouveau.

Attention :

- `nmcli` exige le nom invité exact de chaque interface configurée ;
- Netplan et PowerShell peuvent s'appuyer sur la MAC pour les cartes permanentes ;
- l'isolation finale exige toujours le nom invité de la carte temporaire ;
- ne pas désactiver la carte d'amorçage à cette étape.

## 16. Appliquer la configuration réseau dans les OS — étape 5

Les cartes VMware existent déjà, mais les IP ne sont pas encore nécessairement écrites dans les OS.

1. ouvrir « Contrôle du banc → Commandes » ;
2. cliquer sur « Prévisualiser toute la configuration réseau » ;
3. lire chaque commande et vérifier VM, canal, adresse, interface, IP, préfixe, route et DNS ;
4. laisser « Mode dry-run » coché pour une première exécution de contrôle ;
5. cocher « Je confirme l'exécution du plan exact affiché » ;
6. cliquer sur « Exécuter le plan affiché » ;
7. pour l'exécution réelle, décocher le dry-run, recopier l'empreinte et confirmer de nouveau ;
8. exécuter le plan réel.

Le programme rejoint les VM par leur adresse DHCP temporaire, puis applique les configurations permanentes :

- VM réservées : management et interfaces de scénario/autres ;
- cibles : interface de scénario ;
- carte d'amorçage : laissée en DHCP jusqu'à l'isolation finale.

Si une seule VM a un accès ou un backend incomplet, la prévisualisation globale peut être refusée. Corriger cette VM avant de relancer.

## 17. Déposer les fichiers et préparer CALDERA

Toutes ces opérations doivent être terminées avant l'isolation.

### Fichiers

1. ouvrir l'onglet « Fichiers » ;
2. cliquer sur « Prévisualiser tous les transferts » ;
3. vérifier chaque source et destination ;
4. exécuter d'abord en dry-run, puis réellement avec confirmation et jeton.

Pour SCP, utiliser une clé ou un agent SSH. Pour WinRM, la variable de secret doit exister dans l'environnement du processus de l'application.

### CALDERA

L'intégration réelle de CALDERA reste à qualifier. Les actions suivantes constituent le parcours prévu lorsque la version, l'endpoint et le format de réponse du banc auront été confirmés.

1. vérifier que CALDERA est joignable ;
2. renseigner l'URL, la clé API et l'endpoint ;
3. cliquer sur « Tester la connexion » ;
4. prévisualiser le hand de la cible compromise ;
5. générer la commande via l'API ;
6. vérifier la commande générée avant toute exécution dans la cible.

La clé API CALDERA reste en mémoire et n'est pas enregistrée dans le scénario.

## 18. Démarrer et confirmer les pings

Dans « Contrôle du banc → Pings » :

1. choisir la VM source et la destination ;
2. cliquer sur « Choisir le chemin et prévisualiser » ;
3. si plusieurs chemins existent, sélectionner explicitement le bon ;
4. exécuter d'abord en dry-run ;
5. exécuter réellement avec la confirmation et l'empreinte ;
6. vérifier visuellement le terminal de ping dans la VM source ;
7. répéter pour toutes les communications exigées par le scénario.

Pour ouvrir un terminal visible, l'utilisateur graphique, le programme de terminal et, sous Linux, `DISPLAY` doivent être configurés et la case « Ouverture du terminal visible validée » doit correspondre à un essai réel.

## 19. Isoler le réseau temporaire

Cette opération doit être la dernière commande envoyée par SSH/WinRM sur le réseau d'amorçage.

Avant de continuer, vérifier que :

- les configurations IP sont appliquées ;
- les fichiers sont déposés ;
- les hands sont prêts ;
- les pings nécessaires sont lancés ;
- le nom de la carte temporaire est connu dans chaque VM.

Dans « Isolation et snapshots » :

1. choisir le VMnet temporaire ;
2. cliquer sur « Prévisualiser l'isolation » ;
3. lire une commande par VM ;
4. exécuter en dry-run ;
5. exécuter réellement avec confirmation et jeton ;
6. attendre la rupture attendue des connexions ;
7. cliquer sur « Vérifier maintenant l'injoignabilité ».

Ne pas retirer les adaptateurs dans VMware. L'air gap attendu est obtenu en désactivant la carte dans chaque OS.

## 20. Autoriser et créer les snapshots

La séquence réelle reste verrouillée tant que toutes les preuves ne sont pas réunies.

La création complète des snapshots de `nouveau_20` n'a pas été démontrée. Les contrôles ci-dessous décrivent les préconditions préparées par le prototype.

1. cocher « Je confirme que l'état du banc est satisfaisant » ;
2. cocher « Je confirme que les terminaux de ping attendus sont actifs » ;
3. cliquer sur « Enregistrer ces confirmations » ;
4. cliquer sur « Vérifier les VM démarrées » ;
5. vérifier que toutes les VM réservées et toutes les cibles marquées pour snapshot sont démarrées ;
6. choisir la politique de mémoire ;
7. vérifier le chemin de `vmrun.exe` ;
8. cliquer sur « Prévisualiser les snapshots » ;
9. lire toutes les commandes ;
10. conserver le dry-run pour un premier essai ;
11. pour le réel, décocher le dry-run, cocher la confirmation et recopier l'empreinte ;
12. cliquer sur « Démarrer la séquence de snapshots ».

Avec `vmrun 1.17`, choisir « Ne pas inclure la mémoire ». L'implémentation refuse actuellement de promettre un snapshot avec mémoire, car cette option n'est pas exprimable par cette version de `vmrun`.

Un échec interrompt la séquence afin de ne pas présenter un ensemble partiel comme cohérent.

## 21. Valider, enregistrer et générer les fichiers — étape 6

### Validation

Lire tous les éléments de « Problèmes détectés » :

- une erreur doit être corrigée ;
- un avertissement doit être compris et accepté seulement s'il correspond à une limitation connue ;
- vérifier en particulier l'unique cible compromise, les MAC relues, les chemins de fichiers et les noms d'interfaces d'isolation.

### Sauvegarde

Cliquer sur « Enregistrer le scénario » avant la génération et après tout changement important.

### Génération

- « Générer un brouillon » permet d'inspecter les quatre YAML sans exiger toutes les MAC finales ;
- « Générer les YAML finaux » exige les MAC réellement relues et vérifiées dans VMware ;
- vérifier le dossier `generated` et le manifeste produit ;
- ne pas placer dans le contrôle de versions un fichier contenant des secrets injectés.

Pour `nouveau_20`, seuls les quatre YAML de préparation et leur manifeste ont été obtenus. La génération finale reste bloquée par les boxes non reconnues, les réseaux permanents Mininet à confirmer, le hand CALDERA incomplet, le nom invité de l'interface CALDERA, la politique de mémoire des snapshots et les commandes CyGIL absentes. Les copies publiées avec le dépôt ont été assainies : les identifiants injectés ont été retirés et les empreintes du manifeste ont été recalculées.

L'éditeur YAML avancé remplace le scénario courant lorsqu'on clique sur « Appliquer le YAML ». Une erreur d'indentation ou de type est refusée. Ne l'utiliser que pour un champ qui n'est pas encore exposé dans l'interface.

## 22. Tableau des confirmations importantes

| Confirmation | Quand la cocher | Erreur fréquente |
|---|---|---|
| Exécution des commandes hôte | Après lecture du plan hôte | Oublier la case avant une action UAC |
| Plage MAC validée | Après validation pour la version VMware installée | Cocher sans source réelle |
| DHCP du VMnet d'amorçage | Lorsque VMware confirme le DHCP | Confondre avec `VMnet0` |
| Accès d'amorçage validé | Après test avec les boxes et VM réelles | Le déclarer avant tout essai |
| Création/isolation des VMnet | Après lecture des VMnet attribués | Recopier un ancien jeton |
| Arrêt des VM réservées | Lorsque les VM associées sont réellement éteintes | VM suspendue au lieu d'éteinte |
| Reconstruction destructive | Après lecture complète du diff | Modifier VMware après le diff |
| Exécution Vagrant | Seulement après qualification Linux et Windows sur une copie contrôlée | Confondre un plan préparé avec un déploiement validé |
| Exécution invitée | Après lecture des commandes | Oublier de désactiver le dry-run pour le réel |
| État du banc et pings | Après observation réelle | Confirmer un ping seulement prévisualisé |
| Snapshots | Après air gap et vérification des VM démarrées | Demander la mémoire avec `vmrun 1.17` |

## 23. Diagnostic des messages courants

### « Inventoriez VMnet0 avant de calculer ses adresses »

Cliquer sur « Calculer une proposition ». Cette action inventorie l'adaptateur Windows `VMnet0` et son CIDR.

### « L'adaptateur Windows VMnet0 ne doit pas utiliser DHCP »

Ouvrir les propriétés IPv4 de l'adaptateur Windows VMware Network Adapter VMnet0 et lui attribuer une configuration statique. Désactiver le DHCP dans VMware ne suffit pas.

### « Créez et relisez d'abord les VMnet dédiés manquants »

Inventorier les VMnet, calculer les raccordements, exécuter « Créer et isoler les VMnet Mininet », puis attendre la relecture. Les VM concernées et les VMnet sont deux objets différents.

### « La relecture ne confirme pas la politique Host Connection complète »

Vérifier dans l'inventaire :

- `Yes` pour `VMnet0` et l'amorçage ;
- `No` pour le VMnet interne et les VMnet dédiés.

### « La plage MAC statique doit être confirmée »

Dans « Paramètres → Politique MAC statique VMware validée », vérifier version, bornes et source, cocher la confirmation et cliquer sur « Appliquer les paramètres ».

### « Accès invité incomplet »

Vérifier OS, canal, utilisateur, authentification et adresse DHCP associée. Relire les baux après le démarrage des VM.

### « Backend réseau invité non confirmé »

Choisir Netplan, `nmcli` ou PowerShell dans la configuration de la VM.

### « Nom invité manquant pour l'interface »

Relever le nom par MAC dans l'OS et le renseigner dans « Accès ». Il ne doit pas être inventé à partir du numéro `ethernetN` de VMware.

### VMREST renvoie 403 lors de la création d'un VMnet

VMREST doit être démarré par le bouton de l'application et l'UAC doit être accepté. Vérifier aussi l'authentification et les droits VMware.

### VMREST renvoie 400/404 sur un inventaire

Vérifier que l'application et VMREST ont été redémarrés après une mise à jour, que la version de l'API correspond à celle prise en charge et que le VMnet sélectionné existe. Les baux doivent être lus sur le VMnet d'amorçage DHCP, pas sur un VMnet sans DHCP.

### Le « Contrôle du banc » affiche d'anciennes machines

Enregistrer le scénario puis le recharger. Dans la version actuelle, toute la section est reconstruite depuis le scénario actif et les anciens plans sont invalidés. Si la liste reste incorrecte, arrêter complètement l'application et relancer le serveur.

## 24. Règles de reprise après une erreur

- ne pas cliquer plusieurs fois sur une action en cours ;
- conserver le message complet et la trace d'erreur ;
- ne pas considérer une cible comme gérée par Vagrant tant que sa création n'a pas réellement abouti ;
- conserver un éventuel dossier `.vagrant` et les journaux pendant un diagnostic contrôlé ;
- après un changement de topologie, recalculer les raccordements, le diff et le plan Vagrant ;
- après un changement de box installée, refaire l'inventaire puis recalculer le plan ;
- après un changement dans VMware, refaire l'inventaire global avant une reconstruction ;
- en cas d'erreur après sauvegarde d'un VMX, conserver le manifeste et le jeton de restauration ;
- ne restaurer les VMX que lorsque les VM concernées sont éteintes.

## 25. Checklist condensée

### Préparation prise en charge par le prototype

- [ ] scénario enregistré et topologie logique cohérente
- [ ] réseaux, instances Mininet, switches et liens déclarés
- [ ] exactement une VM ONOS et une cible compromise
- [ ] VMnet0, réseau d'amorçage et réseau interne distincts
- [ ] VMREST opérationnel pour les inventaires
- [ ] VM réservées associées de façon unique
- [ ] adresses VMnet0 calculées et approuvées
- [ ] raccordements VMnet calculés et examinés
- [ ] inventaire global et différentiel VMware relus
- [ ] brouillons des quatre YAML générés sans secrets

### Conditions restant à qualifier pour un déploiement complet

- [ ] boxes importées manuellement et associées sans ambiguïté aux modèles
- [ ] au moins une cible Linux et une cible Windows créées avec succès
- [ ] accès SSH/WinRM et backends réseau testés sur les images réelles
- [ ] baux DHCP et noms d'interfaces découverts par MAC
- [ ] réseaux permanents des VM Mininet confirmés
- [ ] configuration réseau invitée appliquée et vérifiée
- [ ] hand CALDERA généré et testé
- [ ] fichiers et commandes CyGIL renseignés
- [ ] pings visibles lancés et observés
- [ ] interfaces temporaires désactivées et injoignabilité vérifiée
- [ ] politique de snapshots confirmée et snapshots créés
- [ ] MAC finales relues et validation sans erreur
- [ ] quatre YAML finaux transférés, scénario enregistré et exécuté dans CyGIL
