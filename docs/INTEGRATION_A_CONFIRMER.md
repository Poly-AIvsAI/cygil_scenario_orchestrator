# Informations du banc à confirmer avant activation réelle

Le prototype fonctionne en préparation et en simulation. Les points suivants sont volontairement laissés configurables pour éviter une action incorrecte sur le laboratoire.

1. **VMware** : Vagrant avec `vmware_desktop` est retenu uniquement pour créer les cibles; `vmrest` fournit l'inventaire et l'état d'alimentation; la reconstruction réseau des seules VM réservées associées remplace uniquement les blocs `ethernetN.*` de leur VMX sauvegardé, VM `poweredOff`; `vmrun` crée les snapshots de toutes les VM du scénario.
2. **Boxes de VM cibles** : importer manuellement les boxes dans le catalogue Vagrant, vérifier leur fournisseur VMware Desktop, puis associer chaque modèle du scénario à une box installée. L'ancien sélecteur d'archives `.box` valide `metadata.json`, mais il n'a pas permis d'opérationnaliser le provisionnement de `nouveau_20`.
3. **Configuration dans l’OS** : WinRM/SSH disponibles, comptes techniques et commandes validées pour appliquer IP, préfixe, passerelle et l'option de désactivation DNS.
4. **VM réservées** : chemins VMX, IP de management et IP de scénario de CALDERA, ONOS et d'une ou plusieurs VM Mininet. Toutes les VM réservées utilisent VMnet0; aucune cible ne l'utilise. Chaque `MininetInstance` référence sa VM par `infrastructure_vm_id` et l'unique contrôleur par `onos_controller_id`.
5. **CyGIL** : répertoire final des quatre YAML, commandes exactes de lancement et commande/API d’enregistrement du scénario.
6. **CALDERA** : version utilisée, endpoint exact de génération du hand, corps de requête, format de réponse et méthode de lancement sur Windows et Linux. L'interface rend actuellement cet endpoint configurable et attend un champ `command` ou `deploy_command`.
7. **Mininet/ONOS** : scripts existants, arguments, répertoires d’exécution et états permettant de confirmer qu’ils sont prêts.
   Les liens locaux OVS et les tunnels GRE inter-instance sont bidirectionnels; tous les switches utilisent le même ONOS sur TCP 6653.
8. **Champ `subnet`** : confirmer si CyGIL attend l’adresse réseau sans préfixe, comme dans `scenario_two`, ou une autre sémantique.
9. **Découverte** : matrice de pings attendue et conditions de réussite.
10. **Orchestration et amorçage** : ces deux termes désignent le même VMnet host-only, distinct de VMnet0, connecté temporairement à toutes les VM et autorisé à fournir le DHCP VMware. Après le lancement des pings, désactiver l'interface dans chaque OS invité comme dernière commande SSH/WinRM; l'adaptateur VMware reste attaché et n'est jamais retiré à chaud.
11. **Snapshots** : VM incluses, nommage, conservation et comportement si un snapshot du même nom existe déjà. Les VM doivent être démarrées et les pings exigés doivent être en cours au moment de la capture.
12. **vmrest** : la version installée est `vmrest 1.2.1 build-17198959`; son démarrage utilise `-c`, `-k` et `-p`. Cette version ne prend pas en charge `-i`. Le fichier `openssl.cnf` est choisi par l'utilisateur. La commande interactive `vmrest -C` s'ouvre dans une console Windows temporaire; aucun mot de passe n'est transmis par un pipe.
13. **Console invitée** : confirmer pour chaque VM son OS, son canal SSH/WinRM, son utilisateur, son port, sa méthode d'authentification, sa politique d'élévation et le mécanisme permettant d'ouvrir un terminal dans sa session graphique. Les commandes libres et les pings doivent être visibles dans la VM elle-même et ne jamais bloquer NiceGUI.
14. **Isolation invitée** : confirmer pour chaque VM le nom, l'index et la MAC de chaque interface à désactiver. La commande de désactivation sera la dernière commande SSH/WinRM sur cette interface; le retrait à chaud VMware reste interdit.
15. **Fichiers invités** : fournir pour chaque dépôt la source locale, la VM, la destination invitée, les privilèges nécessaires et indiquer si le fichier devient une cible de récompense CyGIL.
16. **Plage MAC statique** : renseigner dans les paramètres hôte la version exacte de VMware Workstation, la première et la dernière MAC autorisées ainsi que la preuve locale de validation. Le générateur reste bloqué tant que cette politique n'est pas explicitement confirmée; aucune plage VMware n'est codée par défaut.
17. **Raccordements cible/VMnet/Mininet** : chaque interface de cible possède un VMnet dédié et impose une carte correspondante sur la VM Mininet qui la dessert, même lorsque plusieurs cibles partagent le même sous-réseau CyGIL. L'application calcule les noms libres, crée les VMnet host-only manquants via VMREST après confirmation, puis relit l'inventaire.

Avant chaque démarrage, l'application vérifie la redirection `portproxy` de l'adresse de l'hôte et du port API vers `127.0.0.1` sur le même port. Elle la crée avec UAC seulement si elle est absente et refuse d'écraser une redirection conflictuelle.

## Fonctions maintenant préparées

- inventaire Vagrant, plugins, boxes installées et Vagrant VMware Utility à la demande;
- installation officielle prévisualisée et protégée par un jeton propre au plan;
- sélection d'une archive `.box` et validation de son fournisseur, conservées comme mécanisme transitoire sans import automatique;
- inventaire des VM enregistrées par `vmrest` et association manuelle aux VM réservées;
- protection des identifiants VMware réservés contre l'adaptateur Vagrant;
- détection du CIDR de VMnet0, contrôle de son adressage statique et proposition d'adresses pour les seules VM réservées;
- Vagrantfile limité aux cibles, sans carte VMnet0, avec amorçage DHCP et correspondance explicite des VMnet d'accès, indices de cartes et MAC;
- plan séquentiel `status`/`up`, `--no-destroy-on-error`, jeton lié aux commandes exactes et exécution hors de la boucle NiceGUI;
- journal persistant par cible dans `work/deployments/<scenario>/state.json` ;
- inventaire global en lecture seule de toutes les VMX et de leurs cartes, avec normalisation des MAC et instantané SHA-256 persisté sous `work/vmware-inventory/`;
- validation globale des MAC demandées contre les VM hors scénario, anciennes cibles et VM réservées;
- dérivation du diff `observé -> attendu` pour CyGIL, CALDERA, Mininet et ONOS, incluant VMnet0 et le VMnet d'amorçage;
- allocation d'un VMnet par accès cible-Mininet et d'un VMnet séparé CALDERA-Mininet pour l'unique cible compromise;
- sauvegarde de retour de chaque VMX sélectionné, empreinte du plan, confirmation destructive distincte, refus des VM démarrées/suspendues et restauration par un second jeton;
- relecture des cartes après application et mode de compilation finale qui exige les MAC VMware effectivement observées.

## Valeurs et qualifications encore requises avant un premier déploiement

- importer manuellement les boxes, puis confirmer SSH/WinRM, l'utilisateur et la méthode d'authentification de chaque image ;
- associer sans ambiguïté les modèles Ubuntu et Windows du scénario aux boxes présentes dans `vagrant box list` ;
- choisir le VMnet host-only d'amorçage et confirmer son DHCP temporaire; l'inventaire du VMnet et des baux existe, mais la création/modification administrative doit encore être qualifiée sur cette version de Workstation;
- confirmer chaque correspondance interface invitée / indice VMware / VMnet Mininet;
- qualifier la plage MAC statique sur la version VMware Workstation installée et conserver la preuve utilisée dans le scénario;
- tester la sauvegarde et la restauration VMX sur une copie contrôlée avant toute reconstruction du banc réel;
- valider sur une VM Linux et une VM Windows les commandes invitées qui appliquent IP, préfixe, passerelle et désactivent le DNS sur les interfaces Mininet concernées;
- ne pas ajouter de serveurs ni de champs DNS au YAML network de CyGIL : le besoin porte sur une option de configuration de l'interface dans l'OS invité;
- ne jamais tenter le retrait à chaud d'un adaptateur VMware : un essai réel a provoqué une erreur fatale;
- qualifier sur chaque image les commandes réseau et de désactivation ainsi que la rupture SSH/WinRM attendue;
- renseigner le terminal graphique, l'utilisateur de session et, sous Linux, `DISPLAY`, puis valider l'ouverture réelle dans la VM;
- choisir les paires de ping obligatoires; le centre de contrôle ne propose que des routes possédant un réseau de scénario commun;
- choisir la politique de snapshot. `vmrun 1.17` ne permet pas d'exprimer l'inclusion de la mémoire; l'application refuse donc cette promesse tant qu'un mécanisme Workstation compatible n'est pas qualifié;
- renseigner et tester chaque dépôt source/destination. Le format historique reste lisible et seule la destination invitée entre dans la récompense CyGIL.

Une fois ces valeurs fournies, les services réels pourront être qualifiés progressivement sans modifier le modèle canonique ni les quatre compilateurs. Le mode de simulation doit rester disponible jusqu'à la validation de chaque opération sur une copie contrôlée du banc.
