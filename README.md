# CyGIL Scenario Orchestrator

Ce dépôt contient le prototype d'un orchestrateur externe destiné à faciliter la préparation de nouveaux scénarios pour un banc CyGIL exécuté avec VMware Workstation. L'application centralise la description d'un scénario, vérifie sa cohérence, prépare les opérations VMware et produit les quatre configurations YAML attendues par CyGIL.

## État du prototype

Le prototype permet actuellement de :

- créer ou charger un scénario canonique YAML ;
- représenter séparément la projection VMware et la topologie SDN ;
- synchroniser les adresses des instances Mininet avec leurs VM d'infrastructure ;
- associer automatiquement toutes les instances Mininet à l'unique VM ONOS ;
- préparer l'hôte Windows, OpenSSH et VMREST;
- inventorier les VM et les VMnet avec VMREST ;
- lire les baux DHCP du réseau d'orchestration ;
- calculer les raccordements cible–Mininet et CALDERA–Mininet ;
- proposer les adresses statiques de management des VM réservées ;
- calculer le différentiel entre les cartes VMware observées et attendues ;
- préparer les commandes invitées, les pings, l'isolation et les snapshots ;
- produire des brouillons des configurations `network`, `command_center`, `reward` et `obs`, accompagnés d'un manifeste d'intégrité.

Le déploiement complet d'un nouveau scénario n'a pas été validé de bout en bout. En particulier, le provisionnement des VM cibles avec Vagrant, la qualification des accès invités, la génération du hand CALDERA, les snapshots, le transfert final des fichiers, les commandes de lancement et l'enregistrement dans CyGIL restent à finaliser sur le banc réel. Les sorties générées ne sont donc pas des artefacts finaux tant que toutes les validations ne sont pas satisfaites.

## Scénarios fournis

- `examples/scenario_two.yml` conserve le scénario historique de référence du banc. Il contient des chemins propres à l'environnement d'origine et n'est pas un modèle portable.
- `examples/nouveau_20.yml` est la copie publiable du démonstrateur construit depuis un canevas vide pour le rapport final.



Les fichiers `generated/nouveau_20_*` sont des copies assainies des brouillons obtenus pendant l'étude. Les identifiants injectés ont été retirés et les empreintes du manifeste ont été recalculées avant publication. Ces fichiers conservent les avertissements qui empêchent encore une compilation finale et ne constituent pas une sortie reproductible à partir d'un banc vierge.

## Vagrant et les VM cibles

Vagrant est réservé aux nouvelles VM cibles et ne doit jamais prendre en charge les VM CyGIL, CALDERA, ONOS ou Mininet déjà présentes.

Les boxes doivent être importées manuellement dans le catalogue local Vagrant. Le prototype sait inventorier Vagrant, ses plugins et ses boxes, et il peut préparer un Vagrantfile et un plan de commandes. L'ancien mécanisme de sélection d'une archive `.box` locale reste présent dans l'interface et valide son fournisseur, mais il n'a pas permis de rendre le provisionnement de `nouveau_20` opérationnel. 

## Installation

Prérequis : Python 3.11 ou une version plus récente.

```powershell
cd cygil_scenario_orchestrator
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
```

L'installation modifiable `-e` permet d'utiliser les changements apportés dans `src/cygil_builder` au prochain démarrage, sans réinstallation.

## Démarrage de l'interface

```powershell
.venv\Scripts\cygil-scenario-gui
```

Ouvrir ensuite `http://127.0.0.1:8080`. Utiliser `Ctrl+C` dans le terminal pour arrêter le serveur.

L'assistant graphique est organisé en six étapes : conception du réseau, configuration des VM, préparation du hand, configuration de l'hôte, contrôle du banc, puis validation et génération.


## Sécurité et données locales

- Les mots de passe et clés API réels ne doivent jamais être placés dans un scénario ou dans Git.
- Les identifiants VMREST sont conservés dans le Gestionnaire d'identification Windows ; le scénario ne contient que leurs noms de référence.
- La clé API CALDERA reste en mémoire.
- Les certificats, clés privées, journaux, inventaires VMware, sauvegardes VMX et états de déploiement restent sous `work/` et sont ignorés par Git.
- Les opérations administratives ou susceptibles de modifier VMware doivent être prévisualisées et confirmées.
- Les adaptateurs temporaires restent attachés à VMware ; l'isolation est réalisée dans les systèmes invités. Aucun retrait de carte à chaud ne doit être effectué.

## Organisation du dépôt

```text
src/cygil_builder/   application, services et compilateurs
tests/               tests de régression
examples/            scénarios de démonstration et de référence
profiles/            profil d'observation de référence
docs/                documentation technique et points à qualifier
generated/           seuls les brouillons publiables de nouveau_20 sont suivis
work/                données locales d'exécution, toujours ignorées
```

Le parcours détaillé, les limites actuelles et les opérations restant à qualifier sont décrits dans [`Guide d'utilisation.md`](Guide%20d'utilisation.md). Le guide de lecture du code se trouve dans [`docs/GUIDE_DU_CODE.md`](docs/GUIDE_DU_CODE.md).

# cygil_scenario_orchestrator
Prototype pour générer des scénarios d'entrainement RL pour CyGIL
