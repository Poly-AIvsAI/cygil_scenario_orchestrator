# Scénarios d'exemple

Ce dossier distingue trois usages.

- `scenario_demo.yml` est un exemple générique, non productif et portable. Il sert de base aux tests qui n'ont pas besoin de reproduire le banc historique.
- `scenario_two.yml` est une donnée de référence héritée du scénario CyGIL initial. Ses noms d'utilisateurs, chemins VMX et adresses décrivent l'environnement d'origine ; ils doivent être adaptés avant toute utilisation sur une autre machine.
- `nouveau_20.yml` est une copie publiable du démonstrateur présenté dans le rapport final. Les états locaux de VMREST, les chemins de certificat, les chemins de clés et les chemins d'archives `.box` ont été retirés. Le fichier conserve la topologie et les associations utiles à l'analyse, mais ne constitue pas un scénario directement déployable.

Les scénarios de travail produits par l'interface restent dans `work/` et ne doivent pas être ajoutés à Git. Les brouillons CyGIL associés à `nouveau_20` sont conservés dans `generated/` uniquement comme résultats de préparation ; ils ne représentent pas une génération finale validée.
