# Rapport pipeline ExtPoCGen — lot v3 (20 ext JOIGNABLES, pipeline corrigé P1–P5)

Rejeu de **20 extensions joignables toutes NON-confirmées auparavant** (0/20 avant) avec le pipeline
corrigé : résolveur handler↔canal multi-hop/stateful (P1), patterns KB (P2), sonde d'entrée de
listener du harness (P3), diagnostic GOD affiné (P5). Oracle différentiel inchangé (0 FP par construction).

## Funnel

- 20 joignables → **10/20 PoC confirmées** par l'oracle (**avant : 0/20**).
- 0 faux positif (toutes `attacker_controlled = true`).
- Diagnostic GOD run-level : 10 confirmed_no_action, 6 poc_llm_deficiency, 4 contract_gap.
- Coût Stage 3 (lot entier) : **$0.3452** · temps séquentiel ≈ 67 min.

## Tableau

| ext | nom | modèle | conf | avant | GOD | wall |
|---|---|---|---|---|---|---|
| gen-AUTH04 | __MSG_extName__ | chat/4 | **OUI** | non | confirmed_no_action | 244.0s |
| gen-AUTH05 | TDOS | chat/4 | **OUI** | non | confirmed_no_action | 121.9s |
| gen-BHT01 | Galago bookmarks | chat/4 | **OUI** | non | confirmed_no_action | 49.9s |
| gen-BHT02 | 鲲圭豆荚 | reasoner/12 | non | non | poc_llm_deficiency | 387.3s |
| gen-BHT17 | Buxenger | chat/4 | non | non | contract_gap | 209.0s |
| gen-CM01 | LiquidVoice PCI | chat/4 | **OUI** | non | confirmed_no_action | 100.3s |
| gen-CM02 | __MSG_appName__ | reasoner/12 | **OUI** | non | confirmed_no_action | 162.1s |
| gen-COOK02 | Captain Data | reasoner/12 | non | non | poc_llm_deficiency | 233.7s |
| gen-DH01 | BPTM Local File Vi | chat/4 | non | non | poc_llm_deficiency | 154.7s |
| gen-DH03 | 记忆体 | chat/4 | non | non | contract_gap | 290.3s |
| gen-DH05 | Go Pipeline Filter | chat/4 | non | non | poc_llm_deficiency | 60.1s |
| gen-DM01 | HTTP Commander | chat/4 | **OUI** | non | confirmed_no_action | 182.9s |
| gen-DM06 | Расширение для Lan | chat/4 | **OUI** | non | confirmed_no_action | 143.4s |
| gen-DM13 | QuickDrag for Chro | reasoner/12 | **OUI** | non | confirmed_no_action | 403.7s |
| gen-DT02 | __MSG_appName__ | chat/4 | **OUI** | non | confirmed_no_action | 225.0s |
| gen-EC02 | TheHub Click To Di | chat/4 | non | non | poc_llm_deficiency | 288.7s |
| gen-EC04 | TheHub | reasoner/12 | non | non | poc_llm_deficiency | 296.5s |
| gen-ESI01 | g7 st card plugin | chat/4 | non | non | contract_gap | 132.1s |
| gen-ESI02 | Fabasoft Folio | chat/4 | **OUI** | non | confirmed_no_action | 126.2s |
| gen-ESI03 | Zebra Printing | chat/4 | non | non | contract_gap | 196.0s |

## Avant / après

Les 20 extensions étaient **toutes à 0 confirmé** dans les lots précédents (sélection ex-non-confirmées).
Le pipeline corrigé en confirme **10**, sans relâcher la soundness (0 FP). Les non-confirmées restantes
se répartissent entre **contract_gap** (relais/état encore trop durs pour le générateur malgré le contrat)
et **poc_llm_deficiency** (forme/timing), plus aucune imputée à l'oracle ni au modèle de menace.

## Confirmées

gen-AUTH04 gen-AUTH05 gen-BHT01 gen-CM01 gen-CM02 gen-DM01 gen-DM06 gen-DM13 gen-DT02 gen-ESI02
