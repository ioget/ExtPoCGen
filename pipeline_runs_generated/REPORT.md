# Rapport pipeline ExtPoCGen — 10 extensions générées (ChromeSecBench)

Échantillon : **1 extension par catégorie de scénario** (AUTH, BHT, CM, COOK, DH, DM, DT, EC, ESI, WA).
Pipeline complet exécuté pour chacune : Stage 1 statique (CoCo + DoubleX×2) → Stage 2 fact sheet →
Stage 3 génération PoC + oracle différentiel (Chrome isolé) → Stage 4 GOD agent.

## Funnel (soundness-first)

- 10 extensions → **2 has-candidate**, 7 clean, 1 incomplete (parser)
- **1 PoC confirmée(s) par l'oracle** (0 faux positif par construction)
- coût LLM Stage 3 total : **$0.1680**

## Tableau par extension

| ext | nom | modèle | triage | findings | confirmed | GOD | malware |
|---|---|---|---|---|---|---|---|
| gen-DT01 | ReqBin HTTP Client | A | has-candidate | 2 | **0** | poc_llm_deficiency | None |
| gen-EC01 | Amazon Seller Tool | A | has-candidate | 3 | **0** | poc_llm_deficiency | None |
| gen-BHT01 | Galago bookmarks | B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-CM01 | LiquidVoice PCI | A+B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-COOK01 | __MSG_appName__ | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-DH01 | BPTM Local File Vi | A+B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-DM01 | HTTP Commander | A+B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-ESI01 | g7 st card plugin | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-WA01 | __MSG_appName__ | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-AUTH01 | CertiFirm.EU | A | incomplete-analysis | 0 | **1** | confirmed_no_action | clean |

## Lecture
- **has-candidate** = l'analyse statique a trouvé un flot attaquant→sink ; le chemin tools_on génère une PoC et l'oracle tranche.
- **clean** = surface d'attaque présente mais aucun flot exploitable ; l'architecture n'invente pas d'exploit (0-FP).
- **incomplete-analysis** = l'analyseur (esprima) a échoué à parser → verdict suspendu, pas « clean ».
- **confirmed** vient uniquement de l'oracle différentiel (sink déclenché AVEC l'attaquant ET pas sans).
