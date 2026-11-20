# Matrice de confusion — dataset labellisé v2

Détection de vulnérabilité (vuln = positif, benign = négatif ; classe malware exclue de l'étude).

**Vérité-terrain :** l'oracle différentiel a prouvé que 8 extensions étiquetées « benign » par le LLM
sont en fait exploitables (le sink tire sous contrôle attaquant, pas sans = `attacker_controlled=True`).
Le label LLM était faux ; ces 8 sont donc **reclassées `vuln` dans le dataset** (`publication/datasets/labels.csv`),
portant la vérité-terrain à **113 vuln / 22 benign / 15 malware**. Parmi elles, 110 vuln et 22 benign
sont chargeables et testées (3 vuln non chargeables).

Ids reclassés : `benign-AUTH01, benign-AUTH06, benign-BHT02, benign-BHT05, benign-BHT15, benign-BHT20, benign-BHT23, benign-BHT24`.

## DeepSeek (générateur de référence)

| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 110)** | TP=67 | FN=43 |
| **benign (réel, 22)** | FP=0 | TN=22 |

recall=0.609 · **precision=1.000** · **FPR=0.000** · FNR=0.391 · accuracy=0.674 · F1=0.757

## Claude Haiku 5.5 (même dataset, même validation)

| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 110)** | TP=36 | FN=74 |
| **benign (réel, 22)** | FP=0 | TN=22 |

recall=0.327 · **precision=1.000** · **FPR=0.000** · FNR=0.673 · accuracy=0.439 · F1=0.493

→ **precision 1.0 / FPR 0 pour les deux modèles** : l'oracle ne confirme jamais un non-exploit.
La soundness est **indépendante du générateur** ; seul le recall en dépend (Haiku ≈ ½ du recall de
DeepSeek). Les 2 benign-exploitables trouvés par Haiku (`BHT05`, `BHT23`) sont un sous-ensemble strict
des 8 de DeepSeek — aucun faux positif réel.

## Note de robustesse (labels LLM bruts, avant reclassification)

| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 102)** | TP=59 | FN=43 |
| **benign (réel, 30)** | FP=8 | TN=22 |

precision=0.881 · recall=0.578 · FPR=0.267 · accuracy=0.614 · F1=0.698 (DeepSeek)

Tout l'écart = les 8 exploits prouvés comptés à tort comme benign avant correction. La reclassification
repose sur la soundness de l'oracle (les 8 portent `attacker_controlled=True` dans leur trace).
Plus largement, les contrôles « benign » générés par LLM sont bruités (~27 % en fait exploitables).
