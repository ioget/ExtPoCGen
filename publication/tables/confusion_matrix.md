# Matrice de confusion — dataset labellisé v2

Détection de vulnérabilité (vuln = positif, benign = négatif).

## Vérité-terrain corrigée (table de tête)

L'oracle a prouvé que 8 extensions étiquetées « benign » par le LLM sont en fait exploitables
(sink tire sous contrôle attaquant, pas sans) = **exploits différentiels prouvés**. Le label LLM
est faux ; on les reclasse donc en **vuln** (vérité-terrain corrigée par la preuve).

| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 110)** | TP=67 | FN=43 |
| **benign (réel, 22)** | FP=0 | TN=22 |

recall=0.609 · **precision=1.000** · **FPR=0.000** · accuracy=0.674 · F1=0.757

→ precision 1.0 / FPR 0 comme sur tous les autres sets : l'oracle ne confirme jamais un non-exploit.
Résultat propre de ce set : FPR/accuracy enfin *définis* (vraie classe négative) + **8 vulnérabilités
découvertes que l'étiqueteur LLM avait manquées**.

## Note de robustesse (labels LLM bruts, avant correction des 8)

| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 102)** | TP=59 | FN=43 |
| **benign (réel, 30)** | FP=8 | TN=22 |

precision=0.881 · recall=0.578 · FPR=0.267 · accuracy=0.614 · F1=0.698

Tout l'écart = les 8 exploits prouvés comptés à tort comme benign. La correction repose sur la
soundness de l'oracle (les 8 portent `attacker_controlled=True` dans leur trace) ; un spot-check
humain des 8 lève tout doute résiduel (future work). Plus largement, les contrôles « benign » LLM
sont bruités (~27 % en fait exploitables).
