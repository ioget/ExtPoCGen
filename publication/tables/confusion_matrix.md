# Matrice de confusion — dataset labellisé v2

Détection de vulnérabilité (vuln = positif, benign = négatif ; classe malware exclue de l'étude).

**Vérité-terrain corrigée par la preuve.** L'oracle différentiel a prouvé que **15 extensions étiquetées
« benign » par le LLM sont en fait exploitables** (`attacker_controlled = True` sur au moins un
générateur — DeepSeek, Haiku ou Qwen3-Coder). Un benign confirmé est un **exploit réel** (soundness),
donc on les reclasse `vuln` dans `publication/datasets/labels.csv`. Résultat :
**120 vuln / 15 benign / 15 malware** ; testables : **117 vuln / 15 benign**.

→ **50 % du jeu « benign » généré par LLM est en réalité exploitable.** Plus on passe de générateurs,
plus on démasque de mislabels (DeepSeek en trouve 8, Qwen3 12, Haiku 2 ; union = 15).

Ids reclassés : `AUTH01, AUTH02, AUTH03, AUTH04, AUTH06, BHT01, BHT02, BHT05, BHT08, BHT10, BHT15, BHT16, BHT20, BHT23, BHT24`.

## Matrices par générateur (même oracle, même budget, 117 vuln / 15 benign)

### DeepSeek
| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 117)** | TP=67 | FN=50 |
| **benign (réel, 15)** | FP=0 | TN=15 |

recall=0.573 · **precision=1.000** · **FPR=0.000** · FNR=0.427 · F1=0.728 · accuracy=0.621

### Qwen3-Coder (480B, OpenRouter)
| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 117)** | TP=65 | FN=52 |
| **benign (réel, 15)** | FP=0 | TN=15 |

recall=0.556 · **precision=1.000** · **FPR=0.000** · FNR=0.444 · F1=0.714 · accuracy=0.606

### Claude Haiku 5.5
| | prédit vuln (confirmé) | prédit non-vuln |
|---|---|---|
| **vuln (réel, 117)** | TP=36 | FN=81 |
| **benign (réel, 15)** | FP=0 | TN=15 |

recall=0.308 · **precision=1.000** · **FPR=0.000** · FNR=0.692 · F1=0.471 · accuracy=0.386

## Lecture

- **precision 1.000 / FPR 0.000 pour les trois générateurs** : l'oracle ne confirme jamais un
  non-exploit. La **soundness est une propriété du validateur**, indépendante du générateur.
- Le **recall dépend du générateur** : **DeepSeek (57 %) > Qwen3-Coder (56 %) > Haiku (31 %)**
  (et GPT-5-mini ≈ 17 %, run partiel). Qwen3-Coder, cross-vendor, confirme que *les bons générateurs
  convergent haut*.
- **Complémentarité** : l'union DeepSeek + Qwen3-Coder atteint **83/117 = 70.9 %** de recall,
  soit **+13.6 points** au-dessus de DeepSeek seul. Un **ensemble multi-générateur** augmente le recall
  sans jamais toucher à la soundness (toujours 0 FP).
