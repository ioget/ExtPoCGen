# ExtPoCGen — Architecture finale

**Génération et validation automatiques de PoC pour extensions de navigateur (Chrome MV2/MV3).**
Adaptation de PoCGen (Simsek, Eghbali, Pradel, FSE'26 — `2506.04962`) au domaine des extensions,
avec **CoCo + DoubleX** comme moteur de taint, un **knowledge base hybride graphe/vecteur**, et
trois modes d'exécution (`tools_on` / `tools_off` / `hybrid`).

---

## 0. Principe directeur

> **Les outils statiques (CoCo/DoubleX) produisent la colonne vertébrale (le taint). Le knowledge
> base ne fait que la décorer. Toute génération passe ensuite par une validation déterministe en
> sandbox.** L'ablation de PoCGen (Table 1) fixe les priorités : taint path **+50 pts**, trigger/usage
> snippets **+36**, few-shot/CVE **+4**. Donc on investit dans le taint et le déclencheur, pas dans le RAG.

Boucle fermée (Fig. 1 des diagrammes) : statique → hypothèse → PoC → exécution → jugement → révision.

---

## 1. Vue d'ensemble (5 étages = 4 composants PoCGen)

```
CRX / source (+ rapport de vuln optionnel)
        │
        ▼
┌─ STAGE 1 : Static Analysis & Fact Extraction ─────────────┐   (= PoCGen comp. i)
│  Isolated Reader (VM/conteneur)                            │
│  ├─ CoCo + DoubleX(défaut+empoweb)  → taint path          │
│  ├─ Manifest parser + listener detection                  │
│  └─ check_permissions.py → candidate_sinks_from_perms      │
│  ⇒ EXTENSION SECURITY FACT SHEET                           │
│     {identité, attacker_entry A/B, findings, triage,       │
│      candidate_sinks, analysis_mode}                       │
└────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ STAGE 2 : Knowledge Base (hybride graphe/vecteur) ───────┐
│  A spine (graphe) : Extension/Finding/Sink/AttackerEntry  │  ← alimenté par Stage 1
│  B Chrome API semantics (graphe + vecteur)                │
│  C Patterns/CWE + permission→sink (graphe)                │
│  D Similar exploits few-shot (BM25) + Skeletons A/B       │
│  retrieve.py : anchor_on_finding | anchor_on_manifest     │
└────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ STAGE 3 : Multi-Agent PoC Generation ────────────────────┐  (= PoCGen comp. ii + iv)
│  Orchestrator (mode selector + refinement loop ≤ N)       │
│  ├─ Vulnerability Analyst  (finding → hypothèse d'exploit)│
│  ├─ Malware Behavior Analyst (classe malware)             │
│  ├─ PoC Generator (prompt: trigger + skeleton + KB)       │
│  └─ PoC Safety & Scope Validator (sandbox-only)           │
└────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ STAGE 4 : Isolated Execution ────────────────────────────┐  (= PoCGen comp. iii)
│  Chrome MV3 Test Harness (instrumenté)                    │
│  ├─ Attacker Model A : page web malveillante              │
│  └─ Attacker Model B : extension zéro-permission          │
│  ⇒ trace d'exécution instrumentée + evidence             │
└────────────────────────────────────────────────────────────┘
        │
        ▼
┌─ STAGE 5 : Deterministic Verification ────────────────────┐
│  Rule-Based Evidence Judge (oracle canari par type        │
│   + sanity check call-stack passe par l'entrée attaquant) │
│  ⇒ verdict + rapport de reproductibilité                 │
│  ⇒ VERIFIED POC REPOSITORY ──┐                            │
└───────────────────────────────┼────────────────────────────┘
                                 └──► réinjecté dans D/skeletons (boucle fermée)
```

---

## 2. Stage 1 — Fact Sheet (déjà implémenté : `tool_outputs/fact_sheets/<id>.json`)

Sortie normalisée commune, produite par fusion CoCo + DoubleX + manifeste :

```jsonc
{
  "extension_id", "name", "manifest_version", "class", "size_kb",
  "permissions", "host_permissions",
  "attacker_entry": { "model": "A|B|A+B|none",
                      "A_web_page": {...}, "B_extension": {...},
                      "listeners": [...], "content_scripts_matches": [...] },
  "analysis": { "coco": {status, coverage, flows, witness}, "doublex_default", "doublex_empoweb" },
  "candidate_sinks_from_permissions": [...],   // via check_permissions.py, SANS lancer DoubleX
  "candidate_findings": [ { source, sink, source_type, sink_type, impact_class,
                            attacker_model, exploitable_hypothesis, confidence,
                            oracle } ],
  "triage": { "state": "has-candidate|clean|incomplete-analysis",
              "attacker_model", "incomplete_analyses" },
  "analysis_mode": "tools_on|tools_off|hybrid"
}
```

Le Fact Sheet **est** la sortie de la « Vulnerability Information Extraction » de PoCGen.

---

## 3. Stage 2 — Knowledge Base : organisation

| Store | Contenu | Source | Index | Rôle |
|---|---|---|---|---|
| **A spine** | Extension/Finding/Sink/AttackerEntry | **CoCo+DoubleX** (Fact Sheet) | graphe | ancrage |
| **B API Chrome** | dispo MV2/MV3, permission, sémantique frontière | doc Chrome | graphe + vecteur | faisabilité + fallback |
| **C patterns** | taxo DoubleX/EmPoWeb/CoCo + CWE + permission→sink | `*_apis.json`, `vul_func_lists.py`, `check_permissions.py` | graphe | classification + tools_off |
| **D few-shot** | (desc → PoC) + skeletons A/B | EmPoWeb/CVE + Verified PoC Repo | BM25 + graphe | génération (+4 pts) |

**Règle de récupération (hybride) :** ancrer sur un nœud (Finding ou AttackerEntry) → **traverser**
le graphe 1-2 sauts (Sink→ChromeAPI, Finding→VulnPattern→PoCTemplate) → **ANN vectoriel contraint
au sous-graphe** (few-shot, prose API). *Graph-filter puis vector-rank.*

**Graphe = relationnel (A/B/C/skeletons). BM25/vecteur = flou (D + prose).** Pas de RAG vectoriel pur :
la requête est un nœud, pas une question.

---

## 4. Les trois modes d'exécution

| | `tools_on` | `tools_off` | `hybrid` (défaut) |
|---|---|---|---|
| Ancre | Finding (taint) | permissions + attacker_entry | on, fallback off |
| Sinks | donnés par CoCo/DoubleX | **candidats** via `check_permissions.py` | selon dispo |
| Flot | fourni | **hypothésé par le LLM** sur code brut | selon dispo |
| Succès attendu (réf. PoCGen) | ~71 % | ~21 % | ≥ 71 %, couvre le reste |
| Quand | extension analysable | parse-error / skip-taille / clean+surface | **par défaut** |

`tools_off` = config `noTaintPath` de PoCGen. Pas de taint, mais le LLM lit le **code brut** +
le manifeste, guidé par la KB ; `check_permissions.py` (lookup pur, sans lancer DoubleX) fournit les
**sinks candidats**. Le sandbox tranche. `hybrid` = `tools_on` puis bascule auto en `tools_off`
quand le Fact Sheet est `incomplete-analysis` ou `clean + attacker_model≠none`.

---

## 5. Stage 4/5 — Attacker models et oracles de validation

**Attacker models (dérivés du manifeste)**
- **A — page web malveillante** : `externally_connectable.matches` OU `content_scripts.matches` + listener `message`/event DOM.
- **B — extension zéro-permission (confused deputy)** : `onMessageExternal` sans `externally_connectable` restrictif.

**Oracles déterministes par type de vuln (équivalents extension du `seteuid(42)` de PoCGen)**

| impact_class | Oracle canari (succès ⇔) |
|---|---|
| code-execution (`tabs.executeScript`/`eval`) | un script canari pose un beacon avec un token secret, observé dans le runtime |
| storage-write | clé/valeur canari écrite dans `chrome.storage`, relue |
| storage-read-exfil / confused-deputy | un secret planté en storage **atteint la page/extension attaquante** |
| cookie-rw | cookie canari écrit/lu |
| network-request / SSRF | requête vers une URL canari contrôlée par l'attaquant, observée |

**Sanity check (anti faux-négatif, comme PoCGen)** : la call-stack / trace d'événements doit **passer
par l'entrée attaquant déclarée** (le listener). Sinon le PoC est invalide, même s'il déclenche l'effet.

---

## 6. Boucle de refinement (= PoCGen comp. iv)

Priority queue de *refiners*, Orchestrator « revise / stop / report », budget ≤ N itérations :
- **context refiners** : body refiner (corps des fonctions du flot), missing-declaration refiner.
- **runtime refiners** : error refiner (message d'erreur du run raté), coverage refiner (quelles lignes
  non exécutées), debugger refiner (valeurs runtime des expressions demandées).

---

## 7. Garde-fous (non négociables)

1. **retrieve-then-cite** : l'agent ne cite qu'un nœud KB réellement récupéré. Pas de CVE halluciné.
2. **provenance obligatoire** : toute hypothèse pointe vers un témoin de code OU un nœud KB. Sinon jetée.
3. **validation sandbox obligatoire** pour tout PoC `kb-only` / `tools_off` avant report.
4. **portail `attacker_entry`** : on ne génère pas de PoC si `attacker_model=none` (évite Token Finder).
5. **3 états de triage** : `has-candidate` / `clean` / `incomplete-analysis` — jamais confondre « rien » et « pas analysé ».
6. **tag de provenance par PoC** : `tool-grounded` vs `kb-only` — rapportés séparément dans le papier.
7. **PoC Safety & Scope Validator** : pas de réseau sortant réel, pas de credentials, effet borné au sandbox.

---

## 8. Ordre de construction (dicté par l'ablation PoCGen, Table 1)

1. **Taint** (+50) — ✅ fait (CoCo/DoubleX + Fact Sheet).
2. **Trigger/usage snippets** (+36) — enrichir le Fact Sheet : message à envoyer + origine attaquante. ← *prochaine brique*
3. **Harness Chrome MV3 instrumenté + oracles canari** (Stage 4/5).
4. **Boucle de refinement** (Stage 3).
5. **Fallback KB** : sémantique API Chrome (store B), mode `tools_off`/`hybrid`.
6. **Few-shot / CVE** (+4) — en dernier (store D).
7. **Graphe complet + boucle fermée** (Neo4j via `import2neo4j.sh` de CoCo) — quand provenance/papier le justifient.

---

## 9. Limites connues (à documenter dans le papier)

- **esprima 4 (ES2017)** dans CoCo *et* DoubleX → parse-errors corrélées sur JS moderne (champs de
  classe statiques, spread). Prétraitement **babel** avant tout chiffre.
- **Bundles multi-Mo** (webpack minifié) → les deux outils échouent (timeout/skip) → mode `tools_off`.
- **`tools_off` ≈ 21 %** → mode par défaut = `hybrid`, jamais `tools_off` systématique.
- **Angles morts des outils** (listener déstructuré, flot interprocédural, cf. Strava) → les **deux**
  outils + fallback KB ; le graphe amplifie la couverture mais ne la crée pas.
- **Coût** dominé par l'analyse statique (CoCo jusqu'à 600 s/extension).

---

## 10. Layout repo cible

```
tool_outputs/            # sorties brutes CoCo/DoubleX + fact_sheets/  (✅ existe)
rag/
  graph/                 # stores A/B/C + skeletons (Neo4j ou SQLite prototype)
  corpora/chrome_api/    # sémantique API (vecteur)
  corpora/similar_exploits/
  skeletons/             # attacker_page.tmpl , zero_perm_ext.tmpl
  retrieve.py            # anchor_on_finding | anchor_on_manifest
harness/                 # Chrome MV3 instrumenté + attacker A/B
judge/                   # oracles canari par type
poc_repo/                # Verified PoC Repository (boucle fermée)
```

*Réf. : PoCGen `2506.04962v4` ; diagrammes `case-diagram.png`, `Rag-agentic-sys.png` ; données `min-set/`.*
