# Pipeline ExtPoCGen — __MSG_appName__ (`gen-COOK01`)
*ChromeSecBench spec `COOK01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=1 · dataflow_hits=0
- CoCo: **nothing** · couverture=68.6% · 6.77s
- durée statique totale: 12.9s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: []
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 3 hypothèses · status=ok
- métriques: 10 appels LLM · $0.007854 · 135.35s
  - `chrome.cookies.getAll({url, name}) returning full cookie values via sendResponse` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.cookies.getAll(details) with arbitrary url` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.cookies.getAll + sendResponse` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-COOK01_20261115-112900.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — cookie/chrome.cookies.set
  - [poc_shape] poc_shape — cookie/chrome.cookies.set
  - [poc_shape] poc_shape — cookie/chrome.cookies.set

