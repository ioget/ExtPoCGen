# Pipeline ExtPoCGen — ReqBin HTTP Client (`gen-DT01`)
*ChromeSecBench spec `DT01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=1 · dataflow_hits=1
- CoCo: **nothing** · couverture=88.2% · 8.78s
- durée statique totale: 15.0s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: []
- **triage: `has-candidate`** · exploitable_count=2
- candidate findings (flux attaquant→sink) :
  - `message` → `fetch` (impact=network-request, expl=True, conf=high, doublex_default)
  - `message` → `fetch` (impact=network-request, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → chemins **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 2 hypothèses · status=ok
- métriques: 7 appels LLM · $0.06911 · 626.6s
  - `fetch` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- log détaillé: `logs/agent_runs/gen-DT01_20261115-112001.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — network/requête sortante
  - [poc_shape] poc_shape — network/requête sortante

