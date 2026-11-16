# Pipeline ExtPoCGen — __MSG_appName__ (`gen-WA01`)
*ChromeSecBench spec `WA01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=2 · dataflow_hits=0
- CoCo: **nothing** · couverture=86.6% · 30.2s
- durée statique totale: 38.9s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: []
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 6 hypothèses · status=ok
- métriques: 21 appels LLM · $0.018889 · 310.42s
  - `chrome_tabs_executeScript_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `keyCache / chrome.storage.local (persistKeys) and getKey return value` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.tabs.executeScript with code built from SCM_LOGIN_SCRIPTS.default(username, password) — string interpolation into injected JS` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.tabs.executeScript injecting login script into arbitrary tab` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `setKey/getKey/deleteKey and login executeScript handlers` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-WA01_20261115-114414.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — code/executeScript
  - [poc_shape] poc_shape — storage/chrome.storage.*
  - [poc_shape] poc_shape — storage/générique
  - [poc_shape] poc_shape — code/executeScript

