# Pipeline ExtPoCGen — g7 st card plugin (`gen-ESI01`)
*ChromeSecBench spec `ESI01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=56.2% · 26.02s
- durée statique totale: 33.9s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- content_scripts: ['http://localhost/test*', 'http://dev.link.g7s.chinawayltd.com/*', 'http://dev.g7s.chinawayltd.com/*', 'http://test.g7s.chinawayltd.com/*', 'http://demo.g7s.chinawayltd.com/*', 'http://g7s.huoyunren.com/*']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 3 hypothèses · status=ok
- métriques: 10 appels LLM · $0.006166 · 152.87s
  - `chrome.runtime.sendMessage -> background handleMessage -> sendToNative(action, payload) -> nativePort.postMessage to com.g7st.cardreader host` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `sendToNative -> nativePort.postMessage to native host` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `nativePort.postMessage({action, payload, requestId})` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-ESI01_20261115-113903.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — any/générique
  - [poc_shape] poc_shape — any/générique
  - [poc_shape] poc_shape — any/générique

