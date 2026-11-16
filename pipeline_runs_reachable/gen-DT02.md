# Pipeline ExtPoCGen — __MSG_appName__ (`gen-DT02`)
*ChromeSecBench spec `DT02` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=54.5% · 80.1s
- durée statique: 90.1s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: {'matches': ['*://*.abtasty.com/*']}
- content_scripts: ['http://*/*', 'https://*/*'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 4 hyp · status=ok · 14 appels · $0.014378 · 205.33s
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `document.documentElement.setAttribute('data-abtasty-variant', clean) via applyVariant` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.runtime.onMessage handler -> applyVariant / showHeatmap / openEditor / updateTabState (background) via sendToTab` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `updateTabState(tabId, ...) and sendToTab(tabId, ...) in background` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-DT02_20261115-205432.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
