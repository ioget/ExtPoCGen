# Pipeline ExtPoCGen — Fabasoft Folio (`gen-ESI02`)
*ChromeSecBench spec `ESI02` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=80.8% · 47.43s
- durée statique: 52.4s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 4 hyp · status=ok · 13 appels · $0.013558 · 191.81s
  - `postToNative(tabId, msg) -> chrome.runtime.connectNative(NATIVE_HOST_NAME).postMessage` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `postToPage({ns, kind:'native', payload: msg}) -> window.postMessage(data, '*')` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `postToPage({ns, kind:'response', payload: msg, requestId}) -> window.postMessage('*')` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `postToPage({ns, kind:'native', payload: msg}) -> window.postMessage('*')` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-ESI02_20261115-210223.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
