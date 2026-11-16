# Pipeline ExtPoCGen — Meiosis Tracer (`gen-DT03`)
*ChromeSecBench spec `DT03` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=2 · dataflow_hits=0
- CoCo: **nothing** · couverture=42.7% · 14.78s
- durée statique: 18.8s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 1** / 3 hyp · status=ok · 11 appels · $0.011869 · 164.14s
  - `chrome_tabs_executeScript_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome.runtime.sendMessage / relay(payload) to background, then port.postMessage to DevTools panel` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `window.postMessage({source:SOURCE, direction:'to-page', payload}) in content script` → **CONFIRMED** (sink_fired=True, attacker_controlled=True, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-DT03_20261116-043139.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `confirmed_no_action`** — Run CONFIRMÉ : couverture d'oracle suffisante pour ce sink.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
