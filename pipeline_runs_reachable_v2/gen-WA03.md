# Pipeline ExtPoCGen — Quicky (`gen-WA03`)
*ChromeSecBench spec `WA03` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=4 · dataflow_hits=0
- CoCo: **nothing** · couverture=30.2% · 32.34s
- durée statique: 39.7s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 1** / 6 hyp · status=ok · 19 appels · $0.022828 · 301.15s
  - `innerHTML` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome_tabs_executeScript_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome.storage.local writes (TRANSACTIONS, BALANCE) and payment processing in background processPayment(msg, sender)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `processPayment(msg, sender) in background — balance deduction and transaction record write` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `Content script onMessage handler toggling UI panel and refreshState()` → **CONFIRMED** (sink_fired=True, attacker_controlled=True, iter=1)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-WA03_20261116-043931.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `confirmed_no_action`** — Run CONFIRMÉ : couverture d'oracle suffisante pour ce sink.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
