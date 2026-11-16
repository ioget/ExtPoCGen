# Pipeline ExtPoCGen — Расширение для LanDocs (`gen-DM06`)
*ChromeSecBench spec `DM06` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=2 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 0.14s
- durée statique: 2.6s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['postMessage', 'runtime.onMessage', 'window.message']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 4 hyp · status=ok · 13 appels · $0.014701 · 189.18s
  - `chrome.runtime.sendMessage({namespace: NS, action: 'download', ...}) relayed to service worker download handler` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `postToPage(...) responses and chrome.runtime.sendMessage relay` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `postToPage(Object.assign({action, requestId}, rest))` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `promptForFile -> file input click / sendResponse({file})` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-DM06_20261116-042854.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
