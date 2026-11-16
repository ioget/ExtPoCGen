# Pipeline ExtPoCGen — Zebra Printing (`gen-ESI03`)
*ChromeSecBench spec `ESI03` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=1 · dataflow_hits=0
- CoCo: **nothing** · couverture=19.4% · 10.87s
- durée statique: 14.7s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **B** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 5 hyp · status=ok · 10 appels · $0.012696 · 170.32s
  - `chrome_storage_local_set_sink` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `fetch` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `fetch(`http://${cfg.host}:${cfg.port}/`, {method:'POST', body: zpl}) in sendZpl` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.storage.local.set({zebraHost, zebraPort}) and subsequent fetch URL construction` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch POST body to attacker-repointed host after config:set` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-ESI03_20261116-043430.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [threat_model_boundary] Canal externe `onMessageExternal` sans origine servable : hors modèle d'attaquant page-web. Correct de NE PAS confirmer ; l'étendre serait une décisio
  - [threat_model_boundary] Canal externe `onMessageExternal` sans origine servable : hors modèle d'attaquant page-web. Correct de NE PAS confirmer ; l'étendre serait une décisio
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
