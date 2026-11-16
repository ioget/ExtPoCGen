# Pipeline ExtPoCGen — QuickDrag for Chrome (`gen-DM13`)
*ChromeSecBench spec `DM13` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=2 · dataflow_hits=0
- CoCo: **detected** · couverture=84.2% · 45.67s
- durée statique: 52.7s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `has-candidate`** · exploitable_count=1
- candidate findings :
  - `document_eventListener_dragstart` → `chrome_downloads_download_sink` (impact=download, expl=True, conf=high, coco)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 1 hyp · status=ok · 6 appels · $0.047092 · 9636.52s
  - `chrome_downloads_download_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
- log: `logs/agent_runs/gen-DM13_20261115-170756.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
