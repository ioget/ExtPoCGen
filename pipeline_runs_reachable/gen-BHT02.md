# Pipeline ExtPoCGen — 鲲圭豆荚 (`gen-BHT02`)
*ChromeSecBench spec `BHT02` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=4 · dataflow_hits=0
- CoCo: **timeout** · couverture=None% · Nones
- durée statique: 190.2s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: {'matches': ['*://*.kunquer.com/*']}
- content_scripts: ['http://*/*', 'https://*/*', '*://*.kunquer.com/*'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- **triage: `has-candidate`** · exploitable_count=1
- incomplete: ['coco:timeout']
- candidate findings :
  - `message` → `storage.local.set` (impact=storage-rw, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 1 hyp · status=ok · 7 appels · $0.058228 · 524.33s
  - `storage.local.set` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
- log: `logs/agent_runs/gen-BHT02_20261115-141203.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
