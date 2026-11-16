# Pipeline ExtPoCGen — TheHub (`gen-EC04`)
*ChromeSecBench spec `EC04` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=43.3% · 6.32s
- durée statique: 10.6s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: {'matches': ['https://localhost/*', 'https://hub.wavetelbusiness.co.uk/*', 'https://hub.wave-tel.com/*', 'https://staging.thehubwork.com/*', 'https://codedesk.thehubwork.com/*']}
- content_scripts: ['http://*/*', 'https://*/*'] · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `has-candidate`** · exploitable_count=3
- candidate findings :
  - `message` → `storage.local.set` (impact=storage-rw, expl=True, conf=high, doublex_empoweb)
  - `message` → `storage.local.set` (impact=storage-rw, expl=True, conf=high, doublex_empoweb)
  - `None` → `storage.local.get` (impact=storage-rw, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 3 hyp · status=ok · 12 appels · $0.018562 · 209.69s
  - `storage.local.set` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `storage.local.set` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `storage.local.get` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
- log: `logs/agent_runs/gen-EC04_20261116-041635.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
