# Pipeline ExtPoCGen — Captain Data (`gen-COOK02`)
*ChromeSecBench spec `COOK02` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=1 · dataflow_hits=0
- CoCo: **nothing** · couverture=53.3% · 8.75s
- durée statique: 15.4s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: {'matches': ['*://app.captaindata.co/*', '*://staging.app.captaindata.co/*', '*://localhost/*', '*://leadgen.localhost/*', '*://api.captaindata.co/*', '*://staging.api.captaindata.co/*', '*://sourcr.captaindata.co/*', '*://prospr.captaindata.co/*', '*://searchr.captaindata.co/*', '*://enrichr.captaindata.co/*']}
- content_scripts: [] · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `has-candidate`** · exploitable_count=1
- candidate findings :
  - `message` → `storage.local.set` (impact=storage-rw, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 1 hyp · status=ok · 4 appels · $0.030786 · 297.31s
  - `storage.local.set` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
- log: `logs/agent_runs/gen-COOK02_20261115-142719.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
