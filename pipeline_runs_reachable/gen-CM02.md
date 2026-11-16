# Pipeline ExtPoCGen — __MSG_appName__ (`gen-CM02`)
*ChromeSecBench spec `CM02` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=4 · dataflow_hits=1
- CoCo: **nothing** · couverture=56.2% · 44.36s
- durée statique: 54.2s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: {'matches': ['*://*.shutterstock.com/*']}
- content_scripts: ['*://*/*'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `has-candidate`** · exploitable_count=2
- candidate findings :
  - `message` → `downloads.download` (impact=download, expl=True, conf=high, doublex_default)
  - `message` → `downloads.download` (impact=download, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 2 hyp · status=ok · 9 appels · $0.068381 · 618.92s
  - `downloads.download` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `downloads.download` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
- log: `logs/agent_runs/gen-CM02_20261115-142222.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
