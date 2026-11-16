# Pipeline ExtPoCGen — __MSG_appName__ (`gen-COOK03`)
*ChromeSecBench spec `COOK03` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=4 · dataflow_hits=1
- CoCo: **detected** · couverture=91.0% · 17.27s
- durée statique: 21.7s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['*://*.hydd.cc/*', '*://qiandao.today/*', '*://qiandao.binux.me/*', '*://127.0.0.1/*'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- **triage: `has-candidate`** · exploitable_count=3
- candidate findings :
  - `cookies_source` → `window_postMessage_sink` (impact=other, expl=True, conf=medium, coco)
  - `event` → `fetch` (impact=network-request, expl=True, conf=high, doublex_default)
  - `event` → `fetch` (impact=network-request, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 1** / 1 hyp · status=ok · 1 appels · $0.003241 · 40.23s
  - `window_postMessage_sink` → **CONFIRMED** (sink_fired=True, attacker_controlled=True, iter=1)
- log: `logs/agent_runs/gen-COOK03_20261116-041305.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `confirmed_no_action`** — Run CONFIRMÉ : couverture d'oracle suffisante pour ce sink.
  - aucune recommandation
