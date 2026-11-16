# Pipeline ExtPoCGen — iQare Fullscreen Site Navigation (`gen-CM04`)
*ChromeSecBench spec `CM04` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=3 · dataflow_hits=0
- CoCo: **timeout** · couverture=None% · Nones
- durée statique: 192.1s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['http://*/*', 'https://*/*'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `incomplete-analysis`** · exploitable_count=0
- incomplete: ['coco:timeout']
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`incomplete-analysis` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 1** / 2 hyp · status=ok · 7 appels · $0.007635 · 129.83s
  - `chrome.runtime.onMessage listener in background.js (FULLSCREEN_MESSAGE / ACTIVITY_MESSAGE handling) and content-script onRuntimeMessage` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `window.location.href assignment in home button handler (window.location.origin + '/')` → **CONFIRMED** (sink_fired=True, attacker_controlled=True, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-CM04_20261116-042431.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `confirmed_no_action`** — Run CONFIRMÉ : couverture d'oracle suffisante pour ce sink.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
