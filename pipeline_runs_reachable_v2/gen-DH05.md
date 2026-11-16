# Pipeline ExtPoCGen — Go Pipeline Filter (`gen-DH05`)
*ChromeSecBench spec `DH05` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 2.5s
- durée statique: 4.7s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: None
- content_scripts: ['*://*/go/pipelines*', '*://*/go/home*'] · listeners: ['document.customEvent', 'postMessage', 'runtime.onMessage']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 1 hyp · status=ok · 4 appels · $0.003248 · 72.4s
  - `window.dispatchEvent(new CustomEvent('go-pipeline-filter:settings', {detail: items})) exposing chrome.storage.local contents to page context` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-DH05_20261116-042544.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
