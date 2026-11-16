# Pipeline ExtPoCGen — TDOS (`gen-AUTH05`)
*ChromeSecBench spec `AUTH05` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 0.24s
- durée statique: 4.8s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['document.customEvent', 'postMessage', 'runtime.onMessage', 'window.message']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 3 hyp · status=ok · 10 appels · $0.008198 · 134.95s
  - `chrome.runtime.sendMessage({ action, payload }) relayed to the service worker` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `window.postMessage({ channel: RESPONSE_CHANNEL, id, ...reply }, '*')` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `window.postMessage({ channel: EVENT_CHANNEL, event: 'records:changed', ts }, '*')` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-AUTH05_20261116-041851.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
