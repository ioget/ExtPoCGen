# Pipeline ExtPoCGen — __MSG_extName__ (`gen-AUTH04`)
*ChromeSecBench spec `AUTH04` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=5 · dataflow_hits=0
- CoCo: **nothing** · couverture=31.3% · 57.12s
- durée statique: 65.8s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['<all_urls>'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 6 hyp · status=ok · 17 appels · $0.018377 · 230.2s
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `fetch` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `showShopOverlay -> addRow -> span.textContent (overlay DOM in page)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `saveShopInfo -> storageSet(STORAGE_KEYS.SHOP, shop) -> chrome.storage.local` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch(SHOP_ENDPOINT + '?url=' + encodeURIComponent(url)) in background` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.runtime.onMessage switch in background (ORIONI_PAGE_READY, ORIONI_GET_IDENTITY, ORIONI_REPORT_SHOP) and content script (ORIONI_SHOW_SHOP, ORIONI_GET_IDENTITY)` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-AUTH04_20261115-204748.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
