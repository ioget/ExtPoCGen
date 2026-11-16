# Pipeline ExtPoCGen — TheHub Click To Dial (`gen-EC02`)
*ChromeSecBench spec `EC02` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **parse-error** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 0.1s
- durée statique: 1.8s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · externally_connectable: {'matches': ['https://localhost/*', 'https://hub.wave-tel.com/*', 'https://staging.thehubwork.com/*', 'https://codedesk.thehubwork.com/*']}
- content_scripts: [] · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `incomplete-analysis`** · exploitable_count=0
- incomplete: ['doublex_default:parse-error', 'doublex_empoweb:parse-error']
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`incomplete-analysis` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 6 hyp · status=ok · 21 appels · $0.022001 · 278.22s
  - `chrome_tabs_executeScript_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `fetch` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch(url) in dialNumber() where url = buildYealinkUrl(settings, number) — attacker-controlled number interpolated into a GET request to the configured Yealink phone` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch(`http://${host}/`) in the test-connection handler, and buildYealinkUrl() used by dialNumber()` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `dialNumber(target) → fetch(buildYealinkUrl(settings, number))` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-EC02_20261115-205911.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
