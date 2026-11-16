# Pipeline ExtPoCGen — 记忆体 (`gen-DH03`)
*ChromeSecBench spec `DH03` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **parse-error** · sinks=3 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 7.18s
- durée statique: 11.5s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · externally_connectable: None
- content_scripts: ['*://*/*'] · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `incomplete-analysis`** · exploitable_count=0
- incomplete: ['doublex_default:parse-error', 'doublex_empoweb:parse-error']
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`incomplete-analysis` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 5 hyp · status=ok · 14 appels · $0.0151 · 197.41s
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome.runtime.sendMessage({type:'MB_LOG_WORD', text}) -> background addWord() -> chrome.storage.local.set(WORDS)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `getSettings() merge -> chrome.storage.local.set(SETTINGS) -> scheduleAlarms(next)` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `saveWords([]) / deliverDailyPrompt() / getWords() responses` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `showNotification body built from words.map(w => '• ' + w.text).join('\n')` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-DH03_20261115-205106.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [threat_model_boundary] Canal externe `externally_connectable / content-script relayed runtime message` sans origine servable : hors modèle d'attaquant page-web. Correct de N
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
