# Pipeline ExtPoCGen — Buxenger (`gen-BHT17`)
*ChromeSecBench spec `BHT17` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **parse-error** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 0.16s
- durée statique: 4.0s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **B** · externally_connectable: None
- content_scripts: ['http://*/*', 'https://*/*'] · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- **triage: `incomplete-analysis`** · exploitable_count=0
- incomplete: ['doublex_default:parse-error', 'doublex_empoweb:parse-error']
- candidate findings: **aucun**

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`incomplete-analysis` → **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 5 hyp · status=ok · 13 appels · $0.013459 · 209.97s
  - `innerHTML` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `shadowRoot.innerHTML in renderBookmarksTab (bookmark list items) and renderTasksTab (task list items / option labels) via escapeHtml(b.title), escapeHtml(b.url), escapeHtml(bm.title)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `urlInput.value / sendMessage('ADD_BOOKMARK', {url}) then <a href="${escapeHtml(b.url)}"> and window.open(bm.url)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `currentState = message.state; renderPanel() -> innerHTML with bookmarks/tasks fields` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `window.open(bm.url) in .open handler and EXECUTE_PENDING flow` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware: niveau=**clean** · sortantes=0
- log: `logs/agent_runs/gen-BHT17_20261116-042221.json` (+ .md jumeau)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [threat_model_boundary] Canal externe `onMessageExternal` sans origine servable : hors modèle d'attaquant page-web. Correct de NE PAS confirmer ; l'étendre serait une décisio
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
  - [poc_shape] Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement la forme du message / le timing de la PoC. Boucle de raffineme
