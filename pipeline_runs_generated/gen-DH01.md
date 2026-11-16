# Pipeline ExtPoCGen — BPTM Local File Viewer Extension (`gen-DH01`)
*ChromeSecBench spec `DH01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=3 · dataflow_hits=0
- CoCo: **nothing** · couverture=97.0% · 34.47s
- durée statique totale: 43.3s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- content_scripts: ['file:///*/index.html', 'http://localhost/BPTMPresentationLocal/', 'http://localhost/BPTMPresentationLocal/index.jsp', 'http://localhost/BPTMPresentationLocal/index.html', 'http://bptm.nat.bt.com/BPTMPresentation/', 'http://bptm.nat.bt.com/BPTMPresentation/index.jsp', 'http://bptm.nat.bt.com/BPTMPresentation/index.html', 'http://bptm.nat.bt.com/BPTMPresentationTest/', 'http://bptm.nat.bt.com/BPTMPresentationTest/index.jsp', 'http://bptm.nat.bt.com/BPTMPresentationTest/index.html']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 4 hypothèses · status=ok
- métriques: 10 appels LLM · $0.010152 · 159.81s
  - `fetch` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `fetch(url) in background.js readLocalFileAsDataUrl / readLocalFileAsText, result returned to page via postResult` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `readLocalFileAsText -> fetch(url) -> blob.text() returned to page` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch(url) in background via runtime message` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-DH01_20261115-113140.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [threat_model_boundary] threat_model_boundary — network/requête sortante
  - [poc_shape] poc_shape — network/requête sortante
  - [poc_shape] poc_shape — network/requête sortante
  - [poc_shape] poc_shape — network/requête sortante

