# Pipeline ExtPoCGen — Galago bookmarks (`gen-BHT01`)
*ChromeSecBench spec `BHT01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=4 · dataflow_hits=0
- CoCo: **nothing** · couverture=100.0% · 52.49s
- durée statique totale: 60.4s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **B** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: ['<all_urls>']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 4 hypothèses · status=ok
- métriques: 4 appels LLM · $0.004208 · 75.57s
  - `chrome_storage_local_set_sink` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `fetch` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `showToast(status, message) -> text.textContent / toast.style.backgroundColor` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `fetch(GALAGO_ENDPOINT, {body: JSON.stringify(payload)}) in background.js` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-BHT01_20261115-112524.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [threat_model_boundary] threat_model_boundary — storage/chrome.storage.*
  - [threat_model_boundary] threat_model_boundary — network/requête sortante
  - [threat_model_boundary] threat_model_boundary — any/générique
  - [poc_shape] poc_shape — network/requête sortante

