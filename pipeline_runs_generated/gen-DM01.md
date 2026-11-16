# Pipeline ExtPoCGen — HTTP Commander (`gen-DM01`)
*ChromeSecBench spec `DM01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=1 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 5.15s
- durée statique totale: 12.5s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: ['http://*/*', 'https://*/*']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 6 hypothèses · status=ok
- métriques: 18 appels LLM · $0.01719 · 288.7s
  - `chrome_downloads_download_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
  - `chrome.downloads.download({url, filename}) in background.js HC_DOWNLOAD handler` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `buildDownloadPath -> chrome.downloads.download filename (path traversal / folder control)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `chrome.runtime.onMessage HC_DOWNLOAD handler (no sender validation)` → **UNREACHABLE** (sink_fired=None, attacker_controlled=None, iter=0)
  - `chrome.pageAction.show(sender.tab.id)` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-DM01_20261115-113629.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — any/générique
  - [poc_shape] poc_shape — storage/chrome.storage.*
  - [poc_shape] poc_shape — any/générique
  - [poc_shape] poc_shape — storage/générique

