# Pipeline ExtPoCGen — LiquidVoice PCI (`gen-CM01`)
*ChromeSecBench spec `CM01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=1 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 4.58s
- durée statique totale: 10.5s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A+B** · listeners: ['document.customEvent', 'onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: ['<all_urls>']
- **triage: `clean`** · exploitable_count=0
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`clean` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 0** / 1 hypothèses · status=ok
- métriques: 5 appels LLM · $0.004147 · 78.89s
  - `chrome_storage_local_set_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=4)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-CM01_20261115-112644.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — storage/chrome.storage.*

