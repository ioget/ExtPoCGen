# Pipeline ExtPoCGen — CertiFirm.EU (`gen-AUTH01`)
*ChromeSecBench spec `AUTH01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **parse-error** · sinks=0 · dataflow_hits=0
- CoCo: **nothing** · couverture=0.0% · 3.8s
- durée statique totale: 10.2s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage', 'window.message']
- content_scripts: ['<all_urls>']
- **triage: `incomplete-analysis`** · exploitable_count=0
- incomplete: ['doublex_default:parse-error', 'doublex_empoweb:parse-error']
- candidate findings: **aucun** (pas de flot attaquant-contrôlé → gate soundness)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`incomplete-analysis` → chemins **['vulnerability', 'malware_behavior']** (model=deepseek-chat, budget=4)
- **confirmed: 1** / 1 hypothèses · status=ok
- métriques: 5 appels LLM · $0.00461 · 86.92s
  - `chrome_cookies_set_sink` → **CONFIRMED** (sink_fired=True, attacker_controlled=True, iter=4)
- oracle malware (Chrome isolé): niveau=**clean** · requêtes sortantes=0
- log détaillé: `logs/agent_runs/gen-AUTH01_20261115-114541.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `confirmed_no_action`** — Run CONFIRMÉ : couverture d'oracle suffisante pour ce sink.
  - aucune recommandation (run confirmé ou hors-périmètre archi)

