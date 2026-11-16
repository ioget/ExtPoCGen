# Pipeline ExtPoCGen — Amazon Seller Toolset (`gen-EC01`)
*ChromeSecBench spec `EC01` · class=generated · mv2*

## Stage 1 — Détection statique (CoCo + DoubleX ×2)
- DoubleX(default): **ok** · sinks=0 · dataflow_hits=0
- CoCo: **detected** · couverture=85.1% · 23.92s
- durée statique totale: 32.5s

## Stage 2 — Fact Sheet (surface + flux + triage)
- attacker_model: **A** · listeners: ['onConnectExternal', 'onMessageExternal', 'postMessage', 'runtime.onMessage']
- content_scripts: ['*://www.amazon.com/*/dp/*', '*://www.amazon.com/*/DP/*', '*://www.amazon.com/dp/*', '*://www.amazon.com/DP/*', '*://www.amazon.com/d/*/*', '*://www.amazon.com/D/*/*', '*://www.amazon.com/gp/product/*', '*://www.amazon.com/gp/product/glance/*', '*://www.amazon.com/gp/offer-listing/*', '*://www.amazon.com/s?marketplaceID=*', '*://www.amazon.com/s?*', '*://www.amazon.com/s*', '*://www.amazon.com/s?merchant=*', '*://www.amazon.ca/*/dp/*', '*://www.amazon.ca/*/DP/*', '*://www.amazon.ca/dp/*', '*://www.amazon.ca/DP/*', '*://www.amazon.ca/d/*/*', '*://www.amazon.ca/D/*/*', '*://www.amazon.ca/gp/product/*', '*://www.amazon.ca/gp/product/glance/*', '*://www.amazon.ca/gp/offer-listing/*', '*://www.amazon.ca/s?marketplaceID=*', '*://www.amazon.ca/s?*', '*://www.amazon.ca/s*', '*://www.amazon.ca/s?merchant=*', '*://www.amazon.co.uk/*/dp/*', '*://www.amazon.co.uk/*/DP/*', '*://www.amazon.co.uk/dp/*', '*://www.amazon.co.uk/DP/*', '*://www.amazon.co.uk/d/*/*', '*://www.amazon.co.uk/D/*/*', '*://www.amazon.co.uk/gp/product/*', '*://www.amazon.co.uk/gp/product/glance/*', '*://www.amazon.co.uk/gp/offer-listing/*', '*://www.amazon.co.uk/s?marketplaceID=*', '*://www.amazon.co.uk/s?*', '*://www.amazon.co.uk/s*', '*://www.amazon.co.uk/s?merchant=*', '*://www.amazon.de/*/dp/*', '*://www.amazon.de/*/DP/*', '*://www.amazon.de/dp/*', '*://www.amazon.de/DP/*', '*://www.amazon.de/d/*/*', '*://www.amazon.de/D/*/*', '*://www.amazon.de/gp/product/*', '*://www.amazon.de/gp/product/glance/*', '*://www.amazon.de/gp/offer-listing/*', '*://www.amazon.de/s?marketplaceID=*', '*://www.amazon.de/s?*', '*://www.amazon.de/s*', '*://www.amazon.de/s?merchant=*', '*://smile.amazon.com/*/dp/*', '*://smile.amazon.com/*/DP/*', '*://smile.amazon.com/dp/*', '*://smile.amazon.com/DP/*', '*://smile.amazon.com/d/*/*', '*://smile.amazon.com/D/*/*', '*://smile.amazon.com/gp/product/*', '*://smile.amazon.com/gp/product/glance/*', '*://smile.amazon.com/gp/offer-listing/*', '*://smile.amazon.com/s?marketplaceID=*', '*://smile.amazon.com/s?*', '*://smile.amazon.com/s*', '*://smile.amazon.com/s?merchant=*', '*://*.sellertoolset.com/*', '*://*.sellertoolset.com/*']
- **triage: `has-candidate`** · exploitable_count=2
- candidate findings (flux attaquant→sink) :
  - `bg_chrome_runtime_MessageExternal` → `fetch_resource_sink` (impact=network-request, expl=True, conf=high, coco)
  - `fetch_source` → `sendResponseExternal_sink` (impact=exfiltration, expl=False, conf=low, coco)
  - `message` → `fetch` (impact=network-request, expl=True, conf=high, doublex_empoweb)

## Stage 3 — Génération PoC + Oracle différentiel (Chrome isolé)
- routing: triage=`has-candidate` → chemins **['vulnerability']** (model=deepseek-reasoner, budget=12)
- **confirmed: 0** / 2 hypothèses · status=ok
- métriques: 6 appels LLM · $0.025635 · 247.05s
  - `fetch_resource_sink` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
  - `fetch` → **FAILED** (sink_fired=False, attacker_controlled=False, iter=3)
- log détaillé: `logs/agent_runs/gen-EC01_20261115-112408.json` (+ .md jumeau avec prompts/PoC/traces)

## Stage 4 — GOD agent (méta-diagnostic, symbolique)
- **triage global: `poc_llm_deficiency`** — Échec probablement côté générateur (forme/timing/responder), pas archi.
  - [poc_shape] poc_shape — network/requête sortante
  - [poc_shape] poc_shape — network/requête sortante

