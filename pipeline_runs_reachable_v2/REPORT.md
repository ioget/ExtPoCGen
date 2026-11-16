# Rapport pipeline ExtPoCGen — 10 extensions générées JOIGNABLES (modèle A)

Sélection : 10 extensions dont la surface (externally_connectable / content_scripts) est
**atteignable par une page attaquante arbitraire** (localhost / `<all_urls>` / wildcard large),
1 par catégorie ChromeSecBench. GOD agent **corrigé** (garde de joignabilité).

## Funnel

- 10 → **2 has-candidate**, 6 clean, 2 incomplete
- **4 PoC confirmée(s)** par l'oracle (0 FP)
- GOD `true_negative_or_threat_model` (corrigé) : **0** · coût Stage 3 : **$0.1164**

## Tableau

| ext | nom | modèle | triage | finds | confirmed | GOD | malware |
|---|---|---|---|---|---|---|---|
| gen-AUTH05 | TDOS | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-BHT17 | Buxenger | B | incomplete-analysis | 0 | **0** | poc_llm_deficiency | clean |
| gen-CM04 | iQare Fullscreen | A+B | incomplete-analysis | 0 | **1** | confirmed_no_action | clean |
| gen-COOK03 | __MSG_appName__ | A+B | has-candidate | 3 | **1** | confirmed_no_action | None |
| gen-DH05 | Go Pipeline Filt | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-DM06 | Расширение для L | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-DT03 | Meiosis Tracer | A+B | clean | 0 | **1** | confirmed_no_action | clean |
| gen-EC04 | TheHub | A | has-candidate | 3 | **0** | poc_llm_deficiency | None |
| gen-ESI03 | Zebra Printing | B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-WA03 | Quicky | A+B | clean | 0 | **1** | confirmed_no_action | clean |
