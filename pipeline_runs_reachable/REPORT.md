# Rapport pipeline ExtPoCGen — 10 extensions générées JOIGNABLES (modèle A)

Sélection : 10 extensions dont la surface (externally_connectable / content_scripts) est
**atteignable par une page attaquante arbitraire** (localhost / `<all_urls>` / wildcard large),
1 par catégorie ChromeSecBench. GOD agent **corrigé** (garde de joignabilité).

## Funnel

- 10 → **5 has-candidate**, 3 clean, 2 incomplete
- **0 PoC confirmée(s)** par l'oracle (0 FP)
- GOD `true_negative_or_threat_model` (corrigé) : **0** · coût Stage 3 : **$0.3849**

## Tableau

| ext | nom | modèle | triage | finds | confirmed | GOD | malware |
|---|---|---|---|---|---|---|---|
| gen-AUTH04 | __MSG_extName__ | A+B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-BHT02 | 鲲圭豆荚 | A | has-candidate | 1 | **0** | poc_llm_deficiency | None |
| gen-CM02 | __MSG_appName__ | A | has-candidate | 2 | **0** | poc_llm_deficiency | None |
| gen-COOK02 | Captain Data | A | has-candidate | 1 | **0** | poc_llm_deficiency | None |
| gen-DH03 | 记忆体 | A+B | incomplete-analysis | 0 | **0** | poc_llm_deficiency | clean |
| gen-DM13 | QuickDrag for Ch | A+B | has-candidate | 1 | **0** | poc_llm_deficiency | None |
| gen-DT02 | __MSG_appName__ | A | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-EC02 | TheHub Click To  | A | incomplete-analysis | 0 | **0** | poc_llm_deficiency | clean |
| gen-ESI02 | Fabasoft Folio | A+B | clean | 0 | **0** | poc_llm_deficiency | clean |
| gen-WA02 | Stash Extension | A+B | has-candidate | 1 | **0** | poc_llm_deficiency | None |

## Diagnostic root-cause (preuve par traces)

Sur les **5 has-candidate joignables**, 0 confirmé — tous `sink_not_reached` (`sink_called=False`).
Inspection des traces (BHT02, COOK02, CM02) : le **résolveur de « handler contract » (retrieval)
lie le sink au MAUVAIS listener**.

| ext | canal résolu (retrieval) | vrai canal (code) |
|---|---|---|
| BHT02 | `document CustomEvent 'keydown'` | `window.message` → `data.tabmemory` → `action==='setData'` |
| COOK02 | `onMessageExternal` | DOM `postMessage` → `data.tabmemory` |
| CM02 | `document CustomEvent 'mouseover'` | `window.postMessage({cmd:'exec'})` relayé par content-script |

**Ce qui N'échoue PAS** (preuves) :
- Oracle / run isolé : charge l'extension, **remappe l'origine servie** sur un hôte autorisé
  (`http://www.kunquer.com:PORT`), sonde le sink, 0 FP. Refus de confirmer = correct.
- LLM générateur : avec le BON contrat (AUTH01 batch-1 : `window.message` + garde `source`),
  convergence en 4 itérations → **CONFIRMED**. Pas le goulot.
- Dataflow statique : DoubleX trouve le bon flux + la bonne provenance (`event.data.tabmemory`).

**Cause-racine** : le binding sink↔canal est heuristique/proximité au lieu d'utiliser la
**provenance DoubleX déjà calculée** (`param_id0 → received_from_wa`). KB aggravant : `channel: None`.

**Preuve comparative** : batch-1 confirme AUTH01 *uniquement* parce que le résolveur a, par chance,
choisi le bon canal ; batch-2 (5 candidats) le choisit toujours faux → 0 confirmé. La confirmation
est donc **gouvernée par le résolveur de canal, pas par le LLM**.

**Correctif proposé** : faire lire au résolveur la provenance DoubleX (quel listener a introduit la
valeur teintée) pour fixer le canal du contrat → devrait convertir plusieurs FAILED→CONFIRMED.
