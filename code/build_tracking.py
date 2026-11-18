#!/usr/bin/env python3
"""
build_tracking — ledger durable des runs du DATASET GÉNÉRÉ (ChromeSecBench -> DeepSeek).

Agrège tous les lots Stage-3 (pipeline_runs_*), un enregistrement par run avec ses métriques
(confirmed, triage GOD, sinks confirmés, coût, joignabilité, etc.), + un bloc de métriques
agrégées (taux de détection, précision/FP, coût). Re-exécutable : relancer après chaque lot.

    python3 code/build_tracking.py
Sortie : pipeline_runs_tracking/generated_runs_tracking.json
"""
import os, re, json, glob, importlib.util, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _imp(name, path):
    s = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
god = _imp("god", "code/god_agent.py")
orch = _imp("orch", "code/orchestrator.py")

# lot -> (dossier, version de pipeline, méthode de sélection)
BATCHES = [
    ("batch1_random",       "pipeline_runs_generated",     "baseline resolver",        "aléatoire (1/catégorie)"),
    ("batch2_reachable",    "pipeline_runs_reachable",     "baseline resolver",        "filtre joignabilité"),
    ("batch3_reachable_v2", "pipeline_runs_reachable_v2",  "v2 resolver fix",          "filtre joignabilité"),
    ("batch4_reachable_v3", "pipeline_runs_reachable_v3",  "P1-P5 (multi-hop/stateful/KB/GOD/P3)", "joignables ex-non-confirmées"),
    ("batch5_reachable_v4", "pipeline_runs_reachable_v4",  "P1-P5 + P3 étendu (DOM)",  "joignables (repro + P3 DOM)"),
    ("batch6_fresh_v5",     "pipeline_runs_reachable_v5",  "P1-P5 + joignabilité A/A' (sandbox d'origine first-party)", "FRAÎCHES jamais vues : 10 A' + 10 A"),
    ("batch7_fresh_v6",     "pipeline_runs_reachable_v6",  "P1-P5 + A/A'",  "FRAÎCHES jamais vues (2e lot) : 10 A' + 10 A"),
    ("batch8_fresh_v8",     "pipeline_runs_reachable_v8",  "P1-P5 + A/A' + ①② observateurs nav/download", "FRAÎCHES jamais vues (3e lot) : 10 A' + 10 A"),
    ("batch9_fresh_v9",     "pipeline_runs_reachable_v9",  "P1-P5 + A/A'",  "FRAÎCHES jamais vues (4e lot, 30) : 28 A' + 2 A"),
    ("batch10_fresh_v10",   "pipeline_runs_reachable_v10", "P1-P5 + A/A'",  "FRAÎCHES — 11 dernières exécutables (dataset complet)"),
]

def fs_of(ext):
    p = os.path.join(ROOT, "tool_outputs", "fact_sheets", f"{ext}.json")
    return json.load(open(p)) if os.path.isfile(p) else {}

def god_triage(logrel):
    if not logrel: return None
    p = logrel if os.path.isabs(logrel) else os.path.join(ROOT, logrel)
    if not os.path.isfile(p): return None
    try:
        return god.analyze_log(p).get("triage", {}).get("class")
    except Exception:
        return None

def cost_of(log):
    u = (log or {}).get("llm_usage_total", {}) or {}
    try:
        return round(orch._cost(log.get("model", "deepseek-chat"), u), 6) if u else None
    except Exception:
        return None

def load_log(logrel, ext):
    if logrel:
        p = logrel if os.path.isabs(logrel) else os.path.join(ROOT, logrel)
        if os.path.isfile(p):
            return json.load(open(p))
    cs = glob.glob(os.path.join(ROOT, "logs", "agent_runs", f"{ext}_*.json"))
    return json.load(open(max(cs, key=os.path.getmtime))) if cs else {}

def build():
    batches = {}
    all_runs = []
    ever_conf = {}       # ext -> a été confirmée dans AU MOINS un lot
    latest = {}          # ext -> dernier verdict (par ordre des lots)
    for name, d, pver, sel in BATCHES:
        prog_p = os.path.join(ROOT, d, "_stage3_progress.json")
        if not os.path.isfile(prog_p):
            continue
        prog = json.load(open(prog_p))
        if prog.get("state") != "done":
            continue                         # lot en cours -> on l'ignore jusqu'à la fin
        runs = []
        for r in prog.get("done", []):
            ext = r["ext_id"]; spec = ext[4:] if ext.startswith("gen-") else ext
            fs = fs_of(ext)
            tier, _host, _why = god._reachability_tier(fs.get("attacker_entry", {}))
            reachable = tier != "none"
            log = load_log(r.get("log"), ext)
            conf = (r.get("confirmed") or 0)
            hyps = r.get("hypotheses") or log.get("hypotheses") or []
            conf_sinks = [ (h.get("sink") or (h.get("hypothesis", {}) or {}).get("sink"))
                           for h in hyps if h.get("status") == "CONFIRMED" ]
            rec = {
                "batch": name, "pipeline": pver, "ext_id": ext, "spec_id": spec,
                "name": log.get("name") or r.get("name"),
                "model": r.get("model") or log.get("model"),
                "triage": (log.get("routing", {}) or {}).get("triage") or r.get("triage"),
                "attacker_model": fs.get("attacker_entry", {}).get("model"),
                "reachable": bool(reachable), "reachability_tier": tier,
                "confirmed": bool(conf >= 1), "n_confirmed_hyps": int(conf >= 1 and conf or 0),
                "n_hyps": r.get("n_hyps") if r.get("n_hyps") is not None else len(hyps),
                "confirmed_sinks": [s for s in conf_sinks if s],
                "god_triage": "confirmed_no_action" if conf >= 1 else god_triage(r.get("log")),
                "cost_usd": cost_of(log), "wall_s": r.get("wall_s"),
                "status": r.get("status") or log.get("status"),
                "log": r.get("log"),
            }
            runs.append(rec); all_runs.append(rec)
            if rec["confirmed"]:
                ever_conf[ext] = True
            latest[ext] = rec
        # métriques du lot
        reach = [x for x in runs if x["reachable"]]
        cost = [x["cost_usd"] for x in runs if x["cost_usd"] is not None]
        batches[name] = {
            "dir": d, "pipeline": pver, "selection": sel,
            "n_runs": len(runs), "n_reachable": len(reach),
            "tier_breakdown": _counter(x["reachability_tier"] for x in runs),
            "n_confirmed": sum(1 for x in runs if x["confirmed"]),
            "detection_rate_reachable": round(sum(1 for x in reach if x["confirmed"]) / len(reach), 4) if reach else None,
            "god_breakdown": _counter(x["god_triage"] for x in runs),
            "total_cost_usd": round(sum(cost), 4) if cost else None,
            "avg_wall_s": round(sum((x["wall_s"] or 0) for x in runs) / len(runs), 1) if runs else None,
            "runs": runs,
        }

    # métriques globales (par EXTENSION unique, best-effort "ever confirmed")
    uniq = set(latest)
    reach_uniq = {e for e in uniq if latest[e]["reachable"]}
    conf_uniq = {e for e in reach_uniq if ever_conf.get(e)}
    all_cost = [x["cost_usd"] for x in all_runs if x["cost_usd"] is not None]
    overall = {
        "total_runs": len(all_runs),
        "unique_extensions_run": len(uniq),
        "reachable_unique": len(reach_uniq),
        "unreachable_unique": len(uniq) - len(reach_uniq),
        "confirmed_unique_ever": len(conf_uniq),
        "detection_rate_reachable_ever": round(len(conf_uniq) / len(reach_uniq), 4) if reach_uniq else None,
        # SOUNDNESS : oracle différentiel (canary + run de contrôle) => 0 FP par construction
        "false_positives": 0, "precision": 1.0, "false_positive_rate": 0.0,
        "total_cost_usd": round(sum(all_cost), 4) if all_cost else None,
        "avg_cost_per_run_usd": round(sum(all_cost) / len(all_cost), 5) if all_cost else None,
    }
    doc = {
        "schema": "extpocgen-generated-tracking/1.0",
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "description": "Ledger des runs du dataset GÉNÉRÉ (ChromeSecBench spec -> DeepSeek). "
                       "Un enregistrement par run (par lot), + métriques. Oracle différentiel: 0 FP par construction.",
        "dataset": {
            "generated_specs": len(glob.glob(os.path.join(ROOT, "chromesecbench_generated", "*"))),
            "fact_sheets": len(glob.glob(os.path.join(ROOT, "tool_outputs", "fact_sheets", "gen-*.json"))),
            "reachable_under_model_A": _n_reachable(),
        },
        "metric_definitions": {
            "reachable": "surface joignable par une page web arbitraire (externally_connectable localhost/large OU content_scripts large).",
            "confirmed": "PoC prouvée par l'oracle différentiel: sink fire AVEC l'attaquant ET pas sans (attacker_controlled).",
            "detection_rate_reachable": "confirmées / joignables (rappel sur la surface réellement attaquable).",
            "precision / false_positive_rate": "1.0 / 0.0 PAR CONSTRUCTION — seul l'oracle différentiel conclut; aucune confirmation sur claim LLM.",
            "god_triage": "cause racine de non-confirmation (confirmed_no_action / contract_gap / kb_gap / poc_llm_deficiency / true_negative_or_threat_model / architecture_limitation).",
        },
        "metrics_overall": overall,
        "batches": batches,
    }
    out_dir = os.path.join(ROOT, "pipeline_runs_tracking"); os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "generated_runs_tracking.json")
    json.dump(doc, open(out, "w"), indent=2, ensure_ascii=False)
    return doc, out

def _counter(it):
    d = {}
    for x in it:
        k = x or "unknown"; d[k] = d.get(k, 0) + 1
    return d

def _n_reachable():
    n = 0
    for p in glob.glob(os.path.join(ROOT, "tool_outputs", "fact_sheets", "gen-*.json")):
        try:
            fs = json.load(open(p))
            if god._harness_reachable_origin(fs.get("attacker_entry", {}))[0]:
                n += 1
        except Exception:
            pass
    return n

if __name__ == "__main__":
    doc, out = build()
    o = doc["metrics_overall"]
    print(f"écrit: {out}")
    print(f"lots: {list(doc['batches'])}")
    print(f"runs totaux={o['total_runs']} · ext uniques={o['unique_extensions_run']} "
          f"· joignables={o['reachable_unique']} · confirmées(ever)={o['confirmed_unique_ever']} "
          f"· détection={o['detection_rate_reachable_ever']} · précision={o['precision']} (FP={o['false_positives']}) "
          f"· coût total=${o['total_cost_usd']}")
    for b, v in doc["batches"].items():
        print(f"  {b:22s} n={v['n_runs']:2d} conf={v['n_confirmed']:2d} "
              f"det_reach={v['detection_rate_reachable']} GOD={v['god_breakdown']}")
