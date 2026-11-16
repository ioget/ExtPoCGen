#!/usr/bin/env python3
"""
god_batch — lance en série le PIPELINE COMPLET (comme le dashboard) sur un lot d'extensions
vulnérables, puis nourrit le GOD agent sur chaque log produit. Objectif : évaluer l'architecture
sur tout le set + produire les rapports GOD manquants.

Chemin identique au serveur : Orchestrator.run(ext_id) = grounding statique → génération LLM
(deepseek-reasoner) → harness Chrome isolé → oracle différentiel. PAS de garde de budget bloquante
(on ne peut pas cliquer « continue » en batch) : les appels LLM sont bornés par budget=3 côté orch.

Usage :
    python3 code/god_batch.py --missing            # vuln sans log existant (défaut)
    python3 code/god_batch.py --all                # toutes les vuln (re-run)
    python3 code/god_batch.py --missing --limit 2  # test sur 2
"""
import os, sys, json, glob, time, datetime, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "code"))
FACT = os.path.join(ROOT, "tool_outputs", "fact_sheets")


def vuln_targets():
    out = []
    for p in sorted(glob.glob(os.path.join(FACT, "*.json"))):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        if d.get("class") == "vulnerable":
            out.append(d["extension_id"])
    return out


def has_log(ext_id):
    return bool(glob.glob(os.path.join(ROOT, "logs", "agent_runs", ext_id + "*.json")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--missing", action="store_true", help="seulement les vuln sans log (défaut)")
    ap.add_argument("--all", action="store_true", help="toutes les vuln (re-run)")
    ap.add_argument("--limit", type=int, default=0, help="limiter à N extensions (test)")
    ap.add_argument("--model", default="deepseek-reasoner")
    args = ap.parse_args()

    from orchestrator import (GraphKB, DeepSeekAgent, MockSafety, TraceJudge,
                              MalwareBehaviorAnalyst, Orchestrator)
    from harness import HarnessCDP
    import god_agent

    targets = vuln_targets()
    if not args.all:
        targets = [e for e in targets if not has_log(e)]   # --missing par défaut
    if args.limit:
        targets = targets[:args.limit]

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = os.path.join(ROOT, "logs", "god_batch", f"run_{ts}")
    os.makedirs(outdir, exist_ok=True)
    prog_path = os.path.join(outdir, "progress.jsonl")
    summ_path = os.path.join(outdir, "summary.json")

    kb = GraphKB()
    print(f"[batch] {len(targets)} extension(s) à lancer → {outdir}", flush=True)
    results = []
    t_all = time.time()
    for i, ext_id in enumerate(targets, 1):
        t0 = time.time()
        rec = {"i": i, "n": len(targets), "ext_id": ext_id, "started": datetime.datetime.now().isoformat(timespec="seconds")}
        print(f"[batch] {i}/{len(targets)} {ext_id} …", flush=True)
        try:
            agent = DeepSeekAgent(model=args.model)   # PAS de call_gate -> pas de pause budget
            orch = Orchestrator(kb, agent, MockSafety(), HarnessCDP(), TraceJudge(),
                                budget=3, malware_analyst=MalwareBehaviorAnalyst())
            out = orch.run(ext_id)
            m = out.get("metrics", {})
            logrel = out.get("log")
            report_path = god_agent.analyze_after_run(logrel) if logrel else None
            rep = god_agent.get_report(os.path.basename(str(report_path)).replace(".json", "")) if report_path else None
            rec.update({
                "ok": True, "name": out.get("extension"),
                "confirmed": out.get("confirmed"),
                "verdict": "CONFIRMED" if out.get("confirmed") else out.get("status", "none"),
                "llm_calls": m.get("llm_calls"), "cost_usd": m.get("cost_usd"),
                "duration_s": round(time.time() - t0, 1), "log": logrel,
                "god_triage": (rep or {}).get("triage", {}).get("class"),
                "god_recos": len((rep or {}).get("recommendations", []) or []),
            })
        except Exception as e:
            rec.update({"ok": False, "error": str(e)[:300], "duration_s": round(time.time() - t0, 1)})
        results.append(rec)
        with open(prog_path, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        print(f"[batch] {i}/{len(targets)} {rec.get('verdict','ERR')} "
              f"triage={rec.get('god_triage')} ${rec.get('cost_usd')} {rec.get('duration_s')}s", flush=True)

    # ---- agrégation : évaluation d'architecture sur le lot ----
    import collections
    tri = collections.Counter(r.get("god_triage") for r in results if r.get("ok"))
    confirmed = sum(1 for r in results if r.get("confirmed"))
    cost = round(sum((r.get("cost_usd") or 0) for r in results), 4)
    # trous d'archi agrégés depuis les reports produits
    gaps = collections.Counter()
    for r in results:
        if not r.get("log"):
            continue
        try:
            rid = os.path.basename(r["log"]).replace(".json", "")
            rep = god_agent.get_report(rid)
            for rc in (rep or {}).get("recommendations", []):
                if rc["root_cause_class"] in ("oracle_coverage_gap", "canary_transformed", "environment_missing"):
                    gaps[rc["failure_signature"].get("sink_class")] += 1
        except Exception:
            pass
    summary = {
        "run": ts, "model": args.model, "n": len(results),
        "ok": sum(1 for r in results if r.get("ok")), "errors": sum(1 for r in results if not r.get("ok")),
        "confirmed": confirmed, "confirm_rate": round(confirmed / max(1, len(results)), 3),
        "triage": dict(tri), "architecture_gaps": dict(gaps),
        "total_cost_usd": cost, "total_minutes": round((time.time() - t_all) / 60, 1),
        "results": results,
    }
    json.dump(summary, open(summ_path, "w"), indent=2, ensure_ascii=False, default=str)
    print("\n[batch] ===== FINI =====", flush=True)
    print(json.dumps({k: summary[k] for k in ("n", "ok", "errors", "confirmed", "confirm_rate",
                                              "triage", "architecture_gaps", "total_cost_usd", "total_minutes")},
                     indent=2, ensure_ascii=False), flush=True)
    print(f"[batch] summary → {summ_path}", flush=True)


if __name__ == "__main__":
    main()
