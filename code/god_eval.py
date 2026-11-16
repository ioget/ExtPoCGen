#!/usr/bin/env python3
"""
god_eval — mesure l'IMPACT d'une reco du GOD agent sur un dataset LABELLISÉ, en REJOUANT les
PoCs déjà sauvées (aucun appel LLM : rapide, déterministe, pas cher).

Usage (modèle reco-gated) :
    1. baseline  : god_eval mesure l'état AVANT (dataset labellisé → taux de confirmation).
    2. un humain valide la reco → un agent de code applique le changement (harness.py…).
    3. impact    : god_eval remesure APRÈS → diff (cible bascule ? régressions ? faux positifs ?).

Jeux :
    - regression_set : extensions déjà CONFIRMÉES → avec leur PoC sauvée, DOIVENT rester CONFIRMED.
    - target_case    : l'extension que la reco doit faire basculer FAILED → CONFIRMED.
    - clean_set      : (optionnel) extensions où le PoC NE DOIT PAS confirmer (anti-faux-positif).

Rejoue via le MÊME chemin de production (HarnessCDP.execute + oracle différentiel), en
reconstruisant la fact-sheet minimale depuis le log du run.
"""
import os, sys, json, glob, time, tempfile, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _victim_dir(ext_id):
    for cls in ("vulnerable", "malware", "unlabel"):
        p = os.path.join(ROOT, "min-set", cls, ext_id)
        if os.path.isdir(p):
            return p
    return None


def _best_log(ext_id, prefer_confirmed=True):
    """ Dernier log de cet ext, en privilégiant un run CONFIRMÉ (qui porte un PoC prouvé). """
    logs = sorted(glob.glob(os.path.join(ROOT, "logs", "agent_runs", ext_id + "*.json")),
                  key=os.path.getmtime, reverse=True)
    if prefer_confirmed:
        for p in logs:
            try:
                if json.load(open(p)).get("confirmed"):
                    return p
            except Exception:
                pass
    return logs[0] if logs else None


def _pick_hypothesis(log, want_sink=None):
    """ Choisit l'hypothèse à rejouer : celle du sink voulu si donné, sinon une CONFIRMED,
        sinon la première avec un exploit non vide. """
    hyps = log.get("hypotheses") or []
    if want_sink:
        for h in hyps:
            if h.get("hypothesis", {}).get("sink") == want_sink and (h.get("exploit") or "").strip():
                return h
    for h in hyps:
        if h.get("status") == "CONFIRMED" and (h.get("exploit") or "").strip():
            return h
    for h in hyps:
        if (h.get("exploit") or "").strip():
            return h
    return None


def _oracle_kind(impact, sink):
    imp, snk = (impact or "").lower(), (sink or "").lower()
    if "storage" in imp or "storage" in snk: return "storage"
    if "cookie" in imp or "cookie" in snk: return "cookie"
    if any(t in imp or t in snk for t in ("network", "fetch", "ajax", "xmlhttp", "exfil", "sendresponse")):
        return "network"
    if "code" in imp: return "code"
    return "any"


def replay_extension(ext_id, want_sink=None, isolate=True):
    """ Rejoue le PoC sauvé de `ext_id` via HarnessCDP.execute. Renvoie un dict résultat. """
    from orchestrator import ExploitCandidate, _cost  # noqa
    from harness import HarnessCDP
    vdir = _victim_dir(ext_id)
    if not vdir:
        return {"ext_id": ext_id, "ran": False, "error": "victim dir introuvable (min-set)"}
    logp = _best_log(ext_id)
    if not logp:
        return {"ext_id": ext_id, "ran": False, "error": "aucun log (pas de PoC sauvé)"}
    log = json.load(open(logp))
    hyp = _pick_hypothesis(log, want_sink)
    if not hyp:
        return {"ext_id": ext_id, "ran": False, "error": "aucune hypothèse avec exploit"}
    H = hyp.get("hypothesis", {}) or {}
    code = hyp.get("exploit") or ""
    ae = (log.get("input_fact_sheet", {}) or {}).get("attacker_entry", {}) or {}
    fs = {
        "manifest_version": log.get("manifest_version"),
        "_victim_dir": vdir,
        "attacker_entry": ae,
        "_channel": H.get("channel"),
        "_oracle_kind": _oracle_kind(H.get("impact_class"), H.get("sink")),
    }
    exploit = ExploitCandidate(code=code, attacker_model=H.get("attacker_model", "A"))
    t0 = time.time()
    res = HarnessCDP(isolate=isolate).execute(exploit, fs)
    tr = res.trace or {}
    return {
        "ext_id": ext_id, "name": log.get("name"), "sink": H.get("sink"),
        "ran": res.ran, "confirmed": (res.coverage == 1.0),
        "stage": tr.get("stage"), "sink_fired": tr.get("sink_fired"),
        "attacker_controlled": tr.get("attacker_controlled"),
        "storage_hit": tr.get("storage_hit"), "t_s": round(time.time() - t0, 1),
        "error": tr.get("error"),
    }


def measure_set(ext_ids, want_sink=None, isolate=True, emit=None):
    """ Rejoue un ensemble d'extensions. emit(dict) = callback de progression (optionnel). """
    out = []
    for e in ext_ids:
        r = replay_extension(e, want_sink=want_sink, isolate=isolate)
        out.append(r)
        if emit:
            emit({"type": "replay", "result": r})
    return out


def measure_reco(report_id, reco_id, isolate=True, emit=None):
    """ Mesure l'impact d'une reco : rejoue target_case + regression_set, écrit `impact` dans le
        report et passe la reco en statut `measured`. À lancer APRÈS application du changement. """
    import god_agent as g
    report = g.get_report(report_id)
    if not report:
        return {"error": "report introuvable"}
    reco = next((r for r in report.get("recommendations", []) if r.get("reco_id") == reco_id), None)
    if not reco:
        return {"error": "reco introuvable"}
    vp = reco.get("validation_plan", {})
    target = vp.get("target_case", {}).get("extension_id")
    regset = vp.get("regression_set", []) or []
    cleanset = vp.get("clean_set", []) or []
    want_sink = reco.get("failure_signature", {}).get("sink")

    if emit: emit({"type": "measure_start", "target": target, "n_regression": len(regset)})
    target_res = replay_extension(target, want_sink=want_sink, isolate=isolate) if target else None
    if emit: emit({"type": "target_done", "result": target_res})
    reg_res = measure_set(regset, isolate=isolate, emit=emit)
    clean_res = measure_set(cleanset, isolate=isolate, emit=emit)

    reg_ok = sum(1 for r in reg_res if r.get("confirmed"))
    regressions = [r["ext_id"] for r in reg_res if not r.get("confirmed")]
    false_pos = [r["ext_id"] for r in clean_res if r.get("confirmed")]
    impact = {
        "measured_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": {"extension_id": target,
                   "confirmed_now": bool(target_res and target_res.get("confirmed")),
                   "detail": target_res},
        "regression": {"total": len(reg_res), "still_confirmed": reg_ok,
                       "regressed": regressions},
        "clean": {"total": len(clean_res), "false_positives": false_pos},
        "verdict": _impact_verdict(target_res, regressions, false_pos, reco),
        "runs": {"target": target_res, "regression": reg_res, "clean": clean_res},
    }
    reco["impact"] = impact
    reco["status"] = "measured"
    g.save_report(report)
    if emit: emit({"type": "measure_done", "impact": impact})
    return impact


def _impact_verdict(target_res, regressions, false_pos, reco):
    want_flip = reco.get("validation_plan", {}).get("target_case", {}).get("expected_after") == "CONFIRMED"
    if regressions:
        return f"REJETÉ — {len(regressions)} régression(s) dans le set confirmé"
    if false_pos:
        return f"REJETÉ — {len(false_pos)} faux positif(s) sur le set sain (soundness)"
    if want_flip and target_res and target_res.get("confirmed"):
        return "ADOPTABLE — cible basculée CONFIRMED, aucune régression, aucun faux positif"
    if want_flip:
        return "SANS EFFET — la cible ne confirme toujours pas"
    return "NEUTRE — aucune régression (reco hors périmètre archi)"


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--replay", help="rejoue le PoC d'un ext_id")
    ap.add_argument("--sink", default=None, help="forcer l'hypothèse de ce sink")
    ap.add_argument("--measure", nargs=2, metavar=("REPORT_ID", "RECO_ID"),
                    help="mesure l'impact d'une reco (target + regression)")
    ap.add_argument("--no-isolate", action="store_true", help="désactive unshare (debug)")
    args = ap.parse_args()
    iso = not args.no_isolate
    if args.replay:
        print(json.dumps(replay_extension(args.replay, want_sink=args.sink, isolate=iso),
                         indent=2, ensure_ascii=False))
    elif args.measure:
        print(json.dumps(measure_reco(args.measure[0], args.measure[1], isolate=iso,
                                      emit=lambda e: print("  ·", e.get("type"), e.get("result", {}).get("ext_id", ""),
                                                           file=sys.stderr)),
                         indent=2, ensure_ascii=False))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
