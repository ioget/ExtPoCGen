#!/usr/bin/env python3
"""
god_agent — méta-agent « Architecte » d'ExtPoCGen.

RÔLE (cf. réflexion) : il ne GÉNÈRE PAS de PoC. Il est lancé APRÈS qu'un run a rendu son
résultat à l'utilisateur, lit la trace du run (logs/agent_runs/*.json), et diagnostique
POURQUOI la *preuve* a échoué. S'il s'agit d'une LIMITE D'ARCHITECTURE (oracle aveugle,
environnement manquant, contexte non attaché…), il consigne une RECOMMANDATION structurée.

GOUVERNANCE (modèle « reco-gated » validé avec l'utilisateur) :
    run → god_agent produit des RECOS (archi FIGÉE) → un humain VALIDE une reco →
    un agent de code applique le changement → god_eval mesure l'impact sur un dataset labellisé.
Le GOD agent n'écrit JAMAIS l'architecture lui-même : il « ouvre des PR » (recos versionnées,
testables). Le cœur de soundness (canary + oracle différentiel) reste intouchable : une reco
ne peut proposer que des OBSERVATEURS ou des ENABLERS d'environnement, jamais d'affaiblir le juge.

────────────────────────────────────────────────────────────────────────────────────────────
SCHÉMA D'UNE RECOMMANDATION (structure claire, exécutable et auto-testante) :

RecommendationReport = {
  "report_id":  str,                  # <ext_id>__<ts>
  "created_at": iso8601,
  "schema":     "god.reco.v1",
  "source_run": {extension_id, name, log_file, verdict, mode, model, confirmed},
  "triage": {                         # la décision (a)/(b)/(c)
     "class":      "architecture_limitation" | "poc_llm_deficiency"
                 | "true_negative_or_threat_model" | "confirmed_no_action" | "unknown",
     "confidence": float 0..1,
     "rationale":  str },
  "recommendations": [ Recommendation, ... ]   # 0..n (0 si rien à changer)
}

Recommendation = {
  "reco_id":      str,                # report_id + "#" + index
  "title":        str,
  "failure_signature": {              # COMMENT reconnaître ce motif d'échec
     "sink": str, "sink_class": str, "channel": str, "oracle_kind": str,
     "stage": str, "observed": {sink_fired, attacker_controlled, sink_called, ...},
     "symptoms": [str] },
  "root_cause_class":  str,           # oracle_coverage_gap | environment_missing | timing
                                      # | canary_transformed | context_not_attached
                                      # | backend_response_gated | threat_model_boundary | poc_shape
  "diagnosis": str,                   # le POURQUOI, justifié
  "proposed_change": {
     "kind": "add_observer" | "add_environment_enabler" | "add_stage_rung"
           | "flag_threat_model" | "feedback_to_generator" | "none",
     "target_files":     [str],       # fichiers qu'un agent de code toucherait
     "summary":          str,
     "declarative_spec": object|null },# si exprimable en données (ex. mapping sink→sonde)
  "validation_plan": {                # rend « runner la reco » DÉTERMINISTE
     "target_case":   {extension_id, name, expected_before, expected_after},
     "regression_set":[extension_id...],   # CONFIRMED connus : doivent rester CONFIRMED
     "clean_set":     [extension_id...],    # sains connus : doivent rester propres
     "expected_trace_delta": str },
  "soundness_guard": str,             # pourquoi ça NE PEUT PAS créer de faux positif
  "status": "proposed" | "validated" | "rejected" | "applied" | "measured",
  "impact": object|null               # rempli par god_eval après application
}
────────────────────────────────────────────────────────────────────────────────────────────
"""
import os, re, sys, json, glob, time, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(ROOT, "logs", "god_reports")
SCHEMA = "god.reco.v1"


# ====================================================================================
# REGISTRE DE CAPACITÉS — la « connaissance de soi » de l'architecture : ce que l'oracle
# sait OBSERVER aujourd'hui, et ses angles morts connus. Mis à jour quand une reco est
# appliquée (c'est, concrètement, la carte de couverture du harness).
# ====================================================================================
CAPABILITY_REGISTRY = {
    "version": "2026-11-11",
    "observers": {
        "code":    {"hooks": ["chrome.tabs.executeScript", "chrome.scripting.executeScript",
                              "Element.innerHTML(setter)", "Element.insertAdjacentHTML",
                              "Document.write", "Function", "eval(indirect)"],
                    "reads": []},
        "storage": {"hooks": ["Storage.prototype.setItem"],
                    "reads": ["chrome.storage.local", "chrome.storage.sync",
                              "window.localStorage", "window.sessionStorage"]},
        "cookie":  {"hooks": ["chrome.cookies.set"], "reads": ["document.cookie (CDP)"]},
        "network": {"hooks": [], "reads": ["sinkhole MAP * (capture payload sortant)"]},
    },
    "environment": {
        "https_serving": True,          # #2
        "ext_id_injection": True,       # Feature 2 (window.__EXT_ID__)
        "external_origin_serving": True,
        "backend_responder": True,      # #4 (responder déclaratif)
    },
    "contexts_attached": ["background_page", "service_worker", "onglets/iframes créés (autoattach)"],
    # Angles morts CONNUS et non encore couverts (sources de faux négatifs) :
    "known_gaps": {
        "code_eval":        "eval DIRECT non interceptable (spec JS) — indirect eval/Function désormais hooké",
        "cookie_document":  "setter document.cookie NON hooké (seul chrome.cookies.set l'est)",
        "storage_indexeddb":"IndexedDB NON lu",
        "canary_transform": "canary hashé/chiffré/encodé non suivi (match sous-chaîne seulement)",
    },
    # Contexte d'instrumentation du sink-probe (où les sondes tournent).
    # ADOPTÉ (cycle updating-learning) : + MONDE ISOLÉ du content-script -> sinks DOM/code du CS
    # désormais observables (prouvé par test synthétique innerHTML CONFIRMED, régression propre).
    "probe_contexts": ["background_page", "service_worker", "content_script_isolated_world"],
}

# Difficulté + bonne approche par trou — ENRICHI par les cycles « updating learning » (le GOD agent
# apprend quels trous sont des observateurs simples vs des chantiers profonds, pour ranker ses recos).
GAP_DIFFICULTY = {
    "code_eval": ("hard", "le eval DIRECT n'est pas interceptable en réécrivant window.eval (spec JS) ; "
                  "il faut instrumenter le MONDE ISOLÉ du content script OU observer l'EFFET aval du code évalué — "
                  "PAS un simple hook d'API"),
    "dom_xss": ("hard", "ces sinks tournent souvent dans le content script (monde isolé) ; le probe n'est posé "
                "que dans background/SW -> étendre l'instrumentation au contexte content-script d'abord"),
    "canary_transform": ("hard", "suivre btoa/encodeURIComponent/JSON.stringify/crypto.subtle, ou rendre un verdict "
                         "honnête `fired_but_canary_transformed`"),
    "cookie_document": ("easy", "hooker le setter document.cookie dans le bon contexte (additif)"),
    "storage_indexeddb": ("medium", "lire toutes les bases IndexedDB via CDP dans read_ext_storage (additif)"),
}


# ------------------------------------------------------------------ résolution sink → observateur
def _resolve_observer(sink, impact, oracle_kind):
    """ Pour un sink donné, renvoie (classe, mécanisme, observé?, clé-observateur-ou-gap).
        C'est le cœur du « contrat tout sink nommé → une sonde » : si le mécanisme n'a pas
        d'observateur dans le registre, c'est un trou de couverture candidat. """
    s = (sink or "").lower() + " " + (impact or "").lower()

    def has(*kw): return any(k in s for k in kw)

    # code
    if has("eval", "function_ctor", "settimeout", "setinterval") and not has("executescript"):
        return ("code", "eval/Function/setTimeout(string)", False, "code_eval")
    if has("executescript", "scripting"):
        return ("code", "executeScript", True, "code")
    # storage
    if has("indexeddb", "idb"):
        return ("storage", "IndexedDB", False, "storage_indexeddb")
    if has("localstorage", "sessionstorage", "setitem", "web_storage", "webstorage"):
        return ("storage", "window.localStorage/sessionStorage", True, "storage")
    if has("chrome_storage", "storage_local", "storage_sync", "storage.set", "storage_set"):
        return ("storage", "chrome.storage.*", True, "storage")
    # cookie
    if has("document_cookie", "document.cookie"):
        return ("cookie", "document.cookie (setter)", False, "cookie_document")
    if has("cookie"):
        return ("cookie", "chrome.cookies.set", True, "cookie")
    # dom — ADOPTÉ : désormais observé (hooks innerHTML/insertAdjacentHTML/document.write dans le
    # monde isolé du content-script). document.write DIRECT dans la page reste hooké aussi.
    if has("innerhtml", "insertadjacent", "document.write", "documentwrite", "outerhtml", "dom_xss"):
        return ("code", "DOM injection (innerHTML/document.write…)", True, "code")
    # network
    if has("fetch", "xmlhttp", "xhr", "sendbeacon", "ajax", "network", "exfil", "sendresponse"):
        return ("network", "requête sortante", True, "network")
    # fallback : s'aligner sur l'oracle_kind déclaré
    ok = (oracle_kind or "any")
    covered = ok in ("storage", "cookie", "network", "code")
    return (ok, "générique", covered, ok if covered else "unknown")


def _last_trace(hyp):
    steps = hyp.get("steps") or []
    for s in reversed(steps):
        if s.get("harness"):
            return s["harness"]
    return {}


def _harness_reachable_origin(ae):
    """ Une page servie par le harness (localhost / origine attaquant arbitraire) peut-elle
        atteindre un canal de l'extension sous MODÈLE A (page web malveillante arbitraire) ?
        - externally_connectable.matches incluant localhost / un wildcard large -> onMessageExternal joignable
        - content_scripts.matches incluant <all_urls> / *://*/* / motif large -> canal window.message joignable
        Si la surface est verrouillée à l'origine first-party (reqbin.com, amazon.com…),
        une page ARBITRAIRE ne peut PAS déclencher le handler -> hors modèle A.
        Renvoie (reachable: bool, reason: str). """
    ae = ae or {}
    ec = ae.get("externally_connectable") or {}
    ec_matches = ec.get("matches", []) if isinstance(ec, dict) else []
    cs_matches = ae.get("content_scripts_matches", []) or []

    def broad(m):
        m = (m or "").lower()
        if m in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*"):
            return True
        if "localhost" in m or "127.0.0.1" in m:
            return True
        # motif d'hôte joker (ex. *://*.foo/* reste first-party ; *://*/* est large)
        return m.startswith("*://*/") or m.startswith("http://*/") or m.startswith("https://*/")

    ec_reach = any(broad(m) for m in ec_matches)
    cs_reach = any(broad(m) for m in cs_matches)
    if ec_reach or cs_reach:
        via = "externally_connectable" if ec_reach else "content_scripts"
        return True, f"origine attaquant servable via {via} (localhost/large)"
    locked = []
    if ec_matches:
        locked.append(f"externally_connectable={list(ec_matches)[:3]}")
    if cs_matches:
        locked.append(f"content_scripts={list(cs_matches)[:2]}")
    return False, ("surface verrouillée first-party (" + " ; ".join(locked) + ")"
                   if locked else "aucune surface web déclarée")


# ------------------------------------------------------------------ dataset labellisé (connu)
def _known_confirmed(exclude=None):
    """ Extensions ayant déjà CONFIRMÉ (depuis les logs) = set de régression : avec le PoC
        sauvé, elles DOIVENT rester CONFIRMED après tout changement d'archi. """
    conf = {}
    for f in glob.glob(os.path.join(ROOT, "logs", "agent_runs", "*.json")):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if d.get("confirmed") and d.get("extension_id"):
            conf[d["extension_id"]] = d.get("name")
    conf.pop(exclude, None)
    return conf


# ------------------------------------------------------------------ diagnostic d'une hypothèse ratée
def _diagnose_hypothesis(hyp, fs):
    """ Renvoie (root_cause_class, triage_class, diagnosis, proposed_change) ou None si rien. """
    H = hyp.get("hypothesis", {}) or {}
    sink, channel, impact = H.get("sink", ""), H.get("channel", ""), H.get("impact_class", "")
    oracle = H.get("oracle", "")
    tr = _last_trace(hyp)
    stage = tr.get("stage")
    cls, mech, observed, obskey = _resolve_observer(sink, impact, _oracle_kind(impact, sink))

    # 1) canal EXTERNE non atteignable (garde reachability) = décision threat-model, PAS un bug d'archi
    if hyp.get("status") == "UNREACHABLE":
        return ("threat_model_boundary", "true_negative_or_threat_model",
                f"Canal externe `{channel}` sans origine servable : hors modèle d'attaquant page-web. "
                "Correct de NE PAS confirmer ; l'étendre serait une décision humaine de threat-model.",
                {"kind": "flag_threat_model", "target_files": [], "summary":
                 "À escalader à un humain si on veut couvrir ce modèle (ex. extension→extension).",
                 "declarative_spec": None})

    # 1.5) JOIGNABILITÉ (modèle A) : sink jamais atteint ET aucune origine attaquant servable
    #      -> l'échec vient du MODÈLE DE MENACE (surface verrouillée first-party : reqbin.com,
    #      amazon.com…), pas du générateur ni de l'oracle. Non-confirmation = vrai négatif.
    reachable, why = _harness_reachable_origin(fs.get("attacker_entry", {}))
    if (stage in ("sink_not_reached", None) and not tr.get("sink_fired")
            and not tr.get("sink_called") and not reachable):
        return ("threat_model_boundary", "true_negative_or_threat_model",
                f"Sink `{sink}` jamais atteint et {why} : sous le modèle A (page web arbitraire), "
                "aucun canal de l'extension n'est joignable par l'attaquant. Non-confirmation CORRECTE "
                "(vrai négatif). Élargir à une autre origine (first-party compromise / extension→extension) "
                "serait une décision humaine de threat-model, pas un correctif d'archi/générateur.",
                {"kind": "flag_threat_model", "target_files": [],
                 "summary": "Surface non joignable sous modèle A ; escalade humaine pour élargir le modèle.",
                 "declarative_spec": None})

    # 2) TROU DE COUVERTURE D'ORACLE : mécanisme non observé ET reconnu comme angle mort connu.
    #    (un sink générique/non classé ne déclenche PAS de reco archi confiante -> plutôt 'unknown')
    if not observed and obskey in CAPABILITY_REGISTRY["known_gaps"]:
        gap = CAPABILITY_REGISTRY["known_gaps"].get(obskey, f"mécanisme `{mech}` non observé")
        tf, spec = _remedy_for_gap(obskey, mech)
        diff, approach = GAP_DIFFICULTY.get(obskey, ("medium", ""))
        spec = dict(spec or {}); spec["difficulty"] = diff
        if approach:
            spec["approach"] = approach
        hard_note = (f" ⚠ DUR ({diff}) : {approach} — pas un observateur one-shot." if diff == "hard"
                     else f" (difficulté: {diff})")
        return ("oracle_coverage_gap", "architecture_limitation",
                f"Le sink `{sink}` est de classe **{cls}/{mech}**, que l'oracle ne sait PAS observer "
                f"({gap}). Même une PoC correcte tomberait en `{stage or 'sink_not_reached'}` : "
                f"faux négatif par couverture, pas par qualité de PoC.{hard_note}",
                {"kind": "add_observer", "target_files": tf, "difficulty": diff,
                 "summary": (f"Ajouter un observateur pour {cls}/{mech}. " +
                             (f"APPROCHE: {approach}" if diff == "hard"
                              else "Additif (sonde + lecture, cf. localStorage).")),
                 "declarative_spec": spec})

    # 3) sink observable mais jamais atteint : distinguer env / backend / poc
    if stage in ("sink_not_reached", None) and not tr.get("sink_fired"):
        served = tr.get("served_url") or ""
        caps = tr.get("captured_requests") or []
        unmatched = [c for c in caps if not c.get("matched")]
        # 3a) backend-response-gated : des appels sortants mais pas de responder
        if unmatched and not tr.get("responder_active"):
            return ("backend_response_gated", "poc_llm_deficiency",
                    "L'extension a émis des requêtes backend sans réponse utile : le sink part "
                    "peut-être APRÈS une réponse serveur. Le harness SAIT le faire (#4) — c'est au "
                    "générateur d'émettre un bloc POC-RESPONDER.",
                    {"kind": "feedback_to_generator", "target_files": [],
                     "summary": "Renvoyer au générateur : déclarer un POC-RESPONDER.",
                     "declarative_spec": None})
        # 3b) rien d'observable côté réseau et sink pas appelé : probable souci de PoC/timing/forme
        return ("poc_shape", "poc_llm_deficiency",
                "Sink observable mais jamais appelé, et aucune piste d'environnement : vraisemblablement "
                "la forme du message / le timing de la PoC. Boucle de raffinement (générateur), pas archi.",
                {"kind": "feedback_to_generator", "target_files": [],
                 "summary": "Laisser les refiners (forme du message exacte + dispatch répété).",
                 "declarative_spec": None})

    # 4) sink appelé sans le canary : soit routage de canary (poc), soit canary transformé (archi)
    if tr.get("sink_called") and not tr.get("sink_fired"):
        return ("canary_transformed", "architecture_limitation",
                "Le sink est APPELÉ mais sans le canary littéral. Soit la PoC n'injecte pas le canary "
                "dans le champ teinté (poc), soit l'extension transforme la valeur (hash/encode/chiffre) "
                "avant le sink → le match sous-chaîne est aveugle (archi).",
                {"kind": "add_observer", "target_files": ["code/harness.py"],
                 "summary": "Suivi des transformations (btoa/encodeURIComponent/JSON.stringify/crypto) "
                            "ou verdict honnête `fired_but_canary_transformed`.",
                 "declarative_spec": None})
    return None


def _oracle_kind(impact, sink):
    imp, snk = (impact or "").lower(), (sink or "").lower()
    if "storage" in imp or "storage" in snk: return "storage"
    if "cookie" in imp or "cookie" in snk: return "cookie"
    if any(t in imp or t in snk for t in ("network", "fetch", "ajax", "xmlhttp", "exfil", "sendresponse")):
        return "network"
    if "code" in imp: return "code"
    return "any"


def _remedy_for_gap(obskey, mech):
    """ Fichiers à toucher + spec déclarative pour combler un trou de couverture connu. """
    H = "code/harness.py"
    table = {
        "code_eval":         ([H], {"add_hook": ["window.eval", "Function", "setTimeout(string)"],
                                    "where": "_install_sink_probe", "marker": "code.eval"}),
        "cookie_document":   ([H], {"hook_setter": "document.cookie", "where": "_install_sink_probe",
                                    "marker": "document.cookie"}),
        "storage_indexeddb": ([H], {"read": "IndexedDB (toutes bases) via CDP", "where": "read_ext_storage"}),
        "dom_xss":           ([H], {"add_hook": ["Element.innerHTML setter", "insertAdjacentHTML", "document.write"],
                                    "where": "_install_sink_probe", "marker": "dom.inject"}),
    }
    return table.get(obskey, ([H], {"note": f"ajouter observateur pour {mech}"}))


# ------------------------------------------------------------------ analyse d'un run complet
def analyze_log(log_path):
    """ Produit (et renvoie) un RecommendationReport pour un log de run donné. """
    d = json.load(open(log_path))
    ext_id = d.get("extension_id")
    fs = d.get("input_fact_sheet", {}) or {}
    verdict = "CONFIRMED" if d.get("confirmed") else (d.get("status") or "none")
    report_id = f"{ext_id}__{d.get('timestamp') or time.strftime('%Y%m%d-%H%M%S')}"

    recos = []
    for hyp in (d.get("hypotheses") or []):
        if hyp.get("status") == "CONFIRMED":
            continue
        diag = _diagnose_hypothesis(hyp, fs)
        if not diag:
            continue
        root_cause, triage_cls, diagnosis, change = diag
        H = hyp.get("hypothesis", {}) or {}
        tr = _last_trace(hyp)
        cls, mech, observed, obskey = _resolve_observer(H.get("sink", ""), H.get("impact_class", ""),
                                                        _oracle_kind(H.get("impact_class"), H.get("sink")))
        regset = _known_confirmed(exclude=ext_id)
        reco = {
            "reco_id": f"{report_id}#{len(recos)}",
            "title": f"{root_cause} — {cls}/{mech}",
            "failure_signature": {
                "sink": H.get("sink"), "sink_class": f"{cls}/{mech}",
                "channel": H.get("channel"), "oracle_kind": _oracle_kind(H.get("impact_class"), H.get("sink")),
                "stage": tr.get("stage"),
                "observed": {k: tr.get(k) for k in ("sink_fired", "attacker_controlled", "sink_called",
                                                    "storage_hit", "responder_active")},
                "symptoms": _symptoms(tr)},
            "root_cause_class": root_cause,
            "diagnosis": diagnosis,
            "proposed_change": change,
            "validation_plan": {
                "target_case": {"extension_id": ext_id, "name": d.get("name"),
                                "expected_before": "FAILED", "expected_after":
                                "CONFIRMED" if root_cause in ("oracle_coverage_gap", "canary_transformed")
                                else "unchanged (hors archi)"},
                "regression_set": list(regset.keys()),
                "clean_set": [],
                "expected_trace_delta": _expected_delta(root_cause)},
            "soundness_guard":
                "Changement d'OBSERVATION/ENVIRONNEMENT uniquement ; le juge (canary + run différentiel) "
                "est inchangé. Validé par : la cible bascule CONFIRMED ET tout le regression_set reste "
                "CONFIRMED avec control propre.",
            "status": "proposed",
            "impact": None,
        }
        recos.append(reco)

    triage = _overall_triage(d, recos)
    report = {
        "report_id": report_id, "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "schema": SCHEMA,
        "source_run": {"extension_id": ext_id, "name": d.get("name"),
                       "log_file": os.path.relpath(log_path, ROOT), "verdict": verdict,
                       "mode": d.get("mode"), "model": d.get("model"), "confirmed": d.get("confirmed")},
        "triage": triage,
        "recommendations": recos,
    }
    return report


def _symptoms(tr):
    out = []
    if tr.get("stage"): out.append(f"stage={tr['stage']}")
    if tr.get("served_url"): out.append(f"served={tr['served_url']}")
    if tr.get("sink_called") and not tr.get("sink_fired"): out.append("sink appelé sans canary")
    caps = tr.get("captured_requests") or []
    if caps: out.append(f"{len(caps)} requête(s) captée(s)")
    return out


def _expected_delta(root_cause):
    return {
        "oracle_coverage_gap": "stage: sink_not_reached → confirmed (le sink devient observable).",
        "canary_transformed": "le canary (ou sa forme transformée) apparaît au sink au run attaquant seul.",
        "backend_response_gated": "responder_active=True → le sink part après la réponse canned.",
    }.get(root_cause, "verdict inchangé (hors périmètre archi).")


def _overall_triage(d, recos):
    if d.get("confirmed"):
        return {"class": "confirmed_no_action", "confidence": 1.0,
                "rationale": "Run CONFIRMÉ : couverture d'oracle suffisante pour ce sink."}
    arch = [r for r in recos if r["root_cause_class"] in
            ("oracle_coverage_gap", "canary_transformed", "context_not_attached", "environment_missing")]
    if arch:
        return {"class": "architecture_limitation", "confidence": 0.8,
                "rationale": f"{len(arch)} limite(s) d'architecture détectée(s) : "
                             + ", ".join(sorted({r['root_cause_class'] for r in arch}))}
    if any(r["root_cause_class"] in ("poc_shape", "backend_response_gated") for r in recos):
        return {"class": "poc_llm_deficiency", "confidence": 0.6,
                "rationale": "Échec probablement côté générateur (forme/timing/responder), pas archi."}
    if any(r["root_cause_class"] == "threat_model_boundary" for r in recos):
        return {"class": "true_negative_or_threat_model", "confidence": 0.7,
                "rationale": "Non-confirmation correcte : hors modèle d'attaquant."}
    return {"class": "unknown", "confidence": 0.3, "rationale": "Pas de cause claire — à inspecter."}


# ------------------------------------------------------------------ persistance + statut
def save_report(report):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    path = os.path.join(REPORTS_DIR, report["report_id"] + ".json")
    json.dump(report, open(path, "w"), indent=2, ensure_ascii=False, default=str)
    return path


def list_reports():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    out = []
    for p in sorted(glob.glob(os.path.join(REPORTS_DIR, "*.json")), key=os.path.getmtime, reverse=True):
        try:
            r = json.load(open(p))
        except Exception:
            continue
        out.append({"report_id": r.get("report_id"), "created_at": r.get("created_at"),
                    "name": r.get("source_run", {}).get("name"),
                    "extension_id": r.get("source_run", {}).get("extension_id"),
                    "verdict": r.get("source_run", {}).get("verdict"),
                    "triage": r.get("triage", {}).get("class"),
                    "n_recos": len(r.get("recommendations") or []),
                    "statuses": [rc.get("status") for rc in (r.get("recommendations") or [])]})
    return out


def get_report(report_id):
    path = os.path.join(REPORTS_DIR, report_id + ".json")
    return json.load(open(path)) if os.path.exists(path) else None


def set_reco_status(report_id, reco_id, status, note=None):
    assert status in ("proposed", "validated", "rejected", "applied", "measured")
    r = get_report(report_id)
    if not r:
        return None
    for rc in r.get("recommendations", []):
        if rc.get("reco_id") == reco_id:
            rc["status"] = status
            if note:
                rc.setdefault("notes", []).append({"at": datetime.datetime.now().isoformat(timespec="seconds"),
                                                   "status": status, "note": note})
    save_report(r)
    return r


# ------------------------------------------------------------------ validation de structure
_ROOT_CAUSES = {"oracle_coverage_gap", "environment_missing", "timing", "canary_transformed",
                "context_not_attached", "backend_response_gated", "threat_model_boundary", "poc_shape"}
_KINDS = {"add_observer", "add_environment_enabler", "add_stage_rung", "flag_threat_model",
          "feedback_to_generator", "none"}


def validate_report(report):
    """ Vérifie qu'un report respecte le schéma god.reco.v1. Renvoie (ok, [erreurs]). """
    errs = []
    for k in ("report_id", "created_at", "schema", "source_run", "triage", "recommendations"):
        if k not in report:
            errs.append(f"champ manquant: {k}")
    if report.get("schema") != SCHEMA:
        errs.append(f"schema != {SCHEMA}")
    for i, rc in enumerate(report.get("recommendations", [])):
        for k in ("reco_id", "title", "failure_signature", "root_cause_class", "diagnosis",
                  "proposed_change", "validation_plan", "soundness_guard", "status"):
            if k not in rc:
                errs.append(f"reco[{i}] champ manquant: {k}")
        if rc.get("root_cause_class") not in _ROOT_CAUSES:
            errs.append(f"reco[{i}] root_cause_class invalide: {rc.get('root_cause_class')}")
        if rc.get("proposed_change", {}).get("kind") not in _KINDS:
            errs.append(f"reco[{i}] proposed_change.kind invalide")
        vp = rc.get("validation_plan", {})
        if "target_case" not in vp or "regression_set" not in vp:
            errs.append(f"reco[{i}] validation_plan incomplet")
    return (not errs, errs)


# ------------------------------------------------------------------ point d'entrée post-run
def analyze_after_run(log_rel_or_abs):
    """ Appelé par le serveur APRÈS qu'un run a rendu son résultat. Lit le log, produit le
        report, le valide, le sauve. Tolérant aux erreurs (ne doit jamais casser le run). """
    try:
        p = log_rel_or_abs if os.path.isabs(log_rel_or_abs) else os.path.join(ROOT, log_rel_or_abs)
        if not os.path.exists(p):
            return None
        report = analyze_log(p)
        ok, errs = validate_report(report)
        report["_schema_valid"] = ok
        if not ok:
            report["_schema_errors"] = errs
        return save_report(report)
    except Exception as e:
        return {"error": str(e)}


def latest_log():
    fs = sorted(glob.glob(os.path.join(ROOT, "logs", "agent_runs", "*.json")), key=os.path.getmtime)
    return fs[-1] if fs else None


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", help="chemin d'un log de run à analyser")
    ap.add_argument("--latest", action="store_true", help="analyser le dernier run")
    ap.add_argument("--list", action="store_true", help="lister les reports existants")
    ap.add_argument("--all", action="store_true", help="(ré)analyser TOUS les logs")
    args = ap.parse_args()
    if args.list:
        print(json.dumps(list_reports(), indent=2, ensure_ascii=False)); return
    if args.all:
        n = 0
        for f in glob.glob(os.path.join(ROOT, "logs", "agent_runs", "*.json")):
            r = analyze_log(f); save_report(r); n += 1
        print(f"{n} logs analysés → {REPORTS_DIR}"); return
    log = args.log or (latest_log() if args.latest else None)
    if not log:
        print("rien à analyser (utiliser --log / --latest / --all)"); return
    report = analyze_log(log)
    ok, errs = validate_report(report)
    path = save_report(report)
    print(f"report: {path}\nschema_valid: {ok} {errs if errs else ''}")
    print(json.dumps(report, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    main()
