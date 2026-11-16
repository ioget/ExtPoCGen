#!/usr/bin/env python3
"""
server — application LOCALE d'ExtPoCGen.
Sert le dashboard et fait tourner le VRAI orchestrator, en streamant les actions de
l'agent en direct (SSE). Stdlib uniquement (http.server + threading + queue).

    python3 code/server.py           # http://127.0.0.1:8750
    python3 code/server.py --port 9000 --no-browser
"""
import os, sys, json, glob, uuid, queue, threading, argparse, zipfile, tempfile, subprocess
import http.server, socketserver
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "code"))
FACT = os.path.join(ROOT, "tool_outputs", "fact_sheets")

RUNS = {}   # run_id -> Queue d'événements
CTRL = {}   # run_id -> {"cap", "ev", "abort"} pour la pause/budget LLM
LLM_BUDGET = 24   # plafond d'appels LLM avant de demander à l'utilisateur
BUDGET_STEP = 24  # +N appels quand l'utilisateur choisit "continue"


def list_extensions():
    out = []
    for p in sorted(glob.glob(os.path.join(FACT, "*.json"))):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        out.append({"ext": d["extension_id"], "name": d.get("name") or d["extension_id"],
                    "cls": d.get("class"), "mv": d.get("manifest_version"),
                    "triage": d.get("triage", {}).get("state"),
                    "model": d.get("attacker_entry", {}).get("model"),
                    "exploitable": d.get("exploitable_count", 0)})
    return out


def list_history():
    runs = []
    for p in sorted(glob.glob(os.path.join(ROOT, "logs", "agent_runs", "*.json")), key=os.path.getmtime, reverse=True):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        m = d.get("metrics", {})
        mb = d.get("malware_behavior")
        status = d.get("status", "ok")
        verdict = ("CONFIRMED" if d.get("confirmed") else "MALICIOUS" if (mb and mb.get("suspicious"))
                   else "STOPPED" if status == "stopped" else "ERROR" if status == "error" else "none")
        runs.append({"id": d.get("timestamp"), "ext": d.get("extension_id"), "name": d.get("name"),
                     "cls": d.get("class"), "mv": d.get("manifest_version"), "model": d.get("model"),
                     "verdict": verdict, "status": status, "time": m.get("duration_s"),
                     "tokens": m.get("total_tokens"), "cost": m.get("cost_usd"),
                     "paths": d.get("routing", {}).get("paths_activated")})
    # nom lisible par extension_id (depuis les fact sheets)
    names = {}
    for fp in glob.glob(os.path.join(FACT, "*.json")):
        try:
            d = json.load(open(fp)); names[d.get("extension_id")] = d.get("name")
        except Exception:
            pass
    # exploits confirmés (poc_repo) — détaillés
    poc = []
    for p in sorted(glob.glob(os.path.join(ROOT, "poc_repo", "*.json")), key=os.path.getmtime, reverse=True):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        ext = d.get("extension")
        poc.append({"file": os.path.basename(p), "ext": ext, "name": names.get(ext) or ext,
                    "sink": d.get("sink"), "impact": d.get("impact_class"), "model": d.get("attacker_model"),
                    "iterations": d.get("iterations"), "oracle": d.get("oracle"),
                    "provenance": d.get("provenance"), "exploit": d.get("exploit", "")})
    # comportements malveillants (behavior_repo) — détaillés
    beh = []
    for p in sorted(glob.glob(os.path.join(ROOT, "behavior_repo", "*.json")), key=os.path.getmtime, reverse=True):
        try:
            b = json.load(open(p))
        except Exception:
            continue
        ex = b.get("exfiltration", {}) or {}
        beh.append({"file": os.path.basename(p), "ext": b.get("extension_id"),
                    "name": b.get("name") or names.get(b.get("extension_id")) or b.get("extension_id"),
                    "category": b.get("category"), "reason": (b.get("verdict", {}) or {}).get("reason"),
                    "iocs": b.get("iocs", {}).get("domains", []), "mitre": b.get("mitre_tags", []),
                    "exfil_confirmed": ex.get("confirmed"), "stolen": ex.get("stolen_kinds", []),
                    "n_external": (b.get("observed_behavior", {}) or {}).get("n_external_requests")})
    return {"runs": runs, "poc": poc, "behavior": beh}


UPLOADS = os.path.join(ROOT, "uploads")


def _safe_extract(zf, dest):
    """ Extraction d'une archive NON FIABLE : refuse tout chemin qui s'échappe (zip-slip). """
    dest = os.path.realpath(dest)
    for m in zf.infolist():
        p = os.path.realpath(os.path.join(dest, m.filename))
        if p != dest and not p.startswith(dest + os.sep):
            raise ValueError("unsafe path in archive: " + m.filename)
    zf.extractall(dest)


def _loose_json(txt):
    """ manifest.json tolérant (commentaires // et /* */, virgules traînantes). """
    import re as _re
    try:
        return json.loads(txt)
    except Exception:
        t = _re.sub(r"/\*.*?\*/", "", txt, flags=_re.S)
        t = _re.sub(r"(^|\s)//[^\n]*", "", t)
        t = _re.sub(r",(\s*[}\]])", r"\1", t)
        return json.loads(t)


def ingest_upload(raw, filename):
    """ Décompresse une extension uploadée (untrusted) et construit un fact sheet
        'incomplete-analysis' (pas de CoCo/DoubleX) → la run partira en behaviour-only. """
    import hashlib, io, zipfile
    if not raw:
        raise ValueError("empty upload")
    ext_id = "upload-" + hashlib.sha1(raw).hexdigest()[:10]
    dest = os.path.join(UPLOADS, ext_id)
    if os.path.isdir(dest):
        import shutil; shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(dest, exist_ok=True)
    data = raw
    if not data[:4] == b"PK\x03\x04":            # .crx : saute l'en-tête jusqu'au ZIP
        i = data.find(b"PK\x03\x04")
        if i == -1:
            raise ValueError("not a zip/crx archive")
        data = data[i:]
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        _safe_extract(zf, dest)
    try:                                   # garde le zip normalisé pour l'analyse statique (DoubleX unpack)
        open(os.path.join(dest, "_src.zip"), "wb").write(data)
    except Exception:
        pass
    # localise le manifest.json le moins profond
    man_path = None
    for root, _dirs, files in os.walk(dest):
        if "manifest.json" in files:
            cand = os.path.join(root, "manifest.json")
            if man_path is None or cand.count(os.sep) < man_path.count(os.sep):
                man_path = cand
    if not man_path:
        raise ValueError("no manifest.json in archive")
    ext_root = os.path.dirname(man_path)
    man = _loose_json(open(man_path, encoding="utf-8", errors="ignore").read())
    size_kb = round(sum(os.path.getsize(os.path.join(r, f))
                        for r, _d, fs in os.walk(ext_root) for f in fs) / 1024, 1)
    name = man.get("name") or os.path.splitext(os.path.basename(filename or ext_id))[0]
    if isinstance(name, str) and name.startswith("__MSG_"):
        name = os.path.splitext(os.path.basename(filename or ext_id))[0]
    mv = int(man.get("manifest_version", 3) or 3)
    import re as _re
    perms = man.get("permissions", []) or []
    # tools_off : sinks candidats dérivés des permissions ...
    PERM_SINK = {"storage": "chrome.storage.local.set", "cookies": "chrome.cookies.set",
                 "downloads": "chrome.downloads.download", "scripting": "chrome.scripting.executeScript",
                 "tabs": "chrome.tabs.executeScript", "nativeMessaging": "chrome.runtime.sendNativeMessage",
                 "webRequest": "chrome.webRequest.onBeforeRequest"}
    sinks = set(PERM_SINK[p] for p in perms if p in PERM_SINK)
    # ... ET découverte LÉGÈRE de candidats DEPUIS LE CODE (grep de sinks concrets + d'un listener
    # attaquant) : sinon une extension sans permission mappable n'a aucun sink à hypothétiser.
    CODE_SINKS = {r"\beval\s*\(": "eval", r"\.innerHTML\s*=": "innerHTML",
                  r"executeScript": "chrome.scripting.executeScript", r"chrome\.cookies\.set": "chrome.cookies.set",
                  r"chrome\.downloads\.download": "chrome.downloads.download",
                  r"chrome\.storage\.(?:local|sync)\.set": "chrome.storage.local.set",
                  r"\bfetch\s*\(": "fetch", r"XMLHttpRequest": "XMLHttpRequest_url_sink", r"document\.write": "document.write"}
    has_listener, nfiles = False, 0
    for rroot, _dd, ffiles in os.walk(ext_root):
        for ffn in ffiles:
            if nfiles > 60 or not ffn.endswith((".js", ".mjs")):
                continue
            nfiles += 1
            try:
                txt = open(os.path.join(rroot, ffn), encoding="utf-8", errors="ignore").read(800000)
            except Exception:
                continue
            for pat, nm in CODE_SINKS.items():
                if _re.search(pat, txt):
                    sinks.add(nm)
            if _re.search(r"addEventListener\(\s*['\"]message|onMessage|onMessageExternal|onConnect", txt):
                has_listener = True
    sinks = sorted(sinks)
    has_cs = bool(man.get("content_scripts"))
    surface = has_cs or bool(man.get("externally_connectable")) or has_listener
    model = "A" if surface else ("B" if sinks else "none")
    if model != "none" and not sinks:   # surface d'attaque mais aucun sink dérivé -> fallback générique
        sinks = ["eval / innerHTML (DOM code execution — resolve from code)"]
    fs = {
        "extension_id": ext_id, "name": name, "class": "upload", "manifest_version": mv,
        "size_kb": size_kb, "permissions": perms,
        "host_permissions": man.get("host_permissions", []), "ground_truth": None,
        "attacker_entry": {"model": model, "listeners": [],
                           "note": "upload — hypothèses tools_off (ancrées sur le manifeste)"},
        "analysis": {"coco": "skipped", "doublex": "skipped",
                     "note": "static tools unavailable on upload; tools_off (KB-only) + behaviour observation"},
        "candidate_findings": [], "exploitable_count": 0,
        "candidate_sinks_from_permissions": sinks,
        "triage": {"state": "incomplete-analysis",
                   "reason": "no static analysis (CoCo/DoubleX) run on uploaded archive"},
        "source_dir": ext_root, "uploaded": True, "upload_filename": filename,
    }
    os.makedirs(FACT, exist_ok=True)
    json.dump(fs, open(os.path.join(FACT, ext_id + ".json"), "w"), indent=2, ensure_ascii=False)
    return {"ext": ext_id, "name": name, "cls": "upload", "mv": mv,
            "permissions": fs["permissions"], "triage": "incomplete-analysis",
            "behavior_only": model == "none", "attacker_model": model,
            "candidate_sinks": sinks, "size_kb": size_kb}


# ---------------------------------------------------------------------------
# Analyse statique (CoCo + DoubleX) sur un upload — MÊME voie que le corpus
# pré-analysé, mais lancée en tâche de fond (CoCo prend des minutes).
# ---------------------------------------------------------------------------
STATIC = {}                                   # ext_id -> {"state", "triage", ...}
TOOLOUT = os.path.join(ROOT, "tool_outputs")
_DX = os.path.join(ROOT, "DoubleX")
_COCO = os.path.join(ROOT, "CoCo")

def _static_py():
    """Interpréteur ayant les deps des analyseurs (func_timeout, sty, jsbeautifier, bs4)."""
    cands = []
    if os.environ.get("EXTPOC_STATIC_PY"):
        cands.append(os.environ["EXTPOC_STATIC_PY"])
    _root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cands.append(os.path.join(_root, ".static_venv", "bin", "python"))
    cands.append(sys.executable)
    for c in cands:
        if c and os.path.exists(c):
            try:
                if subprocess.run([c, "-c", "import func_timeout,sty,jsbeautifier,bs4"],
                                  capture_output=True, timeout=20).returncode == 0:
                    return c
            except Exception:
                continue
    return None

def static_available():
    return bool(_static_py()) and os.path.isdir(_DX) and os.path.isdir(_COCO)

def _run(cmd, cwd, timeout):
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout).returncode
    except Exception:
        return -1

def _static_analyze_upload(ext_id):
    """DoubleX (2 passes) + CoCo sur l'upload, puis (re)build du fact sheet réel."""
    import shutil
    py = _static_py()
    if not py:
        STATIC[ext_id] = {"state": "unavailable"}; return
    try:
        fs_path = os.path.join(FACT, ext_id + ".json")
        fs = json.load(open(fs_path))
        ext_root = fs.get("source_dir")
        base = os.path.join(TOOLOUT, "upload", ext_id)
        for sub in ("doublex_default/extracted", "doublex_empoweb", "coco/generated"):
            os.makedirs(os.path.join(base, sub), exist_ok=True)
        # garantit un manifest pour le build (nom/permissions/listeners)
        if ext_root and os.path.exists(os.path.join(ext_root, "manifest.json")):
            shutil.copy2(os.path.join(ext_root, "manifest.json"),
                         os.path.join(base, "doublex_default/extracted/manifest.json"))
        # --- DoubleX : unpack + 2 passes (zip APLATI → manifest à la racine, sinon unpack ne le trouve pas) ---
        dxwork = os.path.join(base, "dxwork")
        shutil.rmtree(dxwork, ignore_errors=True)
        flat = os.path.join(base, "_ext.zip")
        if ext_root and os.path.isdir(ext_root):
            with zipfile.ZipFile(flat, "w", zipfile.ZIP_STORED) as z:
                for rr, _dd, ff in os.walk(ext_root):
                    for f in ff:
                        full = os.path.join(rr, f)
                        z.write(full, os.path.relpath(full, ext_root))
            _run([py, "src/unpack_extension.py", "-s", flat, "-d", dxwork], cwd=_DX, timeout=120)
            unp = os.path.join(dxwork, "_ext.zip")
            cs, bp = os.path.join(unp, "content_scripts.js"), os.path.join(unp, "background.js")
            man = os.path.join(unp, "manifest.json")
            if os.path.exists(cs):
                for f in ("content_scripts.js", "background.js", "wars.js", "manifest.json"):
                    s = os.path.join(unp, f)
                    if os.path.exists(s):
                        shutil.copy2(s, os.path.join(base, "doublex_default/extracted", f))
                _run([py, "src/doublex.py", "-cs", cs, "-bp", bp, "--manifest", man,
                      "--analysis", os.path.join(base, "doublex_default/analysis.json")], cwd=_DX, timeout=300)
                _run([py, "src/doublex.py", "-cs", cs, "-bp", bp, "--manifest", man, "--apis", "empoweb",
                      "--analysis", os.path.join(base, "doublex_empoweb/analysis_empoweb.json")], cwd=_DX, timeout=300)
        # --- CoCo (sur une COPIE : il écrit dans le dossier) ---
        if ext_root and os.path.isdir(ext_root):
            cocowork = os.path.join(base, "cocowork", ext_id)
            shutil.rmtree(os.path.join(base, "cocowork"), ignore_errors=True)
            shutil.copytree(ext_root, cocowork)
            _run([py, "generate_opg.py", "-t", "chrome_ext", "-crx", "-pq", "--timeout", "180", cocowork],
                 cwd=_COCO, timeout=240)
            gen = os.path.join(cocowork, "opgen_generated_files")
            if os.path.exists(os.path.join(gen, "used_time.txt")):
                shutil.copy2(os.path.join(gen, "used_time.txt"), os.path.join(base, "coco/used_time.txt"))
            for j in glob.glob(os.path.join(gen, "*.js")):
                shutil.copy2(j, os.path.join(base, "coco/generated", os.path.basename(j)))
        # --- (re)construit le fact sheet depuis les sorties RÉELLES ---
        import build_fact_sheets as B
        newfs = B.build("upload", ext_id)
        if newfs:
            newfs["source_dir"] = ext_root
            newfs["uploaded"] = True
            json.dump(newfs, open(fs_path, "w"), indent=2, ensure_ascii=False)
            STATIC[ext_id] = {"state": "done", "triage": newfs["triage"]["state"],
                              "exploitable": newfs.get("exploitable_count", 0),
                              "attacker_model": newfs["attacker_entry"]["model"]}
        else:
            STATIC[ext_id] = {"state": "error", "error": "build returned None"}
    except Exception as e:
        STATIC[ext_id] = {"state": "error", "error": str(e)[:200]}


def run_agent(run_id, ext_id, model):
    """ Lance l'orchestrator réel ; pousse chaque événement dans la queue du run. """
    import time
    q = RUNS[run_id]
    ctrl = {"cap": LLM_BUDGET, "ev": threading.Event(), "abort": False}
    CTRL[run_id] = ctrl
    def emit(e):
        q.put(e)
    t0 = time.time()
    agent = None
    try:
        from orchestrator import (GraphKB, DeepSeekAgent, MockSafety, TraceJudge,
                                  MalwareBehaviorAnalyst, Orchestrator, BudgetStop, _cost)
        from harness import HarnessCDP
        kb = GraphKB()
        agent = DeepSeekAgent(model=model) if model != "mock" else None
        if agent is None:
            from orchestrator import MockAgent
            agent = MockAgent()
        else:
            def gate(calls):                 # appelé avant chaque appel LLM
                if calls >= ctrl["cap"]:
                    q.put({"type": "budget", "calls": calls, "cap": ctrl["cap"], "step": BUDGET_STEP})
                    ctrl["ev"].clear()
                    if not ctrl["ev"].wait(timeout=1800):   # 30 min sans réponse -> stop
                        raise BudgetStop()
                    if ctrl["abort"]:
                        raise BudgetStop()
            agent.call_gate = gate
        orch = Orchestrator(kb, agent, MockSafety(), HarnessCDP(), TraceJudge(),
                            budget=3, malware_analyst=MalwareBehaviorAnalyst())
        out = orch.run(ext_id, emit=emit)
        m = out.get("metrics", {})
        v = out.get("vulnerability") or {}
        mb = out.get("malware_behavior") or {}
        mitre = []
        if out.get("behavior_report"):
            try:
                mitre = json.load(open(os.path.join(ROOT, out["behavior_report"]))).get("mitre_tags", [])
            except Exception:
                pass
        _mlvl = mb.get("level", "malicious" if mb.get("suspicious") else "clean")
        res = {"type": "result",
               "verdict": ("CONFIRMED" if out.get("confirmed") else
                           "MALICIOUS" if _mlvl == "malicious" else
                           "SUSPICIOUS" if _mlvl == "suspicious" else "none"),
               "paths": out.get("paths"), "metrics": m, "name": out.get("extension"),
               "vuln": {"confirmed": v.get("confirmed"), "results": [
                   {"status": r.get("status"), "sink": r.get("hypothesis", {}).get("sink"),
                    "impact": r.get("hypothesis", {}).get("impact_class"), "iter": r.get("iterations"),
                    "oracle": r.get("hypothesis", {}).get("oracle"),
                    "exploit": r.get("exploit"), "saved_to": r.get("saved_to")}
                   for r in v.get("results", [])]},
               "malware": ({"suspicious": mb.get("suspicious"), "level": _mlvl, "n_external": mb.get("n_external"),
                            "external": mb.get("external_requests") or [],
                            "iocs": sorted({(r.get("url") or "").split("/")[2] for r in (mb.get("external_requests") or []) if r.get("url")}),
                            "perms": mb.get("sensitive_permissions"), "mitre": mitre,
                            "exfil_confirmed": bool(mb.get("exfil_confirmed")),
                            "exfiltrated": mb.get("exfiltrated") or [],
                            "stolen": sorted({e.get("canary") for e in (mb.get("exfiltrated") or [])}),
                            "behaviors": mb.get("behaviors") or [],
                            "reproducibility": mb.get("reproducibility"), "n_runs": mb.get("n_runs"),
                            "report": out.get("behavior_report")} if mb else None)}
        # récap STATIQUE (CoCo/DoubleX) + candidats, pour le rapport détaillé (résultat clean/budget)
        try:
            _fs = json.load(open(os.path.join(FACT, ext_id + ".json")))
            res["static"] = {
                "triage": _fs.get("triage", {}).get("state"),
                "attacker_model": _fs.get("attacker_entry", {}).get("model"),
                "findings": [{"source": f.get("source"), "sink": f.get("sink"),
                              "impact": f.get("impact_class"), "confidence": f.get("confidence"),
                              "origin": f.get("origin")} for f in _fs.get("candidate_findings", [])][:12],
                "candidate_sinks": _fs.get("candidate_sinks_from_permissions") or [],
            }
        except Exception:
            res["static"] = None
        q.put(res)
    except BudgetStop:
        u = getattr(agent, "usage", {}) or {}
        from orchestrator import _cost as _costfn
        q.put({"type": "phase", "node": "orc", "msg": "Stopped by user at LLM budget cap", "kind": "alert"})
        _st = None
        try:
            _fs = json.load(open(os.path.join(FACT, ext_id + ".json")))
            _st = {"triage": _fs.get("triage", {}).get("state"),
                   "attacker_model": _fs.get("attacker_entry", {}).get("model"),
                   "findings": [{"source": f.get("source"), "sink": f.get("sink"), "impact": f.get("impact_class"),
                                 "confidence": f.get("confidence"), "origin": f.get("origin")}
                                for f in _fs.get("candidate_findings", [])][:12],
                   "candidate_sinks": _fs.get("candidate_sinks_from_permissions") or []}
        except Exception:
            pass
        q.put({"type": "result", "verdict": "stopped", "static": _st,
               "metrics": {"duration_s": round(time.time() - t0, 2), "llm_calls": u.get("calls", 0),
                           "total_tokens": u.get("prompt_tokens", 0) + u.get("completion_tokens", 0),
                           "cost_usd": _costfn(model, u)}})
    except Exception as e:
        import traceback
        q.put({"type": "phase", "node": "", "msg": "ERROR: " + str(e), "kind": "alert"})
        q.put({"type": "result", "verdict": "error", "error": str(e), "trace": traceback.format_exc()[-800:]})
    finally:
        CTRL.pop(run_id, None)
        # GOD agent (méta-architecte) : lancé APRÈS que le résultat est rendu à l'utilisateur.
        # Lit le log du run tout juste écrit, diagnostique pourquoi la PREUVE a échoué et consigne
        # une recommandation structurée (archi FIGÉE — il « ouvre une PR », il ne l'applique pas).
        q.put({"type": "god", "status": "analyzing"})
        threading.Thread(target=_god_after_run, args=(ext_id, run_id), daemon=True).start()
        q.put({"type": "done"})


def _god_after_run(ext_id, run_id=None):
    """ Analyse post-run du GOD agent sur le dernier log de cet ext (tolérant aux erreurs). """
    try:
        import god_agent
        log = sorted(glob.glob(os.path.join(ROOT, "logs", "agent_runs", ext_id + "*.json")),
                     key=os.path.getmtime)
        if log:
            god_agent.analyze_after_run(log[-1])
    except Exception:
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            html = open(os.path.join(ROOT, "code", "dashboard.html"), encoding="utf-8").read()
            return self._send(200, html, "text/html; charset=utf-8")
        if u.path == "/api/extensions":
            return self._send(200, list_extensions())
        if u.path == "/api/history":
            return self._send(200, list_history())
        if u.path == "/api/stream":
            rid = parse_qs(u.query).get("run", [""])[0]
            return self._sse(rid)
        # ---- GOD agent (méta-architecte) ----
        if u.path in ("/god", "/god.html"):
            html = open(os.path.join(ROOT, "code", "god.html"), encoding="utf-8").read()
            return self._send(200, html, "text/html; charset=utf-8")
        if u.path == "/api/upload_status":
            ext = parse_qs(u.query).get("ext", [""])[0]
            return self._send(200, STATIC.get(ext, {"state": "none"}))
        if u.path == "/api/god/reports":
            import god_agent
            return self._send(200, god_agent.list_reports())
        if u.path == "/api/god/report":
            import god_agent
            r = god_agent.get_report(parse_qs(u.query).get("id", [""])[0])
            return self._send(200 if r else 404, r or {"error": "no such report"})
        if u.path == "/api/god/capabilities":
            import god_agent
            return self._send(200, god_agent.CAPABILITY_REGISTRY)
        return self._send(404, {"error": "not found"})

    def _sse(self, rid):
        q = RUNS.get(rid)
        if q is None:
            return self._send(404, {"error": "no such run"})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                try:
                    e = q.get(timeout=20)
                except queue.Empty:
                    # KEEP-ALIVE : un appel LLM (reasoner 16k/32k) peut durer > 2 min sans émettre
                    # d'event ; sans ça le flux se coupait (dashboard figé « sans résultat »). On ne
                    # termine QUE sur l'event 'done' (toujours émis par run_agent) ou déconnexion client.
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    continue
                self.wfile.write(("data: " + json.dumps(e) + "\n\n").encode())
                self.wfile.flush()
                if e.get("type") == "done":
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            RUNS.pop(rid, None)

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        if u.path == "/api/scan":
            body = json.loads(raw or b"{}")
            ext_id = body.get("ext_id")
            model = body.get("model", "deepseek-reasoner")
            if not ext_id or not os.path.isfile(os.path.join(FACT, ext_id + ".json")):
                return self._send(400, {"error": "unknown extension"})
            rid = uuid.uuid4().hex[:12]
            RUNS[rid] = queue.Queue()
            threading.Thread(target=run_agent, args=(rid, ext_id, model), daemon=True).start()
            return self._send(200, {"run_id": rid})
        if u.path == "/api/decision":
            body = json.loads(raw or b"{}")
            ctrl = CTRL.get(body.get("run"))
            if not ctrl:
                return self._send(404, {"error": "no such run"})
            if body.get("action") == "stop":
                ctrl["abort"] = True
            else:
                ctrl["cap"] += BUDGET_STEP
            ctrl["ev"].set()
            return self._send(200, {"ok": True, "cap": ctrl["cap"]})
        if u.path == "/api/upload":
            fn = self.headers.get("X-Filename", "extension.zip")
            try:
                info = ingest_upload(raw, fn)
            except Exception as e:
                return self._send(400, {"error": "upload failed: " + str(e)})
            if static_available():          # MÊME analyse que le corpus pré-analysé, en tâche de fond
                STATIC[info["ext"]] = {"state": "running"}
                threading.Thread(target=_static_analyze_upload, args=(info["ext"],), daemon=True).start()
                info["static_pending"] = True
            else:
                info["static_pending"] = False
            return self._send(200, info)
        # ---- GOD agent (méta-architecte) ----
        if u.path == "/api/god/analyze":
            body = json.loads(raw or b"{}")
            import god_agent
            log = None
            if body.get("ext_id"):
                ls = sorted(glob.glob(os.path.join(ROOT, "logs", "agent_runs", body["ext_id"] + "*.json")),
                            key=os.path.getmtime)
                log = ls[-1] if ls else None
            elif body.get("all"):
                n = 0
                for f in glob.glob(os.path.join(ROOT, "logs", "agent_runs", "*.json")):
                    try:
                        god_agent.save_report(god_agent.analyze_log(f)); n += 1
                    except Exception:
                        pass
                return self._send(200, {"ok": True, "analyzed": n})
            else:
                log = god_agent.latest_log()
            if not log:
                return self._send(400, {"error": "no log to analyze"})
            path = god_agent.analyze_after_run(log)
            return self._send(200, {"ok": True, "report": os.path.basename(str(path))})
        if u.path == "/api/god/status":
            body = json.loads(raw or b"{}")
            import god_agent
            r = god_agent.set_reco_status(body.get("report_id"), body.get("reco_id"),
                                          body.get("status"), body.get("note"))
            return self._send(200 if r else 404, r or {"error": "not found"})
        if u.path == "/api/god/measure":
            body = json.loads(raw or b"{}")
            rid, cid = body.get("report_id"), body.get("reco_id")
            # mesure d'impact (rejeu PoCs sur dataset labellisé) — lourd -> thread de fond ;
            # l'UI re-fetch le report (champ `impact`) quand c'est fini.
            def _run_measure():
                try:
                    import god_eval
                    god_eval.measure_reco(rid, cid, isolate=True)
                except Exception:
                    pass
            import god_agent
            god_agent.set_reco_status(rid, cid, "validated", note="mesure d'impact lancée")
            threading.Thread(target=_run_measure, daemon=True).start()
            return self._send(200, {"ok": True, "started": True,
                                    "note": "mesure lancée en fond — recharger le report pour l'impact"})
        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8750)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    socketserver.ThreadingTCPServer.allow_reuse_address = True  # rebind despite TIME_WAIT
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", args.port), Handler)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{args.port}"
    print(f"ExtPoCGen Studio (local)  →  {url}")
    print(f"  {len(list_extensions())} pre-analysed extensions ready")
    if not args.no_browser:
        try:
            import webbrowser; webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
