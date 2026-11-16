#!/usr/bin/env python3
"""
build_fact_sheets — Stage 1 : Extension Security Fact Sheet.
Fusionne CoCo + DoubleX(defaut+empoweb) + manifeste -> un JSON par extension dans
tool_outputs/fact_sheets/, avec attacker_entry (A/B), candidate_findings + score
d'exploitabilite, triage (3 etats), oracle. Stdlib only.
"""
import os, re, json, csv, glob

WEB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(WEB, "tool_outputs")
OUT = os.path.join(TOOL, "fact_sheets")
os.makedirs(OUT, exist_ok=True)
META = {r["min_set_path"].split("/")[1]: r
        for r in csv.DictReader(open(os.path.join(WEB, "min-set", "index.csv"), newline=""))}

ATTACKER_SRC = ("messageexternal", "eventlistener_message", "window_message", "windwo_message",
                "document_event_listener", "document_eventlistener", "onmessage", "cs_window_eventlistener",
                "connectexternal", "onmessageexternal")
SENSITIVE_SRC = ("storage", "cookie", "historyitem", "bookmark")
NETWORK_SRC = ("fetch_source", "ajax_result", "xmlhttprequest", "jquery_ajax_result")
EXFIL_SINK = ("sendresponseexternal",)
DANGER_SINK = ("executescript", "eval", "storage_", "cookies_set", "cookies_remove", "downloads_download",
               "localstorage_setitem", "fetch_", "ajax_settings", "xmlhttprequest_", "jq_obj_val",
               "setenabled", "window_postmessage", "storage.local.set", "storage.sync.set")


def cs(s):
    sl = s.lower()
    if any(k in sl for k in ATTACKER_SRC): return "attacker_input"
    if any(k in sl for k in NETWORK_SRC): return "network_response"
    if any(k in sl for k in SENSITIVE_SRC): return "internal_sensitive"
    return "other"


def ck(s):
    sl = s.lower()
    if any(k in sl for k in EXFIL_SINK): return "exfiltration"
    if any(k in sl for k in DANGER_SINK): return "dangerous"
    return "other"


def impact(sink):
    sl = sink.lower()
    if "executescript" in sl or "eval" in sl: return "code-execution"
    if "cookie" in sl: return "cookie-rw"
    if "storage" in sl or "localstorage" in sl: return "storage-rw"
    if "download" in sl: return "download"
    if "fetch" in sl or "ajax" in sl or "xmlhttprequest" in sl: return "network-request"
    if "sendresponseexternal" in sl: return "exfiltration"
    return "other"


def parse_coco(path):
    if not os.path.isfile(path): return {"status": "missing", "flows": []}
    t = open(path, errors="ignore").read()
    o = {"flows": []}
    m = re.search(r"finish within ([\d.]+) seconds#### with code_cov ([\d.]+)%", t)
    if m: o["wall_s"] = round(float(m.group(1)), 2); o["coverage_pct"] = round(float(m.group(2)), 1)
    killed = "~~taint detected" not in t and re.search(r"timeout after \d+ seconds", t)
    flows = {}
    for ln in t.splitlines():
        mm = re.match(r"from (.+?) to (.+)$", ln.strip())
        if mm:
            flows[(mm.group(1).strip(), mm.group(2).strip())] = flows.get((mm.group(1).strip(), mm.group(2).strip()), 0) + 1
    wit = []
    for mm in re.finditer(r"\$FilePath\$(.+?)\nLine (\d+)\t(.+?)\n\t(.*)", t):
        wit.append({"file": os.path.basename(mm.group(1).strip()), "line": int(mm.group(2)),
                    "code": mm.group(3).strip()[:160], "var": mm.group(4).strip()[:80]})
    for (src, sink), c in flows.items():
        o["flows"].append({"source": src, "sink": sink, "count": c,
                           "source_type": cs(src), "sink_type": ck(sink), "impact_class": impact(sink)})
    o["witness"] = wit[:12]
    if "~~taint detected" in t: o["status"] = "detected"
    elif killed: o["status"] = "timeout"
    elif "nothing detected" in t: o["status"] = "nothing"
    else: o["status"] = "incomplete"
    return o


def parse_dx(path):
    if not os.path.isfile(path): return None
    a = json.load(open(path)); b = a.get("benchmarks", {})
    n = 0; hits = []
    for comp in ("cs", "bp"):
        for kind in ("direct_dangers", "indirect_dangers", "exfiltration_dangers"):
            for k, v in a.get(comp, {}).get(kind, {}).items():
                n += 1
                if v.get("dataflow"):
                    prov = v.get("param_id0", {})
                    src = None
                    for pk, pv in prov.items():
                        if isinstance(pv, dict): src = pv.get("wa")
                    hits.append({"component": comp, "danger": v.get("danger"), "line": v.get("line"),
                                 "value": str(v.get("value"))[:200], "received_from_wa": src,
                                 "impact_class": impact(v.get("danger") or "")})
    crash = b.get("crashes", [])
    st = "parse-error" if any("parsing" in c for c in crash) else ("pdg-timeout" if any("pdg-timeout" in c for c in crash) else "ok")
    return {"status": st, "sinks": n, "dataflow_true": len(hits), "hits": hits, "crashes": crash}


def detect_listeners(files):
    pats = {"onMessageExternal": r"onMessageExternal", "onConnectExternal": r"onConnectExternal",
            "runtime.onMessage": r"runtime\.onMessage\b|onMessage\.addListener",
            "window.message": r"addEventListener\(\s*['\"]message['\"]",
            "document.customEvent": r"document\.addEventListener\(\s*['\"](?!message)",
            "postMessage": r"postMessage\("}
    chans = set()
    for f in files:
        if not os.path.isfile(f): continue
        try: txt = open(f, errors="ignore").read()
        except OSError: continue
        for name, p in pats.items():
            if re.search(p, txt): chans.add(name)
    return sorted(chans)


def attacker_entry(manifest, listeners):
    ext_conn = manifest.get("externally_connectable")
    cs_scripts = manifest.get("content_scripts", []) or []
    cs_matches = [m for e in cs_scripts if isinstance(e, dict) for m in e.get("matches", [])]
    A, B = [], []
    if ext_conn and isinstance(ext_conn, dict) and ext_conn.get("matches"):
        A.append("externally_connectable:" + ",".join(ext_conn["matches"][:4]))
    if cs_matches and ("window.message" in listeners or "document.customEvent" in listeners):
        A.append(f"content_script on {','.join(cs_matches[:3])}")
    if ("onMessageExternal" in listeners or "onConnectExternal" in listeners) and not (ext_conn and isinstance(ext_conn, dict) and ext_conn.get("matches")):
        B.append("onMessageExternal without externally_connectable restriction (any extension)")
    model = "none"
    if A: model = "A"
    if B: model = "A+B" if A else "B"
    return {"model": model, "A_web_page": {"possible": bool(A), "via": A},
            "B_extension": {"possible": bool(B), "via": B},
            "externally_connectable": ext_conn or None, "content_scripts_matches": cs_matches,
            "listeners": listeners}


def build(cls, ext_id):
    base = os.path.join(TOOL, cls, ext_id)
    if not os.path.isdir(base): return None
    m = META.get(ext_id, {})
    mp = os.path.join(base, "doublex_default", "extracted", "manifest.json")
    manifest = {}
    if os.path.isfile(mp):
        try: manifest = json.load(open(mp))
        except Exception: pass
    files = glob.glob(os.path.join(base, "coco", "generated", "*.js")) + glob.glob(os.path.join(base, "doublex_default", "extracted", "*.js"))
    ae = attacker_entry(manifest, detect_listeners(files))
    coco = parse_coco(os.path.join(base, "coco", "used_time.txt"))
    dxd = parse_dx(os.path.join(base, "doublex_default", "analysis.json"))
    dxe = parse_dx(os.path.join(base, "doublex_empoweb", "analysis_empoweb.json"))

    findings = []
    for fl in coco["flows"]:
        st, kt = fl["source_type"], fl["sink_type"]
        if st == "attacker_input" and kt in ("dangerous", "exfiltration"): expl, conf = True, "high"
        elif st == "internal_sensitive" and kt == "exfiltration": expl = ae["model"] != "none"; conf = "high" if expl else "low"
        elif st == "network_response": expl, conf = False, "low"
        else: expl = ae["model"] != "none" and kt in ("dangerous", "exfiltration"); conf = "medium"
        findings.append({"origin": "coco", "source": fl["source"], "sink": fl["sink"],
                         "source_type": st, "sink_type": kt, "impact_class": fl["impact_class"],
                         "attacker_model": ae["model"] if expl else "none", "exploitable_hypothesis": expl,
                         "confidence": conf, "count": fl["count"],
                         "oracle": f"sink '{fl['sink']}' se declenche avec une valeur issue de '{fl['source']}'"})
    for tag, dd in (("doublex_default", dxd), ("doublex_empoweb", dxe)):
        if not dd: continue
        for h in dd["hits"]:
            findings.append({"origin": tag, "source": h.get("received_from_wa"), "sink": h["danger"],
                             "source_type": "attacker_input", "sink_type": ck(h["danger"]),
                             "impact_class": h["impact_class"], "attacker_model": ae["model"],
                             "exploitable_hypothesis": True, "confidence": "high",
                             "line": h["line"], "value": h["value"],
                             "oracle": f"sink '{h['danger']}' (ligne {h['line']}) se declenche avec un message attaquant"})

    exploitable = [f for f in findings if f["exploitable_hypothesis"]]
    inc = []
    if coco["status"] in ("timeout", "incomplete", "missing"): inc.append(f"coco:{coco['status']}")
    if dxd is None: inc.append("doublex_default:skip/missing")
    elif dxd["status"] != "ok": inc.append(f"doublex_default:{dxd['status']}")
    if dxe is None: inc.append("doublex_empoweb:skip/missing")
    elif dxe["status"] != "ok": inc.append(f"doublex_empoweb:{dxe['status']}")
    state = "has-candidate" if exploitable else ("incomplete-analysis" if (inc and coco["status"] != "detected") else "clean")

    fs = {"extension_id": ext_id, "name": m.get("name", manifest.get("name", "")), "class": cls,
          "manifest_version": m.get("manifest_version", str(manifest.get("manifest_version", ""))),
          "size_kb": int(m.get("extracted_bytes", 0)) // 1024,
          "permissions": [p for p in (m.get("permissions", "").split(";")) if p],
          "host_permissions": [p for p in (m.get("host_permissions", "").split(";")) if p],
          "ground_truth": {"data_flow": m.get("data_flow", ""), "coco_type": m.get("coco_type", ""),
                           "vul_type": m.get("vul_type", ""), "exploitable_by": m.get("exploitable_by", "")},
          "attacker_entry": ae,
          "analysis": {"coco": {k: coco.get(k) for k in ("status", "coverage_pct", "wall_s")},
                       "coco_flows": coco["flows"], "coco_witness": coco.get("witness", []),
                       "doublex_default": dxd, "doublex_empoweb": dxe},
          "candidate_findings": findings, "exploitable_count": len(exploitable),
          "triage": {"state": state, "incomplete_analyses": inc, "attacker_model": ae["model"]}}
    json.dump(fs, open(os.path.join(OUT, f"{ext_id}.json"), "w"), indent=2, ensure_ascii=False)
    return fs


def main():
    rows = []
    for cls in ("vulnerable", "malware", "unlabel"):
        d = os.path.join(TOOL, cls)
        if not os.path.isdir(d): continue
        for ext_id in sorted(os.listdir(d)):
            if os.path.isdir(os.path.join(d, ext_id)):
                fs = build(cls, ext_id)
                if fs: rows.append(fs)
    cols = ["extension_id", "name", "class", "manifest_version", "size_kb", "attacker_model",
            "triage_state", "exploitable_count", "coco_status"]
    with open(os.path.join(OUT, "_index.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(cols)
        for r in rows:
            w.writerow([r["extension_id"], r["name"][:30], r["class"], r["manifest_version"], r["size_kb"],
                        r["attacker_entry"]["model"], r["triage"]["state"], r["exploitable_count"],
                        r["analysis"]["coco"]["status"]])
    from collections import Counter
    print(f"{len(rows)} fact sheets -> {OUT}/")
    print("triage:", dict(Counter(r["triage"]["state"] for r in rows)))
    print("attacker_model:", dict(Counter(r["attacker_entry"]["model"] for r in rows)))
    print("exploitables (>=1 finding):", sum(1 for r in rows if r["exploitable_count"] > 0))


if __name__ == "__main__":
    main()
