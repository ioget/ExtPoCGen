#!/usr/bin/env python3
"""
data_injection — charge le knowledge base d'ExtPoCGen dans un graphe SQLite.

Injecte :
  - Store A (spine)   : tool_outputs/fact_sheets/*.json  -> Extension / Finding / Source / Sink / AttackerEntry
  - Store B (API)     : rag/corpora/chrome_api/api_features.json -> ChromeAPI (+ Permission)
  - Store C (patterns): DoubleX suspicious_apis/*.json + CoCo vul_func_lists.py -> VulnPattern / Sink

Graphe = deux tables : nodes(id,type,label,props) et edges(src,rel,dst,props).
Stdlib uniquement (sqlite3, json, ast). Idempotent : upsert par id.

Usage:
    python3 code/data_injection.py [--db rag/graph/kb.sqlite] [--reset]
"""
import os, re, json, glob, ast, sqlite3, argparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACT_SHEETS = os.path.join(ROOT, "tool_outputs", "fact_sheets")
API_FEATURES = os.path.join(ROOT, "rag", "corpora", "chrome_api", "api_features.json")
DX_APIS = os.path.join(ROOT, "DoubleX", "src", "suspicious_apis")
COCO_VFL = os.path.join(ROOT, "CoCo", "src", "core", "vul_func_lists.py")

# --- CWE : classes de faiblesse rattachees aux patterns -----------------
CWE = {
    "94":  "Improper Control of Generation of Code (Code Injection)",
    "749": "Exposed Dangerous Method or Function",
    "441": "Unintended Proxy or Intermediary (Confused Deputy)",
    "346": "Origin Validation Error",
    "668": "Exposure of Resource to Wrong Sphere",
    "200": "Exposure of Sensitive Information",
    "539": "Use of Persistent Cookies Containing Sensitive Information",
    "494": "Download of Code Without Integrity Check",
}
CWE_MAP = {  # mot-cle dans le label du pattern -> ids CWE
    "exec": ["94", "749", "441"], "command": ["94", "749"], "execution": ["94", "749", "441"],
    "bypass_sop": ["346", "441"], "ajax": ["346", "441"], "xhr": ["346", "441"], "fetch": ["346", "441"],
    "storage": ["668", "441"], "download": ["494", "441"],
    "cookie": ["539", "441"], "privacy": ["200", "441"], "history": ["200"], "bookmark": ["200"],
}


# ------------------------------------------------------------------ graphe
def connect(db, reset):
    os.makedirs(os.path.dirname(db), exist_ok=True)
    if reset and os.path.exists(db):
        os.remove(db)
    c = sqlite3.connect(db)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS nodes(
            id TEXT PRIMARY KEY, type TEXT, label TEXT, props TEXT);
        CREATE TABLE IF NOT EXISTS edges(
            src TEXT, rel TEXT, dst TEXT, props TEXT,
            UNIQUE(src, rel, dst));
        CREATE INDEX IF NOT EXISTS ix_nodes_type ON nodes(type);
        CREATE INDEX IF NOT EXISTS ix_edges_src  ON edges(src);
        CREATE INDEX IF NOT EXISTS ix_edges_dst  ON edges(dst);
    """)
    return 


def node(c, nid, ntype, label="", **props):
    c.execute(
        "INSERT INTO nodes(id,type,label,props) VALUES(?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET type=excluded.type, label=excluded.label, props=excluded.props",
        (nid, ntype, label, json.dumps(props, ensure_ascii=False)))
    return nid


def edge(c, src, rel, dst, **props):
    c.execute(
        "INSERT OR IGNORE INTO edges(src,rel,dst,props) VALUES(?,?,?,?)",
        (src, rel, dst, json.dumps(props, ensure_ascii=False)))


# ------------------------------------------------------------------ store A
def ingest_fact_sheets(c):
    n_ext = n_find = n_wit = 0
    for p in sorted(glob.glob(os.path.join(FACT_SHEETS, "*.json"))):
        fs = json.load(open(p))
        eid = fs["extension_id"]
        node(c, f"ext:{eid}", "Extension", fs.get("name", eid),
             manifest_version=fs.get("manifest_version"), ext_class=fs.get("class"),
             triage=fs.get("triage", {}).get("state"),
             attacker_model=fs.get("attacker_entry", {}).get("model"),
             exploitable_count=fs.get("exploitable_count", 0))
        n_ext += 1
        # attacker entry
        ae = fs.get("attacker_entry", {})
        aid = node(c, f"entry:{eid}", "AttackerEntry", ae.get("model", "none"),
                   listeners=ae.get("listeners"),
                   content_scripts_matches=ae.get("content_scripts_matches"),
                   externally_connectable=ae.get("externally_connectable"))
        edge(c, f"ext:{eid}", "HAS_ENTRY", aid)
        # permissions
        for perm in fs.get("permissions", []):
            node(c, f"perm:{perm}", "Permission", perm)
            edge(c, f"ext:{eid}", "DECLARES", f"perm:{perm}")
        # findings
        for i, f in enumerate(fs.get("candidate_findings", [])):
            fid = node(c, f"find:{eid}:{i}", "Finding",
                       f"{f.get('source')}→{f.get('sink')}",
                       origin=f.get("origin"), source_type=f.get("source_type"),
                       sink_type=f.get("sink_type"), impact_class=f.get("impact_class"),
                       attacker_model=f.get("attacker_model"),
                       exploitable=f.get("exploitable_hypothesis"),
                       confidence=f.get("confidence"), oracle=f.get("oracle"),
                       # provenance DoubleX (line/value) ; None pour les findings CoCo
                       line=f.get("line"), value=(f.get("value") or None),
                       received_from_wa=f.get("source") if str(f.get("origin", "")).startswith("doublex") else None)
            edge(c, f"ext:{eid}", "HAS_FINDING", fid)
            if f.get("source"):
                sid = node(c, f"src:{f['source']}", "Source", f["source"])
                edge(c, fid, "FROM", sid)
            if f.get("sink"):
                kid = node(c, f"sink:{f['sink']}", "Sink", f["sink"])
                edge(c, fid, "TO", kid)
            n_find += 1
        # witness CoCo (provenance ligne de code) -> rattache a l'extension
        for wi, w in enumerate(fs.get("analysis", {}).get("coco_witness", []) or []):
            wid = node(c, f"wit:{eid}:{wi}", "Witness",
                       f"{w.get('file')}:{w.get('line')}",
                       file=w.get("file"), line=w.get("line"),
                       code=w.get("code"), var=w.get("var"))
            edge(c, f"ext:{eid}", "HAS_WITNESS", wid)
            n_wit += 1
    return n_ext, n_find, n_wit


# ------------------------------------------------------------------ store B
def ingest_chrome_api(c):
    if not os.path.exists(API_FEATURES):
        return 0
    apis = json.load(open(API_FEATURES))
    for name, s in apis.items():
        aid = node(c, f"api:{name}", "ChromeAPI", name,
                   min_mv=s.get("min_manifest_version"), max_mv=s.get("max_manifest_version"),
                   contexts=s.get("contexts"), channel=s.get("channel"),
                   permissions=s.get("permissions"))
        for perm in s.get("permissions", []) or []:
            node(c, f"perm:{perm}", "Permission", perm)
            edge(c, aid, "REQUIRES", f"perm:{perm}")
    return len(apis)


def link_sinks_to_api(c):
    """ Lie chaque Sink a son ChromeAPI. A lancer APRES que tous les sinks existent. """
    if not os.path.exists(API_FEATURES):
        return 0
    api_lc = {n.lower(): n for n in json.load(open(API_FEATURES))}

    def norm(label):
        s = label.lower()
        s = re.sub(r'^(chrome|cs|bg|document|window|jquery|jq)[._]', '', s)
        s = re.sub(r'_(sink|source|value|out|var_name|event|result|options|settings|url|data)$', '', s)
        return s.replace('_', '.')

    linked = 0
    for sid, label in c.execute("SELECT id,label FROM nodes WHERE type='Sink'").fetchall():
        ns = norm(label)
        best = None
        for al, name in api_lc.items():
            if ns == al or ns.startswith(al + '.') or (al in ns) or (ns in al):
                if best is None or len(al) > len(best[0]):
                    best = (al, name)
        if best:
            edge(c, sid, "IS_A", f"api:{best[1]}")
            linked += 1
    return linked


# ------------------------------------------------------------------ store C
def ingest_patterns(c):
    n = 0
    for fn in ("doublex_apis.json", "empoweb_apis.json"):
        p = os.path.join(DX_APIS, fn)
        if not os.path.exists(p):
            continue
        cat = json.load(open(p))
        catalog = os.path.splitext(fn)[0]
        for comp in ("cs", "bp"):
            for kind, groups in cat.get(comp, {}).items():
                for category, apis in groups.items():
                    pid = node(c, f"pattern:{category}", "VulnPattern", category,
                               kind=kind, catalog=catalog)
                    n += 1
                    for api in apis:
                        kid = node(c, f"sink:{api}", "Sink", api)
                        edge(c, kid, "BELONGS_TO", pid, catalog=catalog)
    # CoCo vul_func_lists.py : extraire les listes/sets top-level via ast
    if os.path.exists(COCO_VFL):
        try:
            tree = ast.parse(open(COCO_VFL).read())
            for stmt in tree.body:
                if isinstance(stmt, ast.Assign) and isinstance(stmt.value, (ast.List, ast.Set, ast.Tuple)):
                    name = stmt.targets[0].id if isinstance(stmt.targets[0], ast.Name) else None
                    if not name:
                        continue
                    pid = node(c, f"pattern:coco_{name}", "VulnPattern", name, catalog="coco")
                    n += 1
                    for el in stmt.value.elts:
                        if isinstance(el, ast.Constant) and isinstance(el.value, str):
                            kid = node(c, f"sink:{el.value}", "Sink", el.value)
                            edge(c, kid, "BELONGS_TO", pid, catalog="coco")
        except Exception as e:
            print(f"  [warn] vul_func_lists.py non parse: {e}")
    return n


# ------------------------------------------------------------------ CWE
def ingest_cwe(c):
    for cid, title in CWE.items():
        node(c, f"cwe:{cid}", "CWE", f"CWE-{cid}", title=title)
    n = 0
    for pid, label in c.execute("SELECT id,label FROM nodes WHERE type='VulnPattern'").fetchall():
        ll = label.lower()
        linked = set()
        for kw, cwes in CWE_MAP.items():
            if kw in ll:
                linked.update(cwes)
        if not linked:
            linked = {"441"}  # fallback : confused deputy (classe transverse des extensions)
        for cid in linked:
            edge(c, pid, "CLASSIFIED_AS", f"cwe:{cid}")
            n += 1
    return n


# ------------------------------------------------------------------ store D
def ingest_store_d(c):
    n = 0
    p = os.path.join(ROOT, "rag", "corpora", "poc_examples", "examples.json")
    if os.path.exists(p):
        for ex in json.load(open(p)):
            pid = node(c, f"poc:{ex['id']}", "PoCExample", ex["id"],
                       attacker_model=ex.get("attacker_model"), channel=ex.get("channel"),
                       sink=ex.get("sink"), impact_class=ex.get("impact_class"),
                       description=ex.get("description"), poc_canary=ex.get("poc_canary"),
                       oracle=ex.get("oracle"), source=ex.get("source"))
            pat = ex.get("pattern")
            if pat:
                node(c, f"pattern:{pat}", "VulnPattern", pat, catalog="poc_example")
                edge(c, pid, "ILLUSTRATES", f"pattern:{pat}")
            n += 1
    for model, path in (("A", "attacker_page_A.html"), ("B", "zero_perm_ext_B/manifest.json")):
        fp = os.path.join(ROOT, "rag", "skeletons", path)
        if os.path.exists(fp):
            node(c, f"skeleton:{model}", "Skeleton", f"attacker_model_{model}",
                 attacker_model=model, path=os.path.relpath(fp, ROOT))
    return n


# ------------------------------------------------------------------ reports (on-disk)
def ingest_reports(c):
    n = 0
    for p in glob.glob(os.path.join(FACT_SHEETS, "*.json")):
        fs = json.load(open(p))
        gt = fs.get("ground_truth", {})
        if not gt.get("data_flow"):
            continue
        eid = fs["extension_id"]
        rid = node(c, f"report:{eid}", "Report", f"GT:{(gt.get('vul_type') or '')[:30]}",
                   data_flow=gt.get("data_flow"), vul_type=gt.get("vul_type"),
                   coco_type=gt.get("coco_type"), exploitable_by=gt.get("exploitable_by"),
                   source="index.csv / CoCo (discovery-driven)")
        edge(c, f"ext:{eid}", "HAS_REPORT", rid)
        n += 1
    return n


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="Injecte le knowledge base ExtPoCGen dans SQLite.")
    ap.add_argument("--db", default=os.path.join(ROOT, "rag", "graph", "kb.sqlite"))
    ap.add_argument("--reset", action="store_true", help="recree la base de zero")
    args = ap.parse_args()

    c = connect(args.db, args.reset)
    print("== Store A : Fact Sheets (+ witness/provenance) ==")
    ne, nf, nw = ingest_fact_sheets(c)
    print(f"  {ne} extensions, {nf} findings, {nw} witness")
    print("== Store B : API Chrome ==")
    na = ingest_chrome_api(c)
    print(f"  {na} ChromeAPI")
    print("== Store C : patterns ==")
    npat = ingest_patterns(c)
    print(f"  {npat} VulnPattern (inserts)")
    print("== CWE ==")
    ncwe = ingest_cwe(c)
    print(f"  {len(CWE)} CWE, {ncwe} liens pattern->CWE")
    print("== Store D : PoC examples + skeletons ==")
    nd = ingest_store_d(c)
    print(f"  {nd} PoCExample + skeletons A/B")
    print("== Reports (on-disk) ==")
    nr = ingest_reports(c)
    print(f"  {nr} Report")
    print("== Liens Sink -> ChromeAPI (apres tous les sinks) ==")
    nlink = link_sinks_to_api(c)
    print(f"  {nlink} liens IS_A")
    c.commit()

    print("\n== Graphe ==", args.db)
    for t, cnt in c.execute("SELECT type,COUNT(*) FROM nodes GROUP BY type ORDER BY 2 DESC"):
        print(f"  node {t:14s} {cnt}")
    for r, cnt in c.execute("SELECT rel,COUNT(*) FROM edges GROUP BY rel ORDER BY 2 DESC"):
        print(f"  edge {r:14s} {cnt}")
    c.close()


if __name__ == "__main__":
    main()
