#!/usr/bin/env python3
"""
inject_attack_kb — ajoute la couche CONNAISSANCE DES ATTAQUES au graphe KB.

Charge rag/attack_kb.json (mécanisme + API + trigger + exemple + oracle par type d'attaque,
d'après arXiv:2503.04292 + EmPoWeb) et crée des nœuds `AttackPattern` reliés aux Permissions
et aux Sinks existants. Idempotent (upsert). N'altère pas le reste du graphe.

    python3 code/inject_attack_kb.py
"""
import os, json, sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "rag", "graph", "kb.sqlite")
KB = os.path.join(ROOT, "rag", "attack_kb.json")


def main():
    data = json.load(open(KB, encoding="utf-8"))
    c = sqlite3.connect(DB)
    existing_perm = {r[0] for r in c.execute("SELECT id FROM nodes WHERE type='Permission'")}
    n_a = n_e = 0
    for a in data["attacks"]:
        aid = f"attack:{a['id']}"
        props = {k: a[k] for k in a if k not in ("id", "name")}
        c.execute("INSERT INTO nodes(id,type,label,props) VALUES(?,?,?,?) "
                  "ON CONFLICT(id) DO UPDATE SET type=excluded.type,label=excluded.label,props=excluded.props",
                  (aid, "AttackPattern", a["name"], json.dumps(props, ensure_ascii=False)))
        n_a += 1
        for p in a.get("permissions", []):
            pid = f"perm:{p}"
            if pid not in existing_perm:
                c.execute("INSERT OR IGNORE INTO nodes(id,type,label,props) VALUES(?,?,?,?)",
                          (pid, "Permission", p, "{}"))
                existing_perm.add(pid)
            c.execute("INSERT OR IGNORE INTO edges(src,rel,dst,props) VALUES(?,?,?,?)",
                      (aid, "needs_perm", pid, "{}"))
            n_e += 1
        # lien best-effort vers les Sinks existants par nom de méthode d'API
        for api in a.get("chrome_apis", []):
            method = api.split(".")[-1].split("(")[0].strip()
            if len(method) < 4:
                continue
            for (sid,) in c.execute("SELECT id FROM nodes WHERE type='Sink' AND id LIKE ?", (f"%{method}%",)):
                c.execute("INSERT OR IGNORE INTO edges(src,rel,dst,props) VALUES(?,?,?,?)",
                          (aid, "targets_sink", sid, "{}"))
                n_e += 1
    c.commit()
    print(f"[attack_kb] {n_a} AttackPattern nodes, {n_e} edges (needs_perm / targets_sink)")
    print("[attack_kb] node types:", dict(c.execute("SELECT type,COUNT(*) FROM nodes GROUP BY type")))
    c.close()


if __name__ == "__main__":
    main()
