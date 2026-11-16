#!/usr/bin/env python3
"""
build_prose_index — indexe la prose du store B (doc API Chrome) pour la recup floue.

Index lexical BM25 (stdlib uniquement, aucun modele d'embedding requis). Decoupe chaque
doc en passages, calcule les stats BM25, sauve rag/index/prose_bm25.json.
Upgradable vers des embeddings neuronaux quand un modele/une API sera dispo.

Usage:
    python3 code/build_prose_index.py
    python3 code/build_prose_index.py --query "executeScript manifest v3"
"""
import os, re, json, math, argparse
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "rag", "corpora", "chrome_api", "docs")
OUT = os.path.join(ROOT, "rag", "index", "prose_bm25.json")

STOP = set("the a an of to in and or is are be for on with as by this that it its from at we you your "
           "can will may if then so not no are was were been has have had do does".split())


def tokenize(t):
    return [w for w in re.findall(r"[a-zA-Z_][a-zA-Z0-9_.]+", t.lower()) if w not in STOP and len(w) > 1]


def chunk(text, size=900):
    paras = re.split(r"\n+", text)
    chunks, cur = [], ""
    for p in paras:
        if len(cur) + len(p) < size:
            cur += " " + p
        else:
            if cur.strip():
                chunks.append(cur.strip())
            cur = p
    if cur.strip():
        chunks.append(cur.strip())
    return chunks


def build():
    passages = []
    for fp in sorted(__import__("glob").glob(os.path.join(DOCS, "*.txt"))):
        api = os.path.splitext(os.path.basename(fp))[0]
        txt = open(fp, encoding="utf-8", errors="ignore").read()
        for i, ch in enumerate(chunk(txt)):
            passages.append({"api": api, "cid": f"{api}#{i}", "text": ch, "tf": dict(Counter(tokenize(ch)))})
    N = len(passages)
    df = Counter()
    for p in passages:
        df.update(p["tf"].keys())
    idf = {t: math.log(1 + (N - d + 0.5) / (d + 0.5)) for t, d in df.items()}
    avgdl = sum(sum(p["tf"].values()) for p in passages) / max(N, 1)
    index = {"N": N, "avgdl": avgdl, "idf": idf,
             "passages": [{"api": p["api"], "cid": p["cid"], "len": sum(p["tf"].values()),
                           "tf": p["tf"], "text": p["text"][:600]} for p in passages]}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(index, open(OUT, "w"), ensure_ascii=False)
    return index


def search(index, query, k=5, k1=1.5, b=0.75):
    q = tokenize(query)
    avgdl, idf = index["avgdl"], index["idf"]
    scored = []
    for p in index["passages"]:
        s = 0.0
        for t in q:
            if t in p["tf"]:
                f = p["tf"][t]
                s += idf.get(t, 0) * f * (k1 + 1) / (f + k1 * (1 - b + b * p["len"] / avgdl))
        if s > 0:
            scored.append((s, p))
    scored.sort(key=lambda x: -x[0])
    return scored[:k]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--query")
    args = ap.parse_args()
    if os.path.exists(OUT) and args.query:
        index = json.load(open(OUT))
    else:
        index = build()
        print(f"index BM25 : {index['N']} passages -> {OUT}")
    if args.query:
        print(f"\n== recherche: {args.query!r} ==")
        for s, p in search(index, args.query):
            print(f"  [{s:5.2f}] {p['api']:18s} {p['text'][:90]}...")


if __name__ == "__main__":
    main()
