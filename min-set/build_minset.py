#!/usr/bin/env python3
"""Build MyDataset/min-set: 39 unpacked Chrome extensions per class.

Usage: python3 -I build_minset.py <research_root>

Archives are only extracted as data: nothing is executed, unsafe paths are skipped,
and size limits apply. The output is independent of the source projects (no hard links).
"""
import collections, csv, datetime, hashlib, os, random, re, shutil, sys, zipfile

ROOT = os.path.abspath(sys.argv[1])
DS = os.path.join(ROOT, "MyDataset")
FINAL = os.path.join(DS, "min-set")
OUT = FINAL + ".tmp"
SEED = 20261101
N = 39
QUOTA = {"2": 20, "3": 19}
MAX_BYTES = 200 * 1024 * 1024
MAX_FILES = 20000
csv.field_size_limit(10**8)

if os.path.exists(FINAL) or os.path.exists(OUT):
    sys.exit("Refusing to overwrite: min-set or min-set.tmp already exists")


def load(cls):
    with open(os.path.join(DS, "chrome", cls, "metadata.csv"), encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def tree_info(d):
    files = []
    for base, _, names in os.walk(d):
        files += [os.path.relpath(os.path.join(base, n), d) for n in names]
    h = hashlib.sha256()
    total = 0
    for r in sorted(files):
        p = os.path.join(d, r)
        total += os.path.getsize(p)
        h.update(r.encode("utf-8", "surrogateescape") + b"\0")
        h.update(sha_file(p).encode())
    return h.hexdigest(), len(files), total


def extract(archive, dest):
    """Write archive members under dest. Returns the number of skipped entries, or None to reject."""
    written = skipped = 0
    root = os.path.realpath(dest)
    try:
        with zipfile.ZipFile(archive) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_BYTES:
                return None
            for i in infos:
                name = i.filename.replace("\\", "/")
                parts = name.split("/")
                if name.startswith("/") or ".." in parts or (parts[0].endswith(":")):
                    skipped += 1
                    continue
                target = os.path.realpath(os.path.join(dest, *parts))
                if not target.startswith(root + os.sep):
                    skipped += 1
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                try:
                    with z.open(i) as src, open(target, "xb") as out:
                        for b in iter(lambda: src.read(1 << 20), b""):
                            written += len(b)
                            if written > MAX_BYTES:
                                return None
                            out.write(b)
                except (FileExistsError, IsADirectoryError, NotADirectoryError, OSError):
                    skipped += 1
    except Exception:
        return None
    return skipped if os.path.isfile(os.path.join(dest, "manifest.json")) else None


def usable(r):
    return (r["manifest_status"] == "ok" and r["manifest_path"] == "manifest.json" and int(r["n_js_files"] or 0) > 0
            and r["same_id_as_malware"] == "false" and not r["review_flag"] and r["format"] != "unpacked")


rng = random.Random(SEED)
used_ids, chosen = set(load("vulnerable") and (r["extension_id"] for r in load("vulnerable"))), collections.defaultdict(list)
rejected = collections.Counter()


def pick(cls, pool, mv, n, group_of):
    groups = collections.defaultdict(list)
    for r in sorted(pool, key=lambda x: x["sha256"]):
        if r["manifest_version"] == mv:
            groups[group_of(r)].append(r)
    keys = sorted(groups)
    rng.shuffle(keys)
    for k in keys:
        rng.shuffle(groups[k])
    names = {x["name"].casefold() for x in chosen[cls]}
    got = 0
    while got < n and any(groups[k] for k in keys):
        for k in keys:
            if got >= n:
                break
            while groups[k]:
                r = groups[k].pop()
                nm = r["name"].casefold()
                if r["extension_id"] in used_ids or (nm in names and not nm.startswith("__msg_")):
                    continue
                stem = re.sub(r"\.(crx|zip|xpi)$", "", os.path.basename(r["local_path"]))
                dest = os.path.join(OUT, cls, stem)
                os.makedirs(dest)
                skipped = extract(os.path.join(DS, r["local_path"]), dest)
                if skipped is None:
                    shutil.rmtree(dest)
                    rejected[cls] += 1
                    continue
                r = dict(r, selection_group=k, entries_skipped=skipped, min_set_path=os.path.join(cls, stem))
                chosen[cls].append(r)
                names.add(nm)
                if r["extension_id"]:
                    used_ids.add(r["extension_id"])
                got += 1
                break
    if got < n:
        sys.exit(f"Not enough {cls} candidates for MV{mv}: {got}/{n}")


malware = [r for r in load("malware") if usable(r)]
unlabel = [r for r in load("unlabel") if usable(r) and r["removed_by_store"] == "false" and "chrome_web_store" in r["stores"].split(";")]
print("candidates malware", collections.Counter(r["manifest_version"] for r in malware), "unlabel", collections.Counter(r["manifest_version"] for r in unlabel))


def malware_group(r):
    if r["malware_category"]:
        return "category:" + r["malware_category"]
    return "source:" + (r["source_urls"].split(";")[0] if r["source_urls"] else "unknown")


for mv, n in QUOTA.items():
    pick("malware", malware, mv, n, malware_group)
    pick("unlabel", unlabel, mv, n, lambda r: "stores:" + r["stores"])

for r in load("vulnerable"):
    stem = os.path.basename(r["local_path"])
    src = os.path.join(DS, r["local_path"])
    dest = os.path.join(OUT, "vulnerable", stem)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copytree(src, dest, symlinks=False)
    chosen["vulnerable"].append(dict(r, selection_group="all CoCo extensions", entries_skipped=0, min_set_path=os.path.join("vulnerable", stem)))

BASE = ["min_set_path", "class", "extension_id", "name", "version", "manifest_version", "selection_group", "permissions",
        "host_permissions", "n_content_scripts", "has_background", "extracted_tree_sha256", "extracted_files", "extracted_bytes",
        "entries_skipped", "source_archive_sha256", "format", "dataset_path", "source_datasets", "stores", "removed_by_store",
        "label_source", "malware_category", "source_urls", "date_reported", "date_added", "n_original_copies", "original_paths"]
VULN = ["data_flow", "users", "coco_type", "vul_type", "exploitable_by", "coco_result_file", "tool_outputs_dir"]


def write(path, cols, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


NOTES = {
    "malware": "Labelled malicious by the source datasets. Selected at random with a fixed seed: 20 Manifest V2 and 19 Manifest V3, taken evenly across malware categories and source articles.",
    "vulnerable": "All 39 CoCo extensions, copied without CoCo's generated tool outputs: 38 Manifest V2 and 1 Manifest V3. See `tool_outputs_dir` for the outputs.",
    "unlabel": "Not labelled malicious or vulnerable, and NOT confirmed benign. All crypto-themed Chrome Web Store samples or No-easy seemingly-benign samples. Selected at random with a fixed seed: 20 Manifest V2 and 19 Manifest V3.",
}
all_rows = []
for cls in ("malware", "vulnerable", "unlabel"):
    rows = sorted(chosen[cls], key=lambda r: r["min_set_path"])
    assert len(rows) == N, (cls, len(rows))
    for r in rows:
        tree, files, size = tree_info(os.path.join(OUT, r["min_set_path"]))
        r.update(extracted_tree_sha256=tree, extracted_files=files, extracted_bytes=size, source_archive_sha256=r["sha256"] if r["format"] != "unpacked" else "",
                 dataset_path=r["local_path"])
        r["min_set_path"] = r["min_set_path"].replace(os.sep, "/")
    write(os.path.join(OUT, cls, "metadata.csv"), BASE + (VULN if cls == "vulnerable" else []), rows)
    with open(os.path.join(OUT, cls, "README.md"), "w", encoding="utf-8") as f:
        f.write(f"# min-set / {cls}\n\n{N} unpacked Chrome extensions.\n\n{NOTES[cls]}\n\nSee `metadata.csv`, and `../README.md` for the columns.\n")
    all_rows += rows
write(os.path.join(OUT, "index.csv"), BASE + VULN, all_rows)

with open(os.path.join(OUT, "README.md"), "w", encoding="utf-8") as f:
    f.write(f"""# min-set

Small test set built on {datetime.date.today().isoformat()} by `build_minset.py` (random seed {SEED}): {N} unpacked Chrome extensions in each of `malware/`, `vulnerable/` and `unlabel/`.

**WARNING: this folder contains real malware and exploitable extensions as readable code. Do not load them in a normal browser. Use an isolated VM.**

## Selection

- **Malware and unlabeled:** root `manifest.json`, at least one JavaScript file, a parsed manifest, no review flag, and no ID conflict with malware. Each class has 20 Manifest V2 and 19 Manifest V3 samples and no repeated extension names (except `__MSG_...__` placeholders).
- **Unlabeled also requires:** found in the Chrome Web Store collection (or No-easy seemingly-benign samples) and not removed by a store.
- **Vulnerable:** all 39 CoCo extensions: 38 Manifest V2 and 1 Manifest V3.
- This set is too small for reliable accuracy estimates. Use it for tests and pipeline checks.

## Columns

`index.csv` covers all classes. Each class folder has its own `metadata.csv`.

| Column | Meaning |
|---|---|
| `min_set_path` | Extension folder, relative to `min-set/` |
| `class`, `extension_id`, `name`, `version`, `manifest_version` | Identity; `name` can be a `__MSG_...__` placeholder |
| `selection_group` | Group used to spread the selection |
| `permissions`, `host_permissions`, `n_content_scripts`, `has_background` | From `manifest.json` |
| `extracted_tree_sha256` | Hash of the extracted paths and contents, to detect later changes |
| `extracted_files`, `extracted_bytes` | Extracted size |
| `entries_skipped` | Archive entries not written (unsafe or conflicting paths) |
| `source_archive_sha256`, `format`, `dataset_path` | Original archive and its location under `MyDataset/` |
| `source_datasets`, `stores`, `removed_by_store`, `label_source`, `malware_category` | Origin and label |
| `source_urls`, `date_reported`, `date_added` | From the MaliciousBrowserExtensions database |
| `n_original_copies`, `original_paths` | Source locations, separated by `;` |
| `data_flow`, `users`, `coco_type`, `vul_type`, `exploitable_by` | From CoCo `results/summary.md` (vulnerable only) |
| `coco_result_file`, `tool_outputs_dir` | CoCo outputs in the source project |

Text taken from manifests is untrusted. A cell that starts with `=`, `+`, `-` or `@` has a leading `'`.
""")
shutil.copy2(os.path.abspath(__file__), os.path.join(OUT, "build_minset.py"))
os.rename(OUT, FINAL)
print("rejected", dict(rejected))
