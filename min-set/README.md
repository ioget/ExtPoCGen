# min-set

Small test set built on 2026-11-01 by `build_minset.py` (random seed 20261101): 39 unpacked Chrome extensions in each of `malware/`, `vulnerable/` and `unlabel/`.

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
