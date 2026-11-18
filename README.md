# ExtPoCGen: Sound Proof-of-Concept Generation for Browser-Extension Vulnerabilities and Malicious Behaviors

> *Neuro-symbolic agent that **generates** and, above all, **soundly validates** Proof-of-Concept (PoC) exploits for browser-extension vulnerabilities, plus a malicious-behaviour detection path. A verdict is only ever reached from **observed, deterministic proof**: zero false positives by construction.*

---

**Status: study in progress.** Two core modules (`code/orchestrator.py`, the agent, routing and handler-contract resolver; and `code/harness.py`, the differential oracle) are **withheld** from this public snapshot and are **available on request**: `gnintezemo.m.rosly@aims-senegal.org`.

![ExtPoCGen pipeline](MyThinking-Archi/extpocgen-flow.png)

## Why

Static detectors flag *candidate* vulnerable flows but cannot tell you whether an attacker can *actually* trigger them. LLMs can draft exploit PoCs but hallucinate confirmations. ExtPoCGen couples the two and puts a **differential oracle** in charge of the verdict: an exploit is **CONFIRMED only if the dangerous sink fires with an attacker-controlled value AND does not fire without the attacker**. Nothing else concludes.

## How it works (pipeline)

1. **Static detection**: DoubleX (×2 passes) + CoCo taint → candidate `source → sink` flows.
2. **Fact sheet**: attacker entry model (A = malicious web page, B = another extension), candidate findings, 3-state triage (`has-candidate` / `clean` / `incomplete-analysis`).
3. **PoC generation**: an LLM (DeepSeek) drafts an attacker page from a **handler contract** (exact channel, guards and tainted field) extracted from the code.
4. **Differential oracle**: the extension is loaded in an **isolated, instrumented headless Chrome** (CDP, `--load-extension`), served a local attacker page with a **canary**; the sink is observed with and without the attacker. `attacker_controlled = fired_with AND not fired_without`.
5. **Malicious-behaviour path**: for extensions with no vulnerability surface, behaviour is observed in isolated Chrome (canary + sinkhole) and scored.
6. **GOD agent**: a symbolic, reco-gated meta-diagnostic that reads run traces and classifies *why* a run did not confirm (threat-model boundary vs generator deficiency vs oracle-coverage gap), without ever touching the oracle.

Architecture diagrams: [`MyThinking-Archi/`](MyThinking-Archi/).

## Results

The oracle confirms **only observed** exploits: **zero false positives by construction**.

### Training / validation set: real vulnerable extensions (min-set)

The architecture (oracle, handler-contract resolver, GOD diagnostics) is built and validated on a
labelled **min-set of 54 real vulnerable browser extensions**:

| Stage | Result |
|---|---|
| **Static detection** (attacker-controlled candidate flow found) | **39 / 54 = 72 %** |
| **Oracle-confirmed PoCs** (working, differentially proven) | **22 extensions** |
| &nbsp;&nbsp;↳ of the flagged candidates | 22 / 39 = **56 %** |
| &nbsp;&nbsp;↳ of the full vulnerable set | 22 / 54 = **41 %** |

Every confirmation is **oracle-grounded** (differential, canary-based): the exploit was *observed*
firing under attacker control and *not* firing without it. No verdict rests on an LLM claim.

### Test set: generated extensions (ChromeSecBench)

To evaluate the pipeline on a held-out set never used for tuning, we synthesise full extensions from
the **[ChromeSecBench](https://github.com/yueyueL/ChromeSecBench) benchmark** (arXiv:2510.16823):
each manifest + description specification is completed into a runnable extension with DeepSeek, then
passed through the same pipeline. Reachability is tiered under the web-attacker model: **A** (an
arbitrary web page can reach the surface) and **A'** (a first-party-locked surface, which the harness
serves in the sandbox by impersonating that origin over TLS, i.e. exploitable if an attacker controls
content on the trusted host). Of 140 specifications, **135 are testable** (62 A + 73 A'); 5 expose no
web surface.

Over **10 batches / 171 runs on 131 unique testable extensions**:

| Metric | Result |
|---|---|
| **Detection rate** (oracle-confirmed) | **76 / 131 = 58.0 %** |
| &nbsp;&nbsp;↳ tier A (arbitrary page) | 20 / 32 = **62 %** |
| &nbsp;&nbsp;↳ tier A' (first-party, sandboxed origin) | 40 / 69 = **58 %** |
| **Precision / false positives** | **1.000 / 0** (by construction) |
| **False-positive rate** | **0.000** |
| **F1** | **0.734** |
| Cost | **~$0.014 / run** |

Detection climbed with the architecture work (baseline 0 to 10 %, then 40 %, 50 %, and ~58 % once the
multi-hop/stateful contract resolver and the A/A' reachability tiering were in place) and stayed
**stable at ~58 % as the set grew from 90 to 131 extensions**, at **zero false positives across all
171 runs**. First-party surfaces reached by sandbox origin-impersonation (A') confirm about as often
as arbitrary-page surfaces (A). The remaining non-confirmations are dominated by generator shape/
timing (the PoC not reaching the sink) and a minority of hard multi-hop/stateful contracts, never by
the oracle. Per-run evidence (triage, sinks, GOD diagnosis) lives in `pipeline_runs_*/`, and the full
ledger (one record per run, with metrics) in `pipeline_runs_tracking/generated_runs_tracking.json`;
results are subject to LLM sampling variance, and every attribution is made per-run from the actual
traces.

## Repository layout (what is included here)

| Path | Contents |
|---|---|
| [`code/`](code/) | Implementation: `orchestrator.py`, `harness.py` (CDP oracle), `god_agent.py`, `build_fact_sheets.py`, `server.py` + `dashboard.html`, `eval_*.py` |
| [`rag/`](rag/) | Knowledge base: attack KB + PoC skeletons |
| `pipeline_runs_*/` | Experimental **results** (per-extension reports + funnel) for the generated batches |
| `behavior_repo/` | Malicious-behaviour analysis reports (IOCs, outbound attempts) |
| [`min-set/`](min-set/) | Dataset **index + builder only** (`index.csv`, `build_minset.py`); **no payloads** |
| [`MyThinking-Archi/`](MyThinking-Archi/) | Architecture docs and diagrams |

## Not included (and why)

- **Real malware** and third-party extension payloads (`min-set/malware|vulnerable|unlabel/`, `vuln-set/`): **not redistributed** for safety and copyright. Only the dataset **index + builder** ship here.
- **Working exploit PoCs** (`poc_repo/`): withheld (responsible disclosure).
- **Third-party tools** are **not vendored**. Clone them yourself:
  - DoubleX: <https://github.com/Aurore54F/DoubleX> → `DoubleX/`
  - CoCo: <https://github.com/CoCoAbstractInterpretation/CoCo> → `CoCo/`
- Chromium binaries, Python/Node environments, caches, large derived outputs, and `.env`.

## Setup

```bash
# 1. Python deps for the static analysers (DoubleX/CoCo)
python3 -m venv .static_venv && . .static_venv/bin/activate
pip install func_timeout networkx "sty==1.0.0rc0" tqdm flask jsbeautifier beautifulsoup4 graphviz

# 2. Third-party detectors
git clone https://github.com/Aurore54F/DoubleX.git DoubleX
git clone https://github.com/CoCoAbstractInterpretation/CoCo.git CoCo

# 3. LLM key
cp .env.example .env     # then set Deepseek_API_KEY

# 4. Headless Chromium available on PATH (for the oracle)
```

## Running

```bash
# One extension through the full pipeline (static, PoC, differential oracle)
python3 code/orchestrator.py <ext_id> --agent deepseek --harness cdp \
        --budget 12 --model deepseek-reasoner

# Interactive dashboard (upload an extension / browse pre-analysed set), http://localhost:8750
python3 code/server.py
```

## Safety & ethics

This repository studies **real** malicious and vulnerable extensions. We **do not** redistribute malware or working exploits. Any malware must be executed **only in network/process isolation** (e.g. `unshare -rn`); never load it in a normal browser. The oracle instruments a disposable, isolated Chrome profile.

## Status

**Study in progress.** Research prototype under active development. Two core modules
(`code/orchestrator.py`, `code/harness.py`) are withheld from this public snapshot and
are available on request: `gnintezemo.m.rosly@aims-senegal.org`. No license is set yet
(all rights reserved by default); a license will be added before any third-party reuse.
