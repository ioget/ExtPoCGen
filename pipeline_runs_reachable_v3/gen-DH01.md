# gen-DH01 — BPTM Local File Viewer Extension

- modèle: deepseek-chat · triage: clean · attacker_model: A+B
- **confirmed: 0/4** · avant: 0 · GOD: **poc_llm_deficiency** · coût: $0.0124 · wall: 154.7s

## Hypothèses
- `fetch` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `fetch(url) in background.js readLocalFileAsDataUrl / readLoc` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `readLocalFileAsDataUrl / readLocalFileAsText returning file ` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `fetch(dataUrl) in createDataUrlToBlob and fetch(url) in read` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])

## GOD: poc_llm_deficiency
- root causes: poc_shape, threat_model_boundary
