# gen-ESI03 — Zebra Printing

- modèle: deepseek-chat · triage: clean · attacker_model: B
- **confirmed: 0/6** · avant: 0 · GOD: **contract_gap** · coût: $0.0158 · wall: 196.0s

## Hypothèses
- `chrome_storage_local_set_sink` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `fetch` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `fetch(`http://${cfg.host}:${cfg.port}/`, {method:'POST', bod` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `chrome.storage.local.set({zebraHost, zebraPort}) then used i` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `sendResponse({ok:true, config:{host,port}})` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `fetch URL construction `http://${cfg.host}:${cfg.port}/`` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])

## GOD: contract_gap
- root causes: contract_stateful_gap, poc_shape, threat_model_boundary
