# gen-ESI01 — g7 st card plugin

- modèle: deepseek-chat · triage: clean · attacker_model: A
- **confirmed: 0/3** · avant: 0 · GOD: **contract_gap** · coût: $0.0105 · wall: 132.1s

## Hypothèses
- `chrome.runtime.sendMessage -> background handleMessage -> se` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `sendToNative -> native messaging host (readCard/writeCard/ge` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `nativePort.postMessage via sendToNative` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])

## GOD: contract_gap
- root causes: contract_relay_gap, poc_shape
