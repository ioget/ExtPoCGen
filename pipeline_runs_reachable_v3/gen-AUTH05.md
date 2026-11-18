# gen-AUTH05 — TDOS

- modèle: deepseek-chat · triage: clean · attacker_model: A
- **confirmed: 1/3** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0086 · wall: 121.9s

## Hypothèses
- `chrome.runtime.sendMessage({ action, payload }, ...) relayed` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `window.postMessage({ channel: RESPONSE_CHANNEL, id, ...reply` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `window.postMessage({ channel: EVENT_CHANNEL, event: 'records` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
