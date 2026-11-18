# gen-ESI02 — Fabasoft Folio

- modèle: deepseek-chat · triage: clean · attacker_model: A+B
- **confirmed: 1/3** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0099 · wall: 126.2s

## Hypothèses
- `chrome.runtime.connect port.postMessage -> postToNative -> c` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `postToNative(tabId, msg) in background -> native port.postMe` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `postToPage({ns, kind:'native', payload: msg}) -> window.post` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
