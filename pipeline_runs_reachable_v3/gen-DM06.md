# gen-DM06 — Расширение для LanDocs

- modèle: deepseek-chat · triage: clean · attacker_model: A
- **confirmed: 1/3** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0122 · wall: 143.4s

## Hypothèses
- `chrome.runtime.sendMessage({namespace, action:'download', pa` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `chrome.runtime.sendMessage to background + postToPage respon` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `postToPage(Object.assign({action, requestId}, rest)) — windo` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
