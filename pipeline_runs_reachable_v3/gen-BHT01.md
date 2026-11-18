# gen-BHT01 — Galago bookmarks

- modèle: deepseek-chat · triage: clean · attacker_model: B
- **confirmed: 1/3** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0018 · wall: 49.9s

## Hypothèses
- `chrome_storage_local_set_sink` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `fetch` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `showToast(message.status, message.message) -> text.textConte` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
