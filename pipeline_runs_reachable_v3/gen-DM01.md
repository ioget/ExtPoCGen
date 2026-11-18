# gen-DM01 — HTTP Commander

- modèle: deepseek-chat · triage: clean · attacker_model: A+B
- **confirmed: 1/3** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0135 · wall: 182.9s

## Hypothèses
- `chrome_downloads_download_sink` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `chrome_storage_local_set_sink` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `chrome.downloads.download({url, filename}) in background.js ` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
