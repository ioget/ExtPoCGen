# gen-AUTH04 — __MSG_extName__

- modèle: deepseek-chat · triage: clean · attacker_model: A+B
- **confirmed: 1/6** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0200 · wall: 244.0s

## Hypothèses
- `chrome_storage_local_set_sink` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `fetch` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `addRow -> v.textContent = value (overlay DOM rendering)` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `saveShopInfo -> storageSet(STORAGE_KEYS.SHOP, shop) (chrome.` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `fetch(SHOP_ENDPOINT + '?url=' + encodeURIComponent(url))` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `broadcastToExtensionPage({type:'O...'}) -> chrome.runtime.se` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
