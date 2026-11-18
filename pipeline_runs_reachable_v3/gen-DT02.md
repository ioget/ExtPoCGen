# gen-DT02 — __MSG_appName__

- modèle: deepseek-chat · triage: clean · attacker_model: A
- **confirmed: 1/5** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0173 · wall: 225.0s

## Hypothèses
- `chrome_storage_local_set_sink` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `applyVariant(message.variant) -> document.documentElement.se` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `showHeatmap() / openEditor() / hideHeatmap() / closeEditor()` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `updateTabState(tabId, message.patch) -> sendToTab(tabId, {ty` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `applyVariant -> html.setAttribute('data-abtasty-variant', cl` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
