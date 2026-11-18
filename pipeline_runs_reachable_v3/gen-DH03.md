# gen-DH03 — 记忆体

- modèle: deepseek-chat · triage: incomplete-analysis · attacker_model: A+B
- **confirmed: 0/6** · avant: 0 · GOD: **contract_gap** · coût: $0.0241 · wall: 290.3s

## Hypothèses
- `chrome_storage_local_set_sink` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `chrome.runtime.sendMessage({type:'MB_LOG_WORD', text}) -> ba` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `chrome.runtime.onMessage handler: MB_SET_SETTINGS merges msg` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `saveWords([]) -> chrome.storage.local.set(WORDS=[])` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `deliverDailyPrompt -> showNotification + chrome.storage.loca` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `showNotification body (deliverDailyPrompt / deliverReviewPro` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])

## GOD: contract_gap
- root causes: contract_relay_gap, poc_shape
