# gen-BHT17 — Buxenger

- modèle: deepseek-chat · triage: incomplete-analysis · attacker_model: B
- **confirmed: 0/5** · avant: 0 · GOD: **contract_gap** · coût: $0.0128 · wall: 209.0s

## Hypothèses
- `innerHTML` → **UNREACHABLE** (fired=None, attacker_controlled=None, stage=None, listeners_entered=[])
- `shadowRoot.innerHTML template in renderBookmarksTab (bookmar` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `renderPanel / renderBookmarksTab / renderTasksTab innerHTML ` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `window.open(bm.url, '_blank', 'noopener') in .open handler a` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `content.innerHTML in renderTasksTab (option value, anchor hr` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])

## GOD: contract_gap
- root causes: contract_relay_gap, kb_skeleton_gap, poc_shape, threat_model_boundary
