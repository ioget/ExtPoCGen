# gen-CM01 — LiquidVoice PCI

- modèle: deepseek-chat · triage: clean · attacker_model: A+B
- **confirmed: 1/2** · avant: 0 · GOD: **confirmed_no_action** · coût: $0.0060 · wall: 100.3s

## Hypothèses
- `chrome_storage_local_set_sink` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])
- `setEnabled(!!message.enabled) -> applyTitleSilently(MASKED_T` → **CONFIRMED** (fired=True, attacker_controlled=True, stage=confirmed, listeners_entered=[])
