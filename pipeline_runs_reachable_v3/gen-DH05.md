# gen-DH05 — Go Pipeline Filter

- modèle: deepseek-chat · triage: clean · attacker_model: A
- **confirmed: 0/1** · avant: 0 · GOD: **poc_llm_deficiency** · coût: $0.0032 · wall: 60.1s

## Hypothèses
- `window.dispatchEvent(new CustomEvent('go-pipeline-filter:set` → **FAILED** (fired=False, attacker_controlled=False, stage=sink_not_reached, listeners_entered=[])

## GOD: poc_llm_deficiency
- root causes: poc_shape
