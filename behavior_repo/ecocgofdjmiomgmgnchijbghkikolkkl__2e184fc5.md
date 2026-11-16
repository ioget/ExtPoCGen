# Malware behavior report — __MSG_name__ (`ecocgofdjmiomgmgnchijbghkikolkkl__2e184fc5`)
- observé: 2026-11-08T01:01:01 · mv3 · catégorie: **?**
- **verdict: comportement malveillant** — 1 requête(s) sortante(s) externe(s) tentée(s)

## Techniques (MITRE ATT&CK, heuristique)
- T1071 Application Layer Protocol (C2 / phone-home)
- T1041 Exfiltration Over C2 Channel (tentée)
- T1539 Steal Web Session Cookie
- T1557 Adversary-in-the-Middle (webRequest)
- T1105 Ingress Tool Transfer
- T1217 Browser Information Discovery

## IOCs (indicateurs de compromission)
- domaine C2 : `activity.remotecfgservice.com`
  - `https://activity.remotecfgservice.com/promo2.json?i=2kj5i50bwm3b78x&s=ig_ulti`

## Comportement observé (exécution isolée)
- requêtes sortantes externes tentées : **1**
- permissions sensibles : ['webRequest', 'cookies', 'downloads', 'tabs']

*Provenance : behavioral-observation (Chrome isolé, egress bloqué) · Chromium 157.0.8103.38*
