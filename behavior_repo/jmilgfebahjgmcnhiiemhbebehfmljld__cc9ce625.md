# Malware behavior report — bitcoinrewards (`jmilgfebahjgmcnhiiemhbebehfmljld__cc9ce625`)
- observé: 2026-11-08T01:06:23 · mv2 · catégorie: **adware;scam**
- **verdict: comportement malveillant** — 4 requête(s) sortante(s) externe(s) tentée(s)

## Techniques (MITRE ATT&CK, heuristique)
- T1071 Application Layer Protocol (C2 / phone-home)
- T1041 Exfiltration Over C2 Channel (tentée)
- T1557 Adversary-in-the-Middle (webRequest)
- T1217 Browser Information Discovery
- T1185 Browser Session Hijacking (<all_urls>)

## IOCs (indicateurs de compromission)
- domaine C2 : `spreadsheets.google.com`
- domaine C2 : `www.bitcoinrewards.com`
  - `https://www.bitcoinrewards.com/api/shops`
  - `https://www.bitcoinrewards.com/api/shops/popular`
  - `https://www.bitcoinrewards.com/api/promotions`
  - `https://spreadsheets.google.com/feeds/list/1Ii2gLHckTtjo4YRWEfucwPtlRy4iMUuBGhRQTf0bO2c/1/public/values?alt=js`

## Comportement observé (exécution isolée)
- requêtes sortantes externes tentées : **4**
- permissions sensibles : ['tabs', 'webRequest', '<all_urls>']

*Provenance : behavioral-observation (Chrome isolé, egress bloqué) · Chromium 126.0.6478.182*
