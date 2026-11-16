# Malware behavior report — 划词小窗搜题 (`bblkpdkdloalbiifhhmekiaejmdkgohj__64775056`)
- observé: 2026-11-08T09:20:49 · mv2 · catégorie: **?**
- **verdict: comportement malveillant** — 1 requête(s) sortante(s) externe(s) tentée(s)

## Techniques (MITRE ATT&CK, heuristique)
- T1071 Application Layer Protocol (C2 / phone-home)
- T1041 Exfiltration Over C2 Channel (tentée)
- T1539 Steal Web Session Cookie
- T1185 Browser Session Hijacking (<all_urls>)

## IOCs (indicateurs de compromission)
- domaine C2 : `huacisouti.oss-cn-hangzhou.aliyuncs.com`
  - `https://huacisouti.oss-cn-hangzhou.aliyuncs.com/conf`

## Comportement observé (exécution isolée)
- requêtes sortantes externes tentées : **1**
- permissions sensibles : ['<all_urls>', 'cookies']
- console : ['TypeError: Failed to fetch\n    at chrome-extension://kjlfkmkgdcofgnknhlidfmkpgggpbmdp/js/background.js:5:1']

*Provenance : behavioral-observation (Chrome isolé, egress bloqué) · Chromium 126.0.6478.182*
