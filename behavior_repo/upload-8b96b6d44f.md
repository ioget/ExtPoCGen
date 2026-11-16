# Malware behavior report — Roblox Download (`upload-8b96b6d44f`)
- observé: 2026-11-08T02:16:22 · mv2 · catégorie: **?**
- **verdict: comportement malveillant** — 2 requête(s) sortante(s) externe(s) tentée(s)

## Techniques (MITRE ATT&CK, heuristique)
- T1071 Application Layer Protocol (C2 / phone-home)
- T1041 Exfiltration Over C2 Channel (tentée)
- T1217 Browser Information Discovery

## IOCs (indicateurs de compromission)
- domaine C2 : `9.coolthemestores.com`
- domaine C2 : `coolthemestores.com`
  - `https://9.coolthemestores.com/v1/geo/?uid=null&idt=null&dsb=null&grp=9&ver=null&eid=pkibcjphbikkjjjfjokaokegeo`
  - `https://coolthemestores.com/roblox-wallpaper/?utm_campaign=si_extension&utm_medium=newinstall&utm_source=si_ro`

## Comportement observé (exécution isolée)
- requêtes sortantes externes tentées : **2**
- permissions sensibles : ['topSites']
- console : ['error geolocator: 0Arguments(1)']

*Provenance : behavioral-observation (Chrome isolé, egress bloqué) · Chromium 126.0.6478.182*
