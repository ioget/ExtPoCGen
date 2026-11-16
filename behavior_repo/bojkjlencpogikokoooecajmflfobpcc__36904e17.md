# Malware behavior report — Random Captcha (`bojkjlencpogikokoooecajmflfobpcc__36904e17`)
- observé: 2026-11-12T01:37:56 · mv3 · catégorie: **?**
- **verdict: comportement malveillant** — contact externe vers hôte(s) non réputé(s) (azlabs.tech) SANS exfiltration prouvée — à corroborer
- reproductibilité: **1.0** sur 1 run(s)

## Techniques (MITRE ATT&CK — evidence-grounded)
- **T1071.001 Application Layer Protocol: Web Protocols** (Command and Control) — 13 outbound request(s) to external host(s), no canary captured

## IOCs (indicateurs de compromission)
- domaine C2 : `azlabs.tech`
  - `https://azlabs.tech/login?uuid=acee4801-76db-4c36-d2df-e6e4bd215b55`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPojs`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPo-y`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPp1z`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPpEK`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPrjm`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPrmq`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPrqw`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPr_L`
  - `https://azlabs.tech/socket.io/?EIO=4&transport=polling&t=Q7DPsG4`

## Comportement observé (exécution isolée + sinkhole)
- comportements: ['external_network_contact']
- requêtes sortantes externes : **13**
- stimulation (pages-leurres): ['bank.html', 'mail.html', 'social.html', 'search.html', 'checkout.html', 'wallet.html']
- permissions sensibles : []
- console : ['failed to parseSyntaxError: Unexpected token \'p\', "ping" is not valid JSON\n    at JSON.parse (<anonymous>)\n    at chrome-extension://lgdkfciinlhiaceokhmbmpcklbgmeedd/content.js:11:22', 'the window recieved a messageObject', 'the window recieved a messageObject', 'the window recieved a messageObject', 'the window recieved a messageObject']

*Provenance : behavioral-observation (Chrome isolé + sinkhole MAP *, canaries semés) · Chromium 157.0.8103.38*
