# Malware behavior report — CoinClaim (`epllefgepapckihklfccpocjbnelpojp__12e5c028`)
- observé: 2026-11-08T22:33:00 · mv2 · catégorie: **?**
- **verdict: comportement malveillant** — contact externe vers hôte(s) non réputé(s) (satorify.io) SANS exfiltration prouvée — à corroborer
- reproductibilité: **1.0** sur 1 run(s)

## Techniques (MITRE ATT&CK — evidence-grounded)
- **T1071.001 Application Layer Protocol: Web Protocols** (Command and Control) — 20 outbound request(s) to external host(s), no canary captured

## IOCs (indicateurs de compromission)
- domaine C2 : `satorify.io`
  - `https://satorify.io/api/extension/log?b=2fbaYWJvdXQ6Ymxhbms=`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL2xvY2FsaG9zdDo1OTU3Ny9iYW5rLmh0bWw/dj1DQU5BUlktOUIwNEQ4OD`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL2xvY2FsaG9zdDo1OTU3Ny9iYW5rLmh0bWwjeA==`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL2xvY2FsaG9zdDo1OTU3Ny9sb2dpbg==`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL3NlY3VyZS1wYXlwYWwuY29tL21haWwuaHRtbD92PUNBTkFSWS05QjA0RD`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL3NlY3VyZS1wYXlwYWwuY29tL21haWwuaHRtbCN4`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL3NlY3VyZS1wYXlwYWwuY29tL2xvZ2lu`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL2xvZ2luLWNoYXNlLmNvbS9zb2NpYWwuaHRtbD92PUNBTkFSWS05QjA0RD`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL2xvZ2luLWNoYXNlLmNvbS9zb2NpYWwuaHRtbCN4`
  - `https://satorify.io/api/extension/log?b=2fbaaHR0cDovL2xvZ2luLWNoYXNlLmNvbS9sb2dpbg==`

## Comportement observé (exécution isolée + sinkhole)
- comportements: ['external_network_contact']
- requêtes sortantes externes : **20**
- stimulation (pages-leurres): ['bank.html', 'mail.html', 'social.html', 'search.html', 'checkout.html', 'wallet.html']
- permissions sensibles : ['tabs']
- console : ['http://login-chase.com/social.html?v=CANARY-9B04D883-HISTORY', 'http://login-chase.com/social.html#x', 'http://login-chase.com/login', 'http://accounts-google.com/search.html?v=CANARY-9B04D883-HISTORY', 'http://accounts-google.com/search.html#x']

*Provenance : behavioral-observation (Chrome isolé + sinkhole MAP *, canaries semés) · Chromium 126.0.6478.182*
