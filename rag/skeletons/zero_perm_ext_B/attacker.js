// Skeleton Attacker Model B — extension zero-permission.
// VICTIM_ID + MESSAGE remplis par le PoC Generator. Canari observe par le harness.
const VICTIM_ID = '{{VICTIM_ID}}';

chrome.runtime.sendMessage(VICTIM_ID, {{MESSAGE}}, (resp) => {
  // L'oracle verifie qu'une donnee privilegiee de la victime est revenue a l'attaquant.
  console.log('POC_B_RESPONSE=' + JSON.stringify(resp));
});
