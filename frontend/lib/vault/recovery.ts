/** Recovery-Code für den Tresor — 8 Gruppen à 4 Zeichen (druckbar). */

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

export function generateRecoveryCode(): string {
  const groups: string[] = [];
  for (let g = 0; g < 8; g += 1) {
    const bytes = crypto.getRandomValues(new Uint8Array(4));
    let part = "";
    for (let i = 0; i < 4; i += 1) {
      part += ALPHABET[bytes[i] % ALPHABET.length];
    }
    groups.push(part);
  }
  return groups.join("-");
}

export function normalizeRecoveryCode(code: string): string {
  return code.trim().toUpperCase().replace(/-/g, "").replace(/\s+/g, "");
}
