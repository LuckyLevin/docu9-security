/** Tresor-Entsperrung per PRF auf dem Keycloak-Login-Passkey (kein separater WebAuthn-Passkey). */

import {
  bytesToBase64,
  base64ToBytes,
  importVaultPrivateKey,
  unwrapBytesWithRawKey,
  wrapBytesWithRawKey,
} from "@/lib/vault/crypto";
import { base64UrlToBuffer, bufferToBase64Url } from "@/lib/vault/passkey-encoding";
import { LOGIN_RP_ID } from "@/lib/webauthn-config";

export { base64UrlToBuffer, bufferToBase64Url } from "@/lib/vault/passkey-encoding";

const PRF_SALT_BYTES = 32;

type PrfExtensionResults = {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer; second?: ArrayBuffer };
  };
};

export type PasskeyWrap = {
  credential_id: string;
  wrap_blob_b64: string;
};

function prfKeyBytes(prfOutput: ArrayBuffer): Uint8Array {
  return new Uint8Array(prfOutput).slice(0, 32);
}

function parsePasskeyWrapBlob(wrapBlobB64: string): { prfSalt: Uint8Array; encrypted: Uint8Array } {
  const raw = base64ToBytes(wrapBlobB64);
  if (raw.length < PRF_SALT_BYTES + 12 + 16) throw new Error("Passkey-Wrap ungültig.");
  return {
    prfSalt: raw.slice(0, PRF_SALT_BYTES),
    encrypted: raw.slice(PRF_SALT_BYTES),
  };
}

async function wrapPrivateKeyWithPrf(
  privateKeyPkcs8: Uint8Array,
  prfSalt: Uint8Array,
  prfOutput: ArrayBuffer,
): Promise<string> {
  const encrypted = await wrapBytesWithRawKey(prfKeyBytes(prfOutput), privateKeyPkcs8);
  const out = new Uint8Array(PRF_SALT_BYTES + encrypted.length);
  out.set(prfSalt, 0);
  out.set(encrypted, PRF_SALT_BYTES);
  return bytesToBase64(out);
}

async function runPasskeyPrf(
  loginPasskeyCredentialId: string,
  prfSalt: Uint8Array,
): Promise<ArrayBuffer> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: LOGIN_RP_ID,
      userVerification: "required",
      allowCredentials: [
        { id: base64UrlToBuffer(loginPasskeyCredentialId), type: "public-key" as const },
      ],
      extensions: { prf: { eval: { first: prfSalt.buffer } } },
    },
    mediation: "required",
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error("Passkey-Abbruch.");
  const ext = assertion.getClientExtensionResults() as PrfExtensionResults;
  const out = ext.prf?.results?.first;
  if (!out || out.byteLength < 32) {
    throw new Error("Passkey PRF nicht verfügbar — Passphrase nutzen.");
  }
  return out;
}

export function isPasskeyPrfAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential !== "undefined";
}

export async function probePasskeyPrfSupport(): Promise<boolean> {
  if (!isPasskeyPrfAvailable()) return false;
  const caps = (
    PublicKeyCredential as unknown as {
      getClientCapabilities?: () => Promise<Record<string, boolean>>;
    }
  ).getClientCapabilities;
  if (caps) {
    try {
      const result = await PublicKeyCredential.getClientCapabilities!();
      if (result["extension:prf"] === false) return false;
      if (result["extension:prf"] === true) return true;
    } catch {
      /* Browser ohne Capabilities-API */
    }
  }
  return true;
}

/** Tresor-Wrap für einen bestehenden Login-Passkey anlegen (Touch ID / Face ID). */
export async function createVaultWrapForLoginPasskey(
  loginPasskeyCredentialId: string,
  privateKeyPkcs8: Uint8Array,
): Promise<PasskeyWrap> {
  if (!isPasskeyPrfAvailable()) throw new Error("WebAuthn nicht verfügbar.");
  const prfSalt = crypto.getRandomValues(new Uint8Array(PRF_SALT_BYTES));
  const prfOutput = await runPasskeyPrf(loginPasskeyCredentialId, prfSalt);
  return {
    credential_id: loginPasskeyCredentialId,
    wrap_blob_b64: await wrapPrivateKeyWithPrf(privateKeyPkcs8, prfSalt, prfOutput),
  };
}

/** Tresor mit gespeichertem Login-Passkey-Wrap entsperren. */
export async function unlockPrivateKeyWithPasskeyWraps(wraps: PasskeyWrap[]): Promise<CryptoKey> {
  if (wraps.length === 0) throw new Error("Kein Passkey-Wrap hinterlegt.");

  let wrap: PasskeyWrap;
  if (wraps.length === 1) {
    wrap = wraps[0];
  } else {
    const allowCredentials = wraps.map((w) => ({
      id: base64UrlToBuffer(w.credential_id),
      type: "public-key" as const,
    }));
    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge,
        rpId: LOGIN_RP_ID,
        userVerification: "required",
        allowCredentials,
      },
      mediation: "required",
    })) as PublicKeyCredential | null;
    if (!assertion) throw new Error("Passkey-Abbruch.");
    const usedId = bufferToBase64Url(assertion.rawId);
    const found = wraps.find((w) => w.credential_id === usedId);
    if (!found) {
      throw new Error("Dieser Passkey ist keinem Tresor-Wrap zugeordnet.");
    }
    wrap = found;
  }

  const { prfSalt, encrypted } = parsePasskeyWrapBlob(wrap.wrap_blob_b64);
  const prfOutput = await runPasskeyPrf(wrap.credential_id, prfSalt);
  const pkcs8 = await unwrapBytesWithRawKey(prfKeyBytes(prfOutput), encrypted);
  return importVaultPrivateKey(pkcs8);
}
