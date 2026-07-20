/** Paket AB2: Tresor-Kryptografie im Browser (Web Crypto, X25519 + AES-GCM). */

const PBKDF2_ITERATIONS = 310_000;
const AAD_FILE = new TextEncoder().encode("docu9-vault-file");
const AAD_PAYLOAD = new TextEncoder().encode("docu9-vault-payload");
const AAD_DEK = new TextEncoder().encode("docu9-vault-dek");

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length !== 64) throw new Error("Public-Key muss 32 Bytes (64 Hex) sein.");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function deriveAesKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

export async function generateVaultKeyPair(): Promise<{
  publicKeyRaw: Uint8Array;
  privateKeyPkcs8: Uint8Array;
}> {
  const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey"]);
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const privateKeyPkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  return { publicKeyRaw, privateKeyPkcs8 };
}

export async function exportPrivateKeyPkcs8(privateKey: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
}

export async function wrapSecret(privateKeyPkcs8: Uint8Array, secret: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKeyFromPassphrase(secret, salt, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, privateKeyPkcs8));
  const out = new Uint8Array(salt.length + nonce.length + ct.length);
  out.set(salt, 0);
  out.set(nonce, salt.length);
  out.set(ct, salt.length + nonce.length);
  return bytesToBase64(out);
}

export async function unwrapToPrivateKey(wrapBlobB64: string, secret: string): Promise<CryptoKey> {
  const raw = base64ToBytes(wrapBlobB64);
  const salt = raw.slice(0, 16);
  const nonce = raw.slice(16, 28);
  const ct = raw.slice(28);
  const key = await deriveAesKeyFromPassphrase(secret, salt, ["decrypt"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct));
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveKey"]);
}

/** Passkey-PRF: AES-GCM mit rohem 32-Byte-Schlüssel (kein PBKDF2). */
export async function wrapBytesWithRawKey(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes.slice(0, 32), "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, data));
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

export async function unwrapBytesWithRawKey(keyBytes: Uint8Array, wrapped: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", keyBytes.slice(0, 32), "AES-GCM", false, ["decrypt"]);
  const nonce = wrapped.slice(0, 12);
  const ct = wrapped.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct));
}

export async function importVaultPrivateKey(pkcs8: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveKey"]);
}

async function importPublicKeyRaw(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "X25519" }, true, []);
}

async function deriveAesFromX25519(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "X25519", public: publicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function wrapBytesForPublicKey(data: Uint8Array, publicKeyHex: string): Promise<string> {
  const publicKey = await importPublicKeyRaw(hexToBytes(publicKeyHex));
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey"]);
  const derived = await crypto.subtle.deriveKey(
    { name: "X25519", public: publicKey },
    ephemeral.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD_DEK }, derived, data),
  );
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const out = new Uint8Array(ephPub.length + nonce.length + ct.length);
  out.set(ephPub, 0);
  out.set(nonce, ephPub.length);
  out.set(ct, ephPub.length + nonce.length);
  return bytesToBase64(out);
}

export async function unwrapBytes(wrappedB64: string, privateKey: CryptoKey): Promise<Uint8Array> {
  const raw = base64ToBytes(wrappedB64);
  const ephPub = raw.slice(0, 32);
  const nonce = raw.slice(32, 44);
  const ct = raw.slice(44);
  const ephKey = await importPublicKeyRaw(ephPub);
  const derived = await deriveAesFromX25519(privateKey, ephKey);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD_DEK }, derived, ct),
  );
}

export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function encryptFile(dek: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD_FILE }, key, plaintext),
  );
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

export async function decryptFile(dek: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  const nonce = ciphertext.slice(0, 12);
  const ct = ciphertext.slice(12);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD_FILE }, key, ct),
  );
}

export async function encryptPayload(dek: Uint8Array, payload: unknown): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["encrypt"]);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: AAD_PAYLOAD },
      key,
      enc.encode(JSON.stringify(payload)),
    ),
  );
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return bytesToBase64(out);
}

export async function decryptPayload(dek: Uint8Array, payloadB64: string): Promise<unknown> {
  const raw = base64ToBytes(payloadB64);
  const nonce = raw.slice(0, 12);
  const ct = raw.slice(12);
  const key = await crypto.subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  const plain = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: AAD_PAYLOAD }, key, ct),
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

export type VaultPayload = {
  summary?: string | null;
  action_detail?: string | null;
  details?: unknown;
  extracted_text?: string | null;
  deadlines?: { kind: string; due_date: string; description: string; status: string }[];
};

export function buildVaultPayload(doc: {
  summary: string | null;
  action_detail: string | null;
  details: unknown;
  deadlines: { kind: string; due_date: string; description: string; status: string }[];
}): VaultPayload {
  const payload: VaultPayload = {};
  if (doc.summary) payload.summary = doc.summary;
  if (doc.action_detail) payload.action_detail = doc.action_detail;
  if (doc.details) payload.details = doc.details;
  if (doc.deadlines?.length) payload.deadlines = doc.deadlines;
  return payload;
}
