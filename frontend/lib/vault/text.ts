/** AB4: Dokumenttext für Tresor-KI — aus Payload oder Datei (Plaintext). */

import { API_BASE, authHeader } from "@/lib/api";

import {
  decryptFile,
  decryptPayload,
  unwrapBytes,
  type VaultPayload,
} from "./crypto";

export async function fetchExtractedTextForVaultEnter(documentId: string): Promise<string | null> {
  const resp = await fetch(`${API_BASE}/documents/${documentId}/extracted-text`, {
    headers: await authHeader(),
  });
  if (!resp.ok) return null;
  const data = (await resp.json()) as { text?: string };
  return data.text?.trim() || null;
}

export async function fetchVaultDocumentText(
  documentId: string,
  vaultWrappedDekB64: string,
  vaultPayloadEncB64: string | null | undefined,
  privateKey: CryptoKey,
  mimeType: string,
): Promise<string> {
  if (vaultPayloadEncB64) {
    const dek = await unwrapBytes(vaultWrappedDekB64, privateKey);
    const payload = (await decryptPayload(dek, vaultPayloadEncB64)) as VaultPayload;
    if (payload.extracted_text?.trim()) {
      return payload.extracted_text.trim();
    }
  }

  const resp = await fetch(`${API_BASE}/vault/documents/${documentId}/file`, {
    headers: await authHeader(),
  });
  if (!resp.ok) throw new Error("Tresor-Datei konnte nicht geladen werden.");
  const ciphertext = new Uint8Array(await resp.arrayBuffer());
  const dek = await unwrapBytes(vaultWrappedDekB64, privateKey);
  const plain = await decryptFile(dek, ciphertext);

  if (mimeType.startsWith("text/") || mimeType === "application/json") {
    return new TextDecoder().decode(plain).trim();
  }

  throw new Error(
    "Kein gespeicherter Text — lege das Dokument erneut in den Tresor, nachdem es verarbeitet wurde.",
  );
}

export async function mergeAndUploadVaultPayload(
  documentId: string,
  vaultWrappedDekB64: string,
  vaultPayloadEncB64: string | null | undefined,
  privateKey: CryptoKey,
  patch: Partial<VaultPayload>,
): Promise<void> {
  const { encryptPayload } = await import("./crypto");
  const dek = await unwrapBytes(vaultWrappedDekB64, privateKey);
  let existing: VaultPayload = {};
  if (vaultPayloadEncB64) {
    existing = (await decryptPayload(dek, vaultPayloadEncB64)) as VaultPayload;
  }
  const merged = { ...existing, ...patch };
  const vault_payload_enc_b64 = await encryptPayload(dek, merged);
  const { api } = await import("@/lib/api");
  await api(`/vault/documents/${documentId}/payload`, {
    method: "PATCH",
    body: JSON.stringify({ vault_payload_enc_b64 }),
  });
}
