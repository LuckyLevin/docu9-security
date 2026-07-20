/** AB2: Direkt-Upload in den Tresor — Client verschlüsselt vor dem Upload. */

import { api } from "@/lib/api";
import type { DocumentSummary } from "@/lib/types";
import { encryptFile, generateDek, wrapBytesForPublicKey } from "@/lib/vault/crypto";

const MIME_BY_EXT: Record<string, string> = {
  pdf: "application/pdf",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  tiff: "image/tiff",
  tif: "image/tiff",
  heic: "image/heic",
  webp: "image/webp",
};

/** Browser liefern bei Drag&Drop oft kein file.type — für den Server trotzdem MIME setzen. */
export function uploadMimeType(file: File): string {
  if (file.type) return file.type;
  const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
  const guessed = MIME_BY_EXT[ext];
  if (guessed) return guessed;
  throw new Error("Dateiformat konnte nicht erkannt werden — bitte PDF oder Bild verwenden.");
}

export function formDataFilePart(file: File): [Blob, string] {
  const mime = uploadMimeType(file);
  // Safari/WebKit: immer typisierten Blob materialisieren — verhindert
  // „Load failed“ und abgeschnittene Uploads bei manchen File-Objekten.
  return [new Blob([file], { type: mime }), file.name];
}

export async function uploadFileToVault(file: File, publicKeyHex: string): Promise<DocumentSummary> {
  const key = publicKeyHex.trim();
  if (key.length !== 64) {
    throw new Error("Tresor-Schlüssel ungültig — bitte Seite neu laden.");
  }

  const plain = new Uint8Array(await file.arrayBuffer());
  const dek = generateDek();
  const ciphertext = await encryptFile(dek, plain);
  const wrappedDek = await wrapBytesForPublicKey(dek, key);

  const form = new FormData();
  // Blob wie in VaultCard — new File() führt in Safari/WebKit zu „Load failed“ beim fetch.
  form.append("file", new Blob([ciphertext], { type: "application/octet-stream" }), "vault.bin");
  form.append("vault_wrapped_dek_b64", wrappedDek);
  form.append("original_filename", file.name);
  form.append("mime_type", uploadMimeType(file));

  return api<DocumentSummary>("/vault/documents/upload", { method: "POST", body: form });
}
