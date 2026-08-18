/** Clientseitige Versiegelung: Vorrat-Dokument → Tresor (KEK → X25519). */

import { API_BASE, api, authHeader } from "@/lib/api";
import type { DocumentSummary } from "@/lib/types";
import {
  encryptFile,
  generateDek,
  wrapBytesForPublicKey,
} from "@/lib/vault/crypto";

export async function sealDocumentToVault(
  doc: Pick<DocumentSummary, "id" | "original_filename">,
  publicKeyHex: string,
): Promise<DocumentSummary> {
  const fileResp = await fetch(`${API_BASE}/documents/${doc.id}/file`, {
    headers: await authHeader(),
  });
  if (!fileResp.ok) {
    throw new Error("Original konnte nicht geladen werden.");
  }
  const plain = new Uint8Array(await fileResp.arrayBuffer());
  const dek = generateDek();
  const fileEnc = await encryptFile(dek, plain);
  const wrappedDek = await wrapBytesForPublicKey(dek, publicKeyHex);

  const form = new FormData();
  form.append("file", new Blob([fileEnc]), "vault.bin");
  form.append("vault_wrapped_dek_b64", wrappedDek);
  form.append("purge_confirmed", "true");

  return api<DocumentSummary>(`/vault/documents/${doc.id}/enter`, {
    method: "POST",
    body: form,
  });
}

export async function sealDocumentsToVault(
  docs: Pick<DocumentSummary, "id" | "original_filename">[],
  publicKeyHex: string,
): Promise<void> {
  for (const doc of docs) {
    await sealDocumentToVault(doc, publicKeyHex);
  }
}
