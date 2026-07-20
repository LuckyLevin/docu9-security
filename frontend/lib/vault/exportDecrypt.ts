import { strFromU8, strToU8, unzipSync, zipSync } from "fflate";

import { decryptFile, decryptPayload, unwrapBytes, type VaultPayload } from "@/lib/vault/crypto";

type VaultExportMeta = {
  tresor?: boolean;
  titel?: string;
  typ?: string | null;
  status?: string | null;
  originaldatei?: string | null;
  hochgeladen_am?: string | null;
  hinweis?: string;
  vault_wrapped_dek_b64?: string;
  vault_payload_enc_b64?: string;
  [key: string]: unknown;
};

function extFromFilename(name: string | null | undefined): string {
  if (!name || !name.includes(".")) return "";
  return "." + name.split(".").pop();
}

function uniqueName(base: string, used: Set<string>): string {
  if (!used.has(base)) {
    used.add(base);
    return base;
  }
  const dot = base.lastIndexOf(".");
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const ext = dot > 0 ? base.slice(dot) : "";
  let n = 2;
  let candidate = `${stem}_${n}${ext}`;
  while (used.has(candidate)) {
    n += 1;
    candidate = `${stem}_${n}${ext}`;
  }
  used.add(candidate);
  return candidate;
}

function plaintextMeta(meta: VaultExportMeta, payload: VaultPayload | null): Record<string, unknown> {
  const out: Record<string, unknown> = {
    titel: meta.titel,
    typ: meta.typ,
    status: meta.status,
    originaldatei: meta.originaldatei,
    hochgeladen_am: meta.hochgeladen_am,
    tresor_entschluesselt: true,
  };
  if (payload?.summary) out.zusammenfassung = payload.summary;
  if (payload?.action_detail) out.handlungsbedarf_detail = payload.action_detail;
  if (payload?.details) out.details = payload.details;
  if (payload?.extracted_text) out.extrahierter_text = payload.extracted_text;
  if (payload?.deadlines?.length) out.fristen = payload.deadlines;
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v != null && v !== ""));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rewriteIndexHtml(html: string, replacements: Map<string, string>, remainingVault: number): string {
  let out = html;
  for (const [from, to] of replacements) {
    out = out.split(from).join(to);
    out = out.replace(
      new RegExp(`(<a href="${escapeRegExp(to)}">[^<]*</a>)\\s*<em>\\(Tresor\\)</em>`),
      "$1",
    );
  }
  if (remainingVault === 0) {
    out = out.replace(/\s*Davon \d+ im Tresor \(verschlüsselt, siehe TRESOR-HINWEIS\.txt\)\./g, "");
  } else {
    out = out.replace(
      /Davon \d+ im Tresor \(verschlüsselt, siehe TRESOR-HINWEIS\.txt\)\./,
      `Davon ${remainingVault} im Tresor (verschlüsselt, siehe TRESOR-HINWEIS.txt).`,
    );
  }
  return out;
}

/**
 * Entschlüsselt `.vault.enc`-Dateien im Server-Export-ZIP lokal mit dem Tresor-Private-Key.
 * Schlägt einzelne Dateien fehl, bleiben sie als Chiffrat erhalten.
 */
export async function decryptVaultFilesInExportZip(
  zipBytes: ArrayBuffer,
  privateKey: CryptoKey,
): Promise<{ zip: Uint8Array; decrypted: number; failed: number }> {
  const entries = unzipSync(new Uint8Array(zipBytes));
  const names = Object.keys(entries);
  const vaultFiles = names.filter((n) => n.endsWith(".vault.enc"));
  if (vaultFiles.length === 0) {
    return { zip: new Uint8Array(zipBytes), decrypted: 0, failed: 0 };
  }

  const used = new Set(names.filter((n) => !n.endsWith(".vault.enc") && !n.endsWith(".vault.enc.metadata.json")));
  const replacements = new Map<string, string>();
  let decrypted = 0;
  let failed = 0;

  for (const encName of vaultFiles) {
    const metaName = `${encName}.metadata.json`;
    const encData = entries[encName];
    const metaData = entries[metaName];
    if (!encData || !metaData) {
      failed += 1;
      continue;
    }

    let meta: VaultExportMeta;
    try {
      meta = JSON.parse(strFromU8(metaData)) as VaultExportMeta;
    } catch {
      failed += 1;
      continue;
    }

    const wrapped = meta.vault_wrapped_dek_b64;
    if (!wrapped) {
      failed += 1;
      continue;
    }

    try {
      const dek = await unwrapBytes(wrapped, privateKey);
      const plain = await decryptFile(dek, encData);

      let payload: VaultPayload | null = null;
      if (meta.vault_payload_enc_b64) {
        try {
          payload = (await decryptPayload(dek, meta.vault_payload_enc_b64)) as VaultPayload;
        } catch {
          payload = null;
        }
      }

      const base = encName.slice(0, -".vault.enc".length);
      const ext = extFromFilename(meta.originaldatei) || "";
      const plainName = uniqueName(`${base}${ext}`, used);
      const plainMetaName = `${plainName}.metadata.json`;

      delete entries[encName];
      delete entries[metaName];
      entries[plainName] = Uint8Array.from(plain);
      entries[plainMetaName] = strToU8(JSON.stringify(plaintextMeta(meta, payload), null, 2));
      replacements.set(encName, plainName);
      decrypted += 1;
    } catch {
      failed += 1;
    }
  }

  if (decrypted > 0 && entries["index.html"]) {
    entries["index.html"] = strToU8(rewriteIndexHtml(strFromU8(entries["index.html"]), replacements, failed));
  }

  if (failed === 0 && entries["TRESOR-HINWEIS.txt"]) {
    delete entries["TRESOR-HINWEIS.txt"];
  }

  return { zip: zipSync(entries, { level: 6 }), decrypted, failed };
}
