"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { api } from "@/lib/api";
import { unwrapToPrivateKey } from "@/lib/vault/crypto";
import { unlockPrivateKeyWithPasskeyWraps } from "@/lib/vault/passkey";
import { normalizeRecoveryCode } from "@/lib/vault/recovery";

const LOCK_MS = 15 * 60 * 1000;

type VaultWrap = {
  kind: string;
  credential_id: string | null;
  wrap_blob_b64: string;
};

type VaultSessionContextValue = {
  unlocked: boolean;
  privateKey: CryptoKey | null;
  unlockWithPassphrase: (passphrase: string) => Promise<void>;
  unlockWithPasskey: () => Promise<void>;
  unlockWithRecovery: (recoveryCode: string) => Promise<void>;
  lock: () => void;
  touch: () => void;
};

const VaultSessionContext = createContext<VaultSessionContextValue | null>(null);

export function VaultSessionProvider({ children }: { children: ReactNode }) {
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const lock = useCallback(() => {
    setPrivateKey(null);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = null;
  }, []);

  const touch = useCallback(() => {
    if (!privateKey) return;
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(lock, LOCK_MS);
  }, [lock, privateKey]);

  useEffect(
    () => () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    },
    [],
  );

  async function loadWrap(kind: string): Promise<VaultWrap> {
    const res = await api<{ wraps: VaultWrap[] }>("/vault/wraps");
    const wrap = res.wraps.find((w) => w.kind === kind);
    if (!wrap) throw new Error(`Kein ${kind}-Wrap hinterlegt.`);
    return wrap;
  }

  async function loadPasskeyWraps(): Promise<{ credential_id: string; wrap_blob_b64: string }[]> {
    const res = await api<{ wraps: VaultWrap[] }>("/vault/wraps");
    return res.wraps
      .filter((w) => w.kind === "passkey" && w.credential_id)
      .map((w) => ({ credential_id: w.credential_id!, wrap_blob_b64: w.wrap_blob_b64 }));
  }

  const unlockWithPassphrase = useCallback(
    async (passphrase: string) => {
      const wrap = await loadWrap("passphrase");
      const key = await unwrapToPrivateKey(wrap.wrap_blob_b64, passphrase);
      setPrivateKey(key);
      touch();
    },
    [touch],
  );

  const unlockWithPasskey = useCallback(async () => {
    const passkeys = await loadPasskeyWraps();
    const key = await unlockPrivateKeyWithPasskeyWraps(passkeys);
    setPrivateKey(key);
    touch();
  }, [touch]);

  const unlockWithRecovery = useCallback(
    async (recoveryCode: string) => {
      const wrap = await loadWrap("recovery");
      const key = await unwrapToPrivateKey(wrap.wrap_blob_b64, normalizeRecoveryCode(recoveryCode));
      setPrivateKey(key);
      touch();
    },
    [touch],
  );

  const value = useMemo(
    () => ({
      unlocked: privateKey !== null,
      privateKey,
      unlockWithPassphrase,
      unlockWithPasskey,
      unlockWithRecovery,
      lock,
      touch,
    }),
    [privateKey, unlockWithPassphrase, unlockWithPasskey, unlockWithRecovery, lock, touch],
  );

  return <VaultSessionContext.Provider value={value}>{children}</VaultSessionContext.Provider>;
}

export function useVaultSession() {
  const ctx = useContext(VaultSessionContext);
  if (!ctx) throw new Error("useVaultSession außerhalb von VaultSessionProvider");
  return ctx;
}

export function useVaultSessionOptional() {
  return useContext(VaultSessionContext);
}

/** Leichtgewichtiger Provider ohne Hook-Pflicht (für FileViewer). */
export { VaultSessionContext };
