export type SecretName = string;
export type GrantId = string;
export type SessionToken = string;

export interface KeyPair {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
}

export interface GrantEntry {
  readonly name: SecretName;
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly wrappedDek: Uint8Array;
}

export interface Grant {
  readonly entries: readonly GrantEntry[];
  readonly expiresAt: number;
}

export interface SecretStore {
  put(name: SecretName, value: string): void;
  issueGrant(
    grantId: GrantId,
    secretNames: readonly SecretName[],
    recipientPublicKey: Uint8Array,
    ttlMs: number,
  ): void;
  fetchGrant(grantId: GrantId): Grant | undefined;
  revokeGrant(grantId: GrantId): void;
}

export interface ClientConnection {
  readonly socketPath: string;
  readonly token: SessionToken;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
