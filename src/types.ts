export type SecretName = string;
export type SessionToken = string;

export interface SecretStore {
  put(name: SecretName, value: string): void;
  has(name: SecretName): boolean;
  use<T>(name: SecretName, fn: (value: string) => T | Promise<T>): Promise<T>;
  wipe(name?: SecretName): void;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
