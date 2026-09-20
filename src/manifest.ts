import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { SealError } from "./errors.js";
import { parseSandbox, type Sandbox } from "./sandbox.js";
import { MemorySecretStore } from "./store.js";
import { isRecord, type SecretName } from "./types.js";

export type { Sandbox, SandboxNetwork } from "./sandbox.js";

export type ApprovalMode = "never" | "once" | "each";

export type IdentityAttach =
  | {
      readonly type: "bearer";
      readonly header?: string;
      readonly scheme?: string;
    }
  | { readonly type: "hmac-sha256" }
  | { readonly type: "ed25519" };

export interface SecretSource {
  readonly env?: string;
  readonly file?: string;
  readonly value?: string;
}

export interface IdentityBinding {
  readonly name: string;
  readonly secret: SecretName;
  readonly source?: SecretSource;
  readonly attach: IdentityAttach;
  readonly peers?: readonly string[];
  readonly approve?: ApprovalMode;
}

export interface Manifest {
  readonly sessionId?: string;
  readonly ttlMs: number;
  readonly policies: string;
  readonly identities: readonly IdentityBinding[];
  readonly sandbox?: Sandbox;
}

const DEFAULT_TTL_MS = 5 * 60_000;

export function loadManifestFile(path: string): Manifest {
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(raw) || typeof raw.policies !== "string") {
    throw new Error("manifest must include a policies string");
  }
  if (!Array.isArray(raw.identities)) {
    throw new Error("manifest must include an identities array");
  }

  const policies = looksLikeCedar(raw.policies)
    ? raw.policies
    : readFileSync(resolve(dirname(path), raw.policies), "utf8");

  const session = isRecord(raw.session) ? raw.session : undefined;

  const sandbox = parseSandbox(session?.sandbox);

  return {
    ...(typeof session?.id === "string" ? { sessionId: session.id } : {}),
    ttlMs:
      typeof session?.ttlMs === "number" && Number.isFinite(session.ttlMs)
        ? session.ttlMs
        : DEFAULT_TTL_MS,
    policies,
    identities: raw.identities.map((item, index) => parseIdentity(item, index)),
    ...(sandbox ? { sandbox } : {}),
  };
}

export function storeFromManifest(
  manifest: Manifest,
  env: NodeJS.ProcessEnv = process.env,
): MemorySecretStore {
  const store = new MemorySecretStore();
  for (const identity of manifest.identities) {
    store.put(identity.secret, readSecret(identity, env, process.cwd()));
  }
  return store;
}

export function secretEnvKeys(manifest: Manifest): string[] {
  return manifest.identities.flatMap((identity) =>
    identity.source?.env ? [identity.source.env] : [],
  );
}

export function approvalMode(identity: IdentityBinding): ApprovalMode {
  if (identity.approve) {
    return identity.approve;
  }
  return identity.attach.type === "bearer" ? "never" : "each";
}

function parseIdentity(raw: unknown, index: number): IdentityBinding {
  if (!isRecord(raw) || typeof raw.name !== "string") {
    throw new Error(`identities[${index}] must include name`);
  }
  if (!isRecord(raw.attach) || typeof raw.attach.type !== "string") {
    throw new Error(`identities[${index}] must include attach.type`);
  }

  const attach = parseAttach(raw.attach, index);
  const source = isRecord(raw.source)
    ? {
        ...(typeof raw.source.env === "string" ? { env: raw.source.env } : {}),
        ...(typeof raw.source.file === "string"
          ? { file: raw.source.file }
          : {}),
        ...(typeof raw.source.value === "string"
          ? { value: raw.source.value }
          : {}),
      }
    : undefined;

  const peers = Array.isArray(raw.peers)
    ? raw.peers.filter((peer): peer is string => typeof peer === "string")
    : undefined;

  const approve =
    raw.approve === "never" || raw.approve === "once" || raw.approve === "each"
      ? raw.approve
      : undefined;

  return {
    name: raw.name,
    secret: typeof raw.secret === "string" ? raw.secret : raw.name,
    ...(source && Object.keys(source).length > 0 ? { source } : {}),
    attach,
    ...(peers && peers.length > 0 ? { peers } : {}),
    ...(approve ? { approve } : {}),
  };
}

function parseAttach(
  raw: Record<string, unknown>,
  index: number,
): IdentityAttach {
  if (raw.type === "bearer") {
    return {
      type: "bearer",
      ...(typeof raw.header === "string" ? { header: raw.header } : {}),
      ...(typeof raw.scheme === "string" ? { scheme: raw.scheme } : {}),
    };
  }
  if (raw.type === "hmac-sha256") {
    return { type: "hmac-sha256" };
  }
  if (raw.type === "ed25519") {
    return { type: "ed25519" };
  }
  throw new Error(`identities[${index}] has unknown attach.type`);
}

function readSecret(
  identity: IdentityBinding,
  env: NodeJS.ProcessEnv,
  cwd: string,
): string {
  const source = identity.source;
  if (!source) {
    throw new SealError(
      "unknown_secret",
      `identity ${identity.name} has no secret source`,
    );
  }
  if (source.value !== undefined) {
    return source.value;
  }
  if (source.env) {
    const value = env[source.env];
    if (value) {
      return value;
    }
  }
  if (source.file) {
    return readFileSync(resolve(cwd, source.file), "utf8").trimEnd();
  }
  throw new SealError(
    "unknown_secret",
    `identity ${identity.name}: secret source is empty`,
  );
}

function looksLikeCedar(value: string): boolean {
  return /\b(permit|forbid)\s*\(/.test(value);
}
