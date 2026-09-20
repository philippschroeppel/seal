import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { SealError } from "./errors.js";
import { parseSandbox, type Sandbox } from "./sandbox.js";
import { MemorySecretStore } from "./store.js";
import { isRecord, type SecretName } from "./types.js";

export type { Sandbox, SandboxNetwork } from "./sandbox.js";

export type IdentityAttach = {
  readonly type: "bearer";
  readonly header?: string;
  readonly scheme?: string;
};

export interface SecretSource {
  readonly env?: string;
  readonly file?: string;
  readonly value?: string;
}

export interface IdentityBinding {
  readonly name: string;
  readonly secret: SecretName;
  readonly source?: SecretSource;
  readonly plugins?: readonly string[];
  readonly peers?: readonly string[];
  readonly attach?: IdentityAttach;
  readonly format?: string;
}

export interface Manifest {
  readonly sessionId?: string;
  readonly ttlMs: number;
  readonly passphrase?: string;
  readonly identities: readonly IdentityBinding[];
  readonly sandbox?: Sandbox;
}

const DEFAULT_TTL_MS = 5 * 60_000;

export function loadManifestFile(path: string): Manifest {
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!isRecord(raw)) {
    throw new Error("manifest must be a JSON object");
  }
  if (raw.identities !== undefined && !Array.isArray(raw.identities)) {
    throw new Error("manifest identities must be an array");
  }

  const session = isRecord(raw.session) ? raw.session : undefined;
  const sandbox = parseSandbox(session?.sandbox);

  return {
    ...(typeof session?.id === "string" ? { sessionId: session.id } : {}),
    ttlMs:
      typeof session?.ttlMs === "number" && Number.isFinite(session.ttlMs)
        ? session.ttlMs
        : DEFAULT_TTL_MS,
    ...(typeof session?.passphrase === "string"
      ? { passphrase: session.passphrase }
      : {}),
    identities: Array.isArray(raw.identities)
      ? raw.identities.map((item, index) => parseIdentity(item, index))
      : [],
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

export function identityAllowsPlugin(
  identity: IdentityBinding,
  plugin: string,
): boolean {
  if (!identity.plugins || identity.plugins.length === 0) {
    return true;
  }
  return identity.plugins.includes(plugin);
}

function parseIdentity(raw: unknown, index: number): IdentityBinding {
  if (!isRecord(raw) || typeof raw.name !== "string") {
    throw new Error(`identities[${index}] must include name`);
  }

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

  const plugins = Array.isArray(raw.plugins)
    ? raw.plugins.filter(
        (plugin): plugin is string => typeof plugin === "string",
      )
    : undefined;

  const attach = isRecord(raw.attach)
    ? parseAttach(raw.attach, index)
    : undefined;

  return {
    name: raw.name,
    secret: typeof raw.secret === "string" ? raw.secret : raw.name,
    ...(source && Object.keys(source).length > 0 ? { source } : {}),
    ...(plugins && plugins.length > 0 ? { plugins } : {}),
    ...(peers && peers.length > 0 ? { peers } : {}),
    ...(attach ? { attach } : {}),
    ...(typeof raw.format === "string" ? { format: raw.format } : {}),
  };
}

function parseAttach(
  raw: Record<string, unknown>,
  index: number,
): IdentityAttach {
  if (raw.type !== undefined && raw.type !== "bearer") {
    throw new Error(`identities[${index}] attach.type must be "bearer"`);
  }
  return {
    type: "bearer",
    ...(typeof raw.header === "string" ? { header: raw.header } : {}),
    ...(typeof raw.scheme === "string" ? { scheme: raw.scheme } : {}),
  };
}

export function resolveSecretPath(file: string, cwd: string): string {
  if (file === "~") {
    return homedir();
  }
  if (file.startsWith("~/")) {
    return resolve(homedir(), file.slice(2));
  }
  return resolve(cwd, file);
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
    return readFileSync(resolveSecretPath(source.file, cwd), "utf8").trimEnd();
  }
  throw new SealError(
    "unknown_secret",
    `identity ${identity.name}: secret source is empty`,
  );
}
