import type { CapabilityIdentity, SessionCapabilities } from "./intents.js";
import { SealError } from "./errors.js";
import { urlMatchesPrefix } from "./use.js";

export interface PluginIdentityNeed {
  readonly name: string;
  readonly ops: readonly ("http" | "sign")[];
  readonly peers?: readonly string[];
  readonly formats?: readonly string[];
}

/**
 * Client-side plugin contract. Seal never loads these modules.
 * A plugin is unprivileged glue that may only call `agent.http` / `agent.sign`.
 */
export interface PluginContract {
  readonly name: string;
  readonly version: string;
  readonly identities: readonly PluginIdentityNeed[];
}

/**
 * Fail closed if this session cannot satisfy the plugin's declared identities.
 * Binding only — Cedar still decides each concrete `/v1/http` or `/v1/sign`.
 */
export function assertCompatible(
  plugin: PluginContract,
  capabilities: SessionCapabilities,
): void {
  for (const need of plugin.identities) {
    const have = capabilities.identities.find((item) => item.name === need.name);
    if (!have) {
      throw new SealError(
        "not_granted",
        `${plugin.name}: session has no identity ${need.name}`,
      );
    }
    assertOps(plugin.name, need, have);
    assertPeers(plugin.name, need, have);
    assertFormats(plugin.name, need, have);
  }
}

function assertOps(
  plugin: string,
  need: PluginIdentityNeed,
  have: CapabilityIdentity,
): void {
  for (const op of need.ops) {
    if (!have.ops.includes(op)) {
      throw new SealError(
        "unsupported_op",
        `${plugin}: identity ${need.name} cannot ${op}`,
      );
    }
  }
}

function assertPeers(
  plugin: string,
  need: PluginIdentityNeed,
  have: CapabilityIdentity,
): void {
  if (!need.peers) {
    return;
  }
  for (const peer of need.peers) {
    if (!sessionCoversPeer(have.peers, peer)) {
      throw new SealError(
        "forbidden",
        `${plugin}: identity ${need.name} is not bound to ${peer}`,
      );
    }
  }
}

function assertFormats(
  plugin: string,
  need: PluginIdentityNeed,
  have: CapabilityIdentity,
): void {
  if (!need.formats) {
    return;
  }
  const available = have.formats ?? [];
  for (const format of need.formats) {
    if (!available.includes(format)) {
      throw new SealError(
        "unsupported_op",
        `${plugin}: identity ${need.name} cannot sign as ${format}`,
      );
    }
  }
}

function sessionCoversPeer(
  sessionPeers: readonly string[] | undefined,
  needed: string,
): boolean {
  if (!sessionPeers || sessionPeers.length === 0) {
    return false;
  }
  return sessionPeers.some(
    (bound) => needed === bound || urlMatchesPrefix(needed, bound),
  );
}
