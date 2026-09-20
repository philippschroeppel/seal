import { SealError } from "./errors.js";
import type { IdentityBinding } from "./manifest.js";
import { githubPlugin } from "./plugins/github.js";
import { httpPlugin } from "./plugins/http.js";
import { signPlugin } from "./plugins/sign.js";
import { sshPlugin } from "./plugins/ssh.js";

export interface PluginContext {
  readonly identity: IdentityBinding;
  readonly fetch: typeof fetch;
  readonly passphrase?: string;
}

/**
 * A vault plugin runs inside Seal with the unsealed secret.
 * It must never return credential bytes to the agent.
 */
export interface Plugin {
  readonly name: string;
  use(
    secret: string,
    input: unknown,
    ctx: PluginContext,
  ): Promise<unknown> | unknown;
}

const builtins: ReadonlyMap<string, Plugin> = new Map(
  [httpPlugin, signPlugin, sshPlugin, githubPlugin].map((plugin) => [
    plugin.name,
    plugin,
  ]),
);

export function getPlugin(name: string): Plugin {
  const plugin = builtins.get(name);
  if (!plugin) {
    throw new SealError("unsupported_op", `unknown plugin: ${name}`);
  }
  return plugin;
}

export function builtinPluginNames(): readonly string[] {
  return [...builtins.keys()];
}
