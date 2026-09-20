#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { stdin, stdout } from "node:process";
import { fileURLToPath } from "node:url";
import {
  type Consent,
  type Consenter,
  type PendingIntent,
  runWithManifest,
} from "./agent.js";
import { formatPendingIntent } from "./intents.js";
import { loadManifestFile, storeFromManifest } from "./manifest.js";
import { parseSandbox } from "./sandbox.js";

interface CliArgs {
  readonly manifest: string;
  readonly ttlMs?: number;
  readonly passphrase?: string;
  readonly sandbox?: boolean;
  readonly sandboxNetwork?: "seal" | "host";
  readonly command: string;
  readonly args: readonly string[];
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const parsed = parseArgs(argv);
  const manifest = loadManifestFile(parsed.manifest);
  const store = storeFromManifest(manifest);
  const sandbox = parsed.sandbox
    ? parseSandbox({ network: parsed.sandboxNetwork ?? "seal" })
    : manifest.sandbox;
  const passphrase =
    parsed.passphrase ?? manifest.passphrase ?? process.env.SEAL_PASSPHRASE;
  const result = await runWithManifest({
    store,
    manifest,
    command: parsed.command,
    args: parsed.args,
    ...(parsed.ttlMs === undefined ? {} : { ttlMs: parsed.ttlMs }),
    ...(passphrase === undefined ? {} : { passphrase }),
    ...(sandbox ? { sandbox } : {}),
    consent: createConsenter(),
  });
  return result.exitCode;
}

export function parseArgs(argv: readonly string[]): CliArgs {
  const separator = argv.indexOf("--");
  if (separator < 0) {
    throw usage();
  }
  const flags = argv.slice(0, separator);
  const child = argv.slice(separator + 1);
  const command = child[0];
  if (!command) {
    throw usage();
  }

  let manifest: string | undefined;
  let ttlMs: number | undefined;
  let passphrase: string | undefined;
  let sandbox: boolean | undefined;
  let sandboxNetwork: "seal" | "host" | undefined;
  for (let index = 0; index < flags.length; index += 1) {
    const flag = flags[index];
    const value = flags[index + 1];
    if (flag === "--manifest" && value) {
      manifest = value;
      index += 1;
    } else if (flag === "--ttl" && value) {
      ttlMs = Number(value);
      index += 1;
    } else if (flag === "--passphrase" && value) {
      passphrase = value;
      index += 1;
    } else if (flag === "--sandbox") {
      sandbox = true;
    } else if (flag === "--sandbox-network" && value) {
      if (value !== "seal" && value !== "host") {
        throw new Error('--sandbox-network must be "seal" or "host"');
      }
      sandbox = true;
      sandboxNetwork = value;
      index += 1;
    } else {
      throw new Error(`unknown flag: ${flag}`);
    }
  }
  if (!manifest) {
    throw usage();
  }
  return {
    manifest,
    ...(ttlMs === undefined ? {} : { ttlMs }),
    ...(passphrase === undefined ? {} : { passphrase }),
    ...(sandbox ? { sandbox: true } : {}),
    ...(sandboxNetwork ? { sandboxNetwork } : {}),
    command,
    args: child.slice(1),
  };
}

function createConsenter(): Consenter {
  if (process.env.SEAL_AUTO_APPROVE === "1") {
    return async (intent) => ({
      granted: true,
      passphrase: process.env.SEAL_PASSPHRASE ?? "ok",
      ...(intent.needsSecret
        ? { secret: process.env.SEAL_CONSENT_SECRET ?? "auto-secret" }
        : {}),
    });
  }
  return promptConsent;
}

async function promptConsent(intent: PendingIntent): Promise<Consent> {
  if (!stdin.isTTY) {
    return { granted: false };
  }
  stdout.write(`Seal: ${formatPendingIntent(intent)}\n`);
  try {
    if (intent.op === "put") {
      const secret = await promptHidden("Enter secret: ");
      if (!secret) {
        return { granted: false };
      }
      return { granted: true, secret };
    }
    const passphrase = await promptHidden("Enter passphrase: ");
    if (!passphrase) {
      return { granted: false };
    }
    if (!intent.needsSecret) {
      return { granted: true, passphrase };
    }
    const secret = await promptHidden("Enter secret: ");
    if (!secret) {
      return { granted: false };
    }
    return { granted: true, passphrase, secret };
  } catch {
    return { granted: false };
  }
}

function promptHidden(question: string): Promise<string> {
  stdout.write(question);
  if (!stdin.isTTY) {
    return Promise.resolve("");
  }
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  let value = "";
  return new Promise((resolve, reject) => {
    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === "\n" || char === "\r") {
          cleanup();
          stdout.write("\n");
          resolve(value);
          return;
        }
        if (char === "\u0003") {
          cleanup();
          reject(new Error("interrupted"));
          return;
        }
        if (char === "\u007f" || char === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        if (char >= " ") {
          value += char;
        }
      }
    };
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
    };
    stdin.on("data", onData);
  });
}

function usage(): Error {
  return new Error(
    "usage: seal --manifest <file> [--ttl <ms>] [--passphrase <secret>] [--sandbox] [--sandbox-network seal|host] -- <command> [args...]",
  );
}

function isDirectCliRun(): boolean {
  const entry = process.argv[1];
  if (!entry) {
    return false;
  }
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return entry.endsWith("cli.ts") || entry.endsWith("cli.js");
  }
}

if (isDirectCliRun()) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`${message}\n`);
      process.exitCode = 1;
    });
}
