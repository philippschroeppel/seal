#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { type Approver, type PendingIntent, runWithManifest } from "./agent.js";
import { formatPendingIntent } from "./intents.js";
import { loadManifestFile, storeFromManifest } from "./manifest.js";

interface CliArgs {
  readonly manifest: string;
  readonly ttlMs?: number;
  readonly command: string;
  readonly args: readonly string[];
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const parsed = parseArgs(argv);
  const manifest = loadManifestFile(parsed.manifest);
  const store = storeFromManifest(manifest);
  const result = await runWithManifest({
    store,
    manifest,
    command: parsed.command,
    args: parsed.args,
    ...(parsed.ttlMs === undefined ? {} : { ttlMs: parsed.ttlMs }),
    approve: createApprover(),
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
  for (let index = 0; index < flags.length; index += 1) {
    const flag = flags[index];
    const value = flags[index + 1];
    if (flag === "--manifest" && value) {
      manifest = value;
      index += 1;
    } else if (flag === "--ttl" && value) {
      ttlMs = Number(value);
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
    command,
    args: child.slice(1),
  };
}

function createApprover(): Approver {
  if (process.env.SEAL_AUTO_APPROVE === "1") {
    return async () => true;
  }
  return promptApprover;
}

async function promptApprover(intent: PendingIntent): Promise<boolean> {
  if (!process.stdin.isTTY) {
    return false;
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(
      `Seal: approve ${intent.op} with ${intent.identity}?\n  ${formatPendingIntent(intent)}\n[y/N] `,
    );
    return answer.trim().toLowerCase() === "y";
  } finally {
    rl.close();
  }
}

function usage(): Error {
  return new Error(
    "usage: seal --manifest <file> [--ttl <ms>] -- <command> [args...]",
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
