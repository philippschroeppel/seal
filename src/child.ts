import { spawn } from "node:child_process";
import { buildBwrapArgs, bwrapExecutable, type Sandbox } from "./sandbox.js";

export interface SpawnOptions {
  readonly command: string;
  readonly args?: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly stdio?: "inherit" | "pipe";
  readonly sandbox?: Sandbox;
  readonly bindDirs?: readonly string[];
}

export interface RunResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export function spawnChild(
  options: SpawnOptions,
  extraEnv: NodeJS.ProcessEnv,
  unset: readonly string[] = [],
): Promise<RunResult> {
  if (options.sandbox) {
    return spawnSandboxed(options, extraEnv, unset);
  }

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...options.env,
    ...extraEnv,
  };
  for (const key of unset) {
    delete env[key];
  }

  return waitFor(
    spawn(options.command, options.args ?? [], {
      stdio: options.stdio ?? "inherit",
      env,
    }),
  );
}

function spawnSandboxed(
  options: SpawnOptions,
  extraEnv: NodeJS.ProcessEnv,
  unset: readonly string[],
): Promise<RunResult> {
  if (options.sandbox?.backend !== "bwrap") {
    throw new Error("only the bwrap sandbox backend is supported");
  }
  if (process.platform !== "linux") {
    throw new Error("bwrap sandbox is only supported on Linux");
  }

  const passthrough: NodeJS.ProcessEnv = { ...options.env, ...extraEnv };
  for (const key of unset) {
    delete passthrough[key];
  }
  if (process.env.LANG && passthrough.LANG === undefined) {
    passthrough.LANG = process.env.LANG;
  }
  if (process.env.TERM && passthrough.TERM === undefined) {
    passthrough.TERM = process.env.TERM;
  }

  const args = buildBwrapArgs({
    command: options.command,
    args: options.args ?? [],
    cwd: process.cwd(),
    env: passthrough,
    network: options.sandbox.network,
    ...(options.bindDirs ? { bindDirs: options.bindDirs } : {}),
  });

  return waitFor(
    spawn(bwrapExecutable(), args, {
      stdio: options.stdio ?? "inherit",
    }),
  );
}

function waitFor(child: ReturnType<typeof spawn>): Promise<RunResult> {
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => {
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}
