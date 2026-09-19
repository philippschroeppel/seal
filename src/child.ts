import { spawn } from "node:child_process";

export interface SpawnOptions {
  readonly command: string;
  readonly args?: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly stdio?: "inherit" | "pipe";
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
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...options.env,
    ...extraEnv,
  };
  for (const key of unset) {
    delete env[key];
  }

  const child = spawn(options.command, options.args ?? [], {
    stdio: options.stdio ?? "inherit",
    env,
  });

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
