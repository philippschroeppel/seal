import { existsSync, lstatSync, readlinkSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export type SandboxNetwork = "seal" | "host";

export interface Sandbox {
  readonly backend: "bwrap";
  readonly network: SandboxNetwork;
}

const ROOT_DIRS = [
  "/usr",
  "/etc/ssl",
  "/etc/ca-certificates",
  "/etc/alternatives",
];
const ROOT_LINKS = ["/bin", "/sbin", "/lib", "/lib64", "/lib32"];
const HOST_NET_FILES = ["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"];

export function parseSandbox(raw: unknown): Sandbox | undefined {
  if (raw === undefined || raw === false || raw === "none") {
    return undefined;
  }
  if (raw === true || raw === "bwrap") {
    return { backend: "bwrap", network: "seal" };
  }
  if (raw !== null && typeof raw === "object" && !Array.isArray(raw)) {
    const record = raw as Record<string, unknown>;
    const network = record.network === "host" ? "host" : "seal";
    return { backend: "bwrap", network };
  }
  throw new Error(
    'session.sandbox must be true, "bwrap", or { network: "seal" | "host" }',
  );
}

export function bwrapExecutable(): string {
  return process.env.SEAL_BWRAP ?? "bwrap";
}

export function resolveExecutable(command: string, cwd: string): string {
  if (command.includes("/") || command.startsWith(".")) {
    return realpathSync(resolve(cwd, command));
  }
  const path = process.env.PATH ?? "";
  for (const dir of path.split(":")) {
    if (!dir) {
      continue;
    }
    const candidate = join(dir, command);
    if (existsSync(candidate) && lstatSync(candidate).isFile()) {
      return realpathSync(candidate);
    }
  }
  throw new Error(`cannot resolve command for sandbox: ${command}`);
}

export function buildBwrapArgs(options: {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly network: SandboxNetwork;
  readonly bindDirs?: readonly string[];
}): string[] {
  const cwd = resolve(options.cwd);
  const executable = resolveExecutable(options.command, cwd);
  const args: string[] = [
    "--unshare-user",
    "--unshare-pid",
    "--unshare-uts",
    "--unshare-ipc",
    "--die-with-parent",
    "--dev",
    "/dev",
    "--proc",
    "/proc",
    "--tmpfs",
    "/tmp",
    "--dir",
    "/tmp/home",
  ];
  if (options.network === "seal") {
    args.push("--unshare-net");
  }

  args.push(...bindExisting(ROOT_DIRS));
  args.push(...bindExisting(ROOT_LINKS));
  args.push(...bindFile(executable));
  args.push("--bind", cwd, cwd);
  for (const dir of options.bindDirs ?? []) {
    args.push("--bind", dir, dir);
  }
  if (options.network === "host") {
    args.push(...bindExisting(HOST_NET_FILES));
  }
  args.push("--chdir", cwd);

  args.push(
    "--clearenv",
    "--setenv",
    "HOME",
    "/tmp/home",
    "--setenv",
    "TMPDIR",
    "/tmp",
  );
  args.push("--setenv", "PATH", pathValue(executable));
  args.push("--setenv", "LANG", options.env.LANG ?? "C.UTF-8");
  if (options.env.TERM) {
    args.push("--setenv", "TERM", options.env.TERM);
  }
  for (const [key, value] of Object.entries(options.env)) {
    if (
      value === undefined ||
      key === "HOME" ||
      key === "TMPDIR" ||
      key === "PATH"
    ) {
      continue;
    }
    if (key === "LANG" || key === "TERM") {
      continue;
    }
    args.push("--setenv", key, value);
  }

  args.push("--", executable, ...options.args);
  return args;
}

function pathValue(executable: string): string {
  const dirs = ["/usr/bin", "/bin", dirname(executable)];
  return [...new Set(dirs)].join(":");
}

function bindExisting(paths: readonly string[]): string[] {
  const args: string[] = [];
  for (const path of paths) {
    if (!existsSync(path)) {
      continue;
    }
    if (lstatSync(path).isSymbolicLink()) {
      args.push("--symlink", readlinkSync(path), path);
      continue;
    }
    args.push("--ro-bind", path, path);
  }
  return args;
}

function bindFile(path: string): string[] {
  if (!existsSync(path)) {
    return [];
  }
  return ["--ro-bind", path, path];
}
