import { spawnSync } from "node:child_process";
import { mkdtempSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  type AgentSession,
  runWithManifest,
  startAgentSession,
} from "../src/agent.js";
import { agent } from "../src/agent-client.js";
import type { Manifest } from "../src/manifest.js";
import { buildBwrapArgs, parseSandbox } from "../src/sandbox.js";
import { MemorySecretStore } from "../src/store.js";

const probePath = fileURLToPath(new URL("./sandbox-probe.ts", import.meta.url));
const TOKEN = "sandbox-pat";
const sessions: AgentSession[] = [];
const canaries: string[] = [];

afterEach(() => {
  for (const session of sessions.splice(0)) {
    session.close();
  }
  for (const canary of canaries.splice(0)) {
    try {
      unlinkSync(canary);
    } catch {
      /* test leftover */
    }
  }
});

describe("sandbox", () => {
  it("defaults bwrap to seal-only network", () => {
    expect(parseSandbox(true)).toEqual({
      backend: "bwrap",
      network: "seal",
    });
    expect(parseSandbox({ network: "host" })).toEqual({
      backend: "bwrap",
      network: "host",
    });
  });

  it("builds a jail that unshares net and skips host home", () => {
    const cwd = process.cwd();
    const args = buildBwrapArgs({
      command: process.execPath,
      args: ["-e", "0"],
      cwd,
      env: { SEAL_URL: "unix:///tmp/http.sock", SEAL_TOKEN: "t" },
      network: "seal",
      bindDirs: ["/tmp/seal-http-test"],
    });
    expect(args).toContain("--unshare-net");
    expect(args).toContain("--clearenv");
    expect(args).not.toContain(homedir());
    expect(args.join("\0")).toContain("HOME\0/tmp/home");
    const homeFile = join(homedir(), ".config/gh/hosts.yml");
    const withHomeArg = buildBwrapArgs({
      command: process.execPath,
      args: [homeFile],
      cwd,
      env: {},
      network: "seal",
    });
    expect(withHomeArg).toContain(homeFile);
    const homeBinds = withHomeArg.filter(
      (arg, index) =>
        (withHomeArg[index - 1] === "--bind" ||
          withHomeArg[index - 1] === "--ro-bind") &&
        arg.startsWith(homedir()),
    );
    expect(homeBinds).toEqual([]);
  });

  it("serves agent HTTP over a unix socket", async () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-unix-"));
    const session = await startAgentSession({
      store: seededStore(),
      manifest: testManifest("http://127.0.0.1:9"),
      socketPath: join(dir, "http.sock"),
    });
    sessions.push(session);
    expect(session.url.startsWith("unix://")).toBe(true);

    await expect(
      agent.use(
        {
          plugin: "http",
          identity: "gh-token",
          input: { method: "GET", url: "http://127.0.0.1:9/x" },
        },
        session,
      ),
    ).rejects.toMatchObject({ code: "peer_failed" });
  });

  it.runIf(hasBwrap())(
    "hides host credentials and still uses Seal over the socket",
    async () => {
      const canary = join(homedir(), `.seal-sandbox-canary-${Date.now()}`);
      writeFileSync(canary, "host-secret\n");
      canaries.push(canary);
      const peer = await openPeer();
      try {
        const result = await runWithManifest({
          store: seededStore(),
          manifest: testManifest(peer.url),
          sandbox: { backend: "bwrap", network: "seal" },
          command: process.execPath,
          args: ["--import", "tsx", probePath, canary, peer.url],
          stdio: "pipe",
          env: { GITHUB_TOKEN: TOKEN },
        });

        expect(result.exitCode, result.stdout + result.stderr).toBe(0);
        const body = JSON.parse(result.stdout) as {
          home: string;
          githubToken: boolean;
          hasCanary: boolean;
          fetchOk: boolean;
          http: { status: number; body: string };
          sealUrl: string;
        };
        expect(body.home).toBe("/tmp/home");
        expect(body.githubToken).toBe(false);
        expect(body.hasCanary).toBe(false);
        expect(body.fetchOk).toBe(false);
        expect(body.sealUrl.startsWith("unix://")).toBe(true);
        expect(body.http.status).toBe(200);
        expect(JSON.parse(body.http.body)).toEqual({ ok: true, issues: [] });
        expect(peer.seen.at(-1)?.authorization).toBe(`Bearer ${TOKEN}`);
      } finally {
        peer.close();
      }
    },
  );
});

function hasBwrap(): boolean {
  if (process.platform !== "linux") {
    return false;
  }
  const result = spawnSync("bwrap", ["--version"], { encoding: "utf8" });
  return result.status === 0;
}

function seededStore(): MemorySecretStore {
  const store = new MemorySecretStore();
  store.put("gh-token", TOKEN);
  store.put("me-sign", "sandbox-hmac");
  return store;
}

function testManifest(peerUrl: string): Manifest {
  return {
    ttlMs: 5_000,
    identities: [
      {
        name: "gh-token",
        secret: "gh-token",
        source: { env: "GITHUB_TOKEN" },
        plugins: ["http"],
        peers: [peerUrl],
      },
    ],
  };
}

interface TestPeer {
  readonly url: string;
  readonly seen: { authorization?: string }[];
  close(): void;
}

function openPeer(): Promise<TestPeer> {
  const seen: { authorization?: string }[] = [];
  const server = createServer((req, res) => {
    if (typeof req.headers.authorization === "string") {
      seen.push({ authorization: req.headers.authorization });
    }
    if (req.url === "/repos/acme/seal/issues") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, issues: [] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind peer"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        seen,
        close: () => server.close(),
      });
    });
  });
}
