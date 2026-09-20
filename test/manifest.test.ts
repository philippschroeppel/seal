import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseArgs } from "../src/cli.js";
import { loadManifestFile, storeFromManifest } from "../src/manifest.js";

const cliPath = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

describe("manifest and CLI", () => {
  it("loads identities and materializes secrets", async () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-manifest-"));
    writeFileSync(
      join(dir, "manifest.json"),
      JSON.stringify({
        session: { ttlMs: 1000 },
        identities: [
          {
            name: "gh-token",
            source: { env: "GITHUB_TOKEN" },
            plugins: ["http", "github"],
            peers: ["https://api.github.com/"],
          },
        ],
      }),
    );

    const manifest = loadManifestFile(join(dir, "manifest.json"));
    expect(manifest.identities[0]?.name).toBe("gh-token");
    expect(manifest.identities[0]?.plugins).toEqual(["http", "github"]);
    expect(manifest).not.toHaveProperty("policies");

    const store = storeFromManifest(manifest, { GITHUB_TOKEN: "from-env" });
    expect(await store.use("gh-token", (value) => value)).toBe("from-env");
  });

  it("parses seal --manifest -- child", () => {
    expect(
      parseArgs([
        "--manifest",
        "permissions.json",
        "--ttl",
        "2000",
        "--passphrase",
        "secret",
        "--",
        "agent",
        "--help",
      ]),
    ).toEqual({
      manifest: "permissions.json",
      ttlMs: 2000,
      passphrase: "secret",
      command: "agent",
      args: ["--help"],
    });
  });

  it("parses --sandbox flags", () => {
    expect(
      parseArgs([
        "--manifest",
        "permissions.json",
        "--sandbox",
        "--sandbox-network",
        "host",
        "--",
        "agent",
      ]),
    ).toEqual({
      manifest: "permissions.json",
      sandbox: true,
      sandboxNetwork: "host",
      command: "agent",
      args: [],
    });
  });

  it("rejects a non-object manifest before spawning", () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-empty-"));
    const manifest = join(dir, "manifest.json");
    const marker = join(dir, "child-ran");
    writeFileSync(manifest, "[]");

    const result = runCli(dir, [
      "--manifest",
      manifest,
      "--",
      "sh",
      "-c",
      `echo ran > "${marker}"`,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("manifest must be a JSON object");
    expect(result.marker).toBe(false);
  });

  it("runs when invoked as the seal bin with an empty identity list", () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-bin-"));
    const manifest = join(dir, "manifest.json");
    const marker = join(dir, "child-ran");
    writeFileSync(manifest, JSON.stringify({ identities: [] }));

    const result = runCli(dir, [
      "--manifest",
      manifest,
      "--",
      "sh",
      "-c",
      `echo ran > "${marker}"`,
    ]);

    expect(result.status).toBe(0);
    expect(result.marker).toBe(true);
  });
});

function runCli(
  dir: string,
  args: readonly string[],
): { status: number | null; stderr: string; marker: boolean } {
  const bin = join(dir, "seal");
  symlinkSync(cliPath, bin);
  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", bin, ...args],
    { encoding: "utf8" },
  );
  return {
    status: result.status,
    stderr: result.stderr,
    marker: existsSync(join(dir, "child-ran")),
  };
}
