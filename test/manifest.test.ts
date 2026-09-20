import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseArgs } from "../src/cli.js";
import { loadManifestFile, storeFromManifest } from "../src/manifest.js";
import { generateKeyPair } from "../src/seal.js";

const cliPath = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

describe("manifest and CLI", () => {
  it("loads Cedar from a sibling file and materializes secrets", () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-manifest-"));
    writeFileSync(
      join(dir, "policies.cedar"),
      `permit (principal, action, resource);`,
    );
    writeFileSync(
      join(dir, "manifest.json"),
      JSON.stringify({
        session: { ttlMs: 1000 },
        policies: "./policies.cedar",
        identities: [
          {
            name: "gh-token",
            source: { env: "GITHUB_TOKEN" },
            attach: { type: "bearer" },
            peers: ["https://api.github.com/"],
          },
        ],
      }),
    );

    const manifest = loadManifestFile(join(dir, "manifest.json"));
    expect(manifest.policies).toContain("permit");
    expect(manifest.identities[0]?.name).toBe("gh-token");

    const store = storeFromManifest(manifest, { GITHUB_TOKEN: "from-env" });
    const grantId = "g1";
    store.issueGrant(grantId, ["gh-token"], generateKeyPair().publicKey, 1000);
    expect(store.fetchGrant(grantId)?.entries).toHaveLength(1);
  });

  it("parses seal --manifest -- child", () => {
    expect(
      parseArgs([
        "--manifest",
        "permissions.json",
        "--ttl",
        "2000",
        "--",
        "agent",
        "--help",
      ]),
    ).toEqual({
      manifest: "permissions.json",
      ttlMs: 2000,
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

  it("rejects an empty JSON manifest before spawning", () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-empty-"));
    const manifest = join(dir, "manifest.json");
    const marker = join(dir, "child-ran");
    writeFileSync(manifest, "{}");

    const result = runCli(dir, [
      "--manifest",
      manifest,
      "--",
      "sh",
      "-c",
      `echo ran > "${marker}"`,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("manifest must include a policies string");
    expect(result.marker).toBe(false);
  });

  it("runs when invoked as the seal bin and refuses empty identities", () => {
    const dir = mkdtempSync(join(tmpdir(), "seal-bin-"));
    const manifest = join(dir, "manifest.json");
    const marker = join(dir, "child-ran");
    writeFileSync(
      manifest,
      JSON.stringify({
        policies: "permit (principal, action, resource);",
        identities: [],
      }),
    );

    const result = runCli(dir, [
      "--manifest",
      manifest,
      "--",
      "sh",
      "-c",
      `echo ran > "${marker}"`,
    ]);

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("manifest identities must not be empty");
    expect(result.marker).toBe(false);
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
