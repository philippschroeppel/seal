import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseArgs } from "../src/cli.js";
import { loadManifestFile, storeFromManifest } from "../src/manifest.js";
import { generateKeyPair } from "../src/seal.js";

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
});
