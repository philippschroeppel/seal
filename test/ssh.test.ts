import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { signGit, sshPublicKey } from "../examples/ssh-plugin.js";
import {
  type AgentSession,
  MemorySecretStore,
  resolveSecretPath,
  startAgentSession,
} from "../src/index.js";
import { loadManifestFile, storeFromManifest } from "../src/manifest.js";
import {
  createSshSignature,
  formatOpenSshPublicKey,
  isEncryptedOpenSshKey,
  parseOpenSshPrivateKey,
  sshKeyFingerprint,
} from "../src/ssh-key.js";

const sessions: AgentSession[] = [];

afterEach(() => {
  for (const session of sessions.splice(0)) {
    session.close();
  }
});

describe("OpenSSH keys", () => {
  it("parses an unencrypted ed25519 key and matches ssh-keygen", () => {
    const fixture = generateKey("");
    const key = parseOpenSshPrivateKey(fixture.privateKey);
    expect(key.type).toBe("ssh-ed25519");
    expect(key.encrypted).toBe(false);
    expect(formatOpenSshPublicKey(key)).toBe(fixture.publicKey);
    expect(sshKeyFingerprint(key)).toBe(fixture.fingerprint);
    expect(isEncryptedOpenSshKey(fixture.privateKey)).toBe(false);
  });

  it("unlocks an encrypted key with the key passphrase", () => {
    const fixture = generateKey("key-pass");
    expect(isEncryptedOpenSshKey(fixture.privateKey)).toBe(true);
    expect(() => parseOpenSshPrivateKey(fixture.privateKey)).toThrow(
      /requires a passphrase/,
    );
    expect(() => parseOpenSshPrivateKey(fixture.privateKey, "wrong")).toThrow(
      /did not match|inconsistent|passphrase/,
    );
    const key = parseOpenSshPrivateKey(fixture.privateKey, "key-pass");
    expect(formatOpenSshPublicKey(key)).toBe(fixture.publicKey);
  });

  it("creates an SSH signature ssh-keygen will verify", () => {
    const fixture = generateKey("");
    const key = parseOpenSshPrivateKey(fixture.privateKey);
    const payload = "hello-seal";
    const signature = createSshSignature(key, Buffer.from(payload), "git");
    expect(signature).toContain("BEGIN SSH SIGNATURE");
    expect(signature).not.toContain(fixture.privateKey);
    expect(verifySshsig(fixture, payload, signature)).toBe(true);
  });

  it("expands ~ in a file source", () => {
    expect(resolveSecretPath("~/.ssh/id_ed25519", "/tmp")).toBe(
      join(homedir(), ".ssh/id_ed25519"),
    );
    const dir = mkdtempSync(join(tmpdir(), "seal-ssh-home-"));
    const fixture = generateKey("");
    const keyPath = join(dir, "id_ed25519");
    writeFileSync(keyPath, fixture.privateKey);
    const manifestPath = join(dir, "manifest.json");
    writeFileSync(
      manifestPath,
      JSON.stringify({
        identities: [
          {
            name: "me-ssh",
            source: { file: keyPath },
            plugins: ["ssh"],
          },
        ],
      }),
    );
    const manifest = loadManifestFile(manifestPath);
    const store = storeFromManifest(manifest);
    expect(store.has("me-ssh")).toBe(true);
  });
});

describe("ssh plugin", () => {
  it("returns a public key and a git signature without the private key", async () => {
    const fixture = generateKey("");
    const session = await openSshSession(fixture.privateKey);
    const published = await sshPublicKey("me-ssh", session);
    expect(published.publicKey).toBe(fixture.publicKey);
    expect(published.fingerprint).toBe(fixture.fingerprint);
    expect(JSON.stringify(published)).not.toContain("BEGIN OPENSSH");

    const signed = await signGit("commit-payload", "me-ssh", session);
    expect(signed.namespace).toBe("git");
    expect(signed.signature).toContain("BEGIN SSH SIGNATURE");
    expect(signed.signature).not.toContain(fixture.privateKey);
    expect(verifySshsig(fixture, "commit-payload", signed.signature)).toBe(
      true,
    );
  });

  it("prompts for the key passphrase on first use of an encrypted key", async () => {
    const fixture = generateKey("key-pass");
    const asked: string[] = [];
    const store = new MemorySecretStore();
    store.put("me-ssh", fixture.privateKey);
    const session = await startAgentSession({
      store,
      passphrase: "session-pass",
      consent: async (intent) => {
        asked.push(intent.op);
        return { granted: true, passphrase: "key-pass" };
      },
      manifest: {
        ttlMs: 5_000,
        identities: [{ name: "me-ssh", secret: "me-ssh", plugins: ["ssh"] }],
      },
    });
    sessions.push(session);

    const published = await sshPublicKey("me-ssh", session);
    expect(published.publicKey).toBe(fixture.publicKey);
    expect(asked).toEqual(["unlock"]);

    await sshPublicKey("me-ssh", session);
    expect(asked).toEqual(["unlock"]);
  });

  it("refuses an encrypted key with the wrong passphrase", async () => {
    const fixture = generateKey("key-pass");
    const store = new MemorySecretStore();
    store.put("me-ssh", fixture.privateKey);
    const session = await startAgentSession({
      store,
      consent: async () => ({ granted: true, passphrase: "nope" }),
      manifest: {
        ttlMs: 5_000,
        identities: [{ name: "me-ssh", secret: "me-ssh", plugins: ["ssh"] }],
      },
    });
    sessions.push(session);

    await expect(sshPublicKey("me-ssh", session)).rejects.toMatchObject({
      code: "decrypt_failed",
    });
  });

  it("does not attach the private key to the agent", async () => {
    await expect(signGit("x")).rejects.toMatchObject({ code: "not_attached" });
  });
});

interface SshFixture {
  readonly privateKey: string;
  readonly publicKey: string;
  readonly fingerprint: string;
}

function generateKey(passphrase: string): SshFixture {
  const dir = mkdtempSync(join(tmpdir(), "seal-ssh-"));
  const file = join(dir, "id_ed25519");
  const generated = spawnSync(
    "ssh-keygen",
    ["-t", "ed25519", "-f", file, "-N", passphrase, "-C", "seal-test"],
    { encoding: "utf8" },
  );
  if (generated.status !== 0) {
    throw new Error(generated.stderr || "ssh-keygen failed");
  }
  const fingerprint = spawnSync("ssh-keygen", ["-l", "-f", `${file}.pub`], {
    encoding: "utf8",
  });
  const fp = /SHA256:[A-Za-z0-9+/]+/.exec(fingerprint.stdout)?.[0];
  if (!fp) {
    throw new Error(`could not read fingerprint: ${fingerprint.stdout}`);
  }
  return {
    privateKey: readKey(file),
    publicKey: readKey(`${file}.pub`),
    fingerprint: fp,
  };
}

function readKey(path: string): string {
  return readFileSync(path, "utf8").trimEnd();
}

function verifySshsig(
  fixture: SshFixture,
  payload: string,
  signature: string,
): boolean {
  const dir = mkdtempSync(join(tmpdir(), "seal-sshsig-"));
  const allowed = join(dir, "allowed");
  const sig = join(dir, "payload.sig");
  writeFileSync(allowed, `seal-test namespaces="git" ${fixture.publicKey}\n`);
  writeFileSync(sig, signature);
  const result = spawnSync(
    "ssh-keygen",
    ["-Y", "verify", "-f", allowed, "-I", "seal-test", "-n", "git", "-s", sig],
    { encoding: "utf8", input: payload },
  );
  return result.status === 0;
}

async function openSshSession(privateKey: string): Promise<AgentSession> {
  const store = new MemorySecretStore();
  store.put("me-ssh", privateKey);
  const session = await startAgentSession({
    store,
    manifest: {
      ttlMs: 5_000,
      identities: [{ name: "me-ssh", secret: "me-ssh", plugins: ["ssh"] }],
    },
  });
  sessions.push(session);
  return session;
}
