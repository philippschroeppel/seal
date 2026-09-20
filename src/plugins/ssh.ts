import { wipe } from "../bytes.js";
import { SealError } from "../errors.js";
import type { Plugin } from "../plugin.js";
import {
  createSshSignature,
  formatOpenSshPublicKey,
  parseOpenSshPrivateKey,
  sshKeyFingerprint,
} from "../ssh-key.js";
import { isRecord } from "../types.js";

export const sshPlugin: Plugin = {
  name: "ssh",
  use(secret, input, ctx) {
    const request = parseSshInput(input);
    const key = parseOpenSshPrivateKey(secret, ctx.passphrase);
    try {
      if (request.op === "publicKey") {
        return {
          publicKey: formatOpenSshPublicKey(key),
          type: key.type,
          comment: key.comment,
          fingerprint: sshKeyFingerprint(key),
        };
      }
      return {
        signature: createSshSignature(key, request.payload, request.namespace),
        namespace: request.namespace,
      };
    } finally {
      wipe(key.secretSeed);
    }
  },
};

function parseSshInput(
  input: unknown,
):
  | { op: "publicKey" }
  | { op: "sign"; payload: Uint8Array; namespace: string } {
  if (!isRecord(input)) {
    throw new SealError("bad_request", "ssh input must be an object");
  }
  if (input.op === "publicKey") {
    return { op: "publicKey" };
  }
  if (input.op !== undefined && input.op !== "sign") {
    throw new SealError(
      "bad_request",
      'ssh input op must be "sign" or "publicKey"',
    );
  }
  if (typeof input.payload !== "string") {
    throw new SealError("bad_request", "ssh sign input must include payload");
  }
  return {
    op: "sign",
    payload: decodePayload(input.payload, input.encoding),
    namespace: typeof input.namespace === "string" ? input.namespace : "git",
  };
}

function decodePayload(payload: string, encoding: unknown): Uint8Array {
  if (encoding === undefined || encoding === "utf8") {
    return new TextEncoder().encode(payload);
  }
  if (encoding === "hex") {
    return Uint8Array.from(Buffer.from(payload, "hex"));
  }
  if (encoding === "base64") {
    return Uint8Array.from(Buffer.from(payload, "base64"));
  }
  throw new SealError(
    "bad_request",
    "ssh payload encoding must be utf8, hex, or base64",
  );
}
