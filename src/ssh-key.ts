import { createRequire } from "node:module";
import { ctr } from "@noble/ciphers/aes.js";
import { bytesToHex } from "@noble/ciphers/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8Decode, utf8Encode, wipe } from "./bytes.js";
import { SealError } from "./errors.js";

const require = createRequire(import.meta.url);
const { pbkdf } = require("bcrypt-pbkdf") as {
  pbkdf: (
    pass: Uint8Array,
    passlen: number,
    salt: Uint8Array,
    saltlen: number,
    key: Uint8Array,
    keylen: number,
    rounds: number,
  ) => number;
};

const OPENSSH_MAGIC = utf8Encode("openssh-key-v1\0");
const SSHSIG_MAGIC = utf8Encode("SSHSIG");
const BEGIN_PRIVATE = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END_PRIVATE = "-----END OPENSSH PRIVATE KEY-----";
const BEGIN_SIG = "-----BEGIN SSH SIGNATURE-----";
const END_SIG = "-----END SSH SIGNATURE-----";

export interface OpenSshEd25519Key {
  readonly type: "ssh-ed25519";
  readonly comment: string;
  readonly publicKey: Uint8Array;
  readonly secretSeed: Uint8Array;
  readonly encrypted: boolean;
}

export function isOpenSshPrivateKey(value: string): boolean {
  return value.includes(BEGIN_PRIVATE);
}

export function isEncryptedOpenSshKey(value: string): boolean {
  if (!isOpenSshPrivateKey(value)) {
    return false;
  }
  const header = readOpenSshHeader(
    decodePem(value, BEGIN_PRIVATE, END_PRIVATE),
  );
  return header.cipher !== "none";
}

export function parseOpenSshPrivateKey(
  pem: string,
  passphrase?: string,
): OpenSshEd25519Key {
  const blob = decodePem(pem, BEGIN_PRIVATE, END_PRIVATE);
  const header = readOpenSshHeader(blob);
  const privateBlob = decryptPrivate(
    header,
    passphrase,
    blob.subarray(header.privateOffset),
  );
  try {
    return parseEd25519Private(privateBlob, header.cipher !== "none");
  } finally {
    wipe(privateBlob);
  }
}

export function formatOpenSshPublicKey(key: OpenSshEd25519Key): string {
  const line = `ssh-ed25519 ${Buffer.from(encodeSshPublicKey(key.publicKey)).toString("base64")}`;
  return key.comment ? `${line} ${key.comment}` : line;
}

export function sshKeyFingerprint(key: OpenSshEd25519Key): string {
  const digest = sha256(encodeSshPublicKey(key.publicKey));
  return `SHA256:${Buffer.from(digest).toString("base64").replace(/=+$/, "")}`;
}

export function createSshSignature(
  key: OpenSshEd25519Key,
  payload: Uint8Array,
  namespace: string,
): string {
  const hashAlg = "sha512";
  const digest = sha512(payload);
  const signed = concatBytes(
    SSHSIG_MAGIC,
    encodeSshString(utf8Encode(namespace)),
    encodeSshString(new Uint8Array()),
    encodeSshString(utf8Encode(hashAlg)),
    encodeSshString(digest),
  );
  const raw = ed25519.sign(signed, key.secretSeed);
  const publicBlob = encodeSshPublicKey(key.publicKey);
  const signatureBlob = concatBytes(
    encodeSshString(utf8Encode("ssh-ed25519")),
    encodeSshString(raw),
  );
  const block = concatBytes(
    SSHSIG_MAGIC,
    encodeUint32(1),
    encodeSshString(publicBlob),
    encodeSshString(utf8Encode(namespace)),
    encodeSshString(new Uint8Array()),
    encodeSshString(utf8Encode(hashAlg)),
    encodeSshString(signatureBlob),
  );
  return armor(BEGIN_SIG, END_SIG, block);
}

interface OpenSshHeader {
  readonly cipher: string;
  readonly kdf: string;
  readonly salt?: Uint8Array;
  readonly rounds?: number;
  readonly publicBlob: Uint8Array;
  readonly privateOffset: number;
}

function readOpenSshHeader(blob: Uint8Array): OpenSshHeader {
  const reader = new Reader(blob);
  const magic = reader.bytes(OPENSSH_MAGIC.length);
  if (!bytesEqual(magic, OPENSSH_MAGIC)) {
    throw new SealError("bad_request", "not an OpenSSH private key");
  }
  const cipher = utf8Decode(reader.sshString());
  const kdf = utf8Decode(reader.sshString());
  const kdfOptions = reader.sshString();
  const keyCount = reader.uint32();
  if (keyCount !== 1) {
    throw new SealError(
      "unsupported_op",
      "only single-key OpenSSH files are supported",
    );
  }
  const publicBlob = reader.sshString();
  if (cipher === "none" && kdf === "none") {
    return { cipher, kdf, publicBlob, privateOffset: reader.offset };
  }
  if (cipher !== "aes256-ctr" || kdf !== "bcrypt") {
    throw new SealError(
      "unsupported_op",
      `unsupported OpenSSH protection (${cipher}/${kdf})`,
    );
  }
  const kdfReader = new Reader(kdfOptions);
  const salt = kdfReader.sshString();
  const rounds = kdfReader.uint32();
  return {
    cipher,
    kdf,
    salt,
    rounds,
    publicBlob,
    privateOffset: reader.offset,
  };
}

function decryptPrivate(
  header: OpenSshHeader,
  passphrase: string | undefined,
  remainder: Uint8Array,
): Uint8Array {
  const reader = new Reader(remainder);
  const encrypted = reader.sshString();
  if (header.cipher === "none") {
    return encrypted.slice();
  }
  if (!passphrase) {
    throw new SealError(
      "approval_required",
      "encrypted SSH key requires a passphrase",
    );
  }
  if (header.salt === undefined || header.rounds === undefined) {
    throw new SealError(
      "decrypt_failed",
      "encrypted SSH key is missing KDF parameters",
    );
  }
  const pass = utf8Encode(passphrase);
  const derived = new Uint8Array(32 + 16);
  try {
    const status = pbkdf(
      pass,
      pass.length,
      header.salt,
      header.salt.length,
      derived,
      derived.length,
      header.rounds,
    );
    if (status !== 0) {
      throw new SealError(
        "decrypt_failed",
        "failed to derive SSH key passphrase",
      );
    }
    const key = derived.subarray(0, 32);
    const iv = derived.subarray(32, 48);
    return ctr(key, iv).decrypt(encrypted);
  } finally {
    wipe(pass);
    wipe(derived);
  }
}

function parseEd25519Private(
  privateBlob: Uint8Array,
  encrypted: boolean,
): OpenSshEd25519Key {
  const reader = new Reader(privateBlob);
  const check1 = reader.uint32();
  const check2 = reader.uint32();
  if (check1 !== check2) {
    throw new SealError("decrypt_failed", "SSH key passphrase did not match");
  }
  const type = utf8Decode(reader.sshString());
  if (type !== "ssh-ed25519") {
    throw new SealError(
      "unsupported_op",
      `ssh plugin supports ed25519 keys only (got ${type})`,
    );
  }
  const publicKey = reader.sshString();
  const secret = reader.sshString();
  const comment = utf8Decode(reader.sshString());
  if (publicKey.length !== 32 || secret.length < 32) {
    throw new SealError("bad_request", "invalid ed25519 OpenSSH key");
  }
  const secretSeed = secret.subarray(0, 32).slice();
  const derivedPub = ed25519.getPublicKey(secretSeed);
  if (bytesToHex(derivedPub) !== bytesToHex(publicKey)) {
    throw new SealError("decrypt_failed", "SSH key material is inconsistent");
  }
  return {
    type: "ssh-ed25519",
    comment,
    publicKey: publicKey.slice(),
    secretSeed,
    encrypted,
  };
}

function decodePem(pem: string, begin: string, end: string): Uint8Array {
  const start = pem.indexOf(begin);
  const stop = pem.indexOf(end);
  if (start < 0 || stop < 0 || stop <= start) {
    throw new SealError("bad_request", "malformed PEM");
  }
  const body = pem.slice(start + begin.length, stop).replace(/\s+/g, "");
  return Uint8Array.from(Buffer.from(body, "base64"));
}

function armor(begin: string, end: string, bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString("base64");
  const lines = b64.match(/.{1,70}/g) ?? [b64];
  return `${begin}\n${lines.join("\n")}\n${end}\n`;
}

function encodeSshPublicKey(publicKey: Uint8Array): Uint8Array {
  return concatBytes(
    encodeSshString(utf8Encode("ssh-ed25519")),
    encodeSshString(publicKey),
  );
}

function encodeSshString(payload: Uint8Array): Uint8Array {
  return concatBytes(encodeUint32(payload.length), payload);
}

function encodeUint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < left.length; index += 1) {
    diff |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return diff === 0;
}

class Reader {
  offset = 0;

  constructor(private readonly buf: Uint8Array) {}

  uint32(): number {
    if (this.offset + 4 > this.buf.length) {
      throw new SealError("bad_request", "truncated OpenSSH key");
    }
    const value = new DataView(
      this.buf.buffer,
      this.buf.byteOffset + this.offset,
      4,
    ).getUint32(0);
    this.offset += 4;
    return value;
  }

  bytes(length: number): Uint8Array {
    if (this.offset + length > this.buf.length) {
      throw new SealError("bad_request", "truncated OpenSSH key");
    }
    const slice = this.buf.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  sshString(): Uint8Array {
    return this.bytes(this.uint32());
  }
}
