import type { ErrorCode } from "./errors.js";
import type { SecretName, SessionToken } from "./types.js";

/** Environment variables the broker injects into a child process. */
export const ENV = {
  socket: "SEAL_SOCK",
  token: "SEAL_TOKEN",
  url: "SEAL_URL",
} as const;

export interface DecryptRequest {
  readonly token: SessionToken;
  readonly name: SecretName;
}

export type DecryptResponse =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly error: ErrorCode; readonly message: string };

export function encodeLine(value: unknown): string {
  return `${JSON.stringify(value)}\n`;
}

export function createLineReader(
  onLine: (line: string) => void,
): (chunk: Buffer) => void {
  let buffer = "";
  return (chunk: Buffer) => {
    buffer += chunk.toString("utf8");
    let idx = buffer.indexOf("\n");
    while (idx >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      onLine(line);
      idx = buffer.indexOf("\n");
    }
  };
}

export function parseDecryptRequest(line: string): DecryptRequest {
  const raw: unknown = JSON.parse(line);
  if (
    !isRecord(raw) ||
    typeof raw.token !== "string" ||
    typeof raw.name !== "string"
  ) {
    throw new SyntaxError("request must be { token, name }");
  }
  return { token: raw.token, name: raw.name };
}

export function parseDecryptResponse(line: string): DecryptResponse {
  const raw: unknown = JSON.parse(line);
  if (!isRecord(raw) || typeof raw.ok !== "boolean") {
    throw new SyntaxError("response must include ok");
  }
  if (raw.ok === true) {
    if (typeof raw.value !== "string") {
      throw new SyntaxError("ok response must include value");
    }
    return { ok: true, value: raw.value };
  }
  if (typeof raw.error !== "string" || typeof raw.message !== "string") {
    throw new SyntaxError("error response must include error and message");
  }
  return { ok: false, error: raw.error as ErrorCode, message: raw.message };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
