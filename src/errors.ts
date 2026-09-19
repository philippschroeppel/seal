export const errorCodes = [
  "not_attached",
  "bad_request",
  "unauthorized",
  "grant_expired",
  "not_granted",
  "decrypt_failed",
  "protocol",
  "unknown_secret",
  "forbidden",
  "approval_required",
  "unsupported_op",
  "peer_failed",
] as const;

export type ErrorCode = (typeof errorCodes)[number];

export class SealError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "SealError";
    this.code = code;
  }
}

export function isSealError(error: unknown): error is SealError {
  return error instanceof SealError;
}
