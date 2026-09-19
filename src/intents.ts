export interface HttpIntent {
  readonly identity: string;
  readonly method: string;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface SignIntent {
  readonly identity: string;
  readonly payload: string;
  readonly format: string;
}

export interface CheckIntent {
  readonly op: "http" | "sign";
  readonly identity: string;
  readonly method?: string;
  readonly url?: string;
  readonly format?: string;
}

export interface CheckResult {
  readonly allowed: boolean;
  readonly reason?: "forbidden" | "approval_required";
}

export interface PendingIntent {
  readonly op: "http" | "sign";
  readonly identity: string;
  readonly method?: string;
  readonly url?: string;
  readonly format?: string;
  readonly payloadPreview?: string;
}

export interface SessionCapabilities {
  readonly session: string;
  readonly ops: readonly string[];
  readonly identities: readonly CapabilityIdentity[];
  readonly openapi: string;
}

export interface CapabilityIdentity {
  readonly name: string;
  readonly ops: readonly string[];
  readonly approve: string;
  readonly peers?: readonly string[];
  readonly formats?: readonly string[];
}

export function formatPendingIntent(intent: PendingIntent): string {
  if (intent.op === "http") {
    return `${intent.method ?? ""} ${intent.url ?? ""}`.trim();
  }
  const payload = intent.payloadPreview ? ` ${intent.payloadPreview}` : "";
  return `${intent.format ?? ""}${payload}`.trim();
}
