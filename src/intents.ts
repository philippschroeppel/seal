export type PluginName = "http" | "sign" | "ssh";

export interface UseIntent {
  readonly plugin: string;
  readonly identity: string;
  readonly input: unknown;
}

export interface PutIntent {
  readonly name: string;
  readonly plugin?: string;
  readonly peers?: readonly string[];
  readonly format?: string;
}

export interface RequestIntent {
  readonly name: string;
  readonly plugin?: string;
  readonly peers?: readonly string[];
  readonly format?: string;
  readonly reason?: string;
}

export interface PendingIntent {
  readonly op: "request" | "put" | "unlock";
  readonly identity: string;
  readonly plugin?: string;
  readonly peers?: readonly string[];
  readonly format?: string;
  readonly reason?: string;
  readonly needsSecret: boolean;
}

export function formatPendingIntent(intent: PendingIntent): string {
  const plugin = intent.plugin ? ` via ${intent.plugin}` : "";
  const extra = intent.reason ? ` (${intent.reason})` : "";
  if (intent.op === "put") {
    return `store ${intent.identity}${plugin}${extra}`;
  }
  if (intent.op === "unlock") {
    return `unlock ${intent.identity}${plugin}${extra}`;
  }
  if (intent.needsSecret) {
    return `grant new ${intent.identity}${plugin}${extra}`;
  }
  return `grant ${intent.identity}${plugin}${extra}`;
}
