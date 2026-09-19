import { type ErrorCode, SealError } from "./errors.js";
import { ENV } from "./protocol.js";
import type { SessionToken } from "./types.js";

export interface AgentConnection {
  readonly url: string;
  readonly token: SessionToken;
}

export interface HttpRequest {
  readonly identity: string;
  readonly method: string;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

export interface SignRequest {
  readonly identity: string;
  readonly payload: string;
  readonly format: string;
}

export interface SignResponse {
  readonly signature: string;
}

export interface SessionCapabilities {
  readonly session: string;
  readonly ops: readonly string[];
  readonly identities: readonly {
    readonly name: string;
    readonly ops: readonly string[];
    readonly approve: string;
    readonly peers?: readonly string[];
    readonly formats?: readonly string[];
  }[];
  readonly openapi: string;
}

export const agent = {
  http: postHttp,
  sign: postSign,
  capabilities: getCapabilities,
  openapi: getOpenApi,
};

export function postHttp(
  request: HttpRequest,
  connection?: AgentConnection,
): Promise<HttpResponse> {
  return call("/v1/http", {
    method: "POST",
    body: request,
    connection,
    parse: (raw) => {
      if (
        !isRecord(raw) ||
        typeof raw.status !== "number" ||
        typeof raw.body !== "string" ||
        !isRecord(raw.headers)
      ) {
        throw new SealError("protocol", "malformed http response");
      }
      return {
        status: raw.status,
        headers: Object.fromEntries(
          Object.entries(raw.headers).filter(
            (entry): entry is [string, string] => typeof entry[1] === "string",
          ),
        ),
        body: raw.body,
      };
    },
  });
}

export function postSign(
  request: SignRequest,
  connection?: AgentConnection,
): Promise<SignResponse> {
  return call("/v1/sign", {
    method: "POST",
    body: request,
    connection,
    parse: (raw) => {
      if (!isRecord(raw) || typeof raw.signature !== "string") {
        throw new SealError("protocol", "malformed sign response");
      }
      return { signature: raw.signature };
    },
  });
}

export function getCapabilities(
  connection?: AgentConnection,
): Promise<SessionCapabilities> {
  return call("/v1/capabilities", {
    method: "GET",
    connection,
    parse: (raw) => {
      if (
        !isRecord(raw) ||
        typeof raw.session !== "string" ||
        !Array.isArray(raw.ops) ||
        !Array.isArray(raw.identities) ||
        typeof raw.openapi !== "string"
      ) {
        throw new SealError("protocol", "malformed capabilities response");
      }
      return {
        session: raw.session,
        ops: raw.ops.filter((item): item is string => typeof item === "string"),
        identities: raw.identities.flatMap((item) => {
          if (
            !isRecord(item) ||
            typeof item.name !== "string" ||
            !Array.isArray(item.ops) ||
            typeof item.approve !== "string"
          ) {
            return [];
          }
          return [
            {
              name: item.name,
              ops: item.ops.filter(
                (op): op is string => typeof op === "string",
              ),
              approve: item.approve,
              ...(Array.isArray(item.peers)
                ? {
                    peers: item.peers.filter(
                      (peer): peer is string => typeof peer === "string",
                    ),
                  }
                : {}),
              ...(Array.isArray(item.formats)
                ? {
                    formats: item.formats.filter(
                      (format): format is string => typeof format === "string",
                    ),
                  }
                : {}),
            },
          ];
        }),
        openapi: raw.openapi,
      };
    },
  });
}

export function getOpenApi(connection?: AgentConnection): Promise<unknown> {
  return call("/v1/openapi.json", {
    method: "GET",
    connection,
    parse: (raw) => raw,
  });
}

async function call<T>(
  path: string,
  options: {
    method: "GET" | "POST";
    body?: unknown;
    connection?: AgentConnection | undefined;
    parse: (raw: Record<string, unknown>) => T;
  },
): Promise<T> {
  const url = options.connection?.url ?? process.env[ENV.url];
  const token = options.connection?.token ?? process.env[ENV.token];
  if (!url || !token) {
    throw new SealError(
      "not_attached",
      "not running under seal (no SEAL_URL/SEAL_TOKEN in env)",
    );
  }

  let response: Response;
  try {
    response = await fetch(`${url}${path}`, {
      method: options.method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(options.body === undefined
          ? {}
          : { "content-type": "application/json" }),
      },
      ...(options.body === undefined
        ? {}
        : { body: JSON.stringify(options.body) }),
    });
  } catch (error) {
    throw new SealError(
      "protocol",
      error instanceof Error ? error.message : "request failed",
    );
  }

  let raw: unknown;
  try {
    raw = await response.json();
  } catch {
    throw new SealError("protocol", "expected a JSON response");
  }
  if (!isRecord(raw)) {
    throw new SealError("protocol", "expected a JSON object");
  }
  if (raw.ok === false) {
    throw new SealError(
      typeof raw.error === "string" ? (raw.error as ErrorCode) : "protocol",
      typeof raw.message === "string" ? raw.message : "request failed",
    );
  }
  return options.parse(raw);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
