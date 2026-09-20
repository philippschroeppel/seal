import { request as httpRequest } from "node:http";
import { type ErrorCode, SealError } from "./errors.js";
import type {
  CheckIntent,
  CheckResult,
  HttpIntent,
  SessionCapabilities,
  SignIntent,
} from "./intents.js";
import { ENV } from "./protocol.js";
import { isRecord, type SessionToken } from "./types.js";

export type {
  CheckIntent,
  CheckResult,
  HttpIntent,
  SessionCapabilities,
  SignIntent,
} from "./intents.js";

export interface AgentConnection {
  readonly url: string;
  readonly token: SessionToken;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

export interface SignResponse {
  readonly signature: string;
}

export const agent = {
  http: postHttp,
  sign: postSign,
  check: postCheck,
  capabilities: getCapabilities,
  openapi: getOpenApi,
};

export function postHttp(
  request: HttpIntent,
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
  request: SignIntent,
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

export function postCheck(
  request: CheckIntent,
  connection?: AgentConnection,
): Promise<CheckResult> {
  return call("/v1/check", {
    method: "POST",
    body: request,
    connection,
    parse: (raw) => {
      if (!isRecord(raw) || typeof raw.allowed !== "boolean") {
        throw new SealError("protocol", "malformed check response");
      }
      if (raw.allowed) {
        return { allowed: true };
      }
      if (raw.reason !== "forbidden" && raw.reason !== "approval_required") {
        throw new SealError("protocol", "malformed check response");
      }
      return { allowed: false, reason: raw.reason };
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

  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
    ...(options.body === undefined
      ? {}
      : { "content-type": "application/json" }),
  };
  const payload =
    options.body === undefined ? undefined : JSON.stringify(options.body);

  let raw: unknown;
  try {
    raw = await requestSeal(url, path, {
      method: options.method,
      headers,
      ...(payload === undefined ? {} : { body: payload }),
    });
  } catch (error) {
    throw new SealError(
      "protocol",
      error instanceof Error ? error.message : "request failed",
    );
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

function requestSeal(
  url: string,
  path: string,
  options: {
    method: "GET" | "POST";
    headers: Record<string, string>;
    body?: string;
  },
): Promise<unknown> {
  const unix = unixSocketPath(url);
  if (!unix) {
    return fetchJson(`${url}${path}`, options);
  }
  return unixJson(unix, path, options);
}

function unixSocketPath(url: string): string | undefined {
  if (!url.startsWith("unix://")) {
    return undefined;
  }
  const path = url.slice("unix://".length);
  return path.startsWith("/") ? path : `/${path}`;
}

async function fetchJson(
  url: string,
  options: {
    method: "GET" | "POST";
    headers: Record<string, string>;
    body?: string;
  },
): Promise<unknown> {
  const response = await fetch(url, {
    method: options.method,
    headers: options.headers,
    ...(options.body === undefined ? {} : { body: options.body }),
  });
  try {
    return await response.json();
  } catch {
    throw new SealError("protocol", "expected a JSON response");
  }
}

function unixJson(
  socketPath: string,
  path: string,
  options: {
    method: "GET" | "POST";
    headers: Record<string, string>;
    body?: string;
  },
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        socketPath,
        path,
        method: options.method,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
        });
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            reject(new SealError("protocol", "expected a JSON response"));
          }
        });
      },
    );
    req.on("error", reject);
    if (options.body !== undefined) {
      req.write(options.body);
    }
    req.end();
  });
}
