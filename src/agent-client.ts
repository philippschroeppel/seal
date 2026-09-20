import { request as httpRequest } from "node:http";
import { type ErrorCode, SealError } from "./errors.js";
import type { PutIntent, RequestIntent, UseIntent } from "./intents.js";
import { ENV } from "./protocol.js";
import { isRecord, type SessionToken } from "./types.js";

export type { PutIntent, RequestIntent, UseIntent } from "./intents.js";

export interface AgentConnection {
  readonly url: string;
  readonly token: SessionToken;
}

export interface PutResult {
  readonly name: string;
}

export interface RequestResult {
  readonly granted: true;
  readonly name: string;
}

export const agent = {
  use: postUse,
  put: postPut,
  request: postRequest,
};

export function postUse<T = unknown>(
  request: UseIntent,
  connection?: AgentConnection,
): Promise<T> {
  return call("/v1/use", {
    method: "POST",
    body: request,
    connection,
    parse: (raw) => raw.result as T,
  });
}

export function postPut(
  request: PutIntent,
  connection?: AgentConnection,
): Promise<PutResult> {
  return call("/v1/put", {
    method: "POST",
    body: request,
    connection,
    parse: (raw) => {
      if (typeof raw.name !== "string") {
        throw new SealError("protocol", "malformed put response");
      }
      return { name: raw.name };
    },
  });
}

export function postRequest(
  request: RequestIntent,
  connection?: AgentConnection,
): Promise<RequestResult> {
  return call("/v1/request", {
    method: "POST",
    body: request,
    connection,
    parse: (raw) => {
      if (raw.granted !== true || typeof raw.name !== "string") {
        throw new SealError("protocol", "malformed request response");
      }
      return { granted: true, name: raw.name };
    },
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
