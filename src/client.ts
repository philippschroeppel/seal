import { createConnection } from "node:net";
import { SealError } from "./errors.js";
import {
  createLineReader,
  encodeLine,
  ENV,
  parseDecryptResponse,
  type DecryptRequest,
} from "./protocol.js";
import type { ClientConnection, SecretName } from "./types.js";

/**
 * Ask the parent broker for one granted secret. A cooperating child calls
 * this; it never receives a DEK or the broker's unsealing key.
 */
export function getSecret(name: SecretName, connection?: ClientConnection): Promise<string> {
  const socketPath = connection?.socketPath ?? process.env[ENV.socket];
  const token = connection?.token ?? process.env[ENV.token];
  if (!socketPath || !token) {
    return Promise.reject(
      new SealError("not_attached", "not running under seal (no socket/token in env)"),
    );
  }

  const request: DecryptRequest = { token, name };

  return new Promise((resolve, reject) => {
    let settled = false;
    const conn = createConnection(socketPath, () => {
      conn.write(encodeLine(request));
    });

    const finish = (error: unknown, value?: string) => {
      if (settled) {
        return;
      }
      settled = true;
      conn.end();
      if (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      } else {
        resolve(value ?? "");
      }
    };

    conn.on(
      "data",
      createLineReader((line) => {
        try {
          const response = parseDecryptResponse(line);
          if (response.ok) {
            finish(undefined, response.value);
          } else {
            finish(new SealError(response.error, response.message));
          }
        } catch (error) {
          finish(new SealError("protocol", error instanceof Error ? error.message : "bad response"));
        }
      }),
    );

    conn.on("error", (error) => finish(error));
    conn.on("end", () => {
      finish(new SealError("protocol", "connection closed before a response"));
    });
  });
}
