import { SealError } from "../errors.js";
import type { Plugin } from "../plugin.js";
import { isRecord } from "../types.js";
import { signPayload } from "../use.js";

export const signPlugin: Plugin = {
  name: "sign",
  use(secret, input, ctx) {
    if (
      !isRecord(input) ||
      typeof input.payload !== "string" ||
      typeof input.format !== "string"
    ) {
      throw new SealError(
        "bad_request",
        "sign input must be { payload, format }",
      );
    }
    const format = input.format;
    if (ctx.identity.format && ctx.identity.format !== format) {
      throw new SealError(
        "unsupported_op",
        `identity can only sign as ${ctx.identity.format}`,
      );
    }
    return { signature: signPayload(format, input.payload, secret) };
  },
};
