import { getSecret } from "../src/client.js";
import { isSealError } from "../src/errors.js";

const name = process.argv[2];
if (!name) {
  process.stderr.write("usage: probe <secret-name>\n");
  process.exit(2);
}

try {
  const value = await getSecret(name);
  process.stdout.write(`${JSON.stringify({ ok: true, value })}\n`);
} catch (error) {
  const payload = isSealError(error)
    ? { ok: false, error: error.code, message: error.message }
    : { ok: false, message: error instanceof Error ? error.message : String(error) };
  process.stdout.write(`${JSON.stringify(payload)}\n`);
  process.exitCode = 1;
}
