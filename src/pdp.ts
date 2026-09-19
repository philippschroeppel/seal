import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type {
  AuthorizationAnswer,
  AuthorizationCall,
  CheckParseAnswer,
  Entities,
  ValidationAnswer,
} from "@cedar-policy/cedar-wasm/nodejs";
import { SEAL_SCHEMA } from "./schema.js";

export interface AuthorizationContext {
  readonly url?: string;
  readonly method?: string;
  readonly format?: string;
  readonly userApproved: boolean;
}

export interface DecisionRequest {
  readonly sessionId: string;
  readonly action: "Http" | "Sign";
  readonly identity: string;
  readonly context: AuthorizationContext;
}

export interface PolicyDecisionPoint {
  isAllowed(request: DecisionRequest): boolean;
}

interface CedarBindings {
  isAuthorized(call: AuthorizationCall): AuthorizationAnswer;
  checkParsePolicySet(policies: { staticPolicies: string }): CheckParseAnswer;
  checkParseSchema(schema: string): CheckParseAnswer;
  validate(call: {
    schema: string;
    policies: { staticPolicies: string };
  }): ValidationAnswer;
}

let cedarPromise: Promise<CedarBindings> | undefined;

export async function loadCedar(): Promise<CedarBindings> {
  cedarPromise ??= importCedar();
  return cedarPromise;
}

export async function createCedarPdp(options: {
  readonly policies: string;
  readonly schema?: string;
  readonly identities: readonly string[];
  readonly sessionId: string;
}): Promise<PolicyDecisionPoint> {
  const cedar = await loadCedar();
  const schema = options.schema ?? SEAL_SCHEMA;
  const policies = { staticPolicies: options.policies };

  const schemaParse = cedar.checkParseSchema(schema);
  if (schemaParse.type === "failure") {
    throw new Error(
      `Cedar schema is invalid: ${formatErrors(schemaParse.errors)}`,
    );
  }

  const policyParse = cedar.checkParsePolicySet(policies);
  if (policyParse.type === "failure") {
    throw new Error(
      `Cedar policies are invalid: ${formatErrors(policyParse.errors)}`,
    );
  }

  const validated = cedar.validate({ schema, policies });
  if (validated.type === "failure") {
    throw new Error(
      `Cedar validation failed: ${formatErrors(validated.errors)}`,
    );
  }
  if (validated.validationErrors.length > 0) {
    throw new Error(
      `Cedar validation failed: ${validated.validationErrors
        .map((item) => item.error.message)
        .join("; ")}`,
    );
  }

  const entities = buildEntities(options.sessionId, options.identities);

  return {
    isAllowed(request) {
      const result = cedar.isAuthorized({
        principal: { type: "Seal::Agent", id: request.sessionId },
        action: { type: "Seal::Action", id: request.action },
        resource: { type: "Seal::Identity", id: request.identity },
        context: contextFor(request),
        schema,
        validateRequest: true,
        policies,
        entities,
      });
      if (result.type !== "success") {
        return false;
      }
      return result.response.decision === "allow";
    },
  };
}

function contextFor(
  request: DecisionRequest,
): Record<string, string | boolean> {
  if (request.action === "Http") {
    return {
      url: request.context.url ?? "",
      method: request.context.method ?? "",
      userApproved: request.context.userApproved,
    };
  }
  return {
    format: request.context.format ?? "",
    userApproved: request.context.userApproved,
  };
}

function buildEntities(
  sessionId: string,
  identities: readonly string[],
): Entities {
  return [
    { uid: { type: "Seal::Agent", id: sessionId }, attrs: {}, parents: [] },
    ...identities.map((id) => ({
      uid: { type: "Seal::Identity", id },
      attrs: {},
      parents: [],
    })),
  ];
}

function formatErrors(errors: readonly { message: string }[]): string {
  return errors.map((error) => error.message).join("; ");
}

async function importCedar(): Promise<CedarBindings> {
  try {
    return await import("@cedar-policy/cedar-wasm/nodejs");
  } catch {
    const web = await import("@cedar-policy/cedar-wasm/web");
    const require = createRequire(import.meta.url);
    const wasmPath = require.resolve(
      "@cedar-policy/cedar-wasm/web/cedar_wasm_bg.wasm",
    );
    web.initSync({ module: readFileSync(wasmPath) });
    return web;
  }
}
