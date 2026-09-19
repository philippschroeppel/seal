export const OPENAPI_DOCUMENT = {
  openapi: "3.1.0",
  info: {
    title: "Seal agent API",
    version: "1.0.0",
    description:
      "Authorized loopback surface for a Seal agent session. The child may propose HTTP and sign intents; it never receives credential bytes.",
  },
  servers: [{ url: "/", description: "Session loopback" }],
  paths: {
    "/v1/capabilities": {
      get: {
        summary: "What this session may do",
        security: [{ sessionToken: [] }],
        responses: {
          "200": {
            description: "Identities, ops, and a pointer to this document",
          },
        },
      },
    },
    "/v1/http": {
      post: {
        summary:
          "Seal performs an HTTP request and attaches the bound identity",
        security: [{ sessionToken: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["identity", "method", "url"],
                properties: {
                  identity: { type: "string" },
                  method: { type: "string" },
                  url: { type: "string" },
                  headers: {
                    type: "object",
                    additionalProperties: { type: "string" },
                  },
                  body: {},
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Peer status, headers, and body" },
          "403": { description: "Denied; no key material" },
        },
      },
    },
    "/v1/sign": {
      post: {
        summary: "Seal signs a payload with a signing identity",
        security: [{ sessionToken: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["identity", "payload", "format"],
                properties: {
                  identity: { type: "string" },
                  payload: { type: "string" },
                  format: { type: "string" },
                },
              },
            },
          },
        },
        responses: {
          "200": { description: "Hex signature" },
          "403": {
            description: "Denied or approval required; no key material",
          },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      sessionToken: {
        type: "http",
        scheme: "bearer",
      },
    },
  },
} as const;
