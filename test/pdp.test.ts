import { describe, expect, it } from "vitest";
import { createCedarPdp } from "../src/pdp.js";

const policies = `
permit (
  principal == Seal::Agent::"session-1",
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "https://api.github.com/repos/philippschroeppel/seal/*"
  && ["GET", "POST"].contains(context.method)
};

forbid (
  principal,
  action == Seal::Action::"Http",
  resource == Seal::Identity::"gh-token"
) when {
  context.url like "https://api.github.com/user/keys*"
};

permit (
  principal == Seal::Agent::"session-1",
  action == Seal::Action::"Sign",
  resource == Seal::Identity::"me-sign"
) when {
  context.userApproved == true
};
`;

describe("Cedar PDP", () => {
  it("allows an in-policy GitHub HTTP use and forbids key listing", async () => {
    const pdp = await createCedarPdp({
      policies,
      identities: ["gh-token", "me-sign"],
      sessionId: "session-1",
    });

    expect(
      pdp.isAllowed({
        sessionId: "session-1",
        action: "Http",
        identity: "gh-token",
        context: {
          url: "https://api.github.com/repos/philippschroeppel/seal/issues",
          method: "GET",
          userApproved: false,
        },
      }),
    ).toBe(true);

    expect(
      pdp.isAllowed({
        sessionId: "session-1",
        action: "Http",
        identity: "gh-token",
        context: {
          url: "https://api.github.com/user/keys",
          method: "GET",
          userApproved: false,
        },
      }),
    ).toBe(false);
  });

  it("requires human approval for sign", async () => {
    const pdp = await createCedarPdp({
      policies,
      identities: ["gh-token", "me-sign"],
      sessionId: "session-1",
    });

    expect(
      pdp.isAllowed({
        sessionId: "session-1",
        action: "Sign",
        identity: "me-sign",
        context: { format: "hmac-sha256", userApproved: false },
      }),
    ).toBe(false);

    expect(
      pdp.isAllowed({
        sessionId: "session-1",
        action: "Sign",
        identity: "me-sign",
        context: { format: "hmac-sha256", userApproved: true },
      }),
    ).toBe(true);
  });
});
