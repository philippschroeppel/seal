import { describe, expect, it } from "vitest";
import { createPullRequest, signCommit } from "../examples/github-plugin.js";

describe("github plugin", () => {
  it("only talks to Seal HTTP and never asks for plaintext", async () => {
    await expect(
      createPullRequest("philippschroeppel/seal", {
        title: "demo",
        head: "feature",
        base: "main",
      }),
    ).rejects.toMatchObject({ code: "not_attached" });

    await expect(signCommit("abc123")).rejects.toMatchObject({
      code: "not_attached",
    });
  });
});
