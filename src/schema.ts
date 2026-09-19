/** Bundled Cedar schema for Seal agent sessions. Policies stay in `.cedar` files. */
export const SEAL_SCHEMA = `
namespace Seal {
  entity Agent;
  entity Identity;

  action Http appliesTo {
    principal: Agent,
    resource: Identity,
    context: {
      url: String,
      method: String,
      userApproved: Bool
    }
  };

  action Sign appliesTo {
    principal: Agent,
    resource: Identity,
    context: {
      format: String,
      userApproved: Bool
    }
  };
}
`.trim();
