permit (
  principal is Seal::Agent,
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
  principal is Seal::Agent,
  action == Seal::Action::"Sign",
  resource == Seal::Identity::"me-sign"
) when {
  context.userApproved == true
};
