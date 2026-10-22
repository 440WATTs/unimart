import { handleDeleteAccount, json } from "../_shared/handlers.ts";
import { accountDeps } from "../_shared/deps.ts";

Deno.serve(async (req) => {
  try {
    return await handleDeleteAccount(req, accountDeps);
  } catch {
    accountDeps.log("account.delete", "unhandled error");
    return json(500, { error: "deletion_failed" });
  }
});
