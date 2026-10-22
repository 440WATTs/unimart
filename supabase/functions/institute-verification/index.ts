import { handleVerification, json } from "../_shared/handlers.ts";
import { verificationDeps } from "../_shared/deps.ts";

Deno.serve(async (req) => {
  try {
    return await handleVerification(req, verificationDeps);
  } catch {
    verificationDeps.log("verification", "unhandled error");
    return json(500, { error: "unknown" });
  }
});
