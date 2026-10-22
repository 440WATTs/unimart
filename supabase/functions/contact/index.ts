import { handleContact, json } from "../_shared/handlers.ts";
import { contactDeps } from "../_shared/deps.ts";

Deno.serve(async (req) => {
  try {
    return await handleContact(req, contactDeps);
  } catch {
    contactDeps.log("contact", "unhandled error");
    return json(500, { error: "unknown" });
  }
});
