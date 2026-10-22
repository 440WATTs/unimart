// Production wiring for the handlers (Deno runtime on Supabase Edge Functions).
import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.58.0";
import type { AccountDeps, AuthedUser, ContactDeps, Deps, Json } from "./handlers.ts";

function env(name: string) {
  return Deno.env.get(name) ?? undefined;
}

let admin: SupabaseClient | null = null;
/** Service-role client. The key exists only in the function's environment. */
function adminClient() {
  if (!admin) {
    const url = env("SUPABASE_URL");
    const key = env("SUPABASE_SERVICE_ROLE_KEY");
    if (!url || !key) throw new Error("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are not set");
    admin = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
  }
  return admin;
}

function log(scope: string, message: string, extra: Json = {}) {
  // Structured, no personal data: callers pass only scopes and fixed messages.
  console.error(JSON.stringify({ level: "error", scope, message, ...extra }));
}

async function getUser(authorization: string | null): Promise<AuthedUser | null> {
  const token = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
  if (!token) return null;
  const { data, error } = await adminClient().auth.getUser(token);
  if (error || !data.user) return null;
  return { id: data.user.id, email: data.user.email ?? null };
}

async function sendEmail({ to, subject, text }: { to: string; subject: string; text: string }) {
  const key = env("RESEND_API_KEY");
  const from = env("EMAIL_FROM");
  if (key && from) {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, subject, text }),
    });
    if (!res.ok) {
      log("email", "provider error", { status: res.status });
      return { sent: false, error: "email_send_failed" };
    }
    return { sent: true };
  }
  if (env("UNIKART_ALLOW_DEV_EMAIL_LOG") === "true") {
    console.info(`[email:dev] To: ${to}\nSubject: ${subject}\n\n${text}`);
    return { sent: false, devLogged: true };
  }
  return { sent: false, error: "email_not_configured" };
}

const base: Deps = {
  getUser,
  env,
  log,
  sendEmail,
  async rpc(fn, params) {
    const { data, error } = await adminClient().rpc(fn, params);
    return { data, error: error ? { message: error.message } : null };
  },
  async allow(key, max, windowSeconds) {
    try {
      const { data, error } = await adminClient().rpc("rate_limit_hit", {
        p_key: key, p_max: max, p_window: `${windowSeconds} seconds`,
      });
      if (error) throw error;
      return data === true;
    } catch {
      log("rate-limit", "limiter unavailable", { key: key.split(":")[0] });
      return false; // fail closed
    }
  },
};

export const verificationDeps: Deps = base;

export const accountDeps: AccountDeps = {
  ...base,
  async isAdmin(userId) {
    const { data, error } = await adminClient().from("user_roles").select("role").eq("user_id", userId).eq("role", "admin");
    if (error) throw error;
    return (data ?? []).length > 0;
  },
  async listObjects(bucket, prefix) {
    const { data, error } = await adminClient().storage.from(bucket).list(prefix, { limit: 1000 });
    if (error) throw error;
    return (data ?? []).map((o) => ({ name: o.name, isFolder: !o.id }));
  },
  async removeObjects(bucket, paths) {
    const { error } = await adminClient().storage.from(bucket).remove(paths);
    if (error) throw error;
  },
  async deleteAuthUser(userId) {
    const { error } = await adminClient().auth.admin.deleteUser(userId);
    return { error: error?.message ?? null };
  },
};

export const contactDeps: ContactDeps = {
  ...base,
  async insertContact(row) {
    const { error } = await adminClient().from("contact_messages").insert(row);
    return { error: error?.message ?? null };
  },
};
