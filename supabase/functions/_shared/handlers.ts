/**
 * Logic for the Edge Functions used by native clients (the UniKart iOS app). Kept free of Deno- and
 * npm-specific imports so it runs unchanged in Deno (production) and Node
 * (tests/functions). Each handler receives its dependencies explicitly.
 *
 * Behaviour mirrors the web app's server actions
 * (src/app/(site)/account/actions.ts and contact/actions.ts) so both clients
 * produce identical database state; in particular the verification code hash
 * is HMAC-SHA256(secret, `${userId}:${code}`) as hex, exactly as on the web.
 */

export type Json = Record<string, unknown>;

export interface AuthedUser {
  id: string;
  email: string | null;
}

export interface Deps {
  /** Validates the caller's JWT with Supabase Auth; null when missing or invalid. */
  getUser(authorization: string | null): Promise<AuthedUser | null>;
  /** Calls a database function with the service role. */
  rpc(fn: string, params: Json): Promise<{ data: unknown; error: { message: string } | null }>;
  /** Database-backed limiter (rate_limit_hit). Must fail closed. */
  allow(key: string, max: number, windowSeconds: number): Promise<boolean>;
  sendEmail(msg: { to: string; subject: string; text: string }): Promise<{ sent: boolean; devLogged?: boolean; error?: string }>;
  env(name: string): string | undefined;
  /** Logs without personal data. */
  log(scope: string, message: string, extra?: Json): void;
}

export interface AccountDeps extends Deps {
  isAdmin(userId: string): Promise<boolean>;
  /** Lists object names directly under `prefix` (folders have no id). */
  listObjects(bucket: string, prefix: string): Promise<{ name: string; isFolder: boolean }[]>;
  removeObjects(bucket: string, paths: string[]): Promise<void>;
  deleteAuthUser(userId: string): Promise<{ error: string | null }>;
}

export interface ContactDeps extends Deps {
  insertContact(row: { name: string; email: string; subject: string; body: string; user_id: string | null }): Promise<{ error: string | null }>;
}

export const json = (status: number, body: Json) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });

const fail = (status: number, code: string) => json(status, { error: code });

/** First address in x-forwarded-for as set by the Supabase gateway. */
export function clientIp(req: Request) {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || req.headers.get("x-real-ip")?.trim() || "unknown";
}

async function readJson(req: Request, maxBytes = 16_384): Promise<Json | null> {
  if (req.method !== "POST") return null;
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > maxBytes) return null;
  const text = await req.text();
  if (text.length > maxBytes) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Json) : null;
  } catch {
    return null;
  }
}

const str = (v: unknown) => (typeof v === "string" ? v : "");

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export async function hmacHex(secret: string, message: string) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(message)));
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Uniform 6-digit code from a CSPRNG (rejection sampling avoids modulo bias). */
export function randomCode() {
  const buf = new Uint32Array(1);
  const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return String(buf[0] % 1_000_000).padStart(6, "0");
  }
}

/** Database errors raised by membership functions that may be shown to the user. */
const MEMBERSHIP_CODES = [
  "too_many_codes_for_email", "too_many_codes", "institute_not_available", "email_domain_not_accepted",
  "email_already_used", "already_verified", "membership_revoked", "rate_limited",
];
const knownCode = (message: string | undefined) => MEMBERSHIP_CODES.find((c) => message?.includes(c));

// ---------------------------------------------------------------------------
// POST institute-verification  { action: "request", institute_id, email }
//                              { action: "confirm", institute_id, code }
// ---------------------------------------------------------------------------
export async function handleVerification(req: Request, deps: Deps): Promise<Response> {
  const body = await readJson(req);
  if (!body) return fail(400, "invalid_input");
  const user = await deps.getUser(req.headers.get("authorization"));
  if (!user) return fail(401, "not_authenticated");
  const secret = deps.env("VERIFICATION_CODE_SECRET");
  if (!secret) {
    deps.log("verification", "VERIFICATION_CODE_SECRET is not set");
    return fail(500, "server_misconfigured");
  }
  const instituteId = str(body.institute_id);
  if (!/^[a-z0-9-]{2,40}$/.test(instituteId)) return fail(400, "invalid_input");
  const ip = clientIp(req);

  if (body.action === "request") {
    const email = str(body.email).trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 254) return fail(422, "invalid_input");
    if (!(await deps.allow(`code:ip:${ip}`, 15, 3600))) return fail(429, "rate_limited");
    const code = randomCode();
    const { error } = await deps.rpc("membership_request_email_code", {
      p_user: user.id,
      p_institute: instituteId,
      p_email: email,
      p_code_hash: await hmacHex(secret, `${user.id}:${code}`),
    });
    if (error) {
      const known = knownCode(error.message);
      if (!known) deps.log("verification.request", "rpc failed");
      return fail(known === "rate_limited" || known?.startsWith("too_many") ? 429 : 400, known ?? "unknown");
    }
    // Product name is configurable until the UniMart / UniKart naming is settled.
    const appName = deps.env("APP_NAME") ?? "UniMart";
    const sent = await deps.sendEmail({
      to: email,
      subject: `Your ${appName} verification code: ${code}`,
      text: `Your code to verify your institute membership on ${appName} is ${code}.\n\nIt expires in 15 minutes. If you didn't request this, you can ignore this email.`,
    });
    if (sent.devLogged) return json(200, { status: "dev_logged" });
    if (!sent.sent) return fail(503, sent.error ?? "email_send_failed");
    return json(200, { status: "sent", to: email });
  }

  if (body.action === "confirm") {
    const code = str(body.code).replace(/\D/g, "");
    if (code.length !== 6) return fail(422, "invalid_input");
    if (!(await deps.allow(`confirm:ip:${ip}`, 30, 3600))) return fail(429, "rate_limited");
    const { data, error } = await deps.rpc("membership_confirm_email_code", {
      p_user: user.id,
      p_institute: instituteId,
      p_code_hash: await hmacHex(secret, `${user.id}:${code}`),
    });
    if (error) {
      deps.log("verification.confirm", "rpc failed");
      return fail(500, "unknown");
    }
    switch (data) {
      case "verified":
      case "already_verified":
        return json(200, { status: data });
      case "invalid":
        return fail(400, "invalid_code");
      case "expired":
        return fail(400, "code_expired");
      case "too_many_attempts":
        return fail(429, "too_many_attempts");
      case "no_request":
        return fail(400, "no_request");
      default:
        return fail(500, "unknown");
    }
  }
  return fail(400, "invalid_input");
}

// ---------------------------------------------------------------------------
// POST delete-account  { confirm: "DELETE" }
// ---------------------------------------------------------------------------
export async function handleDeleteAccount(req: Request, deps: AccountDeps): Promise<Response> {
  const body = await readJson(req);
  if (!body) return fail(400, "invalid_input");
  const user = await deps.getUser(req.headers.get("authorization"));
  if (!user) return fail(401, "not_authenticated");
  if (str(body.confirm).trim() !== "DELETE") return fail(422, "confirmation_required");
  if (!(await deps.allow(`delete:user:${user.id}`, 5, 3600))) return fail(429, "rate_limited");
  if (await deps.isAdmin(user.id)) return fail(409, "admin_must_transfer");

  const prep = await deps.rpc("prepare_account_deletion", { p_user: user.id });
  if (prep.error) {
    deps.log("account.delete", "prepare failed");
    return fail(500, "deletion_failed");
  }
  // Uploaded files: listing photos (<uid>/<listing>/<photo>) and avatars (<uid>/avatar-*.jpg).
  for (const bucket of ["listing-images", "avatars"]) {
    try {
      const top = await deps.listObjects(bucket, user.id);
      const files = top.filter((o) => !o.isFolder).map((o) => `${user.id}/${o.name}`);
      for (const folder of top.filter((o) => o.isFolder)) {
        const inner = await deps.listObjects(bucket, `${user.id}/${folder.name}`);
        files.push(...inner.filter((o) => !o.isFolder).map((o) => `${user.id}/${folder.name}/${o.name}`));
      }
      for (let i = 0; i < files.length; i += 100) await deps.removeObjects(bucket, files.slice(i, i + 100));
    } catch {
      // Deletion continues; leftover files are covered by the orphan cleanup described in docs/DEPLOYMENT.md (not yet scheduled).
      deps.log("account.delete", "storage cleanup failed", { bucket });
    }
  }
  const { error } = await deps.deleteAuthUser(user.id);
  if (error) {
    deps.log("account.delete", "auth delete failed");
    return fail(500, "deletion_failed");
  }
  return json(200, { status: "deleted" });
}

// ---------------------------------------------------------------------------
// POST contact  { name, email, subject, body, website? }   (signed in or not)
// ---------------------------------------------------------------------------
export async function handleContact(req: Request, deps: ContactDeps): Promise<Response> {
  const body = await readJson(req);
  if (!body) return fail(400, "invalid_input");
  const ok = json(200, { status: "sent" });
  if (str(body.website)) return ok; // honeypot: bots fill every field
  const name = str(body.name).trim();
  const email = str(body.email).trim();
  const subject = str(body.subject).trim();
  const text = str(body.body).trim();
  if (
    name.length < 1 || name.length > 120 || !EMAIL_RE.test(email) || email.length > 200 ||
    subject.length < 1 || subject.length > 160 || text.length < 10 || text.length > 4000
  ) {
    return fail(422, "invalid_input");
  }
  const ip = clientIp(req);
  if (!(await deps.allow(`contact:ip:${ip}`, 5, 3600)) || !(await deps.allow("contact:global", 300, 3600))) {
    return fail(429, "rate_limited");
  }
  const user = await deps.getUser(req.headers.get("authorization"));
  const { error } = await deps.insertContact({ name, email, subject, body: text, user_id: user?.id ?? null });
  if (error) {
    deps.log("contact", "insert failed");
    return fail(500, "unknown");
  }
  return ok;
}
