/**
 * Edge Function handlers (supabase/functions) run against the real migrations
 * in PGlite: the database calls they make are executed as the service role,
 * exactly as in production. Deno wiring (index.ts, _shared/deps.ts) is not
 * exercised here.
 *
 *   npm run test:functions
 */
import { PGlite } from "@electric-sql/pglite";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { before, beforeEach, describe, it } from "node:test";
import {
  type AccountDeps, type ContactDeps, type Deps, handleContact, handleDeleteAccount, handleVerification, hmacHex, randomCode,
} from "../../supabase/functions/_shared/handlers";

type Who = string | "anon" | "service";

/** Same setup as tests/db/schema.test.ts: Supabase stub + every migration. */
async function openDb() {
  const root = process.cwd();
  const db = new PGlite({ extensions: { pg_trgm } });
  await db.exec(readFileSync(join(root, "tests/db/supabase-stub.sql"), "utf8"));
  const dir = join(root, "supabase/migrations");
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(readFileSync(join(dir, f), "utf8"));
  }
  async function as<T = Record<string, unknown>>(who: Who, sql: string, params: unknown[] = []) {
    return db.transaction(async (tx) => {
      if (who === "anon" || who === "service") {
        await tx.query("select set_config('request.jwt.claim.sub', '', true)");
        await tx.query(`set local role ${who === "anon" ? "anon" : "service_role"}`);
      } else {
        await tx.query("select set_config('request.jwt.claim.sub', $1, true)", [who]);
        await tx.query("set local role authenticated");
      }
      return (await tx.query<T>(sql, params)).rows;
    });
  }
  /** Calls a function with named arguments, like supabase-js rpc(). */
  async function rpc(who: Who, fn: string, params: Record<string, unknown>) {
    const names = Object.keys(params);
    const args = names.map((n, i) => `${n} => $${i + 1}`).join(", ");
    try {
      const rows = await as<{ r: unknown }>(who, `select public.${fn}(${args}) as r`, names.map((n) => params[n]));
      return { data: rows[0]?.r ?? null, error: null };
    } catch (e) {
      return { data: null, error: { message: (e as Error).message } };
    }
  }
  return { db, as, rpc };
}

async function addUser(db: PGlite, id: string, name: string) {
  await db.query("insert into auth.users (id, email, raw_user_meta_data) values ($1, $2, $3)", [
    id, `${id.slice(-4)}@example.com`, JSON.stringify({ full_name: name }),
  ]);
}

const A = "00000000-0000-4000-8000-0000000000a1"; // regular member
const B = "00000000-0000-4000-8000-0000000000b2"; // second member
const ADMIN = "00000000-0000-4000-8000-0000000000d4";
const SECRET = "test-secret-not-for-production";

let api: Awaited<ReturnType<typeof openDb>>;
const outbox: { to: string; subject: string; text: string }[] = [];
const logs: string[] = [];

function baseDeps(): Deps {
  return {
    async getUser(authorization) {
      const id = authorization?.match(/^Bearer (.+)$/)?.[1];
      return id && [A, B, ADMIN].includes(id) ? { id, email: null } : null;
    },
    rpc: (fn, params) => api.rpc("service", fn, params),
    async allow(key, max, windowSeconds) {
      const r = await api.rpc("service", "rate_limit_hit", { p_key: key, p_max: max, p_window: `${windowSeconds} seconds` });
      return r.data === true;
    },
    async sendEmail(m) {
      outbox.push(m);
      return { sent: true };
    },
    env: (n) => (n === "VERIFICATION_CODE_SECRET" ? SECRET : undefined),
    log: (scope, message) => void logs.push(`${scope}: ${message}`),
  };
}

const post = (body: unknown, user?: string, ip = "203.0.113.7") =>
  new Request("https://fn.example/x", {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": `${ip}, 10.0.0.1`, ...(user ? { authorization: `Bearer ${user}` } : {}) },
    body: JSON.stringify(body),
  });

const read = async (r: Response) => ({ status: r.status, body: (await r.json()) as Record<string, unknown> });

before(async () => {
  api = await openDb();
  await addUser(api.db, A, "Asha Member");
  await addUser(api.db, B, "Bilal Member");
  await addUser(api.db, ADMIN, "Dev Admin");
  await api.db.query("insert into public.user_roles (user_id, role) values ($1, 'admin')", [ADMIN]);
});

beforeEach(async () => {
  outbox.length = 0;
  await api.db.query("delete from public.rate_limit_events");
});

describe("code helpers", () => {
  it("hashes exactly like the web server action", async () => {
    const expected = createHmac("sha256", SECRET).update(`${A}:123456`).digest("hex");
    assert.equal(await hmacHex(SECRET, `${A}:123456`), expected);
  });

  it("generates 6-digit codes", () => {
    for (let i = 0; i < 200; i++) assert.match(randomCode(), /^\d{6}$/);
  });
});

describe("institute-verification", () => {
  it("requires a signed-in user and valid input", async () => {
    assert.equal((await handleVerification(post({ action: "request", institute_id: "nit-sikkim", email: "a@nitsikkim.ac.in" }), baseDeps())).status, 401);
    assert.equal((await handleVerification(post({ action: "request", institute_id: "../x", email: "a@x.in" }, A), baseDeps())).status, 400);
    assert.equal((await handleVerification(post({ action: "request", institute_id: "nit-sikkim", email: "nope" }, A), baseDeps())).status, 422);
    assert.equal((await handleVerification(new Request("https://fn.example/x", { method: "GET" }), baseDeps())).status, 400);
  });

  it("refuses unconfirmed domains, as the database decides", async () => {
    const r = await read(await handleVerification(post({ action: "request", institute_id: "nit-sikkim", email: "a1@nitsikkim.ac.in" }, A), baseDeps()));
    assert.deepEqual(r, { status: 400, body: { error: "email_domain_not_accepted" } });
    assert.equal(outbox.length, 0);
  });

  it("emails a code and verifies the member with it", async () => {
    await api.db.query("update public.institutes set email_domains_confirmed = true where id = 'nit-sikkim'");
    const req = await read(await handleVerification(post({ action: "request", institute_id: "nit-sikkim", email: " Asha@NITSikkim.ac.in " }, A), baseDeps()));
    assert.deepEqual(req, { status: 200, body: { status: "sent", to: "asha@nitsikkim.ac.in" } });
    assert.match(outbox[0].subject, /^Your UniMart verification code: \d{6}$/);
    const code = outbox[0].subject.match(/(\d{6})$/)![1];
    assert.ok(outbox[0].text.includes(code));

    const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
    assert.deepEqual(await read(await handleVerification(post({ action: "confirm", institute_id: "nit-sikkim", code: wrong }, A), baseDeps())),
      { status: 400, body: { error: "invalid_code" } });
    // B can't use A's code: the hash includes the user id.
    assert.equal((await handleVerification(post({ action: "confirm", institute_id: "nit-sikkim", code }, B), baseDeps())).status, 400);

    const ok = await read(await handleVerification(post({ action: "confirm", institute_id: "nit-sikkim", code: `${code.slice(0, 3)} ${code.slice(3)}` }, A), baseDeps()));
    assert.deepEqual(ok, { status: 200, body: { status: "verified" } });
    const m = await api.as<{ status: string }>("service", "select status from institute_memberships where user_id = $1", [A]);
    assert.equal(m[0].status, "verified");
  });

  it("stops after five wrong attempts", async () => {
    await handleVerification(post({ action: "request", institute_id: "nit-sikkim", email: "bilal@nitsikkim.ac.in" }, B), baseDeps());
    const code = outbox.at(-1)!.subject.match(/(\d{6})$/)![1];
    const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");
    for (let i = 0; i < 5; i++) await handleVerification(post({ action: "confirm", institute_id: "nit-sikkim", code: wrong }, B), baseDeps());
    const r = await read(await handleVerification(post({ action: "confirm", institute_id: "nit-sikkim", code }, B), baseDeps()));
    assert.deepEqual(r, { status: 429, body: { error: "too_many_attempts" } });
  });

  it("rate-limits code requests per IP", async () => {
    let last = 0;
    for (let i = 0; i < 16; i++) {
      last = (await handleVerification(post({ action: "request", institute_id: "nit-sikkim", email: `x${i}@gmail.com` }, B, "198.51.100.9"), baseDeps())).status;
    }
    assert.equal(last, 429);
  });

  it("reports a missing secret as a server error, without leaking it", async () => {
    const deps = { ...baseDeps(), env: () => undefined };
    assert.deepEqual(await read(await handleVerification(post({ action: "confirm", institute_id: "nit-sikkim", code: "123456" }, A), deps)),
      { status: 500, body: { error: "server_misconfigured" } });
  });
});

describe("delete-account", () => {
  const removed: string[] = [];
  const deleted: string[] = [];
  const accountDeps = (): AccountDeps => ({
    ...baseDeps(),
    async isAdmin(id) {
      const r = await api.as<{ n: number }>("service", "select count(*)::int n from user_roles where user_id = $1 and role = 'admin'", [id]);
      return r[0].n > 0;
    },
    async listObjects(_bucket, prefix) {
      if (prefix === A) return [{ name: "listing-1", isFolder: true }, { name: "avatar-1.jpg", isFolder: false }];
      if (prefix === `${A}/listing-1`) return [{ name: "p1.jpg", isFolder: false }, { name: "p2.jpg", isFolder: false }];
      return [];
    },
    async removeObjects(bucket, paths) {
      removed.push(...paths.map((p) => `${bucket}:${p}`));
    },
    async deleteAuthUser(id) {
      deleted.push(id);
      return { error: null };
    },
  });

  it("requires the typed confirmation", async () => {
    assert.deepEqual(await read(await handleDeleteAccount(post({ confirm: "delete" }, A), accountDeps())),
      { status: 422, body: { error: "confirmation_required" } });
    assert.equal((await handleDeleteAccount(post({ confirm: "DELETE" }), accountDeps())).status, 401);
  });

  it("refuses administrators", async () => {
    assert.deepEqual(await read(await handleDeleteAccount(post({ confirm: "DELETE" }, ADMIN), accountDeps())),
      { status: 409, body: { error: "admin_must_transfer" } });
    assert.equal(deleted.length, 0);
  });

  it("takes listings off sale, removes files and deletes the user", async () => {
    // A is verified (previous suite); give them a live listing.
    await api.as(A, `insert into listings (institute_id, kind, title, description, category_id, price_paise, condition, status)
                     values ('nit-sikkim', 'wanted', 'Need a drafter', 'For the ED lab next week.', 'study', null, null, 'active')`);
    const r = await read(await handleDeleteAccount(post({ confirm: "DELETE" }, A), accountDeps()));
    assert.deepEqual(r, { status: 200, body: { status: "deleted" } });
    const live = await api.as<{ n: number }>("service", "select count(*)::int n from listings where seller_id = $1 and status = 'active'", [A]);
    assert.equal(live[0].n, 0);
    assert.ok(removed.includes(`listing-images:${A}/listing-1/p1.jpg`));
    assert.ok(removed.includes(`avatars:${A}/avatar-1.jpg`));
    assert.deepEqual(deleted, [A]);
  });
});

describe("contact", () => {
  const rows: unknown[] = [];
  const contactDeps = (): ContactDeps => ({
    ...baseDeps(),
    async insertContact(row) {
      // Same insert the service role performs in production.
      await api.as("service", "insert into contact_messages (name, email, subject, body, user_id) values ($1, $2, $3, $4, $5)",
        [row.name, row.email, row.subject, row.body, row.user_id]);
      rows.push(row);
      return { error: null };
    },
  });
  const msg = { name: "Visitor", email: "v@example.com", subject: "Hello", body: "Is UniMart open to staff?" };

  it("accepts a visitor's message and links a signed-in user", async () => {
    assert.equal((await handleContact(post(msg), contactDeps())).status, 200);
    assert.equal((await handleContact(post(msg, B), contactDeps())).status, 200);
    const r = await api.as<{ user_id: string | null }>("service", "select user_id from contact_messages order by created_at");
    assert.deepEqual(r.map((x) => x.user_id), [null, B]);
  });

  it("silently drops honeypot submissions and validates fields", async () => {
    const before = rows.length;
    assert.equal((await handleContact(post({ ...msg, website: "http://spam" }), contactDeps())).status, 200);
    assert.equal(rows.length, before);
    assert.equal((await handleContact(post({ ...msg, body: "short" }), contactDeps())).status, 422);
  });

  it("limits each IP to five messages an hour", async () => {
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await handleContact(post(msg, undefined, "192.0.2.44"), contactDeps())).status);
    assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429]);
  });

  it("visitors still can't insert directly (only this function can)", async () => {
    await assert.rejects(api.as("anon", "insert into contact_messages (name, email, subject, body) values ('a','a@b.co','s','long enough body')"),
      /permission denied/);
  });
});
