// node --test: the Worker's logic against an in-memory KV and a fake fetch.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker, { check, heartbeat, SILENT_AFTER_MS, REPEAT_MS } from "../src/index.js";

let sent;
let env;

beforeEach(() => {
  sent = [];
  const kv = new Map();
  env = {
    WATCHDOG: { get: async (k) => kv.get(k) ?? null, put: async (k, v) => void kv.set(k, v) },
    WATCHDOG_TOKEN: "secret-token",
    CF_EMAIL_TOKEN: "cf-token",
    ACCOUNT_ID: "acct",
    ALERT_FROM: "alerts@example.com",
    ALERT_TO: "a@example.com, b@example.com",
  };
  globalThis.fetch = async (url, init) => {
    sent.push({ url, auth: init.headers.Authorization, body: JSON.parse(init.body) });
    return { ok: true, status: 200 };
  };
});

const post = (token, path = "/heartbeat") =>
  worker.fetch(
    new Request(`https://w.example${path}`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }),
    env,
  );

test("rejects a heartbeat without the token", async () => {
  assert.equal((await post(null)).status, 401);
  assert.equal((await post("wrong")).status, 401);
  assert.equal(await check(env, Date.now()), "unarmed");
});

test("404s anything but POST /heartbeat", async () => {
  assert.equal((await post("secret-token", "/")).status, 404);
});

test("a fresh heartbeat is quiet", async () => {
  assert.equal((await post("secret-token")).status, 204);
  assert.equal(await check(env, Date.now() + 60_000), "ok");
  assert.equal(sent.length, 0);
});

test("silence emails every recipient, once per repeat window", async () => {
  const t0 = 1_000_000_000_000;
  await heartbeat(env, t0);
  assert.equal(await check(env, t0 + SILENT_AFTER_MS - 1), "ok");
  assert.equal(await check(env, t0 + SILENT_AFTER_MS + 1), "alerted");
  assert.deepEqual(sent.map((s) => s.body.to).sort(), ["a@example.com", "b@example.com"]);
  for (const s of sent) {
    assert.equal(s.url, "https://api.cloudflare.com/client/v4/accounts/acct/email/sending/send");
    assert.equal(s.auth, "Bearer cf-token");
    assert.equal(s.body.from, "alerts@example.com");
    assert.match(s.body.subject, /^\[FIRING\] .*silent/);
  }
  assert.equal(await check(env, t0 + SILENT_AFTER_MS + 30 * 60_000), "already-alerted");
  assert.equal(sent.length, 2);
  assert.equal(await check(env, t0 + SILENT_AFTER_MS + REPEAT_MS + 2), "alerted");
  assert.equal(sent.length, 4);
});

test("a heartbeat after silence sends a recovery email and re-arms", async () => {
  const t0 = 1_000_000_000_000;
  await heartbeat(env, t0);
  await check(env, t0 + SILENT_AFTER_MS + 1);
  sent = [];
  await heartbeat(env, t0 + SILENT_AFTER_MS + 5 * 60_000);
  assert.equal(sent.length, 2);
  assert.match(sent[0].body.subject, /^\[RESOLVED\]/);
  sent = [];
  await heartbeat(env, t0 + SILENT_AFTER_MS + 10 * 60_000);
  assert.equal(sent.length, 0, "no second recovery email");
});

test("a failed email is an error (so the cron invocation shows as failed)", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 403 });
  await heartbeat(env, 0);
  await assert.rejects(check(env, SILENT_AFTER_MS + 1), /HTTP 403/);
});
