// node --test: POST /event, the audit trail, against an in-memory KV, an R2 stub that
// can only be written, and a fake fetch for the email API.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker, {
  checkPendingRec,
  checkTangProbe,
  event,
  MAX_BODY,
  REC_GRACE_MS,
  SILENT_AFTER_MS,
  REPEAT_MS,
} from "../src/index.js";

let sent;
let stored;
let reads;
let env;
let kv;

const T0 = 1_000_000_000_000;

beforeEach(() => {
  sent = [];
  stored = [];
  reads = [];
  kv = new Map();
  env = {
    WATCHDOG: {
      get: async (k) => kv.get(k) ?? null,
      put: async (k, v) => void kv.set(k, v),
      delete: async (k) => void kv.delete(k),
      list: async ({ prefix }) => ({ keys: [...kv.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })) }),
    },
    // Write-only: any read, list or delete of the trail is a failure of the test.
    AUDIT: {
      put: async (k, v) => void stored.push({ key: k, value: JSON.parse(v) }),
      get: async (k) => void reads.push(["get", k]),
      head: async (k) => void reads.push(["head", k]),
      list: async (o) => void reads.push(["list", o]),
      delete: async (k) => void reads.push(["delete", k]),
    },
    AUDIT_TOKENS: JSON.stringify({
      "tok-node1": { sender: "node1", kinds: ["boot", "deploy", "ssh_login", "canary", "nomad_acl"] },
      "tok-node2": { sender: "node2", kinds: ["boot", "deploy", "ssh_login", "canary"] },
      "tok-tang": { sender: "tang", kinds: ["tang_rec", "tang_probe"] },
    }),
    TANG_CLIENTS: JSON.stringify({ "10.40.0.11": "node1", "10.40.0.12": "node2" }),
    CLUSTER_NAME: "test-cluster",
    CF_EMAIL_TOKEN: "cf-token",
    ACCOUNT_ID: "acct",
    ALERT_FROM: "alerts@example.com",
    ALERT_TO: "a@example.com",
  };
  globalThis.fetch = async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    return { ok: true, status: 200 };
  };
});

const req = (path, { method = "POST", token, body } = {}) =>
  worker.fetch(
    new Request(`https://w.example${path}`, {
      method,
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: method === "GET" || method === "HEAD" ? undefined : body,
    }),
    env,
  );
const post = (token, ev) => req("/event", { token, body: typeof ev === "string" ? ev : JSON.stringify(ev) });

const boot = (over = {}) => ({
  kind: "boot",
  node: "node1",
  boot_id: "0b8a0c2e-1111-4222-8333-444455556666",
  unlock: "clevis",
  clevis_devices: 2,
  expected_devices: 2,
  initrd_ssh_logins: 0,
  secure_boot: 1,
  setup_mode: 0,
  pcr7: "a".repeat(64),
  generation: 7,
  toplevel: "abcdefghijklmnopqrstuvwxyz012345",
  initrd_ms: 9000,
  at: 1700000000,
  ...over,
});
const rec = (over = {}) => ({ kind: "tang_rec", ip: "10.40.0.11", kid: "kid1", status: 200, at: 1700000000, ...over });
const subjects = () => sent.map((s) => s.body.subject);

test("no token and a wrong token are refused, and nothing is stored", async () => {
  assert.equal((await post(null, boot())).status, 401);
  assert.equal((await post("tok-wrong", boot())).status, 401);
  assert.equal((await post("tok-node1x", boot())).status, 401);
  // The heartbeat's token is not an audit token.
  env.WATCHDOG_TOKEN = "hb";
  assert.equal((await post("hb", boot())).status, 401);
  assert.equal(stored.length, 0);
  assert.equal(sent.length, 0);
});

test("a client-data shaped field is refused", async () => {
  for (const extra of [
    { message: "Accepted publickey for root" },
    { path: "/mnt/jfs/clients/acme/invoice.pdf" },
    { body: "SELECT * FROM customers" },
    { __proto__: null, constructor: "x" },
  ]) {
    const r = await post("tok-node1", { ...boot(), ...extra });
    assert.equal(r.status, 422, JSON.stringify(extra));
    assert.match(await r.text(), /field not allowed/);
  }
  // A value that is not the shape its field allows: free text in an ID field.
  const r = await post("tok-node1", { kind: "ssh_login", node: "node1", user: "root", from: "192.0.2.1", key: "SHA256:x y", at: 1 });
  assert.equal(r.status, 422);
  assert.match(await r.text(), /bad value: key/);
  // A field left out, an unknown kind, a kind that is an Object.prototype name, not an object.
  const { pcr7, ...noPcr } = boot();
  assert.match(await (await post("tok-node1", noPcr)).text(), /missing field: pcr7/);
  assert.equal((await post("tok-node1", { kind: "exfil", node: "node1" })).status, 422);
  assert.equal((await post("tok-node1", { kind: "constructor" })).status, 422);
  assert.equal((await post("tok-node1", { kind: "toString" })).status, 422);
  assert.equal((await post("tok-node1", "[1,2]")).status, 422);
  assert.equal((await post("tok-node1", "null")).status, 422);
  assert.equal((await post("tok-node1", "{not json")).status, 400);
  assert.equal(stored.length, 0);
});

test("an oversized body is refused before it is parsed", async () => {
  const r = await post("tok-node1", JSON.stringify(boot()) + " ".repeat(MAX_BODY));
  assert.equal(r.status, 413);
  assert.equal(stored.length, 0);
});

test("a node cannot speak for another node, or send Tang's kinds", async () => {
  assert.equal((await post("tok-node2", boot({ node: "node1" }))).status, 403);
  assert.equal((await post("tok-node2", rec())).status, 403);
  assert.equal((await post("tok-node2", { kind: "tang_probe" })).status, 403);
  // node2 is not the leader: no Nomad ACL events from it.
  const acl = { kind: "nomad_acl", node: "node2", topic: "ACLToken", type: "ACLTokenUpserted", accessor: "a", name: "n", at: 1 };
  assert.equal((await post("tok-node2", acl)).status, 403);
  // And Tang cannot send a boot report for a node.
  assert.equal((await post("tok-tang", boot())).status, 403);
  assert.equal(stored.length, 0);
  // Its own events go through, attributed to the token's sender.
  assert.equal((await post("tok-node2", boot({ node: "node2" }))).status, 204);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].value.sender, "node2");
});

test("no read or delete path exists", async () => {
  assert.equal((await post("tok-node1", boot())).status, 204);
  const key = stored[0].key;
  for (const method of ["GET", "HEAD", "PUT", "DELETE", "PATCH"]) {
    assert.equal((await req("/event", { method, token: "tok-node1", body: "{}" })).status, 405, method);
  }
  for (const path of ["/", `/${key}`, "/audit", "/audit/", `/event/${key}`, "/events", "/list"]) {
    for (const method of ["GET", "DELETE", "POST"]) {
      assert.equal((await req(path, { method, token: "tok-node1", body: "{}" })).status, 404, `${method} ${path}`);
    }
  }
  // The cron reads nothing back from the trail either.
  await worker.scheduled({ scheduledTime: T0 }, env);
  assert.deepEqual(reads, []);
  // The stored object is the event plus who sent it and when, and nothing else.
  assert.deepEqual(Object.keys(stored[0].value).sort(), [...Object.keys(boot()), "received", "sender"].sort());
  assert.match(key, /^audit\/\d{4}-\d{2}-\d{2}\/.*-boot-[0-9a-f-]{36}\.json$/);
});

test("a normal boot (rec, then a clevis report) is a NOTICE and clears the pending rec", async () => {
  await event(env, rec(), "tang", T0);
  assert.ok(kv.get("rec/node1"));
  await event(env, boot(), "node1", T0 + 30_000);
  assert.deepEqual(subjects(), ["[NOTICE] test-cluster: node1 booted (clevis)"]);
  assert.equal(kv.get("rec/node1"), undefined);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS + 60_000), []);
  assert.equal(sent.length, 1);
});

test("a passphrase boot with no rec fires", async () => {
  await event(env, boot({ unlock: "passphrase", clevis_devices: 0 }), "node1", T0);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster: node1 booted (passphrase)"]);
  assert.doesNotMatch(sent[0].body.text, /Tang was asked/);
  // A mixed unlock is not a clean one either.
  await event(env, boot({ unlock: "mixed", clevis_devices: 1 }), "node1", T0);
  assert.match(subjects()[1], /^\[FIRING\] .*\(mixed\)/);
});

test("a passphrase boot after Tang answered says the Tang share was there", async () => {
  await event(env, rec(), "tang", T0);
  await event(env, boot({ unlock: "passphrase", clevis_devices: 0, initrd_ssh_logins: 2 }), "node1", T0 + 1000);
  assert.match(subjects()[0], /^\[FIRING\]/);
  assert.match(sent[0].body.text, /Tang was asked/);
  assert.match(sent[0].body.text, /logged in to the initrd/);
});

test("a node that claims clevis while Tang saw nothing fires", async () => {
  await event(env, boot(), "node1", T0);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster: node1 booted (clevis)"]);
  assert.match(sent[0].body.text, /Tang saw no \/rec/);
});

test("Secure Boot off fires even on a clevis boot Tang saw", async () => {
  for (const over of [{ secure_boot: 0 }, { setup_mode: 1 }, { secure_boot: -1 }]) {
    sent = [];
    await event(env, rec(), "tang", T0);
    await event(env, boot(over), "node1", T0 + 1000);
    assert.match(subjects()[0], /^\[FIRING\]/, JSON.stringify(over));
  }
});

test("a rec with no boot after the grace period fires once", async () => {
  await event(env, rec(), "tang", T0);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS - 1), []);
  assert.equal(sent.length, 0);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS + 1), ["node1"]);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster: Tang released to node1, no boot followed"]);
  assert.deepEqual(await checkPendingRec(env, T0 + 2 * REC_GRACE_MS), []);
  assert.equal(sent.length, 1);
  // An address Tang serves that no node is listed for is still named, by its address.
  await event(env, rec({ ip: "10.40.0.99" }), "tang", T0);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS + 1), ["10.40.0.99"]);
});

test("a rec for a retired key fires at once, once an hour", async () => {
  await event(env, rec({ status: 404 }), "tang", T0);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster: Tang refused /rec from node1"]);
  await event(env, rec({ status: 404 }), "tang", T0 + 1000);
  assert.equal(sent.length, 1);
});

// A refusal releases nothing, so nothing waits for a boot (review fix: it used to).
test("a refused rec is not a release: no 'released, no boot followed' later", async () => {
  await event(env, rec({ status: 404 }), "tang", T0);
  assert.equal(kv.get("rec/node1"), undefined);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS + 5000), []);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster: Tang refused /rec from node1"]);
});

test("a passphrase boot after a refused rec does not blame the TPM share", async () => {
  await event(env, rec({ status: 404 }), "tang", T0);
  await event(env, boot({ unlock: "passphrase", clevis_devices: 0 }), "node1", T0 + 1000);
  const mail = sent.find((m) => / booted /.test(m.body.subject));
  assert.match(mail.body.subject, /^\[FIRING\]/);
  assert.doesNotMatch(mail.body.text, /Tang was asked/);
});

// The notifier posts status 0 for a POST it could not read: it may have been a release.
test("an unreadable POST is mailed at once and also waits for a boot", async () => {
  await event(env, rec({ kid: "unparsed", ip: "unparsed", status: 0 }), "tang", T0);
  assert.match(subjects()[0], /^\[FIRING\] test-cluster: Tang logged a POST it could not read from unparsed$/);
  assert.match(sent[0].body.text, /possible key release/);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS + 1), ["unparsed"]);
});

// The trail must hold an event whose email then failed: stored first, then mailed.
test("an event is stored even when its email fails", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 500 });
  await assert.rejects(event(env, boot({ unlock: "passphrase", clevis_devices: 0 }), "node1", T0), /HTTP 500/);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].value.kind, "boot");
  // And through the HTTP path a node actually uses: the request fails, the event stays.
  await assert.rejects(post("tok-node1", boot({ unlock: "passphrase", clevis_devices: 0 })), /HTTP 500/);
  assert.equal(stored.length, 2);
});

test("a retry loop neither restarts the grace period nor floods mail", async () => {
  for (let i = 0; i < 57; i++) await event(env, rec(), "tang", T0 + i * 800);
  assert.equal(sent.length, 0);
  assert.equal(JSON.parse(kv.get("rec/node1")).first, T0);
  assert.deepEqual(await checkPendingRec(env, T0 + REC_GRACE_MS + 1), ["node1"]);
  assert.equal(sent.length, 1);
  // Every one of them is in the trail all the same.
  assert.equal(stored.length, 57);
});

test("the Tang probe is a dead-man: unarmed, ok, alerted, repeated", async () => {
  assert.equal(await checkTangProbe(env, T0), "unarmed");
  assert.equal((await post("tok-tang", { kind: "tang_probe" })).status, 204);
  const seen = JSON.parse(kv.get("tang_probe")).lastSeen;
  assert.equal(await checkTangProbe(env, seen + SILENT_AFTER_MS - 1), "ok");
  assert.equal(await checkTangProbe(env, seen + SILENT_AFTER_MS + 1), "alerted");
  assert.match(subjects()[0], /^\[FIRING\] .*Tang self-probe silent/);
  assert.equal(await checkTangProbe(env, seen + SILENT_AFTER_MS + 60_000), "already-alerted");
  assert.equal(await checkTangProbe(env, seen + SILENT_AFTER_MS + REPEAT_MS + 2), "alerted");
  assert.equal(sent.length, 2);
});

test("every kind a node sends is accepted in the shape the node sends it", async () => {
  const events = [
    boot(),
    { kind: "deploy", node: "node1", generation: 12, toplevel: "abcdefghijklmnopqrstuvwxyz012345", result: "contract_blocked", attempts: 0, at: 1 },
    { kind: "deploy", node: "node1", generation: -1, toplevel: "unknown", result: "build_failed", attempts: 0, at: 1 },
    { kind: "deploy", node: "node1", generation: 3, toplevel: "abcdefghijklmnopqrstuvwxyz012345", result: "rollback_held", attempts: 0, at: 1 },
    { kind: "ssh_login", node: "node1", user: "root", from: "2001:db8::1", key: "SHA256:AbC+/dEf=", at: 1 },
    { kind: "ssh_login", node: "node1", user: "root", from: "192.0.2.1", key: "keyboard-interactive/pam", at: 1 },
    { kind: "nomad_acl", node: "node1", topic: "ACLToken", type: "ACLTokenUpserted", accessor: "0b8a0c2e-1111-4222-8333-444455556666", name: "clan-node1-fence", at: 1 },
    { kind: "nomad_acl", node: "node1", topic: "ACLPolicy", type: "ACLPolicyDeleted", accessor: "fence", name: "fence", at: 1 },
    { kind: "canary", node: "node1", path_class: "raw", hits: 0, at: 1 },
  ];
  for (const ev of events) assert.equal((await post("tok-node1", ev)).status, 204, JSON.stringify(ev));
  assert.equal(stored.length, events.length);
});

test("one failing check does not stop the others, and the cron still fails", async () => {
  await event(env, rec(), "tang", T0);
  kv.set("state", JSON.stringify({ lastSeen: T0, alertedAt: null }));
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls++;
    const subject = JSON.parse(init.body).subject;
    return subject.includes("gone silent") ? { ok: false, status: 500 } : { ok: true, status: 200 };
  };
  await assert.rejects(worker.scheduled({ scheduledTime: T0 + REC_GRACE_MS + SILENT_AFTER_MS }, env), /HTTP 500/);
  // The heartbeat email failed; the pending-rec email still went.
  assert.equal(calls, 2);
  assert.equal(kv.get("rec/node1"), undefined);
});
