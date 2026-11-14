// node --test: POST /event, the audit trail, against an in-memory KV with only the
// calls the Worker makes, an R2 stub that can only be written, and a fake fetch for the
// email API.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import worker, { event, MAX_BODY, SILENT_AFTER_MS } from "../src/index.js";

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
      // A token whose list leaves the boot report out.
      "tok-node3": { sender: "node3", kinds: ["deploy", "ssh_login", "canary"] },
    }),
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
  unlock: "tpm",
  tpm_devices: 2,
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

test("a boot report is taken only with the field names and unlock values of the schema", async () => {
  // The count of TPM-unlocked legs under any other name: the name is refused.
  const { tpm_devices, ...rest } = boot();
  const renamed = await post("tok-node1", { ...rest, unlocked_devices: tpm_devices });
  assert.equal(renamed.status, 422);
  assert.match(await renamed.text(), /field not allowed: unlocked_devices/);
  // Left out altogether.
  const missing = await post("tok-node1", rest);
  assert.equal(missing.status, 422);
  assert.match(await missing.text(), /missing field: tpm_devices/);
  // Not a whole number.
  for (const v of ["2", 1.5, null, true]) {
    const r = await post("tok-node1", boot({ tpm_devices: v }));
    assert.equal(r.status, 422, JSON.stringify(v));
    assert.match(await r.text(), /bad value: tpm_devices/);
  }
  // An unlock method the schema does not name.
  for (const unlock of ["network", "TPM", "tpm2", "", 1]) {
    const r = await post("tok-node1", boot({ unlock }));
    assert.equal(r.status, 422, JSON.stringify(unlock));
    assert.match(await r.text(), /bad value: unlock/);
  }
  assert.equal(stored.length, 0);
  assert.equal(sent.length, 0);
  for (const unlock of ["tpm", "mixed", "passphrase"]) {
    assert.equal((await post("tok-node1", boot({ unlock }))).status, 204, unlock);
  }
  assert.equal(stored.length, 3);
});

test("an oversized body is refused before it is parsed", async () => {
  const r = await post("tok-node1", JSON.stringify(boot()) + " ".repeat(MAX_BODY));
  assert.equal(r.status, 413);
  assert.equal(stored.length, 0);
});

test("a node cannot speak for another node, or send a kind its token does not list", async () => {
  const wrongNode = await post("tok-node2", boot({ node: "node1" }));
  assert.equal(wrongNode.status, 403);
  assert.match(await wrongNode.text(), /wrong node/);
  // node2 is not the leader: no Nomad ACL events from it, even about itself.
  const acl = { kind: "nomad_acl", node: "node2", topic: "ACLToken", type: "ACLTokenUpserted", accessor: "a", name: "n", at: 1 };
  const notLeader = await post("tok-node2", acl);
  assert.equal(notLeader.status, 403);
  assert.match(await notLeader.text(), /kind not allowed for sender/);
  // And a token without the boot kind cannot send a boot report, even its own node's.
  const noBoot = await post("tok-node3", boot({ node: "node3" }));
  assert.equal(noBoot.status, 403);
  assert.match(await noBoot.text(), /kind not allowed for sender/);
  assert.equal(stored.length, 0);
  assert.equal(sent.length, 0);
  // Its own events go through, attributed to the token's sender.
  assert.equal((await post("tok-node2", boot({ node: "node2" }))).status, 204);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].value.sender, "node2");
  const canary = { kind: "canary", node: "node3", path_class: "raw", hits: 0, at: 1 };
  assert.equal((await post("tok-node3", canary)).status, 204);
  assert.equal(stored[1].value.sender, "node3");
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

test("a TPM unlock of every leg under Secure Boot is a NOTICE", async () => {
  await event(env, boot(), "node1", T0);
  assert.deepEqual(subjects(), ["[NOTICE] test-cluster: node1 booted (tpm)"]);
  assert.match(sent[0].body.text, /unlock=tpm  devices=2\/2  initrd_ssh=0/);
  assert.doesNotMatch(sent[0].body.text, /TPM slot/);
  assert.doesNotMatch(sent[0].body.text, /logged in to the initrd/);
  // The mail says whose word it is: the Worker has no view of the unlock but the node's.
  assert.match(sent[0].body.text, /node's own report; nothing off the node confirms it/);
  // Nothing is kept about a boot outside the trail.
  assert.equal(kv.size, 0);
});

test("a passphrase or mixed unlock fires", async () => {
  await event(env, boot({ unlock: "passphrase", tpm_devices: 0 }), "node1", T0);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster: node1 booted (passphrase)"]);
  assert.match(sent[0].body.text, /Not every leg opened from its TPM slot/);
  assert.match(sent[0].body.text, /node's own report/);
  // A mixed unlock is not a clean one either.
  await event(env, boot({ unlock: "mixed", tpm_devices: 1 }), "node1", T0);
  assert.match(subjects()[1], /^\[FIRING\] .*\(mixed\)/);
  assert.match(sent[1].body.text, /unlock=mixed  devices=1\/2/);
  assert.match(sent[1].body.text, /Not every leg opened from its TPM slot/);
});

test("an initrd SSH login is named in the mail", async () => {
  await event(env, boot({ unlock: "passphrase", tpm_devices: 0, initrd_ssh_logins: 2 }), "node1", T0);
  assert.match(subjects()[0], /^\[FIRING\]/);
  assert.match(sent[0].body.text, /initrd_ssh=2/);
  assert.match(sent[0].body.text, /logged in to the initrd/);
});

test("Secure Boot off or Setup Mode fires even on a TPM unlock of every leg", async () => {
  for (const over of [{ secure_boot: 0 }, { setup_mode: 1 }, { secure_boot: -1 }, { setup_mode: -1 }]) {
    sent = [];
    await event(env, boot(over), "node1", T0);
    assert.match(subjects()[0], /^\[FIRING\] test-cluster: node1 booted \(tpm\)$/, JSON.stringify(over));
  }
});

// The trail must hold an event whose email then failed: stored first, then mailed.
test("an event is stored even when its email fails", async () => {
  globalThis.fetch = async () => ({ ok: false, status: 500 });
  await assert.rejects(event(env, boot({ unlock: "passphrase", tpm_devices: 0 }), "node1", T0), /HTTP 500/);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].value.kind, "boot");
  // And through the HTTP path a node actually uses: the request fails, the event stays.
  await assert.rejects(post("tok-node1", boot({ unlock: "passphrase", tpm_devices: 0 })), /HTTP 500/);
  assert.equal(stored.length, 2);
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

test("the cron runs the dead-man check, and fails when its email fails", async () => {
  // Never armed: nothing to say.
  await worker.scheduled({ scheduledTime: T0 }, env);
  assert.equal(sent.length, 0);
  kv.set("state", JSON.stringify({ lastSeen: T0, alertedAt: null }));
  await worker.scheduled({ scheduledTime: T0 + SILENT_AFTER_MS - 1 }, env);
  assert.equal(sent.length, 0);
  globalThis.fetch = async () => ({ ok: false, status: 500 });
  await assert.rejects(worker.scheduled({ scheduledTime: T0 + SILENT_AFTER_MS + 1 }, env), /HTTP 500/);
  // The mail did not go, so the silence is not marked as reported: the next run tries again.
  assert.equal(JSON.parse(kv.get("state")).alertedAt, null);
  globalThis.fetch = async (url, init) => {
    sent.push({ url, body: JSON.parse(init.body) });
    return { ok: true, status: 200 };
  };
  await worker.scheduled({ scheduledTime: T0 + SILENT_AFTER_MS + 600_000 }, env);
  assert.deepEqual(subjects(), ["[FIRING] test-cluster has gone silent"]);
  assert.equal(JSON.parse(kv.get("state")).alertedAt, T0 + SILENT_AFTER_MS + 600_000);
});
