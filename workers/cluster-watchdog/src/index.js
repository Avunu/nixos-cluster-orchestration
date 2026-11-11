// cluster-watchdog — the off-cluster dead-man for a cluster's alerting.
//
// Alerting runs on the cluster, so it cannot report the cluster's own death.
// Alertmanager's always-firing Watchdog alert is relayed by the cluster's
// alert-email-bridge to POST /heartbeat here every few minutes; each heartbeat
// therefore proves Prometheus -> Alertmanager -> bridge -> outbound network.
// A cron checks the last heartbeat and emails (Cloudflare Email Sending API,
// the same path as every other alert) when it goes silent, again every
// REPEAT_MS while it stays silent, and once more when heartbeats resume.
//
// State is one KV key: { lastSeen, alertedAt } (epoch ms).
//
// It is also where the nodes' audit trail goes (POST /event, below): boot reports,
// SSH logins, deploys, Nomad ACL changes, canary hits, and the Tang host's key
// recoveries, into an R2 bucket nothing here can read back.

export const SILENT_AFTER_MS = 20 * 60 * 1000;
export const REPEAT_MS = 6 * 60 * 60 * 1000;

const minutes = (ms) => Math.round(ms / 60000);

async function getState(env) {
  const raw = await env.WATCHDOG.get("state");
  return raw ? JSON.parse(raw) : { lastSeen: null, alertedAt: null };
}

const putState = (env, state) => env.WATCHDOG.put("state", JSON.stringify(state));

// Constant-time: the token guards the only write this Worker accepts.
function sameSecret(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export async function sendEmail(env, subject, text) {
  const base = env.API_BASE || "https://api.cloudflare.com/client/v4";
  const to = env.ALERT_TO.split(",").map((s) => s.trim()).filter(Boolean);
  // `to` is one address per request in Cloudflare's schema.
  const results = await Promise.all(
    to.map((addr) =>
      fetch(`${base}/accounts/${env.ACCOUNT_ID}/email/sending/send`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.CF_EMAIL_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ from: env.ALERT_FROM, to: addr, subject, text }),
      }),
    ),
  );
  const failed = results.filter((r) => !r.ok);
  if (failed.length) throw new Error(`email delivery failed: HTTP ${failed.map((r) => r.status).join(", ")}`);
}

export async function heartbeat(env, now) {
  const state = await getState(env);
  if (state.alertedAt) {
    await sendEmail(
      env,
      `[RESOLVED] ${env.CLUSTER_NAME ?? "cluster"} alerting is back`,
      `Alerting heartbeats resumed at ${new Date(now).toISOString()} ` +
        `after ${minutes(now - state.lastSeen)} minutes of silence.\n\n` +
        "Alerts that fired while the cluster was unreachable were not delivered; " +
        "check the cluster (systemctl --failed, the backup timers) now.\n\n-- cluster-watchdog",
    );
  }
  await putState(env, { lastSeen: now, alertedAt: null });
}

export async function check(env, now) {
  const state = await getState(env);
  // Never armed: the cluster has not sent a first heartbeat yet.
  if (state.lastSeen == null) return "unarmed";
  const silent = now - state.lastSeen;
  if (silent < SILENT_AFTER_MS) return "ok";
  if (state.alertedAt && now - state.alertedAt < REPEAT_MS) return "already-alerted";
  await sendEmail(
    env,
    `[FIRING] ${env.CLUSTER_NAME ?? "cluster"} has gone silent`,
    `No alerting heartbeat for ${minutes(silent)} minutes (last: ${new Date(state.lastSeen).toISOString()}).\n\n` +
      "Either the metrics node is down or unreachable, or Prometheus / Alertmanager / " +
      "alert-email-bridge on it has stopped. While this lasts, NO cluster alert can " +
      "reach you -- including failed backups.\n\n" +
      "Check: ssh root@<metrics node> 'systemctl status prometheus alertmanager alert-email-bridge'\n\n" +
      `This repeats every ${REPEAT_MS / 3600000} hours until heartbeats resume.\n\n-- cluster-watchdog`,
  );
  await putState(env, { ...state, alertedAt: now });
  return "alerted";
}

// ── audit events ────────────────────────────────────────────────────────────
// POST /event: the off-host audit trail (design 1.19, Appendix M). Write-only and
// allowlisted. A sender can add to the trail; nothing can read or delete through this
// Worker, and a field not named here is refused, so client data cannot arrive by
// accident: a free-text field, a path, a file name or a body has nowhere to go. Every
// field a schema names is also required, so an event cannot leave out the one that
// says who it is about. Who may send what is per token:
//   AUDIT_TOKENS = {"<token>": {"sender": "node1", "kinds": ["boot", ...]}}
// `avc audit tokens` prints that JSON from each node's `audit/token`.
const ID = /^[A-Za-z0-9._:@=\/+-]{1,128}$/;
const NUM = (v) => Number.isInteger(v);
const SCHEMAS = {
  boot: {
    node: ID, boot_id: ID, unlock: /^(clevis|passphrase|mixed)$/, clevis_devices: NUM, expected_devices: NUM,
    initrd_ssh_logins: NUM, secure_boot: NUM, setup_mode: NUM, pcr7: /^[0-9a-f]{0,64}$/, generation: NUM,
    toplevel: ID, initrd_ms: NUM, at: NUM,
  },
  deploy: {
    node: ID, generation: NUM, toplevel: ID,
    result: /^(ok|activation_failed|contract_blocked|build_failed|rollback_held)$/, attempts: NUM, at: NUM,
  },
  ssh_login: { node: ID, user: ID, from: ID, key: ID, at: NUM },
  nomad_acl: { node: ID, topic: /^(ACLToken|ACLPolicy|ACLRole)$/, type: ID, accessor: ID, name: ID, at: NUM },
  canary: { node: ID, path_class: /^(s3|esp|swap|raw|tmp|journal|coredump)$/, hits: NUM, at: NUM },
  tang_rec: { ip: ID, kid: ID, status: NUM, at: NUM },
  tang_probe: {},
};
export const MAX_BODY = 2048;
export const REC_GRACE_MS = 15 * 60 * 1000;

// Own properties only: a kind or a field named "constructor" or "__proto__" must not
// reach Object.prototype's.
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

export function validate(ev) {
  if (ev === null || typeof ev !== "object" || Array.isArray(ev)) return "not an object";
  if (typeof ev.kind !== "string" || !own(SCHEMAS, ev.kind)) return "unknown kind";
  const schema = SCHEMAS[ev.kind];
  for (const [k, v] of Object.entries(ev)) {
    if (k === "kind") continue;
    if (!own(schema, k)) return `field not allowed: ${k}`;
    const rule = schema[k];
    const ok = typeof rule === "function" ? rule(v) : typeof v === "string" && rule.test(v);
    if (!ok) return `bad value: ${k}`;
  }
  for (const k of Object.keys(schema)) {
    if (!own(ev, k)) return `missing field: ${k}`;
  }
  return null;
}

function auditKey(ev, now) {
  const d = new Date(now).toISOString();
  return `audit/${d.slice(0, 10)}/${d}-${ev.kind}-${crypto.randomUUID()}.json`;
}

// Unplanned /rec: Tang answered, and no boot report from that client's node
// followed. Either someone is trying a rescue boot on the real hardware, or the
// node did not get as far as reporting: both want a human.
async function onEvent(env, ev, sender, now) {
  const name = env.CLUSTER_NAME ?? "cluster";
  if (ev.kind === "tang_rec") {
    const node = JSON.parse(env.TANG_CLIENTS || "{}")[ev.ip] ?? ev.ip;
    // Status 0: the Tang host's notifier saw a POST in tangd's log that it could not
    // read (modules/tang-server.nix fails closed), so a release can't be ruled out.
    const unread = ev.status === 0;
    if (ev.status !== 200 && !(await env.WATCHDOG.get(`recrefused/${node}`))) {
      await sendEmail(env, `[FIRING] ${name}: Tang ${unread ? "logged a POST it could not read" : "refused /rec"} from ${node}`,
        (unread
          ? `tangd logged a POST from ${ev.ip} that the Tang host could not parse. Treat it as a possible key release, and read tangd's journal on the Tang host.`
          : `POST /rec/${ev.kid} from ${ev.ip} => ${ev.status}. A retired or unknown key was requested.`) + "\n\n-- cluster-watchdog");
      await env.WATCHDOG.put(`recrefused/${node}`, "1", { expirationTtl: 3600 });
    }
    // Only a release is waiting for a boot: a refused /rec gave nothing away, and
    // counting it would send "Tang released ... no boot followed" for a retired key and
    // blame the TPM share on a passphrase boot whose real cause was that key.
    // Keep the FIRST: clevis-luks-askpass retries about once a second while it
    // cannot finish, and a refreshed timestamp would never reach the grace period.
    if ((ev.status === 200 || unread) && !(await env.WATCHDOG.get(`rec/${node}`))) {
      await env.WATCHDOG.put(`rec/${node}`, JSON.stringify({ first: now, ip: ev.ip }), { expirationTtl: 86400 });
    }
    return;
  }
  if (ev.kind === "boot") {
    const rec = await env.WATCHDOG.get(`rec/${ev.node}`);
    await env.WATCHDOG.delete(`rec/${ev.node}`);
    const noRec = !rec;
    const lines = [`unlock=${ev.unlock}  devices=${ev.clevis_devices}/${ev.expected_devices}  initrd_ssh=${ev.initrd_ssh_logins}`,
      `secure_boot=${ev.secure_boot}  setup_mode=${ev.setup_mode}  pcr7=${ev.pcr7}`, `generation=${ev.generation}  ${ev.toplevel}`];
    // The node's own claim, and Tang's independent view of the same boot.
    if (ev.unlock === "clevis" && noRec) lines.push("WARNING: node says clevis, but Tang saw no /rec for it.");
    if (ev.unlock !== "clevis" && !noRec) lines.push("Tang was asked, so the Tang share was available: look at the TPM share and PCR 7.");
    if (ev.initrd_ssh_logins > 0) lines.push("Someone logged in to the initrd over SSH during this boot.");
    const bad = ev.unlock !== "clevis" || ev.secure_boot !== 1 || ev.setup_mode !== 0 || (ev.unlock === "clevis" && noRec);
    await sendEmail(env, `[${bad ? "FIRING" : "NOTICE"}] ${name}: ${ev.node} booted (${ev.unlock})`, lines.join("\n") + "\n\n-- cluster-watchdog");
  }
}

// Stored first: the trail holds the event even if the email after it fails. A sender
// that sees the failure sends again, so a retried event can be in the trail twice.
export async function event(env, ev, sender, now) {
  await env.AUDIT.put(auditKey(ev, now), JSON.stringify({ ...ev, sender, received: now }));
  await onEvent(env, ev, sender, now);
  if (ev.kind === "tang_probe") await env.WATCHDOG.put("tang_probe", JSON.stringify({ lastSeen: now }));
}

export async function checkPendingRec(env, now) {
  const fired = [];
  const list = await env.WATCHDOG.list({ prefix: "rec/" });
  for (const { name } of list.keys) {
    const raw = await env.WATCHDOG.get(name);
    if (!raw) continue;
    const rec = JSON.parse(raw);
    if (now - rec.first < REC_GRACE_MS) continue;
    const node = name.slice(4);
    await sendEmail(env, `[FIRING] ${env.CLUSTER_NAME ?? "cluster"}: Tang released to ${node}, no boot followed`,
      `Tang answered /rec from ${rec.ip}, and ${minutes(now - rec.first)} minutes later ${node} has not reported a boot.\n` +
        "Check the KVM console. If nobody rebooted it, treat this as an attempt on the disk key.\n\n-- cluster-watchdog");
    await env.WATCHDOG.delete(name);
    fired.push(node);
  }
  return fired;
}

// The Tang host's self-probe (design D5) posts tang_probe; silence is the alert.
export async function checkTangProbe(env, now) {
  const raw = await env.WATCHDOG.get("tang_probe");
  if (!raw) return "unarmed";
  const st = JSON.parse(raw);
  const silent = now - st.lastSeen;
  if (silent < SILENT_AFTER_MS) return "ok";
  if (st.alertedAt && now - st.alertedAt < REPEAT_MS) return "already-alerted";
  await sendEmail(env, `[FIRING] ${env.CLUSTER_NAME ?? "cluster"}: Tang self-probe silent`,
    `No verified /adv from the Tang host for ${minutes(silent)} minutes. The next reboot of any node will need the passphrase.\n\n-- cluster-watchdog`);
  await env.WATCHDOG.put("tang_probe", JSON.stringify({ ...st, alertedAt: now }));
  return "alerted";
}

function auditAuth(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const tokens = JSON.parse(env.AUDIT_TOKENS || "{}");
  let who = null;
  // Every entry is compared, whichever matches, so the time taken says nothing.
  for (const [t, entry] of Object.entries(tokens)) {
    if (sameSecret(auth, `Bearer ${t}`) && who === null) who = entry;
  }
  return who;
}

async function handleEvent(request, env) {
  if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
  const who = auditAuth(request, env);
  if (!who) return new Response("unauthorized", { status: 401 });
  const raw = await request.text();
  if (raw.length > MAX_BODY) return new Response("too large", { status: 413 });
  let ev;
  try {
    ev = JSON.parse(raw);
  } catch {
    return new Response("bad json", { status: 400 });
  }
  const problem = validate(ev);
  if (problem) return new Response(problem, { status: 422 });
  if (!Array.isArray(who.kinds) || !who.kinds.includes(ev.kind)) {
    return new Response("kind not allowed for sender", { status: 403 });
  }
  // A node may not speak for another node.
  if (own(ev, "node") && who.sender !== ev.node) return new Response("wrong node", { status: 403 });
  await event(env, ev, who.sender, Date.now());
  return new Response(null, { status: 204 });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/event") return handleEvent(request, env);
    if (url.pathname !== "/heartbeat") return new Response("not found", { status: 404 });
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
    const auth = request.headers.get("Authorization") || "";
    if (!env.WATCHDOG_TOKEN || !sameSecret(auth, `Bearer ${env.WATCHDOG_TOKEN}`)) {
      return new Response("unauthorized", { status: 401 });
    }
    await heartbeat(env, Date.now());
    return new Response(null, { status: 204 });
  },

  // Each check runs even when one before it threw (an email that failed), so one
  // broken path cannot silence the others; the invocation still fails afterwards.
  async scheduled(controller, env) {
    const now = controller.scheduledTime ?? Date.now();
    const errors = [];
    for (const run of [check, checkPendingRec, checkTangProbe]) {
      try {
        await run(env, now);
      } catch (e) {
        errors.push(e);
      }
    }
    if (errors.length) throw new AggregateError(errors, errors.map((e) => e.message).join("; "));
  },
};
