// The off-host audit receiver for the VM tests: the REAL Worker's fetch handler
// (workers/cluster-watchdog/src/index.js) behind a plain Node HTTP(S) server, with R2,
// KV and the email API replaced by files. So an event a node sends is accepted only if
// the Worker itself would accept it: its token, its node name, every field.
//
// Environment:
//   WORKER        path to the Worker's src/index.js
//   PORT          port to listen on
//   TLS_CERT, TLS_KEY   optional: serve https with these
//   AUDIT_TOKENS  the Worker's secret, as JSON
//   OUT           directory for requests.jsonl (method, path, status, the body as sent),
//                 audit.jsonl (what the Worker stored) and emails.jsonl (what it mailed)
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";

const worker = (await import(process.env.WORKER)).default;
const out = process.env.OUT;
mkdirSync(out, { recursive: true });
const record = (file, obj) => appendFileSync(`${out}/${file}`, JSON.stringify(obj) + "\n");

const kv = new Map();
const env = {
  CLUSTER_NAME: "vm-test",
  AUDIT_TOKENS: process.env.AUDIT_TOKENS,
  TANG_CLIENTS: process.env.TANG_CLIENTS || "{}",
  CF_EMAIL_TOKEN: "stub",
  ACCOUNT_ID: "stub",
  ALERT_FROM: "alerts@example.com",
  ALERT_TO: "ops@example.com",
  WATCHDOG: {
    get: async (k) => kv.get(k) ?? null,
    put: async (k, v) => void kv.set(k, v),
    delete: async (k) => void kv.delete(k),
    list: async ({ prefix }) => ({ keys: [...kv.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })) }),
  },
  // Write-only, as the Worker uses it.
  AUDIT: { put: async (key, value) => record("audit.jsonl", { key, value: JSON.parse(value) }) },
};
// The Worker's only outbound call is the email API.
globalThis.fetch = async (url, init) => {
  record("emails.jsonl", { url: String(url), ...JSON.parse(init.body) });
  return { ok: true, status: 200 };
};

async function handle(req, res) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks).toString("utf8");
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
  let status = 500;
  let text = "";
  try {
    const r = await worker.fetch(
      new Request(`https://audit.stub${req.url}`, {
        method: req.method,
        headers,
        body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
      }),
      env,
    );
    status = r.status;
    text = await r.text();
  } catch (e) {
    text = String(e);
  }
  record("requests.jsonl", { method: req.method, path: req.url, status, response: text, body });
  res.writeHead(status, { "Content-Type": "text/plain" });
  res.end(text);
}

const server = process.env.TLS_CERT
  ? https.createServer({ cert: readFileSync(process.env.TLS_CERT), key: readFileSync(process.env.TLS_KEY) }, handle)
  : http.createServer(handle);
server.listen(Number(process.env.PORT), "0.0.0.0", () => console.log(`audit stub on ${process.env.PORT}`));
