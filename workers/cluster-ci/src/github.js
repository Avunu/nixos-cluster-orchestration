// The GitHub App's side: webhook signatures, the App's JWT, installation tokens, and the
// few REST calls the pipeline makes. Nothing here keeps state but the token cache.

const enc = new TextEncoder();

const b64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

// Constant-time over the length both share; a length difference is not a secret.
function sameString(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// X-Hub-Signature-256 over the body exactly as it arrived.
export async function verifySignature(secret, body, header) {
  if (!secret || !header?.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return sameString(hex(mac), header.slice("sha256=".length).toLowerCase());
}

function derLength(n) {
  if (n < 0x80) return [n];
  const out = [];
  for (; n > 0; n >>= 8) out.unshift(n & 0xff);
  return [0x80 | out.length, ...out];
}

// GitHub hands out the key as PKCS#1 ("BEGIN RSA PRIVATE KEY") and WebCrypto imports
// only PKCS#8. The second is the first inside a fixed wrapper, so the operator pastes
// the file as downloaded and nobody runs openssl.
export function pemToPkcs8(pem) {
  const text = pem.replace(/\\n/g, "\n");
  const der = Uint8Array.from(atob(text.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "")), (c) => c.charCodeAt(0));
  if (!/BEGIN RSA PRIVATE KEY/.test(text)) return der;
  // INTEGER 0, then AlgorithmIdentifier { rsaEncryption, NULL }.
  const head = [0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
  const octets = [0x04, ...derLength(der.length)];
  const inner = head.length + octets.length + der.length;
  return Uint8Array.from([0x30, ...derLength(inner), ...head, ...octets, ...der]);
}

export class GitHubError extends Error {
  constructor(status, method, path, body) {
    super(`GitHub ${method} ${path}: HTTP ${status} ${body.slice(0, 200)}`);
    this.status = status;
  }
}

export class GitHub {
  // `fetch` is wrapped: called as a method of this object, the runtime's own refuses.
  constructor({ appId, privateKey, fetch: f = (...a) => fetch(...a), apiBase = "https://api.github.com", now = Date.now }) {
    this.appId = appId;
    this.privateKey = privateKey;
    this.fetch = f;
    this.apiBase = apiBase;
    this.now = now;
    this.tokens = new Map(); // repo -> { token, until }
  }

  async appJwt() {
    const at = Math.floor(this.now() / 1000);
    const part = (o) => b64url(enc.encode(JSON.stringify(o)));
    // Issued a minute ago, for a clock that runs ahead of GitHub's.
    const signed = `${part({ alg: "RS256", typ: "JWT" })}.${part({ iat: at - 60, exp: at + 540, iss: String(this.appId) })}`;
    const key = await crypto.subtle.importKey(
      "pkcs8",
      pemToPkcs8(this.privateKey),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return `${signed}.${b64url(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(signed)))}`;
  }

  async raw(token, method, path, body, accept = "application/vnd.github+json") {
    const res = await this.fetch(`${this.apiBase}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: accept,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "cluster-ci",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new GitHubError(res.status, method, path, text);
    return text;
  }

  // A token for the installation that covers `repo`, found by asking as the App. In
  // memory only: it is good for an hour and costs two requests to replace.
  async tokenFor(repo) {
    const key = repo.toLowerCase();
    const hit = this.tokens.get(key);
    if (hit && hit.until > this.now()) return hit.token;
    const jwt = await this.appJwt();
    const { id } = JSON.parse(await this.raw(jwt, "GET", `/repos/${repo}/installation`));
    const { token } = JSON.parse(await this.raw(jwt, "POST", `/app/installations/${id}/access_tokens`));
    this.tokens.set(key, { token, until: this.now() + 50 * 60 * 1000 });
    return token;
  }

  async api(repo, method, path, body, accept) {
    const text = await this.raw(await this.tokenFor(repo), method, `/repos/${repo}${path}`, body, accept);
    return text ? JSON.parse(text) : null;
  }

  // One comment per preview and pull request, edited in place. A comment someone
  // deleted is written again.
  async upsertComment(repo, pr, commentId, body) {
    if (commentId) {
      try {
        await this.api(repo, "PATCH", `/issues/comments/${commentId}`, { body });
        return commentId;
      } catch (e) {
        if (e.status !== 404) throw e;
      }
    }
    return (await this.api(repo, "POST", `/issues/${pr}/comments`, { body })).id;
  }

  setStatus(repo, sha, { state, context, description, targetUrl }) {
    return this.api(repo, "POST", `/statuses/${sha}`, {
      state,
      context,
      description: description.slice(0, 140),
      ...(targetUrl ? { target_url: targetUrl } : {}),
    });
  }

  async readFile(repo, path, ref) {
    const token = await this.tokenFor(repo);
    const q = ref ? `?ref=${encodeURIComponent(ref)}` : "";
    return this.raw(token, "GET", `/repos/${repo}/contents/${path}${q}`, undefined, "application/vnd.github.raw+json");
  }

  dispatchWorkflow(repo, workflow, ref, inputs) {
    return this.api(repo, "POST", `/actions/workflows/${workflow}/dispatches`, { ref, inputs });
  }
}
