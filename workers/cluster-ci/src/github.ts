// The GitHub App's side: webhook signatures, the App's JWT, installation tokens, and the
// few REST calls the pipeline makes. Nothing here keeps state but the token cache.

import type { Fetch, Thrown } from "./types.ts";

// GitHub's answers, as far as they are read. Nothing checks them: each is what
// GitHub documents for the request it answers.
export interface Installation {
  id: number;
  account?: { login?: string } | null;
}
// GET /repos/{owner}/{repo}
export interface RepositoryAnswer {
  default_branch: string;
}
interface TokenAnswer {
  token: string;
  expires_at: string;
}

export interface ScopedToken {
  token: string;
  expiresAt: number;
}

export interface Status {
  state: string;
  context: string;
  description: string;
  targetUrl?: string;
}

export interface GitHubOptions {
  appId: string | number;
  privateKey: string;
  fetch?: Fetch;
  apiBase?: string;
  now?: () => number;
}

const enc = new TextEncoder();

const b64url = (bytes: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const hex = (bytes: ArrayBuffer) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");

// Constant-time over the length both share; a length difference is not a secret.
function sameString(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// X-Hub-Signature-256 over the body exactly as it arrived.
export async function verifySignature(secret: string | undefined, body: string, header: string | null | undefined): Promise<boolean> {
  if (!secret || !header?.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return sameString(hex(mac), header.slice("sha256=".length).toLowerCase());
}

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const out: number[] = [];
  for (; n > 0; n >>= 8) out.unshift(n & 0xff);
  return [0x80 | out.length, ...out];
}

// GitHub hands out the key as PKCS#1 ("BEGIN RSA PRIVATE KEY") and WebCrypto imports
// only PKCS#8. The second is the first inside a fixed wrapper, so the operator pastes
// the file as downloaded and nobody runs openssl.
export function pemToPkcs8(pem: string): Uint8Array<ArrayBuffer> {
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
  declare status: number;

  constructor(status: number, method: string, path: string, body: string) {
    super(`GitHub ${method} ${path}: HTTP ${status} ${body.slice(0, 200)}`);
    this.status = status;
  }
}

export class GitHub {
  declare appId: string | number;
  declare privateKey: string;
  declare fetch: Fetch;
  declare apiBase: string;
  declare now: () => number;
  declare tokens: Map<string, { token: string; until: number }>;
  declare signed: { jwt: string; until: number } | undefined;

  // `fetch` is wrapped: called as a method of this object, the runtime's own refuses.
  constructor({ appId, privateKey, fetch: f = (...a) => fetch(...a), apiBase = "https://api.github.com", now = Date.now }: GitHubOptions) {
    this.appId = appId;
    this.privateKey = privateKey;
    this.fetch = f;
    this.apiBase = apiBase;
    this.now = now;
    this.tokens = new Map(); // repo -> { token, until }
  }

  async appJwt(): Promise<string> {
    const at = Math.floor(this.now() / 1000);
    const part = (o: unknown) => b64url(enc.encode(JSON.stringify(o)));
    // Issued a minute ago, for a clock that runs ahead of GitHub's.
    const signed = `${part({ alg: "RS256", typ: "JWT" })}.${part({ iat: at - 60, exp: at + 540, iss: String(this.appId) })}`;
    if (!this.privateKey) throw new Error("GITHUB_APP_PRIVATE_KEY is not set: `wrangler secret put GITHUB_APP_PRIVATE_KEY`");
    const key = await crypto.subtle.importKey(
      "pkcs8",
      pemToPkcs8(this.privateKey),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return `${signed}.${b64url(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(signed)))}`;
  }

  async raw(token: string, method: string, path: string, body?: unknown, accept = "application/vnd.github+json"): Promise<string> {
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
  async tokenFor(repo: string): Promise<string> {
    const key = repo.toLowerCase();
    const hit = this.tokens.get(key);
    if (hit && hit.until > this.now()) return hit.token;
    const jwt = await this.appJwt();
    const { id } = JSON.parse(await this.raw(jwt, "GET", `/repos/${repo}/installation`)) as Installation;
    const { token } = JSON.parse(await this.raw(jwt, "POST", `/app/installations/${id}/access_tokens`)) as TokenAnswer;
    this.tokens.set(key, { token, until: this.now() + 50 * 60 * 1000 });
    return token;
  }

  // The App's own JWT, kept for half its life: listing what installations cover asks
  // as the App once per repository.
  async jwt(): Promise<string> {
    if (!this.signed || this.signed.until <= this.now()) {
      this.signed = { jwt: await this.appJwt(), until: this.now() + 4 * 60 * 1000 };
    }
    return this.signed.jwt;
  }

  // Every installation of the App, anyone's: it is public. Only the account is read.
  async installations(): Promise<Installation[]> {
    const out: Installation[] = [];
    for (let page = 1; ; page++) {
      const got = JSON.parse(await this.raw(await this.jwt(), "GET", `/app/installations?per_page=100&page=${page}`)) as Installation[];
      out.push(...got);
      if (got.length < 100) return out;
    }
  }

  // The installation that covers `repo`, or null: not installed for its owner, or
  // installed on chosen repositories of which this is not one.
  async repoInstallation(repo: string): Promise<number | null> {
    try {
      return (JSON.parse(await this.raw(await this.jwt(), "GET", `/repos/${repo}/installation`)) as Installation).id;
    } catch (e) {
      if ((e as Thrown).status === 404) return null;
      throw e;
    }
  }

  // A token GitHub narrows itself: these repositories of the installation (names,
  // without the owner) and these permissions, whatever the App holds beyond them.
  async scopedToken(installation: number, repositories: string[], permissions: Record<string, string>): Promise<ScopedToken> {
    const made = JSON.parse(
      await this.raw(await this.jwt(), "POST", `/app/installations/${installation}/access_tokens`, { repositories, permissions }),
    ) as TokenAnswer;
    return { token: made.token, expiresAt: Date.parse(made.expires_at) };
  }

  // GitHub's answer, parsed, or null when it sent none. The caller knows what it asked
  // for, and says so where it reads the answer.
  async api(repo: string, method: string, path: string, body?: unknown, accept?: string): Promise<unknown> {
    const text = await this.raw(await this.tokenFor(repo), method, `/repos/${repo}${path}`, body, accept);
    return text ? JSON.parse(text) : null;
  }

  // One comment per preview and pull request, edited in place. A comment someone
  // deleted is written again.
  async upsertComment(repo: string, pr: number, commentId: number | null | undefined, body: string): Promise<number> {
    if (commentId) {
      try {
        await this.api(repo, "PATCH", `/issues/comments/${commentId}`, { body });
        return commentId;
      } catch (e) {
        if ((e as Thrown).status !== 404) throw e;
      }
    }
    return ((await this.api(repo, "POST", `/issues/${pr}/comments`, { body })) as { id: number }).id;
  }

  setStatus(repo: string, sha: string, { state, context, description, targetUrl }: Status): Promise<unknown> {
    return this.api(repo, "POST", `/statuses/${sha}`, {
      state,
      context,
      description: description.slice(0, 140),
      ...(targetUrl ? { target_url: targetUrl } : {}),
    });
  }

  async readFile(repo: string, path: string, ref?: string): Promise<string> {
    const token = await this.tokenFor(repo);
    const q = ref ? `?ref=${encodeURIComponent(ref)}` : "";
    return this.raw(token, "GET", `/repos/${repo}/contents/${path}${q}`, undefined, "application/vnd.github.raw+json");
  }

  dispatchWorkflow(repo: string, workflow: string, ref: string, inputs: Record<string, string>): Promise<unknown> {
    return this.api(repo, "POST", `/actions/workflows/${workflow}/dispatches`, { ref, inputs });
  }
}
