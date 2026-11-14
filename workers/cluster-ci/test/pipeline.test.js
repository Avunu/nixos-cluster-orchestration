import assert from "node:assert/strict";
import { test } from "node:test";
import { nodeFor } from "../src/auth.js";
import { Pipeline, parseFlakeUrl, renderComment, trackingInputs } from "../src/core.js";
import { GitHub, pemToPkcs8, verifySignature } from "../src/github.js";
import { previewHost, previewLabel } from "../src/slug.js";

const REPO = "acme/shop";
const SITE = "acme/cluster";

function harness({ failTunnel = false } = {}) {
  const calls = [];
  const stored = {};
  let comments = 100;
  let tunnels = 0;
  const lock = {
    root: "root",
    nodes: {
      root: { inputs: { shop: "shop", nixpkgs: ["cluster", "nixpkgs"], pinned: "pinned", other: "other" } },
      shop: { original: { type: "git", url: "https://github.com/acme/shop.git", ref: "main", submodules: true } },
      pinned: { original: { type: "github", owner: "acme", repo: "shop", rev: "abc" } },
      other: { original: { type: "github", owner: "acme", repo: "other" } },
    },
  };
  const github = {
    upsertComment: async (repo, pr, id, body) => (calls.push(["comment", repo, pr, id ?? null, body]), id ?? ++comments),
    setStatus: async (repo, sha, s) => void calls.push(["status", repo, sha, s.state, s.context]),
    api: async (repo, method, path) => (calls.push(["api", repo, method, path]), { default_branch: "main" }),
    readFile: async (repo, path, ref) => (calls.push(["read", repo, path, ref]), JSON.stringify(lock)),
    dispatchWorkflow: async (repo, wf, ref, inputs) => void calls.push(["dispatch", repo, wf, ref, inputs]),
  };
  const cloudflare = {
    createTunnel: async (name) => {
      if (failTunnel) throw new Error("no");
      calls.push(["tunnel", name]);
      return { id: `t${++tunnels}`, secret: "s3cret", account: "acct" };
    },
    routeDns: async (host, id) => (calls.push(["dns", host, id]), `d-${id}`),
    deleteDns: async (id) => void calls.push(["undns", id]),
    deleteTunnel: async (id) => void calls.push(["untunnel", id]),
  };
  const pipeline = new Pipeline({
    storage: { get: async (k) => stored[k], put: async (k, v) => void (stored[k] = structuredClone(v)) },
    github,
    cloudflare,
    config: { domain: "preview.example.com", workflow: "flake-update.yml" },
    now: () => 1000,
    log: () => {},
  });
  const agent = (previews = [], version = 0, node = "node1") =>
    pipeline.sync(node, {
      version,
      flake: `github:${SITE}`,
      apps: [{ app: "shop", repo: REPO, slots: 2 }],
      previews,
    });
  const pr = (action, { number = 7, ref = "feat-x", sha = "a".repeat(40), fork = false } = {}) =>
    pipeline.webhook("pull_request", {
      action,
      repository: { full_name: REPO, default_branch: "main" },
      pull_request: { number, head: { ref, sha, repo: { full_name: fork ? "mallory/shop" : REPO } } },
    });
  return { pipeline, calls, stored, agent, pr, of: (kind) => calls.filter((c) => c[0] === kind) };
}

test("a pull request becomes one preview with its own tunnel, hostname, comment and status", async () => {
  const h = harness();
  await h.agent();
  assert.equal(await h.pr("opened"), "preview");
  assert.deepEqual(h.of("tunnel"), [["tunnel", "preview-feat-x-shop"]]);
  assert.deepEqual(h.of("dns"), [["dns", "feat-x-shop.preview.example.com", "t1"]]);
  assert.deepEqual(h.of("status").at(-1), ["status", REPO, "a".repeat(40), "pending", "preview/shop"]);
  assert.match(h.of("comment")[0][4], /https:\/\/feat-x-shop\.preview\.example\.com/);

  const want = await h.agent();
  assert.deepEqual(want.previews, [
    {
      id: "shop/feat-x", app: "shop", repo: REPO, branch: "feat-x", sha: "a".repeat(40), seed: 1,
      host: "feat-x-shop.preview.example.com",
      tunnel: { id: "t1", account: "acct", secret: "s3cret" },
    },
  ]);
});

test("a push to the branch moves the same preview, and edits the same comment", async () => {
  const h = harness();
  await h.agent();
  await h.pr("opened");
  await h.pr("synchronize", { sha: "b".repeat(40) });
  assert.equal(h.of("tunnel").length, 1);
  assert.equal(Object.keys(h.stored.state.previews).length, 1);
  const [first, second] = h.of("comment");
  assert.equal(first[3], null);
  assert.equal(second[3], 101);
  assert.equal((await h.agent()).previews[0].sha, "b".repeat(40));
});

test("every node offers the app, and each branch goes to the node with fewer previews", async () => {
  const h = harness();
  await h.agent([], 0, "node2");
  await h.agent([], 0, "node1");
  await h.pr("opened", { number: 1, ref: "one" });
  await h.pr("opened", { number: 2, ref: "two" });
  await h.pr("synchronize", { number: 1, ref: "one", sha: "b".repeat(40) });
  const on = async (node) => (await h.agent([], 0, node)).previews.map((p) => `${p.branch}@${p.sha[0]}`);
  // A tie goes to the first name; the second branch to the other node; a push moves nothing.
  assert.deepEqual(await on("node1"), ["one@b"]);
  assert.deepEqual(await on("node2"), ["two@a"]);
});

test("a fork gets nothing, and neither does a repository no app previews", async () => {
  const h = harness();
  await h.agent();
  assert.equal(await h.pr("opened", { fork: true }), "ignored: fork");
  assert.deepEqual(h.calls, []);
  const bare = harness();
  assert.equal(await bare.pr("opened"), "ignored: no app previews this repository");
});

test("the node's report reaches the pull request, but not one about an earlier commit", async () => {
  const h = harness();
  await h.agent();
  await h.pr("opened");
  await h.pr("synchronize", { sha: "b".repeat(40) });
  h.calls.length = 0;
  await h.agent([{ id: "shop/feat-x", sha: "a".repeat(40), seed: 1, state: "live" }]);
  assert.deepEqual(h.calls, []);
  await h.agent([{ id: "shop/feat-x", sha: "b".repeat(40), seed: 1, state: "failed", detail: "error: build ```failed" }]);
  assert.deepEqual(h.of("status"), [["status", REPO, "b".repeat(40), "failure", "preview/shop"]]);
  assert.match(h.of("comment")[0][4], /Failed[\s\S]*error: build '''failed/);
  // The same report again changes nothing.
  h.calls.length = 0;
  await h.agent([{ id: "shop/feat-x", sha: "b".repeat(40), seed: 1, state: "failed", detail: "error: build ```failed" }]);
  assert.deepEqual(h.calls, []);
});

test("closing the last pull request removes the preview once the node has let go of it", async () => {
  const h = harness();
  await h.agent();
  await h.pr("opened");
  await h.pr("opened", { number: 8 });
  assert.equal(await h.pr("closed"), "ignored");
  assert.equal((await h.agent()).previews.length, 1);
  assert.equal(await h.pr("closed", { number: 8 }), "released");
  // Still held on the node: not desired any more, and nothing deleted yet.
  const held = await h.agent([{ id: "shop/feat-x", sha: "a".repeat(40), seed: 1, state: "live" }]);
  assert.deepEqual(held.previews, []);
  assert.deepEqual(h.of("untunnel"), []);
  await h.agent([]);
  assert.deepEqual(h.of("undns"), [["undns", "d-t1"]]);
  assert.deepEqual(h.of("untunnel"), [["untunnel", "t1"]]);
  assert.deepEqual(h.stored.state.previews, {});
});

test("deleting the branch releases it whatever pull requests it had", async () => {
  const h = harness();
  await h.agent();
  await h.pr("opened");
  const r = await h.pipeline.webhook("delete", { ref_type: "branch", ref: "feat-x", repository: { full_name: REPO } });
  assert.equal(r, "released");
});

test("a hostname that could not be made fails the preview, and the next push tries again", async () => {
  const h = harness({ failTunnel: true });
  await h.agent();
  await h.pr("opened");
  assert.equal(h.of("status").at(-1)[3], "failure");
  assert.deepEqual((await h.agent()).previews, []);
});

test("/preview reset asks for a fresh copy, from a collaborator only", async () => {
  const h = harness();
  await h.agent();
  await h.pr("opened");
  const say = (author_association, body = " /preview reset\n") =>
    h.pipeline.webhook("issue_comment", {
      action: "created",
      repository: { full_name: REPO },
      issue: { number: 7, pull_request: {} },
      comment: { body, author_association },
    });
  assert.equal(await say("NONE"), "ignored: not a collaborator");
  assert.equal(await say("MEMBER", "please /preview reset"), "ignored");
  assert.equal(await say("COLLABORATOR"), "reset");
  assert.equal((await h.agent()).previews[0].seed, 2);
});

test("a push to the branch the nodes rebuild from tells them at once", async () => {
  const h = harness();
  const first = await h.agent();
  const push = (repo, ref) =>
    h.pipeline.webhook("push", { ref, repository: { full_name: repo, default_branch: "main" } });
  assert.equal(await push(SITE, "refs/heads/topic"), "ignored");
  assert.equal(await push(SITE, "refs/tags/v1"), "ignored");
  assert.equal(await push(SITE, "refs/heads/main"), "deploy");
  const next = await h.agent([], first.version);
  assert.equal(next.deploySeq, first.deploySeq + 1);
  assert.ok(next.version > first.version);
});

test("a push to a branch the site's lock follows starts the site's lock update", async () => {
  const h = harness();
  await h.agent();
  const push = (ref) => h.pipeline.webhook("push", { ref, repository: { full_name: REPO, default_branch: "main" } });
  assert.equal(await push("refs/heads/feat-x"), "ignored");
  assert.equal(await push("refs/heads/main"), "update shop");
  assert.deepEqual(h.of("dispatch"), [["dispatch", SITE, "flake-update.yml", "main", { inputs: "shop" }]]);
});

test("an agent that knows everything is held until something changes", async () => {
  const h = harness();
  const { version } = await h.agent();
  let answered = false;
  const held = h.pipeline
    .sync("node1", { version, flake: `github:${SITE}`, apps: [{ app: "shop", repo: REPO, slots: 2 }], previews: [] }, 60_000)
    .then((r) => ((answered = true), r));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(answered, false);
  await h.pr("opened");
  assert.equal((await held).previews.length, 1);
});

test("which inputs follow a branch", () => {
  const lock = {
    root: "root",
    nodes: {
      root: { inputs: { a: "a", b: "b", c: "c", d: ["a", "x"], e: "e" } },
      a: { original: { type: "github", owner: "Acme", repo: "Shop" } },
      b: { original: { type: "github", owner: "acme", repo: "shop", ref: "stable" } },
      c: { original: { type: "git", url: "ssh://git@github.com/acme/shop", ref: "main" } },
      e: { original: { type: "git", url: "https://github.com/acme/shop-extras.git" } },
    },
  };
  assert.deepEqual(trackingInputs(lock, "acme/shop", "main", "main"), ["a", "c"]);
  assert.deepEqual(trackingInputs(lock, "acme/shop", "stable", "main"), ["b"]);
});

test("flake URLs, hostnames and comments", async () => {
  assert.deepEqual(parseFlakeUrl("github:acme/cluster"), { repo: "acme/cluster", ref: null });
  assert.deepEqual(parseFlakeUrl("github:acme/cluster/prod"), { repo: "acme/cluster", ref: "prod" });
  assert.equal(parseFlakeUrl("git+https://example.com/x"), null);
  assert.equal(await previewLabel("shop", "feat-x"), "feat-x-shop");
  const slashed = await previewLabel("shop", "feat/x");
  assert.match(slashed, /^feat-x-[0-9a-f]{6}-shop$/);
  const long = await previewLabel("shop", "x".repeat(80));
  assert.equal(long.length, 63);
  assert.notEqual(long, await previewLabel("shop", "x".repeat(81)));
  assert.match(await previewHost("shop", "Ünï", "p.example.com"), /^n-[0-9a-f]{6}-shop\.p\.example\.com$/);
  const body = renderComment({ id: "shop/x", app: "shop", sha: "abcdef0123", host: "h", state: "live", closing: true });
  assert.match(body, /Removed/);
  assert.doesNotMatch(body, /https:\/\/h/);
});

test("webhook signatures and agent tokens", async () => {
  // GitHub's own documented example.
  const sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
  assert.equal(await verifySignature("It's a Secret to Everybody", "Hello, World!", sig), true);
  assert.equal(await verifySignature("another", "Hello, World!", sig), false);
  assert.equal(await verifySignature("It's a Secret to Everybody", "Hello, World?", sig), false);
  assert.equal(await verifySignature("It's a Secret to Everybody", "Hello, World!", undefined), false);
  assert.equal(await verifySignature("", "Hello, World!", sig), false);
  const env = { AGENT_TOKENS: JSON.stringify({ aaa: "node1", bbb: "node2" }) };
  assert.equal(nodeFor(env, "Bearer bbb"), "node2");
  assert.equal(nodeFor(env, "Bearer bb"), null);
  assert.equal(nodeFor(env, null), null);
  assert.equal(nodeFor({}, "Bearer aaa"), null);
});

test("the App signs in with the key as GitHub hands it out, and keeps the token", async () => {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const { createPrivateKey } = await import("node:crypto");
  const pkcs8 = Buffer.from(await crypto.subtle.exportKey("pkcs8", privateKey));
  const pem8 = `-----BEGIN PRIVATE KEY-----\n${pkcs8.toString("base64")}\n-----END PRIVATE KEY-----`;
  const pem1 = createPrivateKey(pem8).export({ type: "pkcs1", format: "pem" });
  assert.deepEqual(Buffer.from(pemToPkcs8(pem1)), pkcs8);

  const seen = [];
  const gh = new GitHub({
    appId: 42,
    privateKey: pem1.replace(/\n/g, "\\n"),
    now: () => 1_700_000_000_000,
    fetch: async (url, init) => {
      seen.push([init.method, url, init.headers.Authorization]);
      const body = url.endsWith("/installation") ? { id: 9 } : url.endsWith("/access_tokens") ? { token: "ghs_x" } : { id: 5 };
      return new Response(JSON.stringify(body));
    },
  });
  assert.equal(await gh.upsertComment("acme/shop", 7, null, "hi"), 5);
  await gh.setStatus("acme/shop", "abc", { state: "success", context: "c", description: "d" });
  assert.deepEqual(seen.map((s) => `${s[0]} ${new URL(s[1]).pathname}`), [
    "GET /repos/acme/shop/installation",
    "POST /app/installations/9/access_tokens",
    "POST /repos/acme/shop/issues/7/comments",
    "POST /repos/acme/shop/statuses/abc",
  ]);
  assert.equal(seen[2][2], "Bearer ghs_x");
  const [head, claims, sig] = seen[0][2].slice("Bearer ".length).split(".");
  const fromB64 = (s) => Buffer.from(s, "base64url");
  assert.deepEqual(JSON.parse(fromB64(claims)), { iat: 1_700_000_000 - 60, exp: 1_700_000_000 + 540, iss: "42" });
  assert.ok(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, fromB64(sig), Buffer.from(`${head}.${claims}`)));
});
