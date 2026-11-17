// What a node may read at GitHub (src/access.js), and what a stranger's installation of
// the public App causes: nothing.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { FLOOR_LEFT_MS, MIN_LEFT_MS, PERMISSIONS, githubRepo, siteRepos } from "../src/access.js";
import { GitHub } from "../src/github.js";
import { handle } from "../src/http.js";
import { SITE, harness } from "./harness.js";

const MIN = 60 * 1000;
const ENV = { AGENT_TOKENS: JSON.stringify({ "tok-1": "node1" }), GITHUB_WEBHOOK_SECRET: "hook" };

const ask = (h, { token = "tok-1", body = {} } = {}) =>
  handle(
    new Request("https://ci.example.com/agent/token", {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: JSON.stringify(body),
    }),
    ENV,
    h.pipeline,
  );

test("only a node's own bearer token is answered, and nothing it says is read", async () => {
  const h = harness();
  assert.equal((await ask(h, { token: null })).status, 401);
  assert.equal((await ask(h, { token: "tok-2" })).status, 401);
  assert.deepEqual(h.calls, []);
  const res = await ask(h, { body: { repositories: ["mallory/secret"], site: "mallory/cluster", permissions: { contents: "write" } } });
  assert.equal(res.status, 200);
  const got = await res.json();
  assert.equal(got.site, SITE);
  assert.deepEqual(
    got.tokens.map((t) => t.repositories),
    [["acme/cluster", "acme/other", "acme/shop"]],
  );
  assert.doesNotMatch(JSON.stringify(h.calls), /mallory/);
});

test("the token is narrowed by GitHub: read-only, and the site's repositories of that owner", async () => {
  const h = harness({ installs: { acme: 1, customer: 2 }, extra: ["customer/content"] });
  const got = await h.pipeline.tokens();
  // Names without the owner, as GitHub takes them, and the two permissions and no more.
  assert.deepEqual(h.of("mint"), [
    ["mint", 1, ["cluster", "other", "shop"], { contents: "read", metadata: "read" }],
    ["mint", 2, ["content"], { contents: "read", metadata: "read" }],
  ]);
  assert.deepEqual(PERMISSIONS, { contents: "read", metadata: "read" });
  assert.deepEqual(got, {
    site: SITE,
    ref: "main",
    tokens: [
      {
        owner: "acme",
        token: "ghs_1_1",
        expires_at: new Date(h.clock.t + 60 * MIN).toISOString(),
        repositories: ["acme/cluster", "acme/other", "acme/shop"],
      },
      { owner: "customer", token: "ghs_2_2", expires_at: new Date(h.clock.t + 60 * MIN).toISOString(), repositories: ["customer/content"] },
    ],
    uncovered: [],
    errors: [],
  });
  // Read from the site's repository, at the branch the nodes deploy.
  assert.deepEqual(h.of("read"), [
    ["read", SITE, "flake.lock", "main"],
    ["read", SITE, "github-repos.json", "main"],
  ]);
});

test("the set is the site, its lock's github.com repositories and its github-repos.json", () => {
  const f = JSON.parse(readFileSync(new URL("./site-repos.json", import.meta.url)));
  assert.deepEqual(siteRepos(f.site, f.lock, f.extra), f.expect);
  assert.deepEqual(siteRepos("acme/cluster", {}, undefined), ["acme/cluster"]);
  assert.equal(githubRepo({ type: "github", owner: "a", repo: "b" }), "a/b");
  assert.equal(githubRepo({ type: "git", url: "https://github.com/a/b.git?ref=x" }), "a/b");
  assert.equal(githubRepo({ type: "git", url: "https://evil.example.net/github.com/a/b" }), null);
  assert.equal(githubRepo({ type: "indirect", id: "nixpkgs" }), null);
  assert.equal(githubRepo(undefined), null);
});

test("a repository no installation covers is named, not dropped, and gets no token", async () => {
  const lock = {
    root: "root",
    nodes: {
      shop: { locked: { type: "github", owner: "acme", repo: "shop" } },
      other: { locked: { type: "github", owner: "acme", repo: "other" } },
      app: { locked: { type: "github", owner: "customer", repo: "app" } },
      nixpkgs: { locked: { type: "github", owner: "NixOS", repo: "nixpkgs" } },
    },
  };
  // acme chose repositories, and `other` is not one of them; customer has not installed.
  const h = harness({ lock, uncoveredRepos: ["acme/other"] });
  const got = await h.pipeline.tokens();
  assert.deepEqual(got.uncovered, ["acme/other", "customer/app", "NixOS/nixpkgs"]);
  assert.deepEqual(got.tokens.map((t) => [t.owner, t.repositories]), [["acme", ["acme/cluster", "acme/shop"]]]);
  assert.deepEqual(h.of("mint"), [["mint", 1, ["cluster", "shop"], PERMISSIONS]]);
  // Only an owner with an installation is asked about.
  assert.deepEqual(h.of("covers").map((c) => c[1]).sort(), ["acme/cluster", "acme/other", "acme/shop"]);

  // The customer installs the App: GitHub says so, and the next answer has its token.
  h.state.installs = { acme: 1, customer: 5 };
  assert.equal(await h.pipeline.webhook("installation", { action: "created", installation: { id: 5 } }), "noted");
  const next = await h.pipeline.tokens();
  assert.deepEqual(next.uncovered, ["acme/other", "NixOS/nixpkgs"]);
  assert.deepEqual(next.tokens.map((t) => t.owner), ["acme", "customer"]);
});

test("a stranger's installation of the public App causes nothing", async () => {
  const h = harness({ installs: { acme: 1, mallory: 66 } });
  // No token, and its installation is not even asked about.
  const got = await h.pipeline.tokens();
  assert.deepEqual(got.tokens.map((t) => t.owner), ["acme"]);
  assert.doesNotMatch(JSON.stringify([got, h.calls]), /mallory|66/);

  // Its webhooks: a push, a pull request, a deleted branch, a comment, an installation.
  h.calls.length = 0;
  await h.agent();
  assert.equal(await h.push("mallory/secret"), "ignored: not a repository of this site");
  assert.equal(await h.pr("opened", { repo: "mallory/secret" }), "ignored: no app previews this repository");
  const hook = (event, extra) => h.pipeline.webhook(event, { repository: { full_name: "mallory/secret" }, ...extra });
  assert.equal(await hook("delete", { ref_type: "branch", ref: "feat-x" }), "ignored");
  assert.equal(
    await hook("issue_comment", { action: "created", issue: { number: 7, pull_request: {} }, comment: { body: "/preview reset", author_association: "OWNER" } }),
    "ignored",
  );
  assert.equal(await h.pipeline.webhook("installation_repositories", { action: "added", installation: { id: 66 } }), "noted");
  assert.deepEqual(h.calls, []);
  assert.deepEqual(h.stored.state.previews, {});
  assert.equal(h.stored.state.deploySeq, 0);

  // Even when a node says one of its apps previews the stranger's repository: what
  // the site uses is read from the site, not from a node.
  await h.agent([], 0, "node1", "mallory/secret");
  assert.equal(await h.pr("opened", { repo: "mallory/secret" }), "ignored: not a repository of this site");
  assert.deepEqual(h.of("tunnel"), []);
  assert.deepEqual(h.of("comment"), []);
  assert.deepEqual(h.of("dispatch"), []);
  assert.deepEqual(h.stored.state.previews, {});
});

test("a node's report of its flake does not say which repository is the site's", async () => {
  const h = harness();
  await h.pipeline.sync("node1", { version: 0, flake: "github:mallory/cluster", apps: [], previews: [] });
  // Not a deploy, and the stranger's lock is never read nor its workflow started.
  assert.equal(await h.push("mallory/cluster"), "ignored: not a repository of this site");
  assert.equal(await h.push("acme/shop"), "update shop");
  assert.deepEqual(h.of("dispatch").map((c) => c[1]), [SITE]);
  assert.doesNotMatch(JSON.stringify(h.of("read")), /mallory/);
  assert.equal((await h.pipeline.tokens()).site, SITE);

  // And a Worker that was not told has no site at all.
  const bare = harness({ site: null });
  await bare.agent();
  assert.equal(await bare.push(SITE), "ignored: SITE_FLAKE is not set");
  const res = await ask(bare);
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /SITE_FLAKE/);
  assert.deepEqual(bare.calls, []);
});

test("a token is minted once and handed out until it has under half an hour left", async () => {
  const h = harness();
  const first = (await h.pipeline.tokens()).tokens[0];
  h.clock.t += 20 * MIN;
  assert.deepEqual((await h.pipeline.tokens()).tokens[0], first);
  h.clock.t += 10 * MIN - 1;
  assert.deepEqual((await h.pipeline.tokens()).tokens[0], first);
  assert.equal(h.of("mint").length, 1);
  // Thirty minutes left is the last it is handed out with.
  h.clock.t += 2;
  const second = (await h.pipeline.tokens()).tokens[0];
  assert.equal(second.token, "ghs_1_2");
  assert.equal(h.of("mint").length, 2);
  for (const t of [first, second]) assert.ok(Date.parse(t.expires_at) - h.clock.t >= MIN_LEFT_MS - 2);
  // Kept in storage, so a Durable Object that was put to sleep does not mint again.
  assert.equal(h.stored.access.tokens["acme#1"].token, "ghs_1_2");
});

test("GitHub refusing a new token leaves the old one, down to a quarter of an hour", async () => {
  const h = harness();
  await h.pipeline.tokens();
  h.fail.mint = true;
  h.clock.t += 60 * MIN - FLOOR_LEFT_MS;
  const held = await h.pipeline.tokens();
  assert.equal(held.tokens[0].token, "ghs_1_1");
  assert.deepEqual(held.errors.map((e) => e.owner), ["acme"]);
  h.clock.t += 1;
  const gone = await h.pipeline.tokens();
  assert.deepEqual(gone.tokens, []);
  assert.match(gone.errors[0].error, /HTTP 500/);
  h.fail.mint = false;
  assert.equal((await h.pipeline.tokens()).tokens[0].token, "ghs_1_2");
});

test("the set follows the site's branch: at its push, and every few minutes without one", async () => {
  const h = harness();
  await h.pipeline.tokens();
  const more = structuredClone(h.state.lock);
  more.nodes.extra = { locked: { type: "github", owner: "acme", repo: "addons" } };
  h.state.lock = more;
  // Not read again on every question.
  h.calls.length = 0;
  assert.deepEqual((await h.pipeline.tokens()).tokens[0].repositories, ["acme/cluster", "acme/other", "acme/shop"]);
  assert.deepEqual(h.calls, []);
  // The merge is a push to the site's branch.
  assert.equal(await h.push(SITE), "deploy");
  const got = await h.pipeline.tokens();
  assert.deepEqual(got.tokens[0].repositories, ["acme/addons", "acme/cluster", "acme/other", "acme/shop"]);
  // A token names its repositories, so a new set is a new token.
  assert.equal(got.tokens[0].token, "ghs_1_2");
  // A repository that left the site leaves the next token, with no push heard of.
  h.state.lock = { root: "root", nodes: {} };
  h.clock.t += 5 * MIN;
  assert.deepEqual((await h.pipeline.tokens()).tokens[0].repositories, ["acme/cluster"]);
});

test("GitHub being away keeps the set that was read, and a set never read is an error", async () => {
  const h = harness();
  h.fail.site = true;
  const res = await ask(h);
  assert.equal(res.status, 502);
  assert.match((await res.json()).error, /could not be read/);
  assert.equal(await h.push("acme/shop"), "error");
  h.fail.site = false;
  await h.pipeline.tokens();
  h.fail.site = true;
  h.clock.t += 10 * MIN;
  const got = await (await ask(h)).json();
  assert.deepEqual(got.tokens[0].repositories, ["acme/cluster", "acme/other", "acme/shop"]);
});

test("what the App asks of GitHub for a narrowed token", async () => {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign"],
  );
  const pem = `-----BEGIN PRIVATE KEY-----\n${Buffer.from(await crypto.subtle.exportKey("pkcs8", privateKey)).toString("base64")}\n-----END PRIVATE KEY-----`;
  const seen = [];
  const gh = new GitHub({
    appId: 42,
    privateKey: pem,
    now: () => 1_700_000_000_000,
    fetch: async (url, init) => {
      const u = new URL(url);
      seen.push([init.method, u.pathname + u.search, init.body ? JSON.parse(init.body) : null, init.headers.Authorization]);
      if (u.pathname === "/app/installations") {
        const page = Number(u.searchParams.get("page"));
        return new Response(JSON.stringify(Array.from({ length: page === 1 ? 100 : 3 }, (_, i) => ({ id: page * 1000 + i, account: { login: `o${i}` } }))));
      }
      if (u.pathname === "/repos/acme/shop/installation") return new Response(JSON.stringify({ id: 9 }));
      if (u.pathname.endsWith("/installation")) return new Response("{}", { status: 404 });
      return new Response(JSON.stringify({ token: "ghs_n", expires_at: "2023-11-14T23:13:20Z" }));
    },
  });
  assert.equal((await gh.installations()).length, 103);
  assert.equal(await gh.repoInstallation("acme/shop"), 9);
  assert.equal(await gh.repoInstallation("acme/none"), null);
  assert.deepEqual(await gh.scopedToken(9, ["shop"], PERMISSIONS), { token: "ghs_n", expiresAt: Date.parse("2023-11-14T23:13:20Z") });
  assert.deepEqual(
    seen.map((s) => s.slice(0, 3)),
    [
      ["GET", "/app/installations?per_page=100&page=1", null],
      ["GET", "/app/installations?per_page=100&page=2", null],
      ["GET", "/repos/acme/shop/installation", null],
      ["GET", "/repos/acme/none/installation", null],
      ["POST", "/app/installations/9/access_tokens", { repositories: ["shop"], permissions: { contents: "read", metadata: "read" } }],
    ],
  );
  // As the App, with one signature for all of it.
  assert.equal(new Set(seen.map((s) => s[3])).size, 1);
  assert.equal(seen[0][3].split(".").length, 3);
});
