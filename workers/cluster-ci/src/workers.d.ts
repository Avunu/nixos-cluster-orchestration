// The Workers runtime, as far as this Worker uses it. This stands in for
// @cloudflare/workers-types (or `wrangler types`): the repository's check type-checks
// in the Nix sandbox, with no npm and no network, and nixpkgs does not package those
// types. Everything else the Worker uses (fetch, Request, Response, crypto) is
// TypeScript's own WebWorker library. Declared here is only what src/ touches; a
// method the code starts to use has to be added.

interface DurableObjectId {
  toString(): string;
}

interface DurableObjectStorage {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
}

interface DurableObjectState {
  readonly id: DurableObjectId;
  readonly storage: DurableObjectStorage;
}

// A Durable Object's public methods as its stub offers them: each over RPC, so each
// answers with a promise.
type DurableObjectStub<T> = {
  [K in keyof T as T[K] extends (...args: never[]) => unknown ? K : never]: T[K] extends (...args: infer A) => infer R
    ? (...args: A) => Promise<Awaited<R>>
    : never;
};

interface DurableObjectNamespace<T = unknown> {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub<T>;
}

declare module "cloudflare:workers" {
  export abstract class DurableObject<Env = unknown> {
    protected ctx: DurableObjectState;
    protected env: Env;
    constructor(ctx: DurableObjectState, env: Env);
  }
}
