// What the tests use of Node. This stands in for @types/node, for the reason
// src/workers.d.ts stands in for the Workers types: the check has no npm. Only what
// test/ calls is declared, as Node documents it.

interface Buffer extends Uint8Array<ArrayBuffer> {
  toString(encoding?: "utf8" | "base64" | "base64url"): string;
}

declare const Buffer: {
  from(data: ArrayBuffer | Uint8Array): Buffer;
  from(text: string, encoding?: "utf8" | "base64" | "base64url"): Buffer;
};

// JSON.parse turns what it is given into a string first, so Node's Buffer is read as
// the text it holds. TypeScript's own declaration takes a string only.
interface JSON {
  parse(text: Buffer): unknown;
}

declare module "node:assert/strict" {
  const assert: {
    ok(value: unknown, message?: string): void;
    equal(actual: unknown, expected: unknown, message?: string): void;
    notEqual(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    match(value: string, regExp: RegExp, message?: string): void;
    doesNotMatch(value: string, regExp: RegExp, message?: string): void;
  };
  export default assert;
}

declare module "node:test" {
  export function test(name: string, fn: () => void | Promise<void>): void;
}

declare module "node:fs" {
  export function readFileSync(path: string | URL): Buffer;
}

declare module "node:crypto" {
  interface KeyObject {
    export(options: { type: "pkcs1" | "pkcs8"; format: "pem" }): string;
  }
  export function createPrivateKey(key: string): KeyObject;
}
