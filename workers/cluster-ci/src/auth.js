// Which node an agent's request speaks for.

function sameSecret(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// Which node a bearer token speaks for. Every entry is compared, so the time taken
// does not say which one matched.
export function nodeFor(env, header) {
  const token = /^Bearer (.+)$/.exec(header ?? "")?.[1];
  if (!token) return null;
  let node = null;
  for (const [known, name] of Object.entries(JSON.parse(env.AGENT_TOKENS || "{}"))) {
    if (sameSecret(known, token)) node = name;
  }
  return node;
}
