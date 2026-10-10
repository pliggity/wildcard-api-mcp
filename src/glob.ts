/**
 * Path glob where `*` matches within one segment and `**` matches across
 * segments. Used by deny rules, so it fails closed on a malformed pattern.
 *
 * Matched with a bottom-up DP table rather than a compiled RegExp: deny
 * patterns are trusted (hardcoded presets or the manifest), but the path being
 * tested comes from whatever the model passes to call_api — untrusted, and
 * potentially injected via API response content. A RegExp with adjacent
 * wildcards can backtrack catastrophically on an adversarial path; the table
 * is exactly (tokens + 1) * (path.length + 1) cells, each filled in constant
 * time, whatever shape the pattern has. Iterative, so no input can exhaust the
 * stack either.
 */

type Token = { type: "lit"; value: string } | { type: "seg" } | { type: "star" };

function tokenize(pattern: string): Token[] {
  return pattern
    .split(/(\*\*|\*)/)
    .filter((part) => part !== "")
    .map((part): Token => {
      if (part === "**") return { type: "star" };
      if (part === "*") return { type: "seg" };
      return { type: "lit", value: part };
    });
}

export function pathMatches(pattern: string, path: string): boolean {
  const tokens = tokenize(pattern);
  const n = path.length;
  // next[s]: whether tokens[t+1..] match path[s..]. Filled from the end.
  let next = new Uint8Array(n + 1);
  next[n] = 1;
  for (let t = tokens.length - 1; t >= 0; t--) {
    const token = tokens[t];
    const cur = new Uint8Array(n + 1);
    for (let s = n; s >= 0; s--) {
      if (token.type === "lit") {
        const end = s + token.value.length;
        cur[s] = end <= n && next[end] && path.startsWith(token.value, s) ? 1 : 0;
      } else if (token.type === "seg") {
        // "*": zero characters, or one non-'/' character and still in "*".
        cur[s] = next[s] || (s < n && path[s] !== "/" && cur[s + 1]) ? 1 : 0;
      } else {
        // "**": zero characters, or one of any kind and still in "**".
        cur[s] = next[s] || (s < n && cur[s + 1]) ? 1 : 0;
      }
    }
    next = cur;
  }
  return next[0] === 1;
}
