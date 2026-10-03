/**
 * Path glob where `*` matches within one segment and `**` matches across
 * segments. Used by deny rules, so it fails closed on a malformed pattern.
 *
 * Matched with memoized DP rather than a compiled RegExp: deny patterns are
 * trusted (hardcoded presets or the manifest), but the path being tested
 * comes from whatever the model passes to call_api — untrusted, and
 * potentially injected via API response content. A pattern with adjacent
 * wildcards compiled to RegExp can hit catastrophic backtracking on an
 * adversarial path; memoization bounds this to tokens.length * path.length
 * subproblems regardless of how the pattern is shaped.
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
  const memo = new Map<string, boolean>();

  function match(t: number, s: number): boolean {
    const key = `${t}:${s}`;
    const cached = memo.get(key);
    if (cached !== undefined) return cached;

    let result: boolean;
    const token = tokens[t];
    if (!token) {
      result = s === path.length;
    } else if (token.type === "lit") {
      result = path.startsWith(token.value, s) && match(t + 1, s + token.value.length);
    } else if (token.type === "seg") {
      // Consume zero or more non-'/' characters.
      let end = s;
      result = match(t + 1, end);
      while (!result && end < path.length && path[end] !== "/") {
        end++;
        result = match(t + 1, end);
      }
    } else {
      // "**": consume zero or more characters of any kind, '/' included.
      let end = s;
      result = match(t + 1, end);
      while (!result && end < path.length) {
        end++;
        result = match(t + 1, end);
      }
    }

    memo.set(key, result);
    return result;
  }

  return match(0, 0);
}
