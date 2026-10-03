#!/usr/bin/env node
/**
 * Fails if package-lock.json holds any version published more recently than
 * the min-release-age in .npmrc. npm applies that window when it resolves new
 * versions; this catches a lockfile written by an older npm that ignores it.
 *
 * Usage: npm run check-age
 */
import { readFileSync } from "node:fs";

const npmrc = readFileSync(".npmrc", "utf8");
const days = Number(npmrc.match(/^\s*min-release-age\s*=\s*(\d+)/m)?.[1]);
if (!days) {
  console.log("No min-release-age in .npmrc; nothing to check.");
  process.exit(0);
}
const cutoff = Date.now() - days * 86_400_000;

const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const wanted = new Map();
for (const [path, meta] of Object.entries(lock.packages)) {
  if (!path || meta.link || !meta.resolved?.startsWith("https://registry.npmjs.org/")) continue;
  const name = meta.name ?? path.slice(path.lastIndexOf("node_modules/") + 13);
  if (!wanted.has(name)) wanted.set(name, new Set());
  wanted.get(name).add(meta.version);
}

const tooNew = [];
const queue = [...wanted];
async function worker() {
  for (let next; (next = queue.shift()); ) {
    const [name, versions] = next;
    const res = await fetch(`https://registry.npmjs.org/${name.replace("/", "%2f")}`);
    if (!res.ok) throw new Error(`${name}: registry returned ${res.status}`);
    const { time } = await res.json();
    for (const v of versions) {
      const published = Date.parse(time?.[v]);
      if (!published) throw new Error(`${name}@${v}: no publish time`);
      if (published > cutoff) tooNew.push(`${name}@${v} (published ${new Date(published).toISOString().slice(0, 10)})`);
    }
  }
}
await Promise.all(Array.from({ length: 8 }, worker));

if (tooNew.length) {
  console.error(`Published less than ${days} days ago:\n  ${tooNew.sort().join("\n  ")}`);
  process.exit(1);
}
console.log(`All ${wanted.size} locked packages are at least ${days} days old.`);
