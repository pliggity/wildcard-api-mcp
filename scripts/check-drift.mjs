#!/usr/bin/env node
/**
 * Reports when an upstream API description has moved on from what a manifest
 * was written against.
 *
 * Nothing here runs at request time — the Worker never fetches docs. This is a
 * maintenance command you run when you choose, so a refresh is a decision
 * rather than something that silently changes behaviour under you.
 */
import { readFileSync } from "node:fs";

const apis = JSON.parse(readFileSync("apis.json", "utf8"));
const tracked = apis.filter((a) => a.spec);
const untracked = apis.filter((a) => !a.spec);

if (!tracked.length) {
  console.log("No manifests record a spec source yet.");
  process.exit(0);
}

let drifted = 0;

for (const api of tracked) {
  const { source, packageVersion } = api.spec;

  if (source.startsWith("npm:")) {
    const pkg = source.slice(4);
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
    if (!res.ok) {
      console.log(`  ${api.id}: could not reach npm (${res.status})`);
      continue;
    }
    const latest = (await res.json())["dist-tags"]?.latest;
    if (latest === packageVersion) {
      console.log(`  ${api.id}: current (${packageVersion})`);
    } else {
      drifted++;
      console.log(`  ${api.id}: DRIFTED — manifest built from ${packageVersion}, npm now has ${latest}`);
      console.log(`      review: https://www.npmjs.com/package/${pkg}?activeTab=versions`);
    }
    continue;
  }

  if (source.startsWith("http")) {
    const res = await fetch(source);
    if (!res.ok) {
      console.log(`  ${api.id}: could not fetch spec (${res.status})`);
      continue;
    }
    const body = await res.text();
    const digest = [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)))]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    if (digest === api.spec.sha256) console.log(`  ${api.id}: current (spec unchanged)`);
    else {
      drifted++;
      console.log(`  ${api.id}: DRIFTED — spec at ${source} no longer matches the saved copy`);
    }
    continue;
  }

  console.log(`  ${api.id}: unknown spec source type "${source}"`);
}

if (untracked.length) {
  console.log(`\nNot tracked (no spec recorded): ${untracked.map((a) => a.id).join(", ")}`);
}
console.log(drifted ? `\n${drifted} manifest(s) may need review.` : "\nEverything matches what it was written from.");
