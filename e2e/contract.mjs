// The API contract against the real hub: every documented GET without path
// parameters is called on a fresh hub, as its owner, and the status and the
// JSON body are checked against Wavvon-docs' openapi.yaml.
//
// The SDKs are generated from that spec, and until this ran nothing compared
// it with what the hub serves: a route-path match was the only check, so a
// missing field or a wrong status reached the SDKs unnoticed.
//
// Usage:  node e2e/contract.mjs
//   OPENAPI_SPEC=<path to openapi.yaml>  use a local spec instead of the
//                                        Wavvon-docs commit in openapi.ref
//
// Known drift lives in contract-allowlist.json. It may only shrink: a new
// mismatch fails, and so does an allowlisted one that no longer happens.

import { hub, identity, authenticate, teardown } from "./lib.mjs";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const HERE = new URL(".", import.meta.url);

async function loadSpec() {
  let path = process.env.OPENAPI_SPEC;
  if (!path) {
    const ref = readFileSync(new URL("openapi.ref", HERE), "utf8").trim();
    const res = await fetch(`https://raw.githubusercontent.com/Wavvon/Wavvon-docs/${ref}/openapi.yaml`);
    if (!res.ok) throw new Error(`openapi.yaml @ ${ref}: HTTP ${res.status}`);
    path = join(tmpdir(), `wavvon-openapi-${ref}.yaml`);
    writeFileSync(path, await res.text());
  }
  // Python's YAML parser rather than a dependency: this directory has no
  // package.json, and PyYAML ships on the CI runners.
  const python = process.platform === "win32" ? "py" : "python3";
  const out = execFileSync(python, ["-c",
    "import json,sys,yaml; json.dump(yaml.safe_load(open(sys.argv[1], encoding='utf-8')), sys.stdout)",
    path], { maxBuffer: 1 << 28 });
  return JSON.parse(out);
}

function resolveRef(spec, ref) {
  return ref.replace(/^#\//, "").split("/").reduce((node, key) => node[key], spec);
}

/** Errors of `value` against an OpenAPI 3.0 schema: the subset the spec uses. */
function validate(spec, schema, value, at, errs) {
  if (!schema) return;
  if (schema.$ref) return validate(spec, resolveRef(spec, schema.$ref), value, at, errs);
  if (schema.allOf) {
    for (const s of schema.allOf) validate(spec, s, value, at, errs);
    return;
  }
  const alternatives = schema.oneOf ?? schema.anyOf;
  if (alternatives) {
    const ok = alternatives.some((s) => {
      const e = [];
      validate(spec, s, value, at, e);
      return e.length === 0;
    });
    if (!ok) errs.push(`${at}: matches none of its alternatives`);
    return;
  }
  if (value === null) {
    if (!schema.nullable && schema.type) errs.push(`${at}: null, not documented as nullable`);
    return;
  }
  const t = schema.type;
  const actual = Array.isArray(value) ? "array"
    : Number.isInteger(value) ? "integer"
    : typeof value;
  const fits = !t || t === actual || (t === "number" && actual === "integer");
  if (!fits) {
    errs.push(`${at}: ${actual}, documented as ${t}`);
    return;
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errs.push(`${at}: ${JSON.stringify(value)} is not one of the documented values`);
  }
  if (actual === "array") {
    value.forEach((v, i) => validate(spec, schema.items, v, `${at}[${i}]`, errs));
  } else if (actual === "object") {
    const props = schema.properties ?? {};
    for (const key of schema.required ?? []) {
      if (!(key in value)) errs.push(`${at}.${key}: required, missing`);
    }
    for (const [key, v] of Object.entries(value)) {
      if (props[key]) validate(spec, props[key], v, `${at}.${key}`, errs);
      else if (typeof schema.additionalProperties === "object") {
        validate(spec, schema.additionalProperties, v, `${at}.${key}`, errs);
      } else if (schema.properties && schema.additionalProperties !== true) {
        errs.push(`${at}.${key}: not in the spec`);
      }
    }
  }
}

const spec = await loadSpec();
const issues = new Set();
let checked = 0;
const skipped = [];

try {
  const owner = identity();
  const h = await hub("contract", owner);
  const token = (await authenticate(h.url, owner)).body.token;

  for (const [path, ops] of Object.entries(spec.paths)) {
    const op = ops.get;
    if (!op || path.includes("{")) continue;
    const name = `GET ${path}`;
    const params = (op.parameters ?? []).map((p) => (p.$ref ? resolveRef(spec, p.$ref) : p));
    // A required query is filled from its documented example; without one,
    // like a WebSocket upgrade, the operation is not something to call blind.
    const required = params.filter((p) => p.in === "query" && p.required);
    const example = (p) => p.example ?? p.schema?.example;
    if (path === "/ws" || required.some((p) => example(p) === undefined)) {
      skipped.push(name);
      continue;
    }
    checked++;
    const query = new URLSearchParams(required.map((p) => [p.name, String(example(p))]));
    const secured = (op.security ?? spec.security ?? []).length > 0;
    const res = await fetch(`${h.url}${path}${required.length ? `?${query}` : ""}`, {
      headers: secured ? { Authorization: `Bearer ${token}` } : {},
    });
    const documented = op.responses?.[String(res.status)] ?? op.responses?.default;
    if (!documented) {
      issues.add(`${name}: ${res.status} is not a documented response`);
      continue;
    }
    const schema = documented.content?.["application/json"]?.schema;
    if (!schema || res.status >= 300) continue;
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch {
      issues.add(`${name}: documented as JSON, body is not`);
      continue;
    }
    const errs = [];
    validate(spec, schema, body, "body", errs);
    // An array reports the same drift once per element; once is enough.
    for (const e of errs) issues.add(`${name}: ${e.replace(/\[\d+\]/g, "[]")}`);
  }
} finally {
  teardown();
}

const allowed = new Set(JSON.parse(readFileSync(new URL("contract-allowlist.json", HERE), "utf8")));
const fresh = [...issues].filter((i) => !allowed.has(i)).sort();
const gone = [...allowed].filter((i) => !issues.has(i)).sort();

for (const i of fresh) console.log(`✗ ${i}`);
for (const i of gone) console.log(`✗ fixed, remove from contract-allowlist.json: ${i}`);
console.log(`\n${checked} operations checked; skipped: ${skipped.join(", ")}`);
console.log(`${issues.size} mismatches, ${fresh.length} new, ${gone.length} fixed`);
if (process.env.CONTRACT_WRITE_ALLOWLIST) {
  writeFileSync(new URL("contract-allowlist.json", HERE), `${JSON.stringify([...issues].sort(), null, 2)}\n`);
  console.log("contract-allowlist.json rewritten");
}
process.exit(fresh.length || gone.length ? 1 : 0);
