// Shared plumbing for the topology e2e: process supervision, port allocation,
// databases, and a tiny assertion reporter.
//
// Processes, not containers. `discovery` has no Dockerfile,
// discovery is a Next app over a SQLite file, and every assertion here is an
// HTTP fact — so an image build would buy nothing and cost two Dockerfiles and
// several minutes per run. Postgres is the exception, because it is already a
// container on this machine. `server/crates/farm/tests/farm_hub_e2e.rs` spawns
// the real hub binary the same way; this is that idea with more of the system
// in the picture.

import { spawn, execSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The monorepo root, derived from this file rather than hardcoded: the four
// repos are siblings, and this harness is the one thing that needs more than one
// of them checked out at once.
/** The server repo root — this file lives in `<repo>/e2e/`. */
export const ROOT = fileURLToPath(new URL("..", import.meta.url)).replace(/[\/]$/, "");
export const PG = "postgres://postgres:postgres@localhost:5432";

const children = [];
const tempDirs = [];
let nextPort = 3400;

export function port() {
  return nextPort++;
}

export function tempDir(prefix) {
  const d = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(d);
  return d;
}

/** Create a database, dropping any leftover of the same name first. */
export function dbName(name) {
  // Identifiers, not labels: a hub called "hub-a" would produce
  // `wavvon_e2e_hub-a`, which Postgres reads as a subtraction.
  return `wavvon_e2e_${name.replace(/[^a-zA-Z0-9]+/g, "_")}`;
}

export function freshDb(name) {
  // A run that inherits the previous run's rows is a run whose failures are
  // about history rather than about the code. Learned the hard way on the live
  // browser suite, whose README used to claim a persistent database was fine.
  const db = dbName(name);
  psql(`DROP DATABASE IF EXISTS ${db}`);
  psql(`CREATE DATABASE ${db}`);
  return `${PG}/${db}`;
}

export function psql(sql) {
  execSync(
    `docker exec wavvon-pg psql -U postgres -c ${JSON.stringify(sql)}`,
    { stdio: "pipe" },
  );
}

/** Start a long-running process and keep it for teardown. */
export function start(name, cmd, args, opts = {}) {
  const child = spawn(cmd, args, {
    cwd: opts.cwd,
    env: { ...process.env, ...(opts.env ?? {}) },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const log = [];
  const keep = (buf) => {
    const s = buf.toString();
    log.push(s);
    if (log.length > 400) log.shift();
    if (process.env.E2E_VERBOSE) process.stdout.write(`[${name}] ${s}`);
  };
  child.stdout.on("data", keep);
  child.stderr.on("data", keep);
  const entry = { name, child, log };
  children.push(entry);
  return entry;
}

/** Run a command to completion, keeping its output for the failure message. */
export function run(name, cmd, args, opts = {}) {
  const entry = start(name, cmd, args, opts);
  return new Promise((resolve) => {
    entry.child.on("close", (code) => resolve({ code, log: entry.log.join("") }));
  });
}

/** Poll a URL until it answers, or fail with the process's own output. */
export async function waitForHttp(entry, url, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return;
    } catch { /* not up yet */ }
    if (entry?.child.exitCode !== null && entry?.child.exitCode !== undefined) {
      throw new Error(
        `${entry.name} exited (${entry.child.exitCode}) before answering ${url}\n` +
          entry.log.join(""),
      );
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(
    `${entry?.name ?? url} never answered ${url} in ${timeoutMs}ms\n` +
      (entry?.log.join("") ?? ""),
  );
}

export function teardown() {
  for (const { child } of children) {
    // Kill the tree, not just the process: on Windows a child that spawned its
    // own workers (next dev does) outlives a plain kill and keeps the port.
    try { execSync(`taskkill /PID ${child.pid} /T /F`, { stdio: "ignore" }); } catch {}
    try { child.kill("SIGKILL"); } catch { /* already gone */ }
  }
  // The hub locks its own binary on Windows while running, so give the kills a
  // moment to land before anything tries to rebuild.
  try { execSync("taskkill //IM wavvon-hub.exe //F", { stdio: "ignore" }); } catch {}
  try { execSync("taskkill //IM wavvon-farm.exe //F", { stdio: "ignore" }); } catch {}
  for (const d of tempDirs) {
    try { rmSync(d, { recursive: true, force: true }); } catch {}
  }
}

// ── assertions ──────────────────────────────────────────────────────────────

const results = [];

export async function scenario(name, fn) {
  process.stdout.write(`\n▶ ${name}\n`);
  try {
    await fn();
    results.push({ name, ok: true });
    process.stdout.write(`  ✓ ${name}\n`);
  } catch (e) {
    results.push({ name, ok: false, error: e });
    process.stdout.write(`  ✗ ${name}\n    ${e.message?.split("\n")[0]}\n`);
  }
}

export function check(cond, msg) {
  if (!cond) throw new Error(msg);
}

export function checkEq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg}\n    expected: ${expected}\n    actual:   ${actual}`);
  }
}

export function report() {
  const failed = results.filter((r) => !r.ok);
  process.stdout.write(
    `\n${results.length - failed.length}/${results.length} scenarios passed\n`,
  );
  for (const f of failed) {
    process.stdout.write(`\n✗ ${f.name}\n${f.error.stack ?? f.error.message}\n`);
  }
  return failed.length === 0;
}

// ── hub helpers ─────────────────────────────────────────────────────────────

export async function json(url, init) {
  const res = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  return { status: res.status, body };
}

export function hubBinary() {
  return join(ROOT, "target/debug/wavvon-hub.exe");
}

// ── identities ──────────────────────────────────────────────────────────────
//
// Node's own Ed25519 rather than importing `@wavvon/core`: this script sits
// above the repos and must not depend on one of them being built. The hub only
// ever sees a hex pubkey and a hex signature, so the algorithm is the contract.

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign } from "node:crypto";

/** The same identity every time, from a 32-byte seed — the shape the browser
 *  suite's owner is defined as. PKCS8 for Ed25519 is a fixed 16-byte header
 *  then the raw seed, so no key-derivation library is needed for it. */
export function identityFromSeed(seedHex) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const raw = createPublicKey(privateKey).export({ type: "spki", format: "der" }).subarray(12);
  return {
    pubkey: raw.toString("hex"),
    sign: (bytes) => nodeSign(null, bytes, privateKey).toString("hex"),
  };
}

export function identity() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // SPKI DER for Ed25519 is a 12-byte header then the raw 32-byte key.
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(12);
  return {
    pubkey: raw.toString("hex"),
    sign: (bytes) => nodeSign(null, bytes, privateKey).toString("hex"),
  };
}

/** Full challenge-response against a hub, returning its session token. */
export async function authenticate(hubUrl, id, extra = {}) {
  const ch = await json(`${hubUrl}/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({ public_key: id.pubkey }),
  });
  check(ch.status === 200, `challenge failed: ${ch.status} ${JSON.stringify(ch.body)}`);
  const signature = id.sign(Buffer.from(ch.body.challenge, "hex"));
  const v = await json(`${hubUrl}/auth/verify`, {
    method: "POST",
    body: JSON.stringify({
      public_key: id.pubkey,
      challenge: ch.body.challenge,
      signature,
      ...extra,
    }),
  });
  return v;
}

// ── booting the things under test ───────────────────────────────────────

/** Boot a hub with its own database, port pair, work dir and owner. */
export async function hub(name, owner) {
  const httpPort = port();
  const voicePort = port();
  // `localhost`, not `127.0.0.1`: identical for the HTTP assertions here, but
  // the web client demonstrably misbehaves against a hub reached by IP — the
  // same spec is 5/5 in 22s on localhost and 3 failures in 3.3 minutes on
  // 127.0.0.1, with isolated working directories both times. Nobody pointing a
  // browser at one of these hubs should have to rediscover that.
  const url = `http://localhost:${httpPort}`;
  // Its own directory and database, kept so the hub can be stopped and started
  // again as the *same* hub — identity, alliances and all. A hub that goes down
  // and comes back is an ordinary thing for a federated network, so the harness
  // has to be able to do it.
  const cwd = tempDir(`wavvon-e2e-${name}-`);
  const env = {
    WAVVON_DATABASE_URL: freshDb(name),
    WAVVON_HTTP_PORT: String(httpPort),
    WAVVON_VOICE_UDP_PORT: String(voicePort),
    WAVVON_PUBLIC_URL: url,
    WAVVON_OWNER_PUBKEY: owner.pubkey,
    // API-only: nothing here drives a browser, and a hub that insists on a
    // web-client directory it has not got refuses to start.
    WAVVON_WEB_CLIENT_DIR: "",
  };
  const boot = async () => {
    const entry = start(name, hubBinary(), [], { cwd, env });
    await waitForHttp(entry, `${url}/info`);
    return entry;
  };
  const h = { name, url, entry: await boot(), owner };
  h.stop = () => new Promise((resolve) => {
    h.entry.child.once("close", resolve);
    h.entry.child.kill("SIGKILL");
  });
  h.start = async () => {
    h.entry = await boot();
  };
  return h;
}

/** Boot a farm that can spawn its own hubs, with `admin` as its admin. */
export async function farm(name, admin) {
  const httpPort = port();
  const url = `http://localhost:${httpPort}`;
  const entry = start(name, join(ROOT, "target/debug/wavvon-farm.exe"), [], {
    // Its own directory, for the same reason a hub needs one: the farm writes
    // its identity beside itself.
    cwd: tempDir(`wavvon-e2e-${name}-`),
    env: {
      WAVVON_DATABASE_URL: freshDb(name),
      WAVVON_HTTP_PORT: String(httpPort),
      WAVVON_FARM_URL: url,
      WAVVON_HUB_BIN: hubBinary(),
      // Well clear of the hub ports this script hands out itself, and of the
      // other farm's block.
      WAVVON_HUB_BASE_PORT: String(port() + 500),
      WAVVON_HUBS_DIR: tempDir(`wavvon-e2e-${name}-hubs-`),
      // Without this the farm has no admin, `creation_policy` is 'admin_only',
      // and every hub creation is refused with no way to appoint anyone.
      WAVVON_FARM_ADMIN_PUBKEY: admin.pubkey,
    },
  });
  await waitForHttp(entry, `${url}/farm/info`);
  return { name, url, entry, admin };
}

/** The live browser suite's deterministic owner, read out of the suite itself
 *  rather than copied: a changed seed would otherwise leave this stage booting
 *  a hub the suite does not own, and the failure would be a UI timeout.
 *
 *  The seed comes back too, because a farm-hosted hub cannot be handed an
 *  owner — the farm makes whoever created the hub its owner, so the harness
 *  has to *be* that identity, which means signing as it. */

/** Authenticate against a farm (its own challenge/verify pair). */
export async function farmToken(farmUrl, id) {
  const ch = await json(`${farmUrl}/auth/challenge`, {
    method: "POST",
    body: JSON.stringify({ public_key: id.pubkey }),
  });
  check(ch.status === 200, `farm challenge: ${ch.status} ${JSON.stringify(ch.body)}`);
  const signature = id.sign(Buffer.from(ch.body.challenge, "hex"));
  const v = await json(`${farmUrl}/auth/verify`, {
    method: "POST",
    body: JSON.stringify({
      public_key: id.pubkey,
      challenge: ch.body.challenge,
      signature,
    }),
  });
  check(v.status === 200, `farm verify: ${v.status} ${JSON.stringify(v.body)}`);
  return v.body.token;
}
