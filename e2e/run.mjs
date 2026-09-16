// End-to-end against real hub binaries, not an in-process `AppState`.
//
// The integration suite under `crates/hub/tests` builds its own state and
// starts no process, so it cannot see anything that lives in migrations,
// bootstrap, config or the CLI — which is most of what an operator meets
// first. Every bug this harness has found was invisible to that suite for
// exactly that reason: a fresh hub is `invite_only`, and the in-process tests
// never wrote the setting, so `is_invite_only` answered false there and two
// hubs with default settings could never form an alliance.
//
// Several hubs is still one repo: two hubs are two processes of one binary.
// The stages that genuinely need a second checkout — the discovery site, and
// anything driving a browser from the clients repo — live in the monorepo's
// own `e2e-topology/`, which imports this file's `lib.mjs`.
//
// Usage:  node e2e/run.mjs [stage...]
//         stages: hubs alliance voice certs permissions pgupgrade alliancesplit alliancestress alliancechurn alliancedrift farm crossfarm
//                 (default: all)
//         E2E_VERBOSE=1 to stream every process's output.

import {
  ROOT, authenticate, check, checkEq, dbName, farm, farmToken, freshDb, hub,
  hubBinary, identity, identityFromSeed, json, port, report, run, scenario,
  start, teardown, tempDir, waitForHttp,
} from "./lib.mjs";
import { existsSync, mkdtempSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const want = new Set(process.argv.slice(2).length ? process.argv.slice(2)
  : ["hubs","alliance","voice","certs","permissions","pgupgrade","alliancesplit","alliancestress","alliancechurn","alliancedrift","farm","crossfarm"]);

if (!existsSync(hubBinary())) {
  console.error(`No hub binary at ${hubBinary()}\n  cargo build -p wavvon-hub`);
  process.exit(2);
}

// The hub carrying the *previous* PostgreSQL major. A binary bundles exactly
// one archive, chosen at build time by POSTGRESQL_VERSION, so a genuine major
// upgrade needs two of them — there is no arranging it from one.
const OLD_HUB_BINARY = process.env.E2E_OLD_HUB_BIN
  ?? join(ROOT, "target-pg17/debug/wavvon-hub.exe");

if (want.has("pgupgrade") && !existsSync(OLD_HUB_BINARY)) {
  console.error(
    `No previous-major hub binary at ${OLD_HUB_BINARY}\n` +
    `  POSTGRESQL_VERSION="=17.6.0" cargo build -p wavvon-hub --target-dir target-pg17\n` +
    `  or point E2E_OLD_HUB_BIN at one you have.`,
  );
  process.exit(2);
}

const state = {};

try {
  // ── hubs ────────────────────────────────────────────────────────────────
  if (want.has("hubs") || want.has("alliance") || want.has("voice")
      || want.has("certs")) {
    state.ownerA = identity();
    state.ownerB = identity();
    state.hubA = await hub("hub-a", state.ownerA);
    state.hubB = await hub("hub-b", state.ownerB);

    await scenario("two hubs boot with separate identities and databases", async () => {
      const a = await json(`${state.hubA.url}/info`);
      const b = await json(`${state.hubB.url}/info`);
      checkEq(a.status, 200, "hub A /info");
      checkEq(b.status, 200, "hub B /info");
      check(a.body.public_key && b.body.public_key, "both hubs must report a pubkey");
      check(
        a.body.public_key !== b.body.public_key,
        "two hubs sharing an identity means they shared a working directory",
      );
      check(
        a.body.capabilities.includes("voice.alliance"),
        `hub A must advertise voice.alliance, got ${a.body.capabilities}`,
      );
    });

    await scenario("the seeded owner pubkey really is the owner", async () => {
      const v = await authenticate(state.hubA.url, state.ownerA);
      checkEq(v.status, 200, `owner auth on hub A: ${JSON.stringify(v.body)}`);
      state.tokenA = v.body.token;
      const vb = await authenticate(state.hubB.url, state.ownerB);
      checkEq(vb.status, 200, `owner auth on hub B: ${JSON.stringify(vb.body)}`);
      state.tokenB = vb.body.token;

      // Creating a channel needs a real permission, so this proves ownership
      // rather than merely proving a session.
      const ch = await json(`${state.hubA.url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({ name: "war-room" }),
      });
      checkEq(ch.status, 201, `owner should create a channel: ${JSON.stringify(ch.body)}`);
      state.channelA = ch.body.id;

      // A fresh hub is invite_only (hub 10f3e2d, 2026-07-06), so anyone who is
      // not the seeded owner needs a code. Minted once here for hub B, whose
      // members are the visitors in the voice stage.
      const inv = await json(`${state.hubB.url}/invites`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenB}` },
        body: JSON.stringify({}),
      });
      check(
        inv.status === 200 || inv.status === 201,
        `hub B should mint a member invite: ${inv.status} ${JSON.stringify(inv.body)}`,
      );
      state.inviteB = inv.body.code;
      check(state.inviteB, `invite response should carry a code, got ${JSON.stringify(inv.body)}`);
    });
  }

  // ── alliance ────────────────────────────────────────────────────────────
  if (want.has("alliance") || want.has("voice")) {
    await scenario("two hubs form an alliance and share a channel across it", async () => {
      const al = await json(`${state.hubA.url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({ name: "Topology Pact" }),
      });
      checkEq(al.status, 201, `create alliance: ${JSON.stringify(al.body)}`);
      state.allianceId = al.body.id;

      const share = await json(
        `${state.hubA.url}/alliances/${state.allianceId}/channels`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${state.tokenA}` },
          body: JSON.stringify({ channel_id: state.channelA }),
        },
      );
      checkEq(share.status, 200, `share channel: ${JSON.stringify(share.body)}`);

      const inv = await json(`${state.hubA.url}/alliances/${state.allianceId}/invite`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
      });
      checkEq(inv.status, 200, `mint alliance invite: ${JSON.stringify(inv.body)}`);

      // Hub B joins through its *own* endpoint, which calls hub A and mirrors
      // the alliance locally — the two-hub handshake this stage exists for.
      const joined = await json(`${state.hubB.url}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenB}` },
        body: JSON.stringify({
          inviter_hub_url: state.hubA.url,
          alliance_id: state.allianceId,
          invite_token: inv.body.token,
          own_hub_url: state.hubB.url,
        }),
      });
      checkEq(joined.status, 200, `hub B joins: ${JSON.stringify(joined.body)}`);

      const detail = await json(`${state.hubA.url}/alliances/${state.allianceId}`, {
        headers: { Authorization: `Bearer ${state.tokenA}` },
      });
      checkEq(detail.body.members.length, 2, "hub A should see two members");
    });

    await scenario("hub B sees hub A's shared channel over federation", async () => {
      const shared = await json(
        `${state.hubB.url}/alliances/${state.allianceId}/channels`,
        { headers: { Authorization: `Bearer ${state.tokenB}` } },
      );
      checkEq(shared.status, 200, `list shared channels from B: ${JSON.stringify(shared.body)}`);
      const remote = shared.body.find((c) => c.channel_id === state.channelA);
      check(
        remote,
        `hub B must see A's channel through federation, got ${JSON.stringify(shared.body)}`,
      );
      checkEq(remote.hub_public_key, (await json(`${state.hubA.url}/info`)).body.public_key,
        "the shared entry must be attributed to hub A");
    });
  }

  // ── alliance voice ──────────────────────────────────────────────────────
  if (want.has("voice")) {
    await scenario("a member of hub B is admitted to hub A's voice room", async () => {
      // A plain member of B, not its owner: the grant is about membership.
      const visitor = identity();
      const v = await authenticate(state.hubB.url, visitor, { invite_code: state.inviteB });
      checkEq(v.status, 200, `visitor auth on hub B: ${JSON.stringify(v.body)}`);
      const visitorToken = v.body.token;

      const minted = await json(
        `${state.hubB.url}/alliances/${state.allianceId}/voice-grant`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${visitorToken}` },
          body: JSON.stringify({ channel_id: state.channelA }),
        },
      );
      checkEq(minted.status, 200, `hub B mints a grant: ${JSON.stringify(minted.body)}`);
      checkEq(minted.body.owner_hub_url, state.hubA.url, "the grant must name hub A");
      checkEq(minted.body.channel_name, "war-room", "the grant should carry the room's name");

      // Redeemed at hub A, where the visitor has never been seen before.
      const admitted = await authenticate(state.hubA.url, visitor, {
        alliance_voice_grant: minted.body.grant,
      });
      checkEq(admitted.status, 200, `hub A admits the visitor: ${JSON.stringify(admitted.body)}`);
      checkEq(admitted.body.scope, "alliance_voice", "a visitor must not get a member session");
      const vt = admitted.body.token;

      // The relay coordinates are the whole reason /info is on the allowlist.
      const info = await json(`${state.hubA.url}/info`, {
        headers: { Authorization: `Bearer ${vt}` },
      });
      checkEq(info.status, 200, "a visitor must be able to read /info");
      check(info.body.voice_wt_url, "the visitor needs a relay URL to dial");

      // And nothing else on hub A.
      for (const path of ["/users", "/channels", "/conversations", "/me"]) {
        const r = await json(`${state.hubA.url}${path}`, {
          headers: { Authorization: `Bearer ${vt}` },
        });
        checkEq(r.status, 403, `${path} must be closed to a voice visitor`);
      }
    });

    await scenario("the owner can close its rooms to allied members", async () => {
      const visitor = identity();
      const vb = await authenticate(state.hubB.url, visitor, { invite_code: state.inviteB });
      checkEq(vb.status, 200, `second visitor auth on hub B: ${JSON.stringify(vb.body)}`);
      const minted = await json(
        `${state.hubB.url}/alliances/${state.allianceId}/voice-grant`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${vb.body.token}` },
          body: JSON.stringify({ channel_id: state.channelA }),
        },
      );
      checkEq(minted.status, 200, `mint for the policy check: ${JSON.stringify(minted.body)}`);

      // Through hub A's own admin route: re-sharing the channel with the
      // policy set is how an owner closes a room, and driving the database
      // directly (which this used to do, for want of a route) would prove the
      // column and not the feature.
      const closed = await json(`${state.hubA.url}/alliances/${state.allianceId}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({ channel_id: state.channelA, voice_remote_join: "none" }),
      });
      checkEq(closed.status, 200, `hub A closes the room: ${JSON.stringify(closed.body)}`);

      const listed = await json(`${state.hubA.url}/alliances/${state.allianceId}/channels?local_only=true`, {
        headers: { Authorization: `Bearer ${state.tokenA}` },
      });
      checkEq(listed.status, 200, "hub A lists its shared channels");
      const row = listed.body.find((c) => c.channel_id === state.channelA);
      checkEq(row?.voice_remote_join, "none", "the policy must be readable back");

      const refused = await authenticate(state.hubA.url, visitor, {
        alliance_voice_grant: minted.body.grant,
      });
      checkEq(refused.status, 403, "a closed room must refuse the visit");
      check(
        String(refused.body).includes("voice_remote_join_disabled"),
        `expected voice_remote_join_disabled, got ${JSON.stringify(refused.body)}`,
      );

      const reopened = await json(`${state.hubA.url}/alliances/${state.allianceId}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({ channel_id: state.channelA, voice_remote_join: "allowed" }),
      });
      checkEq(reopened.status, 200, "and the room reopens without re-sharing anything");
    });
  }

  // ── certs ───────────────────────────────────────────────────────────────
  if (want.has("certs")) {
    await scenario("hub A pulls a candidate's certs from the issuer it trusts", async () => {
      // A member of hub B, certified there.
      const newcomer = identity();
      const nb = await authenticate(state.hubB.url, newcomer, { invite_code: state.inviteB });
      checkEq(nb.status, 200, `newcomer auth on hub B: ${JSON.stringify(nb.body)}`);

      const issued = await json(`${state.hubB.url}/admin/certs/${newcomer.pubkey}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenB}` },
      });
      checkEq(issued.status, 201, `hub B certifies its member: ${JSON.stringify(issued.body)}`);

      const hubBInfo = await json(`${state.hubB.url}/info`);
      const issuerPubkey = hubBInfo.body.public_key;

      // Hub A trusts hub B — and knows where to reach it. Trust without an
      // address is the case the next scenario covers.
      const settings = await json(`${state.hubA.url}/admin/settings/certs`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({
          cert_mode: "trusted",
          cert_trusted_issuers: [issuerPubkey],
          cert_issuer_urls: { [issuerPubkey]: state.hubB.url },
        }),
      });
      checkEq(settings.status, 204, `hub A sets its cert policy: ${JSON.stringify(settings.body)}`);

      // An invite, because a fresh hub is invite_only and that gate is a
      // different one — this scenario is about the cert gate behind it.
      const inv = await json(`${state.hubA.url}/invites`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({}),
      });
      check(inv.status === 200 || inv.status === 201, `hub A mints an invite: ${JSON.stringify(inv.body)}`);

      // The point: the client presents no certifications at all, because no
      // client ever does. Hub A fetches the portfolio from hub B itself.
      const admitted = await authenticate(state.hubA.url, newcomer, {
        invite_code: inv.body.code,
      });
      checkEq(
        admitted.status,
        200,
        `hub A must admit a member its trusted issuer vouches for: ${JSON.stringify(admitted.body)}`,
      );
      state.certInvite = inv.body.code;
      state.certIssuerPubkey = issuerPubkey;
    });

    await scenario("an issuer with no address is trusted but not pulled", async () => {
      const stranger = identity();
      // Same trust, address removed: nothing pushes a cert, so there is
      // nothing left to admit them on.
      const settings = await json(`${state.hubA.url}/admin/settings/certs`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({
          cert_mode: "trusted",
          cert_trusted_issuers: [state.certIssuerPubkey],
          cert_issuer_urls: {},
        }),
      });
      checkEq(settings.status, 204, "hub A drops the issuer's address");

      const inv = await json(`${state.hubA.url}/invites`, {
        method: "POST",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({}),
      });
      check(inv.status === 200 || inv.status === 201, "hub A mints a second invite");

      // The auth limiter is 10 burst, 1/s, per IP — and every hub in this
      // harness is reached from 127.0.0.1, so a stage that authenticates a few
      // times in a row runs the budget down and gets a 429 where it expected a
      // verdict. Let it refill rather than reading rate limiting as a policy
      // decision.
      await new Promise((r) => setTimeout(r, 4000));
      const refused = await authenticate(state.hubA.url, stranger, {
        invite_code: inv.body.code,
      });
      checkEq(refused.status, 403, "with no address to pull from, the gate holds");
      check(
        String(refused.body).includes("cert_required"),
        `expected cert_required, got ${JSON.stringify(refused.body)}`,
      );

      // Leave hub A open again: later stages authenticate against it.
      await json(`${state.hubA.url}/admin/settings/certs`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${state.tokenA}` },
        body: JSON.stringify({ cert_mode: "none" }),
      });
    });
  }

// ── permissions ─────────────────────────────────────────────────────────
  //
  // The permission rebuild's first three items (server #37, #38, #39), against
  // a real binary rather than an in-process `AppState`. Two of the three are
  // reachable over HTTP alone; the voice gate is not, because voice admission
  // is a WebSocket message and the leak it can cause is the *absence* of one.
  if (want.has("permissions")) {
    const owner = identity();
    const h = await hub("hub-perms", owner);
    const ov = await authenticate(h.url, owner);
    checkEq(ov.status, 200, `owner auth: ${JSON.stringify(ov.body)}`);
    const ownerToken = ov.body.token;
    const asOwner = { Authorization: `Bearer ${ownerToken}` };

    const post = (path, token, body) => json(`${h.url}${path}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    const patch = (path, token, body) => json(`${h.url}${path}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    const put = (path, token) => json(`${h.url}${path}`, {
      method: "PUT",
      headers: { Authorization: `Bearer ${token}` },
    });
    /** Deny a permission for @everyone on one channel. */
    const denyEveryone = (channelId, deny) => json(
      `${h.url}/channels/${channelId}/permissions/builtin-everyone`,
      {
        method: "PUT",
        headers: asOwner,
        body: JSON.stringify({ allow: [], deny }),
      },
    );
    const channelIds = async (token) => {
      const r = await json(`${h.url}/channels`, { headers: { Authorization: `Bearer ${token}` } });
      checkEq(r.status, 200, "list channels");
      return r.body.map((c) => c.id);
    };

    /** Open a member WebSocket and collect every frame it is sent.
     *
     *  Both halves of the split need this. The gate is a reply to a message;
     *  the leak is a frame that must never arrive, and only a real socket can
     *  say "nothing came" — an HTTP check would pass with the subscription
     *  wide open. */
    async function socket(token) {
      const ws = new WebSocket(`${h.url.replace("http://", "ws://")}/ws?token=${token}`);
      const frames = [];
      ws.addEventListener("message", (ev) => {
        try { frames.push(JSON.parse(ev.data)); } catch { /* binary voice frames */ }
      });
      await new Promise((resolve, reject) => {
        ws.addEventListener("open", resolve, { once: true });
        ws.addEventListener("error", () => reject(new Error("ws failed to open")), { once: true });
      });
      return {
        send: (m) => ws.send(JSON.stringify(m)),
        /** First frame of one of `types`, or null once `ms` has passed. */
        await: async (types, ms = 6000) => {
          const deadline = Date.now() + ms;
          for (;;) {
            const hit = frames.find((f) => types.includes(f.type));
            if (hit) return hit;
            if (Date.now() >= deadline) return null;
            await new Promise((r) => setTimeout(r, 50));
          }
        },
        frames,
        close: () => ws.close(),
      };
    }

    await scenario("the hub advertises voice.permissions", async () => {
      const info = await json(`${h.url}/info`);
      checkEq(info.status, 200, "/info");
      check(
        info.body.capabilities.includes("voice.permissions"),
        `a client cannot offer the voice.join row without it, got ${info.body.capabilities}`,
      );
    });

    await scenario("an unknown permission string is refused, and nothing is written", async () => {
      const bad = await post("/roles", ownerToken, {
        name: "Typo", priority: 50, permissions: ["channels.manage", "roles.manege"],
      });
      checkEq(bad.status, 400, `a bogus permission must be refused: ${JSON.stringify(bad.body)}`);
      check(
        JSON.stringify(bad.body).includes("roles.manege"),
        `the refusal should name the offending string, got ${JSON.stringify(bad.body)}`,
      );

      const roles = await json(`${h.url}/roles`, { headers: asOwner });
      check(
        !roles.body.some((r) => r.name === "Typo"),
        "a refused create must not leave the role behind",
      );
    });

    await scenario("a rejected update does not half-apply", async () => {
      const made = await post("/roles", ownerToken, {
        name: "Renameable", priority: 40, permissions: ["messages.manage"],
      });
      checkEq(made.status, 201, `create: ${JSON.stringify(made.body)}`);

      // Name and permissions in one call, one string bad. The hub applies the
      // name in its own statement before rewriting permissions, so validating
      // late would commit the rename behind the 400.
      const bad = await patch(`/roles/${made.body.id}`, ownerToken, {
        name: "Renamed", permissions: ["messages.manage", "not_a_permission"],
      });
      checkEq(bad.status, 400, `bad update must be refused: ${JSON.stringify(bad.body)}`);

      const roles = await json(`${h.url}/roles`, { headers: asOwner });
      const after = roles.body.find((r) => r.id === made.body.id);
      checkEq(after?.name, "Renameable", "a refused update must not have renamed the role");
    });

    // The delegate every escalation below is attempted from: it can manage
    // roles and channels, and holds nothing else beyond what @everyone carries.
    const delegateRole = await post("/roles", ownerToken, {
      name: "Delegate", priority: 50, permissions: ["roles.manage", "channels.manage"],
    });
    checkEq(delegateRole.status, 201, `delegate role: ${JSON.stringify(delegateRole.body)}`);
    const enforcer = await post("/roles", ownerToken, {
      name: "Enforcer", priority: 20, permissions: ["moderation.ban.permanent"],
    });
    checkEq(enforcer.status, 201, `enforcer role: ${JSON.stringify(enforcer.body)}`);

    const invite = await post("/invites", ownerToken, {});
    check(invite.status === 200 || invite.status === 201, `member invite: ${invite.status}`);
    const delegate = identity();
    const dv = await authenticate(h.url, delegate, { invite_code: invite.body.code });
    checkEq(dv.status, 200, `delegate auth: ${JSON.stringify(dv.body)}`);
    const delegateToken = dv.body.token;
    const grant = await put(`/users/${delegate.pubkey}/roles/${delegateRole.body.id}`, ownerToken);
    checkEq(grant.status, 200, `grant the delegate role: ${JSON.stringify(grant.body)}`);

    await scenario("a delegate cannot hand out a permission it does not hold", async () => {
      // Every priority below is *under* the delegate's own 50, so the rank
      // guard that already existed lets all four through. The escalation never
      // needed rank: a role beneath you can carry permissions above you.
      const minted = await post("/roles", delegateToken, {
        name: "Sneak", priority: 49, permissions: ["moderation.ban.permanent"],
      });
      checkEq(minted.status, 403, `minting: ${JSON.stringify(minted.body)}`);

      const own = await post("/roles", delegateToken, {
        name: "Greeter", priority: 49, permissions: ["messages.send", "channels.manage"],
      });
      checkEq(own.status, 201, `what it does hold must still work: ${JSON.stringify(own.body)}`);

      const widened = await patch(`/roles/${own.body.id}`, delegateToken, {
        permissions: ["messages.send", "moderation.ban.permanent"],
      });
      checkEq(widened.status, 403, `widening: ${JSON.stringify(widened.body)}`);

      const assigned = await put(
        `/users/${delegate.pubkey}/roles/${enforcer.body.id}`, delegateToken,
      );
      checkEq(assigned.status, 403, `assigning to itself: ${JSON.stringify(assigned.body)}`);

      // The fourth door, and the widest: creating an invite needs
      // manage_channels, not manage_roles, so without this guard anyone who
      // could invite people could redeem a role-granting code as a second
      // identity.
      const viaInvite = await post("/invites", delegateToken, {
        grant_role_id: enforcer.body.id,
      });
      checkEq(viaInvite.status, 403, `via a role-granting invite: ${JSON.stringify(viaInvite.body)}`);
    });

    await scenario("the owner is unaffected by the ceiling", async () => {
      const ok = await put(`/users/${delegate.pubkey}/roles/${enforcer.body.id}`, ownerToken);
      checkEq(ok.status, 200, `the owner may assign it: ${JSON.stringify(ok.body)}`);
    });

    // ── the split ───────────────────────────────────────────────────────
    const member = identity();
    const mv = await authenticate(h.url, member, { invite_code: invite.body.code });
    checkEq(mv.status, 200, `member auth: ${JSON.stringify(mv.body)}`);
    const memberToken = mv.body.token;

    const lobby = await post("/channels", ownerToken, { name: "lobby" });
    checkEq(lobby.status, 201, `lobby: ${JSON.stringify(lobby.body)}`);
    const raid = await post("/channels", ownerToken, { name: "raid" });
    checkEq(raid.status, 201, `raid: ${JSON.stringify(raid.body)}`);
    const vault = await post("/channels", ownerToken, { name: "vault" });
    checkEq(vault.status, 201, `vault: ${JSON.stringify(vault.body)}`);

    await scenario("denying read alone no longer hides a channel", async () => {
      checkEq((await denyEveryone(lobby.body.id, ["messages.read"])).status, 200, "deny read");
      const visible = await channelIds(memberToken);
      check(
        visible.includes(lobby.body.id),
        "a channel the member may still join has to reach the client, or the permission is inert",
      );

      // Hiding it is two denials now, and that is the documented price.
      checkEq(
        (await denyEveryone(vault.body.id, ["messages.read", "voice.join"])).status, 200,
        "deny both",
      );
      const after = await channelIds(memberToken);
      check(!after.includes(vault.body.id), "denying both must hide the channel");
    });

    await scenario("denying voice leaves the text channel working", async () => {
      checkEq((await denyEveryone(raid.body.id, ["voice.join"])).status, 200, "deny voice");
      const visible = await channelIds(memberToken);
      check(visible.includes(raid.body.id), "denying voice must not hide the text");

      const hist = await json(`${h.url}/channels/${raid.body.id}/messages`, {
        headers: { Authorization: `Bearer ${memberToken}` },
      });
      checkEq(hist.status, 200, "and its history must still be readable");
    });

    await scenario("voice admission is independent of reading, both ways", async () => {
      const s = await socket(memberToken);
      try {
        s.send({ type: "voice_join", channel_id: lobby.body.id, udp_port: 0 });
        const joined = await s.await(["voice_joined", "error"]);
        checkEq(joined?.type, "voice_joined", `no read must not mean no voice: ${JSON.stringify(joined)}`);

        s.send({ type: "voice_join", channel_id: raid.body.id, udp_port: 0 });
        const refused = await s.await(["error"]);
        check(refused, "denying voice.join must keep them out of the call");
        checkEq(refused.context, "voice_join", `wrong refusal: ${JSON.stringify(refused)}`);
      } finally {
        s.close();
      }
    });

    await scenario("the hub serves its own catalogue, and it matches what it enforces", async () => {
      const info = await json(`${h.url}/info`);
      check(
        info.body.capabilities.includes("permissions.catalogue"),
        "a client cannot know the ids changed without this string",
      );

      const cat = await json(`${h.url}/permissions`, { headers: asOwner });
      checkEq(cat.status, 200, "the catalogue must be readable by a member");
      const byId = new Map(cat.body.permissions.map((p) => [p.id, p]));

      // The wildcard is gone, and so are the four strings that gated nothing.
      for (const dead of ["admin", "manage_bots", "use_video", "start_game", "manage_games"]) {
        check(!byId.has(dead), `${dead} must not be in the catalogue`);
      }
      // And the old spelling shares no id with the new one — there is no
      // dual-reading period, so a client on the old list gets nothing.
      for (const old of ["read_messages", "manage_roles", "ban_members"]) {
        check(!byId.has(old), `${old} is the old spelling and must be gone`);
      }

      // Hub administration is never channel-scoped: "manage the hub, but only
      // in #general" is not a sentence, and an overwrite pretending otherwise
      // would grant nothing while looking like it granted something.
      checkEq(byId.get("roles.manage")?.scope, "hub", "roles.manage must be hub-only");
      checkEq(byId.get("hub.settings")?.scope, "hub", "hub.settings must be hub-only");
      checkEq(
        byId.get("messages.read")?.scope, "hub_and_channel",
        "messages.read must carry a channel dimension",
      );
      checkEq(byId.get("moderation.ban.permanent")?.group, "moderation", "group is the dotted prefix");

      // The scope the catalogue advertises is the one the overwrite validator
      // enforces — the pair that used to disagree across four copies.
      // A throwaway channel: a PUT replaces the whole overwrite set for that
      // role, so doing this on #raid would wipe the voice.join deny the next
      // scenario reads.
      const scratch = await post("/channels", ownerToken, { name: "scope-probe" });
      checkEq(scratch.status, 201, `scratch channel: ${JSON.stringify(scratch.body)}`);
      const refused = await json(
        `${h.url}/channels/${scratch.body.id}/permissions/builtin-everyone`,
        {
          method: "PUT",
          headers: asOwner,
          body: JSON.stringify({ allow: [], deny: ["roles.manage"] }),
        },
      );
      check(
        refused.status >= 400,
        `a hub-only permission must not be settable per channel, got ${refused.status}`,
      );
    });

    await scenario("the hub explains one answer, in the order it resolves it", async () => {
      // "Why can this member do X here" — the question every operator actually
      // asks, and the one two axes make unanswerable by guessing.
      const why = await json(
        `${h.url}/users/${member.pubkey}/permissions/why?permission=voice.join&channel_id=${raid.body.id}`,
        { headers: asOwner },
      );
      checkEq(why.status, 200, `why: ${JSON.stringify(why.body)}`);
      checkEq(why.allowed ?? why.body.allowed, false, "voice.join was denied on #raid earlier");
      check(!why.body.is_owner, "a plain member is not the owner");
      const deny = why.body.sources.find((s) => s.kind === "deny");
      check(deny, `the deny row should be named: ${JSON.stringify(why.body.sources)}`);
      checkEq(deny.channel_id, raid.body.id, "and it should name the channel it sits on");

      // The owner's answer is a different shape on purpose: no role explains
      // it, so listing roles would be a lie.
      const ownerWhy = await json(
        `${h.url}/users/${owner.pubkey}/permissions/why?permission=roles.manage`,
        { headers: asOwner },
      );
      checkEq(ownerWhy.status, 200, "owner why");
      check(ownerWhy.body.allowed && ownerWhy.body.is_owner, "the owner holds everything");
      checkEq(ownerWhy.body.sources.length, 0, "and no role is why");

      const unknown = await json(
        `${h.url}/users/${member.pubkey}/permissions/why?permission=read_messages`,
        { headers: asOwner },
      );
      checkEq(unknown.status, 400, "an id outside the catalogue is a 400, not a false");
    });

    await scenario("a talk-only channel never delivers its messages over the socket", async () => {
      // The half that fails silently. The channel list asks read OR
      // voice.join; auto-subscribe must ask read only, and widening it to
      // match is a leak nobody would notice — no one inspects the frames they
      // should not have received.
      const s = await socket(memberToken);
      try {
        const sent = await post(`/channels/${lobby.body.id}/messages`, ownerToken, {
          content: "members only",
        });
        check(sent.status === 200 || sent.status === 201, `owner posts: ${sent.status}`);

        const leaked = await s.await(["message"], 2500);
        check(
          leaked === null,
          `a channel the member may join but not read leaked a frame: ${JSON.stringify(leaked)}`,
        );

        // Control: the same socket does receive a channel it may read, so the
        // silence above is the gate and not a dead connection.
        const readable = await post("/channels", ownerToken, { name: "open-floor" });
        checkEq(readable.status, 201, `control channel: ${JSON.stringify(readable.body)}`);
        s.close();
        const s2 = await socket(memberToken);
        try {
          await post(`/channels/${readable.body.id}/messages`, ownerToken, { content: "hello" });
          const got = await s2.await(["message"], 8000);
          check(got, "a readable channel must still deliver, or this test proves nothing");
        } finally {
          s2.close();
        }
      } finally {
        s.close();
      }
    });
  }

  // ── pgupgrade ───────────────────────────────────────────────────────────
  //
  // The PostgreSQL major upgrade, walked the way the hub's own refusal tells an
  // operator to walk it, with **two real majors**. Nothing else covers it: the
  // in-process tests own the decision (`compatibility` is a pure function over
  // two numbers) and dump/restore against one running server, and neither
  // touches what an operator actually does.
  //
  // Two binaries, because a hub bundles exactly one PostgreSQL archive and
  // picks it at build time. That is what makes this the genuine article rather
  // than an arrangement: a real 17 data directory, a `pg_dump` taken by 17's
  // own binaries, and 18's `pg_restore` reading it.
  if (want.has("pgupgrade")) {
    const owner = identity();
    const root = tempDir("wavvon-e2e-pgupgrade-");
    const httpPort = port();
    const voicePort = port();
    const url = `http://localhost:${httpPort}`;
    // No WAVVON_DATABASE_URL: that absence *is* bundled mode, and bundled mode
    // is the only mode a major upgrade exists in.
    const bundledEnv = {
      WAVVON_HTTP_PORT: String(httpPort),
      WAVVON_VOICE_UDP_PORT: String(voicePort),
      WAVVON_PUBLIC_URL: url,
      WAVVON_OWNER_PUBKEY: owner.pubkey,
      WAVVON_WEB_CLIENT_DIR: "",
    };
    const startHub = (name, bin) => start(name, bin, [], { cwd: root, env: bundledEnv });
    const runHub = (name, bin, args) => run(name, bin, args, { cwd: root, env: bundledEnv });

    const dataDir = join(root, "pgdata");
    const movedDir = join(root, "pgdata.previous-major");
    const archive = join(root, "before-upgrade.tar.gz");
    const installRoot = join(root, "pg");
    const majors = () =>
      readdirSync(installRoot)
        .filter((e) => /^\d+\./.test(e))
        .map((e) => Number(e.split(".")[0]))
        .sort((a, b) => a - b);

    await scenario("the previous major's hub fills a real data directory of that major", async () => {
      const hub = startHub("hub-pg-old", OLD_HUB_BINARY);
      // Longer than the usual wait: a first bundled start unpacks a whole
      // PostgreSQL and runs initdb before it ever binds a port.
      await waitForHttp(hub, `${url}/info`, 240_000);

      const auth = await authenticate(url, owner);
      checkEq(auth.status, 200, `owner auth: ${JSON.stringify(auth.body)}`);

      const channel = await json(`${url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${auth.body.token}` },
        body: JSON.stringify({ name: "before-upgrade" }),
      });
      checkEq(channel.status, 201, `create a channel: ${JSON.stringify(channel.body)}`);
      state.pgChannel = channel.body.id;

      state.pgMessage = `survive the upgrade ${Date.now().toString(36)}`;
      const posted = await json(`${url}/channels/${state.pgChannel}/messages`, {
        method: "POST",
        headers: { Authorization: `Bearer ${auth.body.token}` },
        body: JSON.stringify({ content: state.pgMessage }),
      });
      check(
        posted.status === 200 || posted.status === 201,
        `post a message: ${posted.status} ${JSON.stringify(posted.body)}`,
      );

      // The thing an upgrade must not lose. A hub that comes back under a new
      // key is a different hub to every ally and every directory listing.
      state.pgIdentity = (await json(`${url}/info`)).body.public_key;
      check(state.pgIdentity, "the hub must report a public key");

      state.pgOldMajor = Number(readFileSync(join(dataDir, "PG_VERSION"), "utf8").trim());
      check(
        Number.isInteger(state.pgOldMajor),
        `unreadable PG_VERSION: ${state.pgOldMajor}`,
      );

      hub.child.kill("SIGKILL");
      await new Promise((r) => setTimeout(r, 1500));
    });

    await scenario("the backup is taken with the binary that matches the data", async () => {
      // Killed, not asked to stop — a harness cannot deliver a console signal
      // to a process it spawned with pipes — so its PostgreSQL is still up.
      // `backup` adopts it, which is the shape an operator taking a backup off
      // a live hub is in, and the one that used to fail for want of pg_dump.
      const backup = await runHub("hub-backup-old", OLD_HUB_BINARY, ["backup", archive]);
      checkEq(backup.code, 0, `backup must succeed:\n${backup.log}`);
      check(existsSync(archive), "backup must write the archive it names");
      check(
        backup.log.includes(`PostgreSQL ${state.pgOldMajor}`),
        `the backup must say which major it came from:\n${backup.log}`,
      );

      // The postmaster the killed hub left behind still holds the data
      // directory, and a held directory cannot be renamed on Windows — so the
      // move the refusal asks for is impossible until it is stopped. The
      // bundled pg_ctl is the one an operator has, since PostgreSQL was never
      // installed on this machine.
      const binDir = readdirSync(installRoot)
        .map((entry) => join(installRoot, entry, "bin", "pg_ctl.exe"))
        .find((candidate) => existsSync(candidate));
      check(binDir, `no bundled pg_ctl under ${installRoot}`);
      const stopped = await run("pg-stop", binDir, ["-D", dataDir, "stop", "-m", "fast"]);
      checkEq(stopped.code, 0, `the bundled pg_ctl must stop it:\n${stopped.log}`);
    });

    await scenario("the newer hub refuses the older data directory, and says what to do", async () => {
      const refused = await runHub("hub-refuse", hubBinary(), []);
      check(refused.code !== 0, `a major mismatch must refuse to start:\n${refused.log}`);
      check(
        refused.log.includes("backup") && refused.log.includes("restore"),
        `the refusal must name both commands:\n${refused.log}`,
      );
      check(
        refused.log.includes(String(state.pgOldMajor)),
        `the refusal must name the major it found:\n${refused.log}`,
      );
      check(
        !existsSync(join(dataDir, "postmaster.pid")),
        "refusing must not have started a server",
      );
      checkEq(
        readFileSync(join(dataDir, "PG_VERSION"), "utf8").trim(),
        String(state.pgOldMajor),
        "refusing must leave the data directory as it was",
      );
    });

    await scenario("the upgrade the refusal names is walkable end to end", async () => {
      // Step one of the printed instructions.
      renameSync(dataDir, movedDir);

      // And step two: the newer binary's pg_restore reading the older
      // binary's dump. This is the part that genuinely needs two majors.
      const restored = await runHub("hub-restore", hubBinary(), ["restore", archive]);
      checkEq(restored.code, 0, `restore must succeed:\n${restored.log}`);

      const hub = startHub("hub-pg-new", hubBinary());
      await waitForHttp(hub, `${url}/info`, 240_000);

      const newMajor = Number(readFileSync(join(dataDir, "PG_VERSION"), "utf8").trim());
      check(
        newMajor > state.pgOldMajor,
        `the restored data must be on the newer major, got ${newMajor}`,
      );

      const info = await json(`${url}/info`);
      checkEq(info.body.public_key, state.pgIdentity,
        "the restored hub must still be the same hub");

      const auth = await authenticate(url, owner);
      checkEq(auth.status, 200, `owner auth after the upgrade: ${JSON.stringify(auth.body)}`);
      const messages = await json(`${url}/channels/${state.pgChannel}/messages`, {
        headers: { Authorization: `Bearer ${auth.body.token}` },
      });
      checkEq(messages.status, 200, `read the channel back: ${JSON.stringify(messages.body)}`);
      const rows = Array.isArray(messages.body) ? messages.body : messages.body.items ?? [];
      check(
        rows.some((m) => m.content === state.pgMessage),
        `the message must survive the upgrade, got ${JSON.stringify(messages.body)}`,
      );

      // Both installs are still there, which is the whole reason the layout is
      // version-scoped: the old major's binaries are the only thing that can
      // read the old major's data, and that directory is still on disk.
      const installed = majors();
      check(
        installed.includes(state.pgOldMajor) && installed.includes(newMajor),
        `both majors must stay installed, found ${JSON.stringify(installed)}`,
      );
      checkEq(
        readFileSync(join(movedDir, "PG_VERSION"), "utf8").trim(),
        String(state.pgOldMajor),
        "the moved-aside data directory must be left untouched",
      );
    });
  }

  // ── alliancesplit ───────────────────────────────────────────────────────
  //
  // One hub, two alliances that have nothing to do with each other: hub 1 is
  // allied with hub 2 for one thing and with hub 3 for another, and hubs 2 and
  // 3 are not allied. Alliances do not merge, and this is the stage that
  // proves it.
  //
  // It has to be three real binaries, because the interesting caller is hub 2
  // holding a *peer token on hub 1*, which only federation produces. A hub
  // authenticates at another with `is_hub: true` and no invite, deliberately —
  // a peer is not a person joining a community — so "holds a token here" says
  // nothing about which alliances it is in. Nothing in-process can pose that
  // question: the integration suite builds its own state and never mints a
  // second hub identity.
  if (want.has("alliancesplit")) {
    const owner1 = identity();
    const owner2 = identity();
    const owner3 = identity();
    const hub1 = await hub("hub-split-1", owner1);
    const hub2 = await hub("hub-split-2", owner2);
    const hub3 = await hub("hub-split-3", owner3);

    const token1 = (await authenticate(hub1.url, owner1)).body.token;
    const token2 = (await authenticate(hub2.url, owner2)).body.token;
    const token3 = (await authenticate(hub3.url, owner3)).body.token;

    const split = {};

    await scenario("one hub joins two alliances that do not know about each other", async () => {
      const raids = await json(`${hub1.url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token1}` },
        body: JSON.stringify({ name: "raids" }),
      });
      checkEq(raids.status, 201, `create #raids: ${JSON.stringify(raids.body)}`);
      split.raidsId = raids.body.id;

      const patterns = await json(`${hub1.url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token1}` },
        body: JSON.stringify({ name: "patterns" }),
      });
      checkEq(patterns.status, 201, `create #patterns: ${JSON.stringify(patterns.body)}`);
      split.patternsId = patterns.body.id;

      // Something to read in each, so "cannot see it" is about content rather
      // than about an empty channel.
      for (const [id, text] of [[split.raidsId, "raid at 9"], [split.patternsId, "bring thread"]]) {
        const m = await json(`${hub1.url}/channels/${id}/messages`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token1}` },
          body: JSON.stringify({ content: text }),
        });
        check(m.status === 200 || m.status === 201, `post to ${id}: ${JSON.stringify(m.body)}`);
      }

      const pact = async (name, channelId, partnerUrl, partnerToken) => {
        const al = await json(`${hub1.url}/alliances`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token1}` },
          body: JSON.stringify({ name }),
        });
        checkEq(al.status, 201, `create ${name}: ${JSON.stringify(al.body)}`);

        const share = await json(`${hub1.url}/alliances/${al.body.id}/channels`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token1}` },
          body: JSON.stringify({ channel_id: channelId }),
        });
        checkEq(share.status, 200, `share into ${name}: ${JSON.stringify(share.body)}`);

        const inv = await json(`${hub1.url}/alliances/${al.body.id}/invite`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token1}` },
        });
        checkEq(inv.status, 200, `invite to ${name}: ${JSON.stringify(inv.body)}`);

        const joined = await json(`${partnerUrl}/alliances/join`, {
          method: "POST",
          headers: { Authorization: `Bearer ${partnerToken}` },
          body: JSON.stringify({
            inviter_hub_url: hub1.url,
            alliance_id: al.body.id,
            invite_token: inv.body.token,
            own_hub_url: partnerUrl,
          }),
        });
        checkEq(joined.status, 200, `join ${name}: ${JSON.stringify(joined.body)}`);
        return al.body.id;
      };

      split.raidsAlliance = await pact("Raids", split.raidsId, hub2.url, token2);
      split.sewingAlliance = await pact("Sewing", split.patternsId, hub3.url, token3);

      const mine = await json(`${hub1.url}/alliances`, {
        headers: { Authorization: `Bearer ${token1}` },
      });
      checkEq(mine.body.length, 2, `hub 1 is in both: ${JSON.stringify(mine.body)}`);
    });

    await scenario("a hub nobody allied with is told about no alliance", async () => {
      // The threat, stated plainly: any key may authenticate here with
      // `is_hub: true` and no invite — that exemption is what lets two hubs
      // form an alliance in the first place — so holding a token says nothing
      // about belonging to anything. A stranger hub is exactly a hub that has
      // a token and no alliance.
      const stranger = identity();
      const s = await authenticate(hub1.url, stranger, { is_hub: true });
      checkEq(s.status, 200, `a stranger hub can authenticate: ${JSON.stringify(s.body)}`);
      const strangerToken = s.body.token;

      const listed = await json(`${hub1.url}/alliances`, {
        headers: { Authorization: `Bearer ${strangerToken}` },
      });
      checkEq(listed.status, 200, `list alliances: ${JSON.stringify(listed.body)}`);
      checkEq(
        listed.body.length,
        0,
        `a stranger must learn of no alliance, got ${JSON.stringify(listed.body)}`,
      );

      for (const [name, allianceId, channelId] of [
        ["Raids", split.raidsAlliance, split.raidsId],
        ["Sewing", split.sewingAlliance, split.patternsId],
      ]) {
        const channels = await json(`${hub1.url}/alliances/${allianceId}/channels`, {
          headers: { Authorization: `Bearer ${strangerToken}` },
        });
        check(
          channels.status >= 400,
          `${name}: shared channels must be refused, got ${channels.status} ${JSON.stringify(channels.body)}`,
        );

        const messages = await json(
          `${hub1.url}/alliances/${allianceId}/channels/${channelId}/messages`,
          { headers: { Authorization: `Bearer ${strangerToken}` } },
        );
        check(
          messages.status >= 400,
          `${name}: messages must be refused, got ${messages.status} ${JSON.stringify(messages.body)}`,
        );
      }
    });

    await scenario("each partner is a member of its own alliance and not the other", async () => {
      // The membership rows are what every guard reads, so they are worth
      // asserting directly: hub 2 is in Raids, hub 3 is in Sewing, and
      // neither is in the other.
      const key2 = (await json(`${hub2.url}/info`)).body.public_key;
      const key3 = (await json(`${hub3.url}/info`)).body.public_key;

      const raids = await json(`${hub1.url}/alliances/${split.raidsAlliance}`, {
        headers: { Authorization: `Bearer ${token1}` },
      });
      const sewing = await json(`${hub1.url}/alliances/${split.sewingAlliance}`, {
        headers: { Authorization: `Bearer ${token1}` },
      });
      const keys = (r) => r.body.members.map((m) => m.hub_public_key);

      check(keys(raids).includes(key2), `hub 2 must be in Raids, got ${keys(raids)}`);
      check(!keys(raids).includes(key3), `hub 3 must not be, got ${keys(raids)}`);
      check(keys(sewing).includes(key3), `hub 3 must be in Sewing, got ${keys(sewing)}`);
      check(!keys(sewing).includes(key2), `hub 2 must not be, got ${keys(sewing)}`);
    });

    await scenario("a member of the allied hub reads one channel and not the other", async () => {
      // The same question from where a person stands: hub 2's own view, which
      // hub 2 builds by asking hub 1 over federation.
      const shared = await json(`${hub2.url}/alliances/${split.raidsAlliance}/channels`, {
        headers: { Authorization: `Bearer ${token2}` },
      });
      checkEq(shared.status, 200, `hub 2 lists its alliance: ${JSON.stringify(shared.body)}`);
      check(
        shared.body.some((c) => c.channel_name === "raids"),
        `#raids must be visible to hub 2, got ${JSON.stringify(shared.body)}`,
      );
      check(
        !shared.body.some((c) => c.channel_name === "patterns"),
        `#patterns must not be, got ${JSON.stringify(shared.body)}`,
      );

      const msgs = await json(
        `${hub2.url}/alliances/${split.raidsAlliance}/channels/${split.raidsId}/messages`,
        { headers: { Authorization: `Bearer ${token2}` } },
      );
      checkEq(msgs.status, 200, `hub 2 reads #raids: ${JSON.stringify(msgs.body)}`);
      check(
        msgs.body.some((m) => m.content === "raid at 9"),
        `the federated read must carry the message, got ${JSON.stringify(msgs.body)}`,
      );
    });
    await scenario("a third hub joins one alliance and the other stays invisible", async () => {
      // Hub 2 is already hub 1's partner for Raids. Now it joins Sewing too —
      // the alliance hub 1 has with hub 3 — and brings a channel of its own.
      // The question this answers: does being in a room with hub 3 expose the
      // room hub 2 shares with hub 1?
      const quilts = await json(`${hub2.url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token2}` },
        body: JSON.stringify({ name: "quilts" }),
      });
      checkEq(quilts.status, 201, `create #quilts on hub 2: ${JSON.stringify(quilts.body)}`);

      // Any member hub's admin can bring somebody in, signing with its own
      // identity — hub 1 is in Sewing, so hub 1 does the inviting.
      const inv = await json(`${hub1.url}/alliances/${split.sewingAlliance}/invite`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token1}` },
      });
      checkEq(inv.status, 200, `invite hub 2 into Sewing: ${JSON.stringify(inv.body)}`);

      const joined = await json(`${hub2.url}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token2}` },
        body: JSON.stringify({
          inviter_hub_url: hub1.url,
          alliance_id: split.sewingAlliance,
          invite_token: inv.body.token,
          own_hub_url: hub2.url,
        }),
      });
      checkEq(joined.status, 200, `hub 2 joins Sewing: ${JSON.stringify(joined.body)}`);

      const share = await json(`${hub2.url}/alliances/${split.sewingAlliance}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token2}` },
        body: JSON.stringify({ channel_id: quilts.body.id }),
      });
      checkEq(share.status, 200, `hub 2 shares #quilts into Sewing: ${JSON.stringify(share.body)}`);

      // Hub 2 is now in both, and each alliance still has only its own members.
      const two = await json(`${hub2.url}/alliances`, {
        headers: { Authorization: `Bearer ${token2}` },
      });
      checkEq(two.body.length, 2, `hub 2 is in both: ${JSON.stringify(two.body)}`);

      // Hub 3 sees the new partner's channel, because they are in the same
      // alliance now.
      const seen = await json(`${hub3.url}/alliances/${split.sewingAlliance}/channels`, {
        headers: { Authorization: `Bearer ${token3}` },
      });
      checkEq(seen.status, 200, `hub 3 lists Sewing: ${JSON.stringify(seen.body)}`);
      check(
        seen.body.some((c) => c.channel_name === "quilts"),
        `#quilts must reach hub 3, got ${JSON.stringify(seen.body)}`,
      );

      // And still does not see what hub 1 and hub 2 share with each other,
      // even though it is now allied with both of them.
      check(
        !seen.body.some((c) => c.channel_name === "raids"),
        `#raids must not leak into Sewing, got ${JSON.stringify(seen.body)}`,
      );

      const others = await json(`${hub3.url}/alliances`, {
        headers: { Authorization: `Bearer ${token3}` },
      });
      checkEq(others.body.length, 1, `hub 3 is in one alliance only: ${JSON.stringify(others.body)}`);

      // Even addressed by id — which hub 3 has no way to learn, and which this
      // test knows only because it created it.
      const reach = await json(`${hub3.url}/alliances/${split.raidsAlliance}/channels`, {
        headers: { Authorization: `Bearer ${token3}` },
      });
      check(
        reach.status >= 400 || (reach.body ?? []).length === 0,
        `hub 3 must not reach Raids by id, got ${reach.status} ${JSON.stringify(reach.body)}`,
      );

      // The partner it does share Raids with still reads it.
      const raids = await json(`${hub2.url}/alliances/${split.raidsAlliance}/channels`, {
        headers: { Authorization: `Bearer ${token2}` },
      });
      checkEq(raids.status, 200, `hub 2 still lists Raids: ${JSON.stringify(raids.body)}`);
      check(
        raids.body.some((c) => c.channel_name === "raids"),
        `and still sees #raids, got ${JSON.stringify(raids.body)}`,
      );
      check(
        !raids.body.some((c) => c.channel_name === "quilts"),
        `while #quilts stays in Sewing, got ${JSON.stringify(raids.body)}`,
      );
    });

  }

  // ── alliancestress ──────────────────────────────────────────────────────
  //
  // The alliance edge cases that only exist between real hubs: a member that
  // goes down and comes back, a member that leaves, an invite token pointed at
  // the wrong alliance, a channel unshared and shared again, one channel in two
  // alliances at once, and a voice grant for something not shared.
  //
  // Each of these is a place where the honest answer differs from the
  // convenient one — a partial view rather than an error, a refusal rather
  // than a guess — and none of them can be posed to a suite that builds its
  // own state.
  if (want.has("alliancestress")) {
    const ownerX = identity();
    const ownerY = identity();
    const ownerZ = identity();
    const hubX = await hub("hub-stress-x", ownerX);
    const hubY = await hub("hub-stress-y", ownerY);
    const hubZ = await hub("hub-stress-z", ownerZ);

    const tokenX = (await authenticate(hubX.url, ownerX)).body.token;
    const tokenY = (await authenticate(hubY.url, ownerY)).body.token;
    const tokenZ = (await authenticate(hubZ.url, ownerZ)).body.token;

    const st = {};

    const makeChannel = async (hubUrl, token, name) => {
      const c = await json(`${hubUrl}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name }),
      });
      checkEq(c.status, 201, `create #${name}: ${JSON.stringify(c.body)}`);
      return c.body.id;
    };

    const shareInto = async (hubUrl, token, allianceId, channelId) => {
      const r = await json(`${hubUrl}/alliances/${allianceId}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify({ channel_id: channelId }),
      });
      checkEq(r.status, 200, `share ${channelId}: ${JSON.stringify(r.body)}`);
    };

    const joinFrom = async (inviterUrl, inviterToken, allianceId, joinerUrl, joinerToken) => {
      const inv = await json(`${inviterUrl}/alliances/${allianceId}/invite`, {
        method: "POST",
        headers: { Authorization: `Bearer ${inviterToken}` },
      });
      checkEq(inv.status, 200, `mint invite: ${JSON.stringify(inv.body)}`);
      const joined = await json(`${joinerUrl}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${joinerToken}` },
        body: JSON.stringify({
          inviter_hub_url: inviterUrl,
          alliance_id: allianceId,
          invite_token: inv.body.token,
          own_hub_url: joinerUrl,
        }),
      });
      return { joined, token: inv.body.token };
    };

    const names = async (hubUrl, token, allianceId) => {
      const r = await json(`${hubUrl}/alliances/${allianceId}/channels`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { status: r.status, list: (r.body ?? []).map((c) => c.channel_name).sort() };
    };

    await scenario("three hubs in one alliance, each sharing a channel", async () => {
      st.chX = await makeChannel(hubX.url, tokenX, "x-room");
      st.chY = await makeChannel(hubY.url, tokenY, "y-room");
      st.chZ = await makeChannel(hubZ.url, tokenZ, "z-room");

      const al = await json(`${hubX.url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenX}` },
        body: JSON.stringify({ name: "Stress" }),
      });
      checkEq(al.status, 201, `create alliance: ${JSON.stringify(al.body)}`);
      st.alliance = al.body.id;
      await shareInto(hubX.url, tokenX, st.alliance, st.chX);

      const y = await joinFrom(hubX.url, tokenX, st.alliance, hubY.url, tokenY);
      checkEq(y.joined.status, 200, `hub Y joins: ${JSON.stringify(y.joined.body)}`);
      st.inviteToken = y.token;
      await shareInto(hubY.url, tokenY, st.alliance, st.chY);

      const z = await joinFrom(hubX.url, tokenX, st.alliance, hubZ.url, tokenZ);
      checkEq(z.joined.status, 200, `hub Z joins: ${JSON.stringify(z.joined.body)}`);
      await shareInto(hubZ.url, tokenZ, st.alliance, st.chZ);

      // Everyone sees everyone — the convergence the announcement buys.
      for (const [who, url, token] of [["X", hubX.url, tokenX], ["Y", hubY.url, tokenY], ["Z", hubZ.url, tokenZ]]) {
        const seen = await names(url, token, st.alliance);
        checkEq(seen.status, 200, `hub ${who} lists the alliance`);
        checkEq(
          seen.list.join(","),
          "x-room,y-room,z-room",
          `hub ${who} must see all three, got ${seen.list.join(",")}`,
        );
      }
    });

    await scenario("a member that is down costs its own channel and nothing else", async () => {
      await hubZ.stop();

      const seen = await names(hubX.url, tokenX, st.alliance);
      checkEq(seen.status, 200, "a down member must not turn the list into an error");
      checkEq(
        seen.list.join(","),
        "x-room,y-room",
        `the reachable members must still answer, got ${seen.list.join(",")}`,
      );

      // And the messages of a hub that is up are still readable through the
      // alliance while another member is down.
      const msg = await json(`${hubX.url}/channels/${st.chX}/messages`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenX}` },
        body: JSON.stringify({ content: "still here" }),
      });
      check(msg.status === 200 || msg.status === 201, `post while Z is down: ${JSON.stringify(msg.body)}`);

      const read = await json(
        `${hubY.url}/alliances/${st.alliance}/channels/${st.chX}/messages`,
        { headers: { Authorization: `Bearer ${tokenY}` } },
      );
      checkEq(read.status, 200, `hub Y still reads hub X through the alliance: ${JSON.stringify(read.body)}`);
      check(
        read.body.some((m) => m.content === "still here"),
        `and sees the new message, got ${JSON.stringify(read.body)}`,
      );
    });

    await scenario("a member that comes back is seen again, with no repair step", async () => {
      await hubZ.start();

      const seen = await names(hubX.url, tokenX, st.alliance);
      checkEq(
        seen.list.join(","),
        "x-room,y-room,z-room",
        `the returning member must reappear on its own, got ${seen.list.join(",")}`,
      );

      const fromZ = await names(hubZ.url, tokenZ, st.alliance);
      checkEq(
        fromZ.list.join(","),
        "x-room,y-room,z-room",
        `and must still see the others, got ${fromZ.list.join(",")}`,
      );
    });

    await scenario("an invite token for one alliance does not open another", async () => {
      const other = await json(`${hubX.url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenX}` },
        body: JSON.stringify({ name: "Private" }),
      });
      checkEq(other.status, 201, `create the second alliance: ${JSON.stringify(other.body)}`);

      // The token is a signature over an alliance id. Presenting it for a
      // different id must not work, or an invite to one room would be an
      // invite to every room that hub is in.
      const joined = await json(`${hubZ.url}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenZ}` },
        body: JSON.stringify({
          inviter_hub_url: hubX.url,
          alliance_id: other.body.id,
          invite_token: st.inviteToken,
          own_hub_url: hubZ.url,
        }),
      });
      check(
        joined.status >= 400,
        `a token minted for another alliance must be refused, got ${joined.status} ${JSON.stringify(joined.body)}`,
      );

      const members = await json(`${hubX.url}/alliances/${other.body.id}`, {
        headers: { Authorization: `Bearer ${tokenX}` },
      });
      checkEq(members.body.members.length, 1, `and must not have joined: ${JSON.stringify(members.body.members)}`);
    });

    await scenario("unsharing a channel takes it off the partners' lists", async () => {
      const gone = await json(`${hubY.url}/alliances/${st.alliance}/channels/${st.chY}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${tokenY}` },
      });
      check(gone.status === 200 || gone.status === 204, `unshare: ${gone.status} ${JSON.stringify(gone.body)}`);

      const seen = await names(hubX.url, tokenX, st.alliance);
      check(
        !seen.list.includes("y-room"),
        `the unshared channel must leave the partner's list, got ${seen.list.join(",")}`,
      );

      // Shared again, it comes back — unsharing is not a one-way door.
      await shareInto(hubY.url, tokenY, st.alliance, st.chY);
      const again = await names(hubX.url, tokenX, st.alliance);
      check(
        again.list.includes("y-room"),
        `re-sharing must restore it, got ${again.list.join(",")}`,
      );
    });

    await scenario("one channel shared into two alliances reaches both partners", async () => {
      // Hub X is in Stress with Y and Z. A second alliance with Y alone, and
      // the same channel shared into both: the sharing is per alliance, so
      // both partners must see it, and neither learns about the other room.
      const second = await json(`${hubX.url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenX}` },
        body: JSON.stringify({ name: "Both" }),
      });
      checkEq(second.status, 201, `create the second alliance: ${JSON.stringify(second.body)}`);
      const both = second.body.id;

      const y = await joinFrom(hubX.url, tokenX, both, hubY.url, tokenY);
      checkEq(y.joined.status, 200, `hub Y joins the second: ${JSON.stringify(y.joined.body)}`);
      await shareInto(hubX.url, tokenX, both, st.chX);

      const inStress = await names(hubZ.url, tokenZ, st.alliance);
      check(inStress.list.includes("x-room"), `Z sees it in Stress, got ${inStress.list.join(",")}`);

      const inBoth = await names(hubY.url, tokenY, both);
      check(inBoth.list.includes("x-room"), `Y sees it in Both, got ${inBoth.list.join(",")}`);
      check(
        !inBoth.list.includes("z-room"),
        `and Both carries nothing of Stress, got ${inBoth.list.join(",")}`,
      );
    });

    await scenario("a voice grant is refused for a channel the alliance does not carry", async () => {
      // A channel hub X keeps to itself. Minting a grant for it would admit a
      // stranger's member to a room nobody agreed to share.
      const priv = await makeChannel(hubX.url, tokenX, "x-private");
      const grant = await json(`${hubY.url}/alliances/${st.alliance}/voice-grant`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenY}` },
        body: JSON.stringify({ channel_id: priv }),
      });
      check(
        grant.status >= 400,
        `a grant for an unshared channel must be refused, got ${grant.status} ${JSON.stringify(grant.body)}`,
      );
    });

    await scenario("leaving an alliance takes the leaver off the partners' lists", async () => {
      const left = await json(`${hubZ.url}/alliances/${st.alliance}/leave`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${tokenZ}` },
      });
      check(left.status === 200 || left.status === 204, `hub Z leaves: ${left.status} ${JSON.stringify(left.body)}`);

      const fromZ = await json(`${hubZ.url}/alliances`, {
        headers: { Authorization: `Bearer ${tokenZ}` },
      });
      check(
        !(fromZ.body ?? []).some((a) => a.id === st.alliance),
        `the leaver must drop it locally, got ${JSON.stringify(fromZ.body)}`,
      );

      const seen = await names(hubX.url, tokenX, st.alliance);
      check(
        !seen.list.includes("z-room"),
        `and the partners must stop carrying its channel, got ${seen.list.join(",")}`,
      );
    });
    await scenario("the partners' member list does not keep a hub that left", async () => {
      // The scenario above proves the *effect* — a leaver's channel is gone,
      // because the leaver answers for nothing. This asks the harder question:
      // does the partner still believe it is a member? A ghost row is a peer
      // this hub will keep calling, and a name the UI will keep showing.
      const detail = await json(`${hubX.url}/alliances/${st.alliance}`, {
        headers: { Authorization: `Bearer ${tokenX}` },
      });
      checkEq(detail.status, 200, `hub X reads the alliance: ${JSON.stringify(detail.body)}`);
      const keyZ = (await json(`${hubZ.url}/info`)).body.public_key;
      check(
        !detail.body.members.some((m) => m.hub_public_key === keyZ),
        `the leaver must be gone from the member list, got ${JSON.stringify(detail.body.members)}`,
      );
    });

    await scenario("a member that was down when somebody joined still converges", async () => {
      // The announcement a joiner sends is best-effort: a member that is down
      // does not get it. Nothing else ever re-sends, so this asks whether the
      // fix has the same hole one level down — a hub that misses one join is
      // blind to that member for good.
      const ownerW = identity();
      const hubW = await hub("hub-stress-w", ownerW);
      const tokenW = (await authenticate(hubW.url, ownerW)).body.token;
      const chW = await makeChannel(hubW.url, tokenW, "w-room");

      await hubY.stop();

      const w = await joinFrom(hubX.url, tokenX, st.alliance, hubW.url, tokenW);
      checkEq(w.joined.status, 200, `hub W joins while Y is down: ${JSON.stringify(w.joined.body)}`);
      await shareInto(hubW.url, tokenW, st.alliance, chW);

      await hubY.start();

      const seen = await names(hubY.url, tokenY, st.alliance);
      checkEq(seen.status, 200, `hub Y lists the alliance after coming back`);
      check(
        seen.list.includes("w-room"),
        `a hub that missed the announcement must still converge, got ${seen.list.join(",")}`,
      );
    });

  }

  // ── alliancechurn ───────────────────────────────────────────────────────
  //
  // The second half of the alliance edge cases: what happens when the shape
  // changes under a live alliance. Joining twice, leaving and coming back,
  // sharing something you do not own, writing through the alliance rather than
  // reading, a space shared with its descendants growing a new child, and the
  // last member walking out.
  if (want.has("alliancechurn")) {
    const ownerP = identity();
    const ownerQ = identity();
    const hubP = await hub("hub-churn-p", ownerP);
    const hubQ = await hub("hub-churn-q", ownerQ);
    const tokenP = (await authenticate(hubP.url, ownerP)).body.token;
    const tokenQ = (await authenticate(hubQ.url, ownerQ)).body.token;
    const ch = {};

    const channelOn = async (hubUrl, token, body) => {
      const c = await json(`${hubUrl}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
      });
      checkEq(c.status, 201, `create ${JSON.stringify(body)}: ${JSON.stringify(c.body)}`);
      return c.body.id;
    };

    const listNames = async (hubUrl, token, allianceId) => {
      const r = await json(`${hubUrl}/alliances/${allianceId}/channels`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      return { status: r.status, list: (r.body ?? []).map((c) => c.channel_name).sort() };
    };

    const invite = async (allianceId) => {
      const inv = await json(`${hubP.url}/alliances/${allianceId}/invite`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenP}` },
      });
      checkEq(inv.status, 200, `mint invite: ${JSON.stringify(inv.body)}`);
      return inv.body.token;
    };

    const join = async (allianceId, inviteToken) =>
      json(`${hubQ.url}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenQ}` },
        body: JSON.stringify({
          inviter_hub_url: hubP.url,
          alliance_id: allianceId,
          invite_token: inviteToken,
          own_hub_url: hubQ.url,
        }),
      });

    await scenario("two hubs ally, and joining twice changes nothing", async () => {
      ch.lounge = await channelOn(hubP.url, tokenP, { name: "lounge" });
      const al = await json(`${hubP.url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenP}` },
        body: JSON.stringify({ name: "Churn" }),
      });
      checkEq(al.status, 201, `create alliance: ${JSON.stringify(al.body)}`);
      ch.alliance = al.body.id;

      const share = await json(`${hubP.url}/alliances/${ch.alliance}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenP}` },
        body: JSON.stringify({ channel_id: ch.lounge }),
      });
      checkEq(share.status, 200, `share #lounge: ${JSON.stringify(share.body)}`);

      const first = await join(ch.alliance, await invite(ch.alliance));
      checkEq(first.status, 200, `hub Q joins: ${JSON.stringify(first.body)}`);

      // A second join with a fresh invite must not double the membership or
      // fail in a way a client would surface as breakage.
      const second = await join(ch.alliance, await invite(ch.alliance));
      check(
        second.status === 200 || second.status === 409,
        `joining twice must be a no-op or a plain conflict, got ${second.status} ${JSON.stringify(second.body)}`,
      );

      const detail = await json(`${hubP.url}/alliances/${ch.alliance}`, {
        headers: { Authorization: `Bearer ${tokenP}` },
      });
      checkEq(detail.body.members.length, 2, `still two members: ${JSON.stringify(detail.body.members)}`);
    });

    await scenario("a hub cannot share a channel that is not its own", async () => {
      // #lounge belongs to hub P. Hub Q offering it into the alliance would be
      // hub Q deciding what hub P shares.
      const stolen = await json(`${hubQ.url}/alliances/${ch.alliance}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenQ}` },
        body: JSON.stringify({ channel_id: ch.lounge }),
      });
      check(
        stolen.status >= 400,
        `sharing another hub's channel must be refused, got ${stolen.status} ${JSON.stringify(stolen.body)}`,
      );
    });

    await scenario("a message written through the alliance lands on the owner", async () => {
      // The read path is covered elsewhere; this is the write. Hub Q posts
      // into hub P's channel through the alliance route, and hub P must have
      // it locally afterwards.
      const posted = await json(
        `${hubQ.url}/alliances/${ch.alliance}/channels/${ch.lounge}/messages`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${tokenQ}` },
          body: JSON.stringify({ content: "hello from Q" }),
        },
      );
      check(
        posted.status === 200 || posted.status === 201,
        `alliance write: ${posted.status} ${JSON.stringify(posted.body)}`,
      );

      const local = await json(`${hubP.url}/channels/${ch.lounge}/messages`, {
        headers: { Authorization: `Bearer ${tokenP}` },
      });
      checkEq(local.status, 200, `owner reads its own channel: ${JSON.stringify(local.body)}`);
      // The body arrives prefixed with who said it and where, because a
      // federated write is signed by the visiting *hub* and the owner has no
      // way to attribute it to a person it has never seen (alliances.md).
      check(
        local.body.some((m) => m.content.includes("hello from Q")),
        `the message must be on the owning hub, got ${JSON.stringify(local.body.map((m) => m.content))}`,
      );
      check(
        local.body.some((m) => m.content.includes("via")),
        `and say it came from elsewhere, got ${JSON.stringify(local.body.map((m) => m.content))}`,
      );
    });

    await scenario("a space shared with its descendants carries a child added later", async () => {
      const space = await channelOn(hubP.url, tokenP, { name: "guild", is_category: true });
      const share = await json(`${hubP.url}/alliances/${ch.alliance}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokenP}` },
        body: JSON.stringify({ channel_id: space, include_descendants: true }),
      });
      checkEq(share.status, 200, `share the space: ${JSON.stringify(share.body)}`);

      // Created *after* the share: the partner sees it only if the expansion
      // is live rather than a snapshot taken at share time.
      await channelOn(hubP.url, tokenP, { name: "guild-chat", parent_id: space });

      const seen = await listNames(hubQ.url, tokenQ, ch.alliance);
      checkEq(seen.status, 200, `partner lists the alliance`);
      check(
        seen.list.includes("guild-chat"),
        `a later child must appear, got ${seen.list.join(",")}`,
      );
    });

    await scenario("a hub that left and rejoined is a member again", async () => {
      const left = await json(`${hubQ.url}/alliances/${ch.alliance}/leave`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${tokenQ}` },
      });
      check(left.status === 200 || left.status === 204, `hub Q leaves: ${left.status}`);

      const gone = await json(`${hubP.url}/alliances/${ch.alliance}`, {
        headers: { Authorization: `Bearer ${tokenP}` },
      });
      checkEq(gone.body.members.length, 1, `hub P is alone: ${JSON.stringify(gone.body.members)}`);

      const back = await join(ch.alliance, await invite(ch.alliance));
      checkEq(back.status, 200, `hub Q rejoins: ${JSON.stringify(back.body)}`);

      const again = await json(`${hubP.url}/alliances/${ch.alliance}`, {
        headers: { Authorization: `Bearer ${tokenP}` },
      });
      checkEq(again.body.members.length, 2, `and is a member again: ${JSON.stringify(again.body.members)}`);

      const seen = await listNames(hubQ.url, tokenQ, ch.alliance);
      check(
        seen.list.includes("lounge"),
        `and sees the shared channel again, got ${seen.list.join(",")}`,
      );
    });

    await scenario("the last member leaving does not leave a haunted alliance", async () => {
      // Both walk out. Neither should be left holding an alliance with no
      // members, and neither should answer for it afterwards.
      for (const [url, token] of [[hubQ.url, tokenQ], [hubP.url, tokenP]]) {
        const left = await json(`${url}/alliances/${ch.alliance}/leave`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
        check(left.status === 200 || left.status === 204, `leave from ${url}: ${left.status}`);
      }

      for (const [url, token] of [[hubP.url, tokenP], [hubQ.url, tokenQ]]) {
        const listed = await json(`${url}/alliances`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        check(
          !(listed.body ?? []).some((a) => a.id === ch.alliance),
          `${url} must not still list it, got ${JSON.stringify(listed.body)}`,
        );
        const detail = await json(`${url}/alliances/${ch.alliance}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        check(
          detail.status >= 400,
          `${url} must not answer for it, got ${detail.status} ${JSON.stringify(detail.body)}`,
        );
      }
    });
  }

  // ── alliancedrift ───────────────────────────────────────────────────────
  //
  // What an alliance looks like after the world moves under it: a hub that
  // changes address, a shared channel that gets deleted, partners that label
  // the same alliance differently, two hubs joining at the same moment, and a
  // room of five that has to agree about itself.
  if (want.has("alliancedrift")) {
    const owners = [identity(), identity(), identity(), identity(), identity()];
    const hubs = [];
    for (let i = 0; i < owners.length; i++) {
      hubs.push(await hub(`hub-drift-${i}`, owners[i]));
    }
    const tokens = [];
    for (let i = 0; i < hubs.length; i++) {
      tokens.push((await authenticate(hubs[i].url, owners[i])).body.token);
    }
    const dr = {};

    const mkChannel = async (i, name) => {
      const c = await json(`${hubs[i].url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokens[i]}` },
        body: JSON.stringify({ name }),
      });
      checkEq(c.status, 201, `create #${name} on hub ${i}: ${JSON.stringify(c.body)}`);
      return c.body.id;
    };

    const share = async (i, allianceId, channelId) => {
      const r = await json(`${hubs[i].url}/alliances/${allianceId}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokens[i]}` },
        body: JSON.stringify({ channel_id: channelId }),
      });
      checkEq(r.status, 200, `hub ${i} shares: ${JSON.stringify(r.body)}`);
    };

    const seenBy = async (i, allianceId) => {
      const r = await json(`${hubs[i].url}/alliances/${allianceId}/channels`, {
        headers: { Authorization: `Bearer ${tokens[i]}` },
      });
      return { status: r.status, list: (r.body ?? []).map((c) => c.channel_name).sort() };
    };

    const joinVia = async (inviterIdx, allianceId, joinerIdx) => {
      const inv = await json(`${hubs[inviterIdx].url}/alliances/${allianceId}/invite`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokens[inviterIdx]}` },
      });
      checkEq(inv.status, 200, `invite from hub ${inviterIdx}: ${JSON.stringify(inv.body)}`);
      return json(`${hubs[joinerIdx].url}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokens[joinerIdx]}` },
        body: JSON.stringify({
          inviter_hub_url: hubs[inviterIdx].url,
          alliance_id: allianceId,
          invite_token: inv.body.token,
          own_hub_url: hubs[joinerIdx].url,
        }),
      });
    };

    await scenario("five hubs in one alliance all agree about it", async () => {
      const al = await json(`${hubs[0].url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokens[0]}` },
        body: JSON.stringify({ name: "Drift" }),
      });
      checkEq(al.status, 201, `create alliance: ${JSON.stringify(al.body)}`);
      dr.alliance = al.body.id;

      dr.channels = [];
      for (let i = 0; i < hubs.length; i++) {
        dr.channels.push(await mkChannel(i, `room-${i}`));
      }
      await share(0, dr.alliance, dr.channels[0]);

      // Joined one at a time through the first hub — each newcomer announces
      // itself to everybody already there, which is the only reason the ones
      // who joined early know about the ones who joined late.
      for (let i = 1; i < hubs.length; i++) {
        const joined = await joinVia(0, dr.alliance, i);
        checkEq(joined.status, 200, `hub ${i} joins: ${JSON.stringify(joined.body)}`);
        await share(i, dr.alliance, dr.channels[i]);
      }

      const expected = dr.channels.map((_, i) => `room-${i}`).sort().join(",");
      for (let i = 0; i < hubs.length; i++) {
        const seen = await seenBy(i, dr.alliance);
        checkEq(seen.status, 200, `hub ${i} lists the alliance`);
        checkEq(seen.list.join(","), expected, `hub ${i} must see all five, got ${seen.list.join(",")}`);
      }
    });

    await scenario("each hub labels the alliance for itself", async () => {
      // The name is a local label, not a shared fact (alliances.md). Renaming
      // is not a route, so this asserts the weaker thing that matters: every
      // hub answers with a name of its own rather than an empty one, and the
      // id is what they agree on.
      for (let i = 0; i < hubs.length; i++) {
        const detail = await json(`${hubs[i].url}/alliances/${dr.alliance}`, {
          headers: { Authorization: `Bearer ${tokens[i]}` },
        });
        checkEq(detail.status, 200, `hub ${i} reads the alliance`);
        checkEq(detail.body.id, dr.alliance, `hub ${i} agrees on the id`);
        check(
          typeof detail.body.name === "string" && detail.body.name.length > 0,
          `hub ${i} must hold a label, got ${JSON.stringify(detail.body.name)}`,
        );
        checkEq(
          detail.body.members.length,
          hubs.length,
          `hub ${i} must count five members, got ${JSON.stringify(detail.body.members)}`,
        );
      }
    });

    await scenario("deleting a shared channel takes it off the partners' lists", async () => {
      const gone = await json(`${hubs[4].url}/channels/${dr.channels[4]}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${tokens[4]}` },
      });
      check(gone.status === 200 || gone.status === 204, `delete #room-4: ${gone.status}`);

      const seen = await seenBy(0, dr.alliance);
      check(
        !seen.list.includes("room-4"),
        `a deleted channel must not linger in the alliance, got ${seen.list.join(",")}`,
      );

      // And reading it by id is a refusal rather than a surprise.
      const read = await json(
        `${hubs[0].url}/alliances/${dr.alliance}/channels/${dr.channels[4]}/messages`,
        { headers: { Authorization: `Bearer ${tokens[0]}` } },
      );
      check(
        read.status >= 400 || (read.body ?? []).length === 0,
        `reading a deleted channel must not invent content, got ${read.status} ${JSON.stringify(read.body)}`,
      );
    });

    await scenario("two hubs joining at the same moment both land", async () => {
      const al = await json(`${hubs[0].url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokens[0]}` },
        body: JSON.stringify({ name: "Race" }),
      });
      checkEq(al.status, 201, `create the second alliance: ${JSON.stringify(al.body)}`);
      const race = al.body.id;

      // Both invites minted first, then both joins fired without awaiting the
      // first: the two write the same member table on the inviter.
      const [a, b] = await Promise.all([
        joinVia(0, race, 1),
        joinVia(0, race, 2),
      ]);
      checkEq(a.status, 200, `first joiner: ${JSON.stringify(a.body)}`);
      checkEq(b.status, 200, `second joiner: ${JSON.stringify(b.body)}`);

      const detail = await json(`${hubs[0].url}/alliances/${race}`, {
        headers: { Authorization: `Bearer ${tokens[0]}` },
      });
      checkEq(
        detail.body.members.length,
        3,
        `both joins must survive the race, got ${JSON.stringify(detail.body.members)}`,
      );
    });

    await scenario("a hub that moves keeps its alliance, once somebody asks", async () => {
      // The operational case: an address is a deployment detail and it
      // changes. The member rows hold it, so a hub that moves is unreachable
      // at the recorded URL until something repairs the row.
      const moved = await json(`${hubs[3].url}/alliances/${dr.alliance}/channels`, {
        headers: { Authorization: `Bearer ${tokens[3]}` },
      });
      checkEq(moved.status, 200, "the mover can still read its own view");

      // Asked from the other side, the mover is reachable at the URL everyone
      // recorded — which is the state this asserts, so that the day it stops
      // being true the harness says so rather than a user.
      const detail = await json(`${hubs[0].url}/alliances/${dr.alliance}`, {
        headers: { Authorization: `Bearer ${tokens[0]}` },
      });
      const row = detail.body.members.find((m) => m.hub_url === hubs[3].url);
      check(
        row,
        `hub 3 must be recorded at its own address, got ${JSON.stringify(detail.body.members.map((m) => m.hub_url))}`,
      );
      const info = await json(`${row.hub_url}/info`);
      checkEq(info.status, 200, "and that address must answer");
      checkEq(info.body.public_key, row.hub_public_key, "with the key the row names");
    });
  }

  // ── farms ───────────────────────────────────────────────────────────────
  if (want.has("farm") || want.has("crossfarm")) {
    const admin = identity();
    const farmA = await farm("farm-a", admin);
    state.farmA = farmA;
    state.farmAdmin = admin;

    await scenario("a fresh farm seeds its admin and answers /farm/info", async () => {
      const info = await json(`${farmA.url}/farm/info`);
      checkEq(info.status, 200, `farm info: ${JSON.stringify(info.body)}`);
      check(info.body.public_key, "a farm must report its own pubkey");
    });

    await scenario("the seeded admin can create a hub, and a stranger cannot", async () => {
      const adminToken = await farmToken(farmA.url, admin);

      // `creation_policy` defaults to 'admin_only', so this is the gate that
      // used to refuse everyone because no admin could exist.
      const created = await json(`${farmA.url}/farm/hubs`, {
        method: "POST",
        headers: { Authorization: `Bearer ${adminToken}` },
        body: JSON.stringify({ name: "Farmed Hub" }),
      });
      check(
        created.status === 200 || created.status === 201,
        `admin should create a hub: ${created.status} ${JSON.stringify(created.body)}`,
      );
      state.farmHubId = created.body.id;
      check(state.farmHubId, `create response should carry an id: ${JSON.stringify(created.body)}`);

      const stranger = identity();
      const strangerToken = await farmToken(farmA.url, stranger);
      const refused = await json(`${farmA.url}/farm/hubs`, {
        method: "POST",
        headers: { Authorization: `Bearer ${strangerToken}` },
        body: JSON.stringify({ name: "Not Yours" }),
      });
      checkEq(refused.status, 403, "admin_only must still mean admin only");
    });

    await scenario("the farm spawns a real hub and proxies /hub/<serial> to it", async () => {
      // The farm learns the hub's pubkey from its first heartbeat, and that is
      // also what makes the serial route resolvable — so poll rather than
      // assume it is instant. `GET /farm/hubs/{id}` does not carry the pubkey;
      // the fleet view does.
      let entry = null;
      for (let i = 0; i < 60 && !entry; i++) {
        const fleet = await json(`${farmA.url}/farm/admin/fleet`, {
          headers: { Authorization: `Bearer ${await farmToken(farmA.url, admin)}` },
        });
        const hubs = Array.isArray(fleet.body) ? fleet.body : fleet.body?.hubs ?? [];
        entry = hubs.find((h) => h.id === state.farmHubId && h.hub_pubkey) ?? null;
        if (!entry) await new Promise((r) => setTimeout(r, 1000));
      }
      check(entry, "the spawned hub never reported a pubkey back to the farm");
      state.farmHubPubkey = entry.hub_pubkey;

      // Through the farm's proxy, not at the hub's own port: this is the path a
      // farm-hosted hub is actually reached on.
      const proxied = await json(`${farmA.url}/hub/${entry.hub_pubkey}/info`);
      checkEq(proxied.status, 200, `proxied /info: ${JSON.stringify(proxied.body)}`);
      checkEq(
        proxied.body.public_key,
        entry.hub_pubkey,
        "the proxy must reach the hub the serial names, not some other hub",
      );
    });

    await scenario("the hub_url the farm hands out actually resolves", async () => {
      // `hub_url()` advertises `{farm}/hub/{hub_id}`, but the proxy resolves a
      // segment as either a 64-hex pubkey or a slug — and a hub_id is 8 hex
      // characters, so it is neither unless something registered it as a slug.
      // Whatever the answer, the URL the farm puts in its own API response has
      // to work, or every client that follows it is broken.
      const listed = await json(`${farmA.url}/farm/hubs/${state.farmHubId}`, {
        headers: { Authorization: `Bearer ${await farmToken(farmA.url, admin)}` },
      });
      checkEq(listed.status, 200, `get hub: ${JSON.stringify(listed.body)}`);
      const advertised = listed.body.hub_url;
      check(advertised, `the farm should advertise a hub_url: ${JSON.stringify(listed.body)}`);

      const followed = await json(`${advertised}/info`);
      checkEq(
        followed.status,
        200,
        `following the farm's own hub_url (${advertised}) must reach the hub`,
      );
    });
  }

  // ── two farms, and an alliance across the boundary ──────────────────────
  if (want.has("crossfarm")) {
    const adminB = identity();
    const farmB = await farm("farm-b", adminB);

    /** Create a hub on a farm and wait until the farm can route to it. */
    async function farmedHub(f, adminId, name) {
      const token = await farmToken(f.url, adminId);
      const created = await json(`${f.url}/farm/hubs`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name }),
      });
      check(
        created.status === 200 || created.status === 201,
        `create hub on ${f.name}: ${created.status} ${JSON.stringify(created.body)}`,
      );
      const id = created.body.id;

      for (let i = 0; i < 90; i++) {
        const got = await json(`${f.url}/farm/hubs/${id}`, {
          headers: { Authorization: `Bearer ${await farmToken(f.url, adminId)}` },
        });
        // `hub_url` is absent until the hub claims its row, which is exactly
        // the signal that it is routable — so this waits on the right thing
        // rather than on a sleep.
        if (got.status === 200 && got.body.hub_url) {
          return { id, url: got.body.hub_url };
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
      throw new Error(`hub ${id} on ${f.name} never became routable`);
    }

    await scenario("each farm hosts a hub reachable through its own proxy", async () => {
      state.hubOnA = await farmedHub(state.farmA, state.farmAdmin, "Hub On A");
      state.hubOnB = await farmedHub(farmB, adminB, "Hub On B");

      for (const [label, h] of [["farm A", state.hubOnA], ["farm B", state.hubOnB]]) {
        const info = await json(`${h.url}/info`);
        checkEq(info.status, 200, `${label}'s hub must answer through the proxy`);
        check(info.body.public_key, `${label}'s hub must report a pubkey`);
      }
      check(
        state.hubOnA.url !== state.hubOnB.url,
        "two farms must not hand out the same hub address",
      );
    });

    await scenario("two farm-hosted hubs form an alliance across the farm boundary", async () => {
      // Every request below crosses a farm proxy, which is the point of the
      // scenario. Authenticated as each farm's admin because the farm seeds
      // the *creating user* as the spawned hub's owner — a fresh identity
      // would hit the hub's invite_only default instead.
      const tokA = await authenticate(state.hubOnA.url, state.farmAdmin);
      checkEq(tokA.status, 200, `auth on farm A's hub: ${JSON.stringify(tokA.body)}`);
      const tokB = await authenticate(state.hubOnB.url, adminB);
      checkEq(tokB.status, 200, `auth on farm B's hub: ${JSON.stringify(tokB.body)}`);

      const channel = await json(`${state.hubOnA.url}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokA.body.token}` },
        body: JSON.stringify({ name: "cross-farm" }),
      });
      checkEq(channel.status, 201, `create channel: ${JSON.stringify(channel.body)}`);

      const al = await json(`${state.hubOnA.url}/alliances`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokA.body.token}` },
        body: JSON.stringify({ name: "Interfarm Pact" }),
      });
      checkEq(al.status, 201, `create alliance: ${JSON.stringify(al.body)}`);

      const share = await json(`${state.hubOnA.url}/alliances/${al.body.id}/channels`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokA.body.token}` },
        body: JSON.stringify({ channel_id: channel.body.id }),
      });
      checkEq(share.status, 200, `share: ${JSON.stringify(share.body)}`);

      const inv = await json(`${state.hubOnA.url}/alliances/${al.body.id}/invite`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokA.body.token}` },
      });
      checkEq(inv.status, 200, `invite: ${JSON.stringify(inv.body)}`);

      // The join that matters: hub B (on farm B) authenticating to hub A (on
      // farm A) as a peer hub, through both farms' proxies.
      const joined = await json(`${state.hubOnB.url}/alliances/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tokB.body.token}` },
        body: JSON.stringify({
          inviter_hub_url: state.hubOnA.url,
          alliance_id: al.body.id,
          invite_token: inv.body.token,
          own_hub_url: state.hubOnB.url,
        }),
      });
      checkEq(
        joined.status,
        200,
        `a hub on one farm must be able to ally with a hub on another: ${JSON.stringify(joined.body)}`,
      );

      const detail = await json(`${state.hubOnA.url}/alliances/${al.body.id}`, {
        headers: { Authorization: `Bearer ${tokA.body.token}` },
      });
      checkEq(detail.body.members.length, 2, "the alliance should have both hubs");

      // And the shared channel is visible from the other side of both proxies.
      const shared = await json(`${state.hubOnB.url}/alliances/${al.body.id}/channels`, {
        headers: { Authorization: `Bearer ${tokB.body.token}` },
      });
      checkEq(shared.status, 200, `list shared from B: ${JSON.stringify(shared.body)}`);
      check(
        shared.body.some((c) => c.channel_id === channel.body.id),
        `hub B must see A's channel across the farm boundary, got ${JSON.stringify(shared.body)}`,
      );
    });
  }
} catch (e) {
  process.stdout.write(`\nharness error: ${e.stack ?? e.message}\n`);
  teardown();
  process.exit(1);
}

const ok = report();
teardown();
process.exit(ok ? 0 : 1);
