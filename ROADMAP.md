# Voxply Hub Workspace — Roadmap

## Next up
_Nothing scheduled yet._

## Wishlist
_Ideas not yet designed._

## Known issues / future work
- **`hub_spawned` reply is not acted on by the farm.** When a server agent responds
  with `{"type":"hub_spawned","port":N}`, `handle_agent_socket` only bumps
  `last_seen_at`. The farm has no runtime record that the hub is actually listening.
  Fix needed if we ever want the farm to proxy connections, show a "running" badge,
  or route clients to the real port.

## Won't do
_Decisions not to implement something._
