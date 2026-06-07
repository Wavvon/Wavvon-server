# Voxply Hub Workspace — Roadmap

## Next up
- **Unified screen share modal** — replace the two-step flow (ScreenSharePicker + OS native
  picker) with a single Voxply-native modal that enumerates screens and windows with thumbnails
  and folds in audio/webcam settings. Requires a new `list_capture_sources` Tauri command.
  Design doc: `docs/screen-share-modal.md`.

## Wishlist
_Ideas not yet designed._

## Known issues / future work
- **`hub_spawned` reply is not acted on by the farm.** When a server agent responds
  with `{"type":"hub_spawned","port":N}`, `handle_agent_socket` only bumps
  `last_seen_at`. The farm has no runtime record that the hub is actually listening.
  Fix needed if we ever want the farm to proxy connections, show a "running" badge,
  or route clients to the real port.
- **Banner `banner_file_id` upload flow is manual.** The three-step flow (create banner
  channel → upload image → PATCH with file id) is exposed as separate API calls. The
  desktop creation modal defers the upload step to channel settings. A future polish
  pass could make this seamless in the creation modal itself.

## Won't do
_Decisions not to implement something._
