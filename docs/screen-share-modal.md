# Unified Screen Share Modal

## Problem

The current screen share flow has two sequential UI steps:

1. **ScreenSharePicker modal** — audio toggle, webcam toggle + device selector, "Start sharing" button.
2. **OS/browser native picker** — `navigator.mediaDevices.getDisplayMedia()` opens the platform's own overlay for source selection (screens, windows, browser tabs).

Users experience these as two nested modals. The goal is to collapse them into a single Voxply-native modal that handles both source selection (with thumbnail previews) and audio/webcam settings in one place.

---

## Key Constraint

Standard browser APIs (`getDisplayMedia()`) cannot enumerate capture sources or produce thumbnails without showing the OS picker. To display custom previews inside a Voxply modal, the desktop app (Tauri) must call platform APIs directly via a new Tauri command.

The web and android clients cannot implement custom source enumeration — they fall back to the system picker. The unified modal is a **desktop-only** feature.

---

## New Tauri Command: `list_capture_sources`

### Rust side (`src-tauri/src/lib.rs`)

Returns a list of capturable screens and windows, each with a small thumbnail image.

```rust
#[derive(serde::Serialize)]
pub struct CaptureSource {
    pub id: String,            // opaque handle passed back to getDisplayMedia
    pub name: String,
    pub kind: String,          // "screen" | "window"
    pub thumbnail_b64: String, // PNG, ~160×90, base64-encoded
}

#[tauri::command]
pub async fn list_capture_sources() -> Result<Vec<CaptureSource>, String> { ... }
```

**Windows implementation:** Use `IDXGIOutput` enumeration for screens. Use `EnumWindows` + `PrintWindow` (or `BitBlt`) for visible application windows. Encode each thumbnail as PNG via the `image` crate.

**macOS implementation:** Use `CGWindowListCopyWindowInfo` + `CGWindowListCreateImageFromArray` for thumbnails.

Both platforms: filter out the Voxply window itself, hidden windows, and tiny windows (< 100px on either axis).

### Frontend call

```typescript
import { invoke } from "@tauri-apps/api/core";

const sources = await invoke<CaptureSource[]>("list_capture_sources");
```

---

## Updated `ScreenShareOpts`

```typescript
export interface ScreenShareOpts {
  sourceId: string;       // id from CaptureSource, passed to getDisplayMedia constraints
  includeAudio: boolean;
  includeWebcam: boolean;
  webcamDeviceId: string;
}
```

---

## Unified Modal: `ScreenShareModal`

Replaces `ScreenSharePicker.tsx`. Rendered as a full dialog.

### Layout

```
┌─────────────────────────────────────────────────────────┐
│  Share your screen                                       │
│                                                          │
│  [ Screens ]  [ Windows ]   ← tab strip                 │
│                                                          │
│  ┌──────┐ ┌──────┐ ┌──────┐                            │
│  │ img  │ │ img  │ │ img  │  ← thumbnail grid           │
│  │      │ │      │ │      │    selected = ring border   │
│  │name  │ │name  │ │name  │                            │
│  └──────┘ └──────┘ └──────┘                            │
│                                                          │
│  ── Settings ──────────────────────────────────────────  │
│  [✓] Include audio     [✓] Include webcam               │
│       Webcam: [ Built-in Camera ▼ ]                     │
│                                                          │
│  [ Cancel ]                        [ Share ]            │
└─────────────────────────────────────────────────────────┘
```

### Behaviour

- On open: calls `list_capture_sources`, splits results into "Screens" and "Windows" tabs.
- Loading state: spinner while sources enumerate.
- First screen is auto-selected.
- Share button is disabled until a source is selected.
- Clicking Share calls `handleShareStart(opts)` with the selected `sourceId`.

### getDisplayMedia constraints

`useVoice.ts` `handleShareStart` uses the source ID to constrain the picker:

```typescript
const stream = await navigator.mediaDevices.getDisplayMedia({
  video: {
    // Chromium (Tauri's webview on Windows/macOS) honours these to skip its own picker
    mandatory: {
      chromeMediaSource: "desktop",
      chromeMediaSourceId: opts.sourceId,
    },
  } as MediaTrackConstraints,
  audio: opts.includeAudio,
});
```

This bypasses the OS overlay entirely — the user has already picked in Voxply's own UI.

> **Note:** `chromeMediaSource: "desktop"` works in Chromium-based webviews (WKWebView on macOS also supports it via `desktopCapturer` equivalents). It is not part of the W3C spec and has no effect in Firefox.

---

## Files to Change

| File | Change |
|------|--------|
| `src-tauri/src/lib.rs` | Add `list_capture_sources` command + `CaptureSource` struct; register in `Builder` |
| `src-tauri/Cargo.toml` | Add `image` crate for PNG encoding; platform deps for capture APIs |
| `desktop/src/types.ts` | Update `ScreenShareOpts` to include `sourceId` |
| `desktop/src/components/ScreenSharePicker.tsx` | Replace entirely with `ScreenShareModal.tsx` |
| `desktop/src/hooks/useVoice.ts` | Update `handleShareStart` to pass `chromeMediaSource` constraints |
| `desktop/src/App.tsx` | Rename import; prop types unchanged (`onStart`, `onCancel`) |

---

## Out of Scope

- Live preview of the selected source inside the modal (costs a capture stream just for preview — YAGNI).
- Audio device selection (beyond the binary include/exclude toggle already present).
- Quality / bitrate settings in the picker — those live in voice settings.
- Web and Android clients: they keep the current `getDisplayMedia()` system picker since no native enumeration API is available.
