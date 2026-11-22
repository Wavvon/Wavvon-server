# Default soundboard clips

The six clips a new hub starts with (`seed_default_clips` in
`crates/hub/src/routes/soundboard.rs`). They were made for this project,
synthesised with ffmpeg's `lavfi` generators (sine, square-wave sums,
pink and white noise) on 2026-11-22: no recording or third-party sample is
in them. They are covered by this repository's licence.

Each is mono Opus in Ogg, 48 kHz, 64 kb/s, under 3 s and 25 KB, well inside
the hub's per-clip limits (10 s, 512 KB).

| File | Name | Emoji |
|---|---|---|
| `airhorn.ogg` | Airhorn | 📯 |
| `applause.ogg` | Applause | 👏 |
| `ding.ogg` | Ding | 🔔 |
| `drum-roll.ogg` | Drum roll | 🥁 |
| `sad-trombone.ogg` | Sad trombone | 🎺 |
| `tada.ogg` | Ta-da | 🎉 |

To replace one, keep the file name, re-encode with
`ffmpeg -i in.wav -ac 1 -ar 48000 -c:a libopus -b:a 64k out.ogg`, and run the
`soundboard_flow` tests. Hubs that already installed the defaults keep their
copies; only new hubs get the new file.
