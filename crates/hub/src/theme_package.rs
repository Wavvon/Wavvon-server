//! Server-side check of a `.wavvontheme` package (themes.md §1, §2).
//!
//! A port of the client's loader (`packages/ui/src/themes/theme.ts` and
//! friends in Wavvon-clients): a hub must never serve a package the client
//! would reject, so the two keep the same rules. Change one, change both.

use std::collections::HashMap;
use std::io::{Cursor, Read};

pub const MAX_ZIP_BYTES: usize = 8 * 1024 * 1024;
const MAX_IMAGE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SOUND_BYTES: u64 = 256 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_ICON_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 200;
const MAX_SOUND_SECONDS: f64 = 5.0;
const MANIFEST: &str = "theme.json";

const IMAGE_EXT: &[&str] = &["png", "webp", "jpg", "jpeg", "svg"];
const SOUND_EXT: &[&str] = &["ogg", "mp3", "wav"];

const SOUND_NAMES: &[&str] = &[
    "message",
    "mention",
    "voice_join",
    "voice_leave",
    "mute",
    "unmute",
    "deafen",
    "undeafen",
];

const CHANNEL_GLYPHS: &[&str] = &[
    "chat",
    "mic",
    "headphones",
    "speaker",
    "video",
    "music",
    "game",
    "film",
    "book",
    "star",
    "heart",
    "shield",
    "crown",
    "lock",
    "key",
    "bolt",
    "home",
    "globe",
    "info",
    "warning",
    "person",
    "group",
    "trophy",
    "rocket",
    "tools",
    "megaphone",
    "news",
];

const ICON_NAMES: &[&str] = &[
    "phone-off",
    "mic",
    "mic-off",
    "deafen",
    "screen-share",
    "camera",
    "camera-off",
    "pin",
    "search",
    "members",
    "link",
    "flag",
    "reply",
    "edit",
    "trash",
    "settings",
    "plus",
    "close",
    "chevron",
    "expand",
    "reset",
    "forum",
    "bell-off",
    "lock",
    "paperclip",
    "speaker",
    "clock",
    "whisper",
    "cake",
    "calendar",
    "wave",
    "reaction-add",
    "messages",
    "discover",
    "mention",
    "channel-text",
    "channel-voice",
    "channel-forum",
    "channel-spawner",
];

fn is_icon_name(name: &str) -> bool {
    ICON_NAMES.contains(&name)
        || name
            .strip_prefix("channel-")
            .is_some_and(|g| CHANNEL_GLYPHS.contains(&g))
}

#[derive(Clone, Copy, PartialEq)]
enum TokenType {
    Color,
    Shadow,
    Radius,
}

fn token_type(name: &str) -> Option<TokenType> {
    Some(match name {
        "--bg" | "--bg-elevated" | "--bg-sunken" | "--surface" | "--surface-hover" | "--text"
        | "--text-muted" | "--text-faint" | "--accent" | "--accent-hover" | "--accent-text"
        | "--info" | "--info-hover" | "--success" | "--warning" | "--danger" | "--danger-hover"
        | "--danger-bg" | "--border" | "--ring" | "--overlay" => TokenType::Color,
        "--shadow-sm" | "--shadow-md" | "--shadow-lg" => TokenType::Shadow,
        "--skin-radius-scale" => TokenType::Radius,
        _ => return None,
    })
}

/// A validated package: its preview image, when it names one.
pub struct ThemeCheck {
    pub preview: Option<(Vec<u8>, &'static str)>,
}

pub fn extension_of(path: &str) -> String {
    path.rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn image_mime(path: &str) -> Option<&'static str> {
    Some(match extension_of(path).as_str() {
        "png" => "image/png",
        "webp" => "image/webp",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        _ => return None,
    })
}

fn is_sound(path: &str) -> bool {
    SOUND_EXT.contains(&extension_of(path).as_str())
}

fn check_relative_path(path: &str) -> Result<(), String> {
    if path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.split('/').any(|s| s == ".." || s.is_empty())
    {
        return Err(format!(
            "Path \"{path}\" must be relative, with no \"..\", no absolute path"
        ));
    }
    Ok(())
}

pub fn validate(bytes: &[u8]) -> Result<ThemeCheck, String> {
    if bytes.len() > MAX_ZIP_BYTES {
        return Err("Package is larger than 8 MB".into());
    }
    let mut ar =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| "Not a valid zip file".to_string())?;
    let mut files: HashMap<String, Vec<u8>> = HashMap::new();
    let mut entries = 0;
    for i in 0..ar.len() {
        let f = ar.by_index(i).map_err(|_| "Not a valid zip file")?;
        let name = f.name().map_err(|_| "Not a valid zip file")?.to_string();
        if f.is_symlink() || f.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
            return Err(format!(
                "\"{name}\" is a link, which a package may not hold"
            ));
        }
        if name.ends_with('/') {
            continue;
        }
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(format!("Package has more than {MAX_ENTRIES} files"));
        }
        check_relative_path(&name)?;
        let is_manifest = name == MANIFEST;
        let ext = extension_of(&name);
        if !is_manifest && !IMAGE_EXT.contains(&ext.as_str()) && !SOUND_EXT.contains(&ext.as_str())
        {
            return Err(format!(
                "File \"{name}\" has a type that is not allowed in a package"
            ));
        }
        let limit = if is_manifest {
            MAX_MANIFEST_BYTES
        } else if is_sound(&name) {
            MAX_SOUND_BYTES
        } else {
            MAX_IMAGE_BYTES
        };
        let too_big = || format!("File \"{name}\" is larger than {} KB", limit / 1024);
        if f.size() > limit {
            return Err(too_big());
        }
        // The declared size can lie; read one byte past the limit to know.
        let mut data = Vec::new();
        f.take(limit + 1)
            .read_to_end(&mut data)
            .map_err(|_| "Not a valid zip file")?;
        if data.len() as u64 > limit {
            return Err(too_big());
        }
        files.insert(name, data);
    }

    let manifest = files
        .get(MANIFEST)
        .ok_or_else(|| format!("Missing {MANIFEST}"))?;
    let m: serde_json::Value =
        serde_json::from_slice(manifest).map_err(|_| format!("{MANIFEST} is not valid JSON"))?;
    validate_manifest(&m, &files)
}

fn object<'a>(
    v: &'a serde_json::Value,
    what: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{what} must be an object"))
}

fn validate_manifest(
    m: &serde_json::Value,
    files: &HashMap<String, Vec<u8>>,
) -> Result<ThemeCheck, String> {
    let m = m.as_object().ok_or("theme.json is not an object")?;
    if m.get("format").and_then(|v| v.as_str()) != Some("wavvon.theme") {
        return Err("Invalid format field".into());
    }
    if m.get("version").and_then(|v| v.as_f64()) != Some(1.0) {
        return Err("Unsupported version".into());
    }
    let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.trim().is_empty() || name.encode_utf16().count() > 48 {
        return Err("Invalid name (must be 1-48 characters)".into());
    }

    let colors = m
        .get("colors")
        .and_then(|v| v.as_object())
        .ok_or("Missing colors block")?;
    let mut any_scheme = false;
    for scheme in ["dark", "light"] {
        if let Some(map) = colors.get(scheme) {
            validate_tokens(map, scheme)?;
            any_scheme = true;
        }
    }
    if !any_scheme {
        return Err("colors needs a dark or a light map".into());
    }

    let mut wanted: Vec<(String, String)> = Vec::new();
    if let Some(icons) = m.get("icons") {
        for (name, path) in object(icons, "icons")? {
            if !is_icon_name(name) {
                continue;
            }
            let path = path
                .as_str()
                .ok_or_else(|| format!("icons.{name}: expected a path"))?;
            check_relative_path(path)?;
            wanted.push((format!("icons.{name}"), path.to_string()));
        }
    }
    let mut background: Option<String> = None;
    if let Some(bg) = m.get("background") {
        let image = object(bg, "background")?
            .get("image")
            .and_then(|v| v.as_str())
            .ok_or("background.image: expected a path")?;
        check_relative_path(image)?;
        background = Some(image.to_string());
    }
    let mut sounds: Vec<(String, String)> = Vec::new();
    if let Some(s) = m.get("sounds") {
        for (name, path) in object(s, "sounds")? {
            if !SOUND_NAMES.contains(&name.as_str()) {
                continue;
            }
            let path = path
                .as_str()
                .ok_or_else(|| format!("sounds.{name}: expected a path"))?;
            check_relative_path(path)?;
            sounds.push((name.clone(), path.to_string()));
        }
    }
    let preview = match m.get("preview").and_then(|v| v.as_str()) {
        Some(p) => {
            check_relative_path(p)?;
            Some(p.to_string())
        }
        None => None,
    };

    for (name, path) in &sounds {
        let file = files
            .get(path)
            .ok_or_else(|| format!("sounds.{name}: {path} is not in the package"))?;
        if !is_sound(path) {
            return Err(format!(
                "sounds.{name}: {path} is not an Ogg, MP3 or WAV file"
            ));
        }
        match audio_duration_seconds(file, path) {
            None => {
                return Err(format!(
                    "sounds.{name}: could not read the length of {path}"
                ))
            }
            Some(s) if s > MAX_SOUND_SECONDS => {
                return Err(format!(
                    "sounds.{name}: {path} is longer than {MAX_SOUND_SECONDS} seconds"
                ))
            }
            _ => {}
        }
    }
    let image = |what: &str, path: &str, max: usize, max_label: &str| -> Result<(), String> {
        let file = files
            .get(path)
            .ok_or_else(|| format!("{what}: {path} is not in the package"))?;
        if image_mime(path).is_none() {
            return Err(format!("{what}: {path} is not an image"));
        }
        if file.len() > max {
            return Err(format!("{what}: {path} is larger than {max_label}"));
        }
        Ok(())
    };
    if let Some(p) = &preview {
        image("preview", p, MAX_IMAGE_BYTES as usize, "2 MB")?;
    }
    if let Some(p) = &background {
        image("background", p, MAX_IMAGE_BYTES as usize, "2 MB")?;
    }
    for (what, path) in &wanted {
        image(what, path, MAX_ICON_BYTES, "64 KB")?;
    }

    Ok(ThemeCheck {
        preview: preview.map(|p| {
            let mime = image_mime(&p).unwrap_or("application/octet-stream");
            (files[&p].clone(), mime)
        }),
    })
}

const FORBIDDEN: &[&str] = &["url(", "var(", "@", "expression", "/*", ";", "}", "<"];

fn validate_tokens(raw: &serde_json::Value, scheme: &str) -> Result<(), String> {
    let map = raw
        .as_object()
        .ok_or_else(|| format!("colors.{scheme} must be an object"))?;
    for (k, v) in map {
        let Some(ty) = token_type(k) else { continue };
        let v = v
            .as_str()
            .ok_or_else(|| format!("colors.{scheme} {k}: expected string value"))?;
        if FORBIDDEN.iter().any(|f| v.contains(f)) {
            return Err(format!("colors.{scheme} {k}: contains forbidden content"));
        }
        let ok = match ty {
            TokenType::Color => is_valid_color(v),
            TokenType::Shadow => {
                v.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c.is_ascii_whitespace() || ".%,()#-".contains(c)
                }) && !v.is_empty()
            }
            TokenType::Radius => is_valid_radius(v),
        };
        if !ok {
            let what = match ty {
                TokenType::Color => "color",
                TokenType::Shadow => "shadow",
                TokenType::Radius => "radius scale (0.5 to 2)",
            };
            return Err(format!("colors.{scheme} {k}: invalid {what} value"));
        }
    }
    Ok(())
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// `\d*\.?\d+`, the shape the client accepts for a decimal.
fn is_decimal(s: &str) -> bool {
    match s.split_once('.') {
        None => is_digits(s),
        Some((int, frac)) => (int.is_empty() || is_digits(int)) && is_digits(frac),
    }
}

fn is_valid_radius(v: &str) -> bool {
    let t = v.trim();
    is_decimal(t) && t.parse::<f64>().is_ok_and(|n| (0.5..=2.0).contains(&n))
}

fn is_valid_color(v: &str) -> bool {
    if let Some(hex) = v.strip_prefix('#') {
        return matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    let (args, hsl) = if let Some(a) = v.strip_prefix("rgba(").or_else(|| v.strip_prefix("rgb(")) {
        (a, false)
    } else if let Some(a) = v.strip_prefix("hsla(").or_else(|| v.strip_prefix("hsl(")) {
        (a, true)
    } else {
        return false;
    };
    let Some(args) = args.strip_suffix(')') else {
        return false;
    };
    let parts: Vec<&str> = args.split(',').map(str::trim).collect();
    if parts.len() != 3 && parts.len() != 4 {
        return false;
    }
    let pct = |p: &str| p.strip_suffix('%').is_some_and(is_decimal_or_dotted);
    let first_three = if hsl {
        is_digits(parts[0]) && pct(parts[1]) && pct(parts[2])
    } else {
        parts[..3].iter().all(|p| is_digits(p))
    };
    first_three && parts.get(3).is_none_or(|a| is_decimal_or_dotted(a))
}

/// `[\d.]+`, as loose as the client's pattern for alpha and percentages.
fn is_decimal_or_dotted(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

fn audio_duration_seconds(b: &[u8], path: &str) -> Option<f64> {
    match extension_of(path).as_str() {
        "wav" => wav(b),
        "ogg" => ogg(b),
        "mp3" => mp3(b),
        _ => None,
    }
}

fn u32_be(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
}
fn u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn wav(b: &[u8]) -> Option<f64> {
    if b.len() < 44 || u32_be(b, 0) != 0x52494646 || u32_be(b, 8) != 0x57415645 {
        return None;
    }
    let mut byte_rate = 0u32;
    let mut p = 12usize;
    while p + 8 <= b.len() {
        let id = u32_be(b, p);
        let size = u32_le(b, p + 4) as usize;
        if id == 0x666d7420 && p + 20 <= b.len() {
            byte_rate = u32_le(b, p + 16);
        }
        if id == 0x64617461 {
            return (byte_rate > 0)
                .then(|| size.min(b.len() - p - 8) as f64 / f64::from(byte_rate));
        }
        p = p.checked_add(8 + size + size % 2)?;
    }
    None
}

fn ogg(b: &[u8]) -> Option<f64> {
    let head = |at: usize, s: &[u8]| b.get(at..at + s.len()) == Some(s);
    if b.len() < 64 || !head(0, b"OggS") {
        return None;
    }
    let first = 27 + b[26] as usize;
    let (rate, skip) = if head(first, b"OpusHead") {
        let skip = u16::from_le_bytes(b.get(first + 10..first + 12)?.try_into().ok()?);
        (48000u32, u64::from(skip))
    } else if head(first + 1, b"vorbis") {
        (u32_le(b.get(..first + 16)?, first + 12), 0)
    } else {
        return None;
    };
    let last = (0..=b.len() - 14).rev().find(|&i| head(i, b"OggS"))?;
    if rate == 0 {
        return None;
    }
    let granule = u64::from_le_bytes(b[last + 6..last + 14].try_into().unwrap());
    (granule > 0).then(|| granule.saturating_sub(skip) as f64 / f64::from(rate))
}

const MP3_BITRATES: [u32; 15] = [
    0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
];

// Constant-bitrate estimate from the first frame, as the client does.
fn mp3(b: &[u8]) -> Option<f64> {
    let mut p = 0usize;
    if b.len() >= 10 && &b[..3] == b"ID3" {
        p = 10
            + (((b[6] as usize & 0x7f) << 21)
                | ((b[7] as usize & 0x7f) << 14)
                | ((b[8] as usize & 0x7f) << 7)
                | (b[9] as usize & 0x7f));
    }
    while p + 4 < b.len() {
        if b[p] == 0xff && (b[p + 1] & 0xe0) == 0xe0 {
            let layer = (b[p + 1] >> 1) & 3;
            let version = (b[p + 1] >> 3) & 3;
            let idx = (b[p + 2] >> 4) as usize;
            if layer == 1 && version == 3 && idx != 0 && idx <= 14 {
                return Some(((b.len() - p) * 8) as f64 / f64::from(MP3_BITRATES[idx] * 1000));
            }
        }
        p += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn pack(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, data) in entries {
            w.start_file(*name, SimpleFileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn manifest(extra: &str) -> String {
        format!(
            r##"{{"format":"wavvon.theme","version":1,"name":"T","colors":{{"dark":{{"--accent":"#ff8fb1"}}}}{extra}}}"##
        )
    }

    #[test]
    fn accepts_a_valid_package_and_returns_its_preview() {
        let m = manifest(r#","preview":"p.png","icons":{"mic":"i/mic.svg","nope":"x.svg"}"#);
        let c = validate(&pack(&[
            ("theme.json", m.as_bytes()),
            ("p.png", b"png"),
            ("i/mic.svg", b"<svg/>"),
        ]))
        .unwrap();
        assert_eq!(c.preview.unwrap(), (b"png".to_vec(), "image/png"));
    }

    #[test]
    fn rejects_bad_paths_links_tokens_and_types() {
        let m = manifest("");
        let cases: Vec<Vec<u8>> = vec![
            pack(&[("theme.json", m.as_bytes()), ("../x.png", b"x")]),
            pack(&[("theme.json", m.as_bytes()), ("/x.png", b"x")]),
            pack(&[("theme.json", m.as_bytes()), ("x.gif", b"x")]),
            pack(&[(
                "theme.json",
                manifest("").replace("#ff8fb1", "url(x)").as_bytes(),
            )]),
            pack(&[(
                "theme.json",
                manifest(r#","background":{"image":"bg.bmp"}"#).as_bytes(),
            )]),
            {
                let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
                w.start_file("theme.json", SimpleFileOptions::default())
                    .unwrap();
                w.write_all(m.as_bytes()).unwrap();
                w.add_symlink("l.png", "/etc/passwd", SimpleFileOptions::default())
                    .unwrap();
                w.finish().unwrap().into_inner()
            },
            vec![0u8; MAX_ZIP_BYTES + 1],
            pack(&[
                ("theme.json", m.as_bytes()),
                ("big.png", &vec![0u8; 2 * 1024 * 1024 + 1]),
            ]),
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(validate(c).is_err(), "case {i} should be rejected");
        }
    }

    #[test]
    fn colour_rules_match_the_client() {
        for ok in [
            "#abc",
            "#aabbccdd",
            "rgb(1, 2, 3)",
            "rgba(1,2,3,0.5)",
            "hsl(10, 50%, 20%)",
        ] {
            assert!(is_valid_color(ok), "{ok}");
        }
        for bad in ["#abcde", "red", "rgb(1,2)", "hsl(1.5, 5%, 5%)", "rgb(1,2,3"] {
            assert!(!is_valid_color(bad), "{bad}");
        }
        assert!(is_valid_radius("1.5") && !is_valid_radius("3") && !is_valid_radius("1e0"));
    }

    #[test]
    fn a_long_wav_is_rejected() {
        let mut wav = Vec::new();
        wav.extend_from_slice(b"RIFF\0\0\0\0WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&[1, 0, 1, 0]);
        wav.extend_from_slice(&8000u32.to_le_bytes());
        wav.extend_from_slice(&8000u32.to_le_bytes()); // byte rate: 1 s per 8000 bytes
        wav.extend_from_slice(&[1, 0, 8, 0]);
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&48000u32.to_le_bytes());
        wav.extend_from_slice(&vec![0u8; 48000]);
        assert_eq!(audio_duration_seconds(&wav, "a.wav"), Some(6.0));
        let m = manifest(r#","sounds":{"mention":"a.wav"}"#);
        assert!(validate(&pack(&[("theme.json", m.as_bytes()), ("a.wav", &wav)])).is_err());
    }
}
