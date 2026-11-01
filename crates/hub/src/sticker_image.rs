//! The sticker image pipeline (sticker-storage.md §1): decode an untrusted
//! image fully, then produce the one canonical WebP the hub stores and hashes.
//!
//! Pure Rust end to end. Decoding is `image` (PNG, JPEG, GIF, WebP, APNG);
//! encoding is `image-webp`'s lossless VP8L encoder, and an animation is that
//! same encoder's frames muxed into the WebP container by hand (`ANIM`/`ANMF`),
//! because no pure-Rust crate writes animated WebP and libwebp (C) would put a
//! C toolchain into every musl release build. Lossless-only means a large
//! photographic input can come out bigger than it went in; that is checked
//! against the file cap like any other file.
//!
//! The settings are fixed on purpose: changing the maximum dimension or the
//! encoder changes every hash, so a copy on hub B stops matching hub A's.

use std::io::Cursor;

use image::codecs::gif::GifDecoder;
use image::codecs::png::PngDecoder;
use image::codecs::webp::{WebPDecoder, WebPEncoder};
use image::imageops::FilterType;
use image::{AnimationDecoder, ImageDecoder, ImageFormat, Limits, RgbaImage};

/// Longest side of a stored sticker. Not a setting (see the module doc).
pub const MAX_DIM: u32 = 512;
/// Largest input side accepted for decoding; bigger is refused before any
/// pixel is allocated.
const MAX_INPUT_DIM: u32 = 2048;

/// What one caller of the pipeline allows: the output bound and the decode
/// bound. Fixed per caller, never a setting (see the module doc).
#[derive(Clone, Copy)]
pub struct Profile {
    pub max_dim: u32,
    pub max_input_dim: u32,
    /// Decoded pixels of a still, so a 8192 x 8192 bomb is refused although
    /// each side is in bounds.
    pub max_input_pixels: u64,
    /// A photo stays a (lossy, re-encoded) JPEG: the only WebP encoder here is
    /// lossless, which makes a photo several times larger than its JPEG.
    pub jpeg_stays_jpeg: bool,
    pub what: &'static str,
}

pub const STICKER: Profile = Profile {
    max_dim: MAX_DIM,
    max_input_dim: MAX_INPUT_DIM,
    max_input_pixels: (MAX_INPUT_DIM as u64) * (MAX_INPUT_DIM as u64),
    jpeg_stays_jpeg: false,
    what: "sticker",
};

/// Message attachments: shown at up to 4096 px on the long edge.
pub const ATTACHMENT: Profile = Profile {
    max_dim: 4096,
    max_input_dim: 8192,
    max_input_pixels: 40 * 1024 * 1024,
    jpeg_stays_jpeg: true,
    what: "image",
};
const MAX_FRAMES: usize = 60;
/// Decoded pixels across all frames of one animation (RGBA, so 4 bytes each).
const MAX_ANIM_PIXELS: u64 = 16 * 1024 * 1024;
/// Decoding is CPU and memory heavy: at most this many at once, hub-wide.
const DECODE_SLOTS: usize = 2;
const MIN_FRAME_MS: u64 = 20;

static DECODE_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(DECODE_SLOTS);

#[derive(Debug)]
pub struct Canonical {
    pub bytes: Vec<u8>,
    pub mime: &'static str,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug)]
pub enum IngestError {
    TooLarge(String),
    NotAnImage(String),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::TooLarge(m) | IngestError::NotAnImage(m) => f.write_str(m),
        }
    }
}

fn bad(e: impl std::fmt::Display) -> IngestError {
    IngestError::NotAnImage(format!("not a valid image: {e}"))
}

/// Normalizes `input` off the async runtime, behind a hub-wide semaphore.
pub async fn canonicalize(input: Vec<u8>, max_bytes: usize) -> Result<Canonical, IngestError> {
    canonicalize_with(input, max_bytes, STICKER).await
}

pub async fn canonicalize_with(
    input: Vec<u8>,
    max_bytes: usize,
    profile: Profile,
) -> Result<Canonical, IngestError> {
    let _permit = DECODE_PERMITS
        .acquire()
        .await
        .map_err(|_| IngestError::NotAnImage("decoder unavailable".into()))?;
    tokio::task::spawn_blocking(move || canonicalize_profile(&input, max_bytes, profile))
        .await
        .map_err(|_| IngestError::NotAnImage("decoder crashed".into()))?
}

pub fn canonicalize_blocking(input: &[u8], max_bytes: usize) -> Result<Canonical, IngestError> {
    canonicalize_profile(input, max_bytes, STICKER)
}

pub fn canonicalize_profile(
    input: &[u8],
    max_bytes: usize,
    p: Profile,
) -> Result<Canonical, IngestError> {
    if input.len() > max_bytes {
        return Err(IngestError::TooLarge(format!(
            "file exceeds the {} KB {} limit",
            max_bytes / 1024,
            p.what
        )));
    }
    let format = image::guess_format(input).map_err(bad)?;
    if !matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP
    ) {
        return Err(IngestError::NotAnImage(format!(
            "{}s must be PNG, JPEG, GIF, WebP or APNG",
            p.what
        )));
    }

    let frames = decode(input, format, &p)?;
    let (w, h) = frames[0].0.dimensions();

    // Already canonical: in bounds, so only the metadata chunks go.
    if format == ImageFormat::WebP && w <= p.max_dim && h <= p.max_dim {
        if let Some(bytes) = strip_webp_metadata(input) {
            return Ok(Canonical {
                bytes,
                mime: "image/webp",
                width: w,
                height: h,
            });
        }
    }

    let (nw, nh) = fit(w, h, p.max_dim);
    let frames: Vec<(RgbaImage, u64)> = frames
        .into_iter()
        .map(|(img, ms)| {
            if (nw, nh) == (w, h) {
                (img, ms)
            } else {
                (
                    image::imageops::resize(&img, nw, nh, FilterType::Lanczos3),
                    ms,
                )
            }
        })
        .collect();
    let jpeg = p.jpeg_stays_jpeg && format == ImageFormat::Jpeg;
    let bytes = if jpeg {
        encode_jpeg(&frames[0].0)?
    } else if frames.len() == 1 {
        encode_still(&frames[0].0)?
    } else {
        encode_animation(&frames, nw, nh)?
    };
    if bytes.len() > max_bytes {
        return Err(IngestError::TooLarge(format!(
            "converted {} exceeds the {} KB limit",
            p.what,
            max_bytes / 1024
        )));
    }
    Ok(Canonical {
        bytes,
        mime: if jpeg { "image/jpeg" } else { "image/webp" },
        width: nw,
        height: nh,
    })
}

fn fit(w: u32, h: u32, max_dim: u32) -> (u32, u32) {
    if w <= max_dim && h <= max_dim {
        return (w, h);
    }
    let scale = max_dim as f64 / w.max(h) as f64;
    (
        ((w as f64 * scale).round() as u32).max(1),
        ((h as f64 * scale).round() as u32).max(1),
    )
}

fn limits(p: &Profile) -> Limits {
    let mut l = Limits::default();
    l.max_image_width = Some(p.max_input_dim);
    l.max_image_height = Some(p.max_input_dim);
    l.max_alloc = Some(512 * 1024 * 1024);
    l
}

/// Every frame composited to the full canvas, with its delay in ms. One entry
/// means a still.
fn decode(
    input: &[u8],
    format: ImageFormat,
    p: &Profile,
) -> Result<Vec<(RgbaImage, u64)>, IngestError> {
    let cursor = || Cursor::new(input);
    macro_rules! dim_check {
        ($d:expr) => {{
            let (w, h) = $d.dimensions();
            if w == 0
                || h == 0
                || w > p.max_input_dim
                || h > p.max_input_dim
                || w as u64 * h as u64 > p.max_input_pixels
            {
                return Err(IngestError::TooLarge(format!(
                    "image is {w}x{h}; the limit is {0}x{0}",
                    p.max_input_dim
                )));
            }
            $d.set_limits(limits(p)).map_err(bad)?;
        }};
    }
    macro_rules! still {
        ($d:expr) => {{
            let img = image::DynamicImage::from_decoder($d).map_err(bad)?;
            Ok(vec![(img.to_rgba8(), 0)])
        }};
    }
    match format {
        ImageFormat::Gif => {
            let mut d = GifDecoder::new(cursor()).map_err(bad)?;
            dim_check!(d);
            collect_frames(d.into_frames())
        }
        ImageFormat::Png => {
            let mut d = PngDecoder::new(cursor()).map_err(bad)?;
            dim_check!(d);
            if d.is_apng().map_err(bad)? {
                collect_frames(d.apng().map_err(bad)?.into_frames())
            } else {
                still!(d)
            }
        }
        ImageFormat::WebP => {
            let mut d = WebPDecoder::new(cursor()).map_err(bad)?;
            dim_check!(d);
            if d.has_animation() {
                collect_frames(d.into_frames())
            } else {
                still!(d)
            }
        }
        _ => {
            let mut d = image::codecs::jpeg::JpegDecoder::new(cursor()).map_err(bad)?;
            dim_check!(d);
            still!(d)
        }
    }
}

fn collect_frames(frames: image::Frames<'_>) -> Result<Vec<(RgbaImage, u64)>, IngestError> {
    let mut out = Vec::new();
    let mut pixels = 0u64;
    for frame in frames {
        let frame = frame.map_err(bad)?;
        let (n, d) = frame.delay().numer_denom_ms();
        let ms = (n as u64 / d.max(1) as u64).max(MIN_FRAME_MS);
        let img = frame.into_buffer();
        pixels += img.width() as u64 * img.height() as u64;
        if out.len() >= MAX_FRAMES || pixels > MAX_ANIM_PIXELS {
            return Err(IngestError::TooLarge(format!(
                "animation exceeds {MAX_FRAMES} frames or {} megapixels in total",
                MAX_ANIM_PIXELS / 1_000_000
            )));
        }
        out.push((img, ms));
    }
    if out.is_empty() {
        return Err(IngestError::NotAnImage("image has no frames".into()));
    }
    Ok(out)
}

/// Re-encoding drops EXIF (location included) and anything appended to the file.
fn encode_jpeg(img: &RgbaImage) -> Result<Vec<u8>, IngestError> {
    let rgb = image::DynamicImage::ImageRgba8(img.clone()).to_rgb8();
    let mut out = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85)
        .encode_image(&rgb)
        .map_err(bad)?;
    Ok(out)
}

fn encode_still(img: &RgbaImage) -> Result<Vec<u8>, IngestError> {
    let mut out = Vec::new();
    WebPEncoder::new_lossless(&mut out)
        .encode(
            img.as_raw(),
            img.width(),
            img.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(bad)?;
    Ok(out)
}

/// The `VP8L` chunk (header and payload, padding included) of a still WebP.
fn vp8l_chunk(webp: &[u8]) -> Result<&[u8], IngestError> {
    let mut pos = 12;
    while pos + 8 <= webp.len() {
        let size = u32::from_le_bytes(webp[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let end = pos + 8 + size + (size & 1);
        if &webp[pos..pos + 4] == b"VP8L" {
            return webp
                .get(pos..end)
                .ok_or_else(|| bad("truncated encoder output"));
        }
        pos = end;
    }
    Err(bad("encoder produced no VP8L chunk"))
}

fn u24(v: u32) -> [u8; 3] {
    let b = v.to_le_bytes();
    [b[0], b[1], b[2]]
}

fn chunk(out: &mut Vec<u8>, tag: &[u8; 4], payload: &[u8]) {
    out.extend_from_slice(tag);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    if payload.len() & 1 == 1 {
        out.push(0);
    }
}

/// Animated WebP: full-canvas lossless frames, no blending, no disposal, so
/// a decoder needs no compositing state, and the loop count is infinite.
fn encode_animation(frames: &[(RgbaImage, u64)], w: u32, h: u32) -> Result<Vec<u8>, IngestError> {
    let has_alpha = frames
        .iter()
        .any(|(img, _)| img.pixels().any(|p| p.0[3] != 255));
    let mut body = Vec::new();
    body.extend_from_slice(b"WEBP");

    let mut vp8x = vec![0x02 | if has_alpha { 0x10 } else { 0 }, 0, 0, 0];
    vp8x.extend_from_slice(&u24(w - 1));
    vp8x.extend_from_slice(&u24(h - 1));
    chunk(&mut body, b"VP8X", &vp8x);
    chunk(&mut body, b"ANIM", &[0, 0, 0, 0, 0, 0]);

    for (img, ms) in frames {
        let still = encode_still(img)?;
        let mut anmf = Vec::new();
        anmf.extend_from_slice(&[0; 6]); // x, y offsets
        anmf.extend_from_slice(&u24(w - 1));
        anmf.extend_from_slice(&u24(h - 1));
        anmf.extend_from_slice(&u24((*ms).min(0xFF_FFFF) as u32));
        anmf.push(0x02); // do not blend, do not dispose
        anmf.extend_from_slice(vp8l_chunk(&still)?);
        chunk(&mut body, b"ANMF", &anmf);
    }

    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Drops the `ICCP`, `EXIF` and `XMP ` chunks (and anything after the RIFF
/// size) and keeps every other byte. `None` when the container is malformed.
/// A file with nothing to drop comes back byte-identical, which is what lets a
/// copy hash the same on every hub.
fn strip_webp_metadata(webp: &[u8]) -> Option<Vec<u8>> {
    if webp.len() < 12 || &webp[..4] != b"RIFF" || &webp[8..12] != b"WEBP" {
        return None;
    }
    let riff = u32::from_le_bytes(webp[4..8].try_into().ok()?) as usize;
    let end = riff.checked_add(8)?;
    if end > webp.len() || end < 12 {
        return None;
    }
    let mut dropped = end != webp.len();
    let mut body = Vec::with_capacity(end);
    body.extend_from_slice(b"WEBP");
    let mut pos = 12;
    while pos < end {
        if pos + 8 > end {
            return None;
        }
        let tag = &webp[pos..pos + 4];
        let size = u32::from_le_bytes(webp[pos + 4..pos + 8].try_into().ok()?) as usize;
        let next = pos
            .checked_add(8)?
            .checked_add(size)?
            .checked_add(size & 1)?;
        if next > end {
            return None;
        }
        if matches!(tag, b"ICCP" | b"EXIF" | b"XMP ") {
            dropped = true;
        } else if tag == b"VP8X" && size >= 10 {
            // ICC (0x20), EXIF (0x08) and XMP (0x04) flags no longer hold.
            let mut c = webp[pos..next].to_vec();
            if c[8] & 0x2c != 0 {
                dropped = true;
                c[8] &= !0x2c;
            }
            body.extend_from_slice(&c);
        } else {
            body.extend_from_slice(&webp[pos..next]);
        }
        pos = next;
    }
    if !dropped {
        return Some(webp[..end].to_vec());
    }
    let mut out = Vec::with_capacity(body.len() + 8);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgba, RgbaImage};

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_fn(w, h, |x, y| {
            Rgba([(x % 256) as u8, (y % 256) as u8, 7, 200])
        });
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    fn gif(frames: u8) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
            for i in 0..frames {
                let img = RgbaImage::from_pixel(32, 24, Rgba([(i % 6) * 40, 10, 10, 255]));
                enc.encode_frame(image::Frame::new(img)).unwrap();
            }
        }
        out
    }

    #[test]
    fn png_becomes_webp_and_is_stable() {
        let c = canonicalize_blocking(&png(64, 48), 512 * 1024).unwrap();
        assert_eq!(&c.bytes[..4], b"RIFF");
        assert_eq!((c.width, c.height), (64, 48));
        // Our own output is canonical: it comes back byte for byte.
        let again = canonicalize_blocking(&c.bytes, 512 * 1024).unwrap();
        assert_eq!(c.bytes, again.bytes);
    }

    #[test]
    fn oversized_is_scaled_down() {
        let c = canonicalize_blocking(&png(1024, 256), 4 * 1024 * 1024).unwrap();
        assert_eq!((c.width, c.height), (512, 128));
    }

    #[test]
    fn gif_becomes_animated_webp() {
        let c = canonicalize_blocking(&gif(3), 512 * 1024).unwrap();
        let d = WebPDecoder::new(Cursor::new(&c.bytes)).unwrap();
        assert!(d.has_animation());
        assert_eq!(d.into_frames().count(), 3);
        let again = canonicalize_blocking(&c.bytes, 512 * 1024).unwrap();
        assert_eq!(c.bytes, again.bytes);
    }

    #[test]
    fn metadata_chunks_are_stripped_and_nothing_else() {
        let c = canonicalize_blocking(&png(16, 16), 512 * 1024).unwrap();
        // Rebuild the file as VP8X + EXIF + VP8L.
        let vp8l = vp8l_chunk(&c.bytes).unwrap().to_vec();
        let mut body = b"WEBP".to_vec();
        let mut vp8x = vec![0x10 | 0x08, 0, 0, 0];
        vp8x.extend_from_slice(&u24(15));
        vp8x.extend_from_slice(&u24(15));
        chunk(&mut body, b"VP8X", &vp8x);
        chunk(&mut body, b"EXIF", b"secret gps");
        body.extend_from_slice(&vp8l);
        let mut file = b"RIFF".to_vec();
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&body);

        let out = canonicalize_blocking(&file, 512 * 1024).unwrap();
        assert!(!out.bytes.windows(4).any(|w| w == b"EXIF"));
        assert!(out.bytes.windows(4).any(|w| w == b"VP8L"));
        assert_eq!(out.bytes[20] & 0x08, 0);
    }

    #[test]
    fn disguised_non_image_is_refused() {
        let err = canonicalize_blocking(b"<html>not an image</html>", 512 * 1024).unwrap_err();
        assert!(matches!(err, IngestError::NotAnImage(_)));
        let mut fake = b"\x89PNG\r\n\x1a\n".to_vec();
        fake.extend_from_slice(&[0u8; 64]);
        assert!(canonicalize_blocking(&fake, 512 * 1024).is_err());
    }

    #[test]
    fn limits_are_enforced() {
        assert!(matches!(
            canonicalize_blocking(&png(64, 64), 100).unwrap_err(),
            IngestError::TooLarge(_)
        ));
        assert!(matches!(
            canonicalize_blocking(&png(3000, 10), 4 * 1024 * 1024).unwrap_err(),
            IngestError::TooLarge(_)
        ));
        assert!(matches!(
            canonicalize_blocking(&gif(61), 4 * 1024 * 1024).unwrap_err(),
            IngestError::TooLarge(_)
        ));
    }
}

#[cfg(test)]
mod attachment_profile_tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_fn(w, h, |x, y| {
            image::Rgba([(x % 256) as u8, (y % 256) as u8, 1, 255])
        });
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn attachments_keep_up_to_4096_px_and_stickers_do_not() {
        let big = png(4200, 8);
        let c = canonicalize_profile(&big, usize::MAX, ATTACHMENT).unwrap();
        assert_eq!((c.width, c.height), (4096, 8));
        let c = canonicalize_profile(&png(1000, 8), usize::MAX, ATTACHMENT).unwrap();
        assert_eq!((c.width, c.height), (1000, 8));
        let s = canonicalize_profile(&png(1000, 8), usize::MAX, STICKER).unwrap();
        assert_eq!(s.width, 512);
    }

    #[test]
    fn a_decompression_bomb_is_refused_before_decoding() {
        // In bounds on each side, over the pixel budget together.
        let mut flat = Vec::new();
        image::GrayImage::from_pixel(8000, 8000, image::Luma([5]))
            .write_to(&mut Cursor::new(&mut flat), ImageFormat::Png)
            .unwrap();
        let err = canonicalize_profile(&flat, usize::MAX, ATTACHMENT);
        assert!(matches!(err, Err(IngestError::TooLarge(_))));
        let err = canonicalize_profile(&png(8300, 4), usize::MAX, ATTACHMENT);
        assert!(matches!(err, Err(IngestError::TooLarge(_))));
    }
}
