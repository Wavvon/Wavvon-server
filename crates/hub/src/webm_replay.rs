//! What a late viewer of a screen share needs to start decoding.
//!
//! A sharer's MediaRecorder writes one continuous WebM byte stream and the
//! relay forwards it in arbitrary slices. A viewer who subscribes mid-stream
//! cannot start from whatever slice comes next: it lands inside a cluster,
//! after frames it never saw, and the browser reports a decode error. This
//! follows the stream's element structure and keeps the header plus every
//! byte since the start of the newest cluster that opens on a video keyframe,
//! which is a valid stream on its own and continues seamlessly into the next
//! relayed slice.

use bytes::Bytes;

const EBML_SEGMENT: u32 = 0x1853_8067;
const EBML_CLUSTER: u32 = 0x1F43_B675;
const EBML_TRACKS: u32 = 0x1654_AE6B;
const EBML_TRACK_ENTRY: u32 = 0xAE;
const EBML_TRACK_NUMBER: u32 = 0xD7;
const EBML_TRACK_TYPE: u32 = 0x83;
const EBML_SIMPLE_BLOCK: u32 = 0xA3;
const TRACK_TYPE_VIDEO: u64 = 1;

/// Past this, the group since the last keyframe is dropped and a late viewer
/// waits for the next one: a sharer whose browser ignores the keyframe
/// interval would otherwise grow it for the whole share.
const MAX_GROUP_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default, Clone)]
pub struct WebmReplay {
    /// Everything before the first cluster: EBML header, segment info, tracks.
    header: Option<Bytes>,
    /// Bytes not yet discarded: from the stream start until the first
    /// keyframe cluster, then from the newest keyframe cluster on.
    buf: Vec<u8>,
    /// Parse position in `buf`; may run past its end while skipping an
    /// element whose bytes have not all arrived.
    pos: usize,
    cluster_start: Option<usize>,
    seen_video_in_cluster: bool,
    video_track: Option<u64>,
    /// `buf` starts at a keyframe cluster.
    valid: bool,
    /// Not WebM as expected; nothing is replayed from here.
    failed: bool,
}

/// An element header: id, the size of the payload (None when unknown) and
/// the header's own length.
fn element_header(b: &[u8]) -> Option<(u32, Option<u64>, usize)> {
    let first = *b.first()?;
    let id_len = first.leading_zeros() as usize + 1;
    if id_len > 4 || b.len() < id_len {
        return None;
    }
    let id = b[..id_len]
        .iter()
        .fold(0u32, |acc, &x| (acc << 8) | u32::from(x));
    let (size, size_len) = vint(&b[id_len..])?;
    Some((id, size, id_len + size_len))
}

/// A variable-length integer with its marker bit removed; None for the
/// all-ones "unknown size" value.
fn vint(b: &[u8]) -> Option<(Option<u64>, usize)> {
    let first = *b.first()?;
    if first == 0 {
        return None;
    }
    let len = first.leading_zeros() as usize + 1;
    if b.len() < len {
        return None;
    }
    let mut value = u64::from(first) & ((1u64 << (8 - len)) - 1);
    for &x in &b[1..len] {
        value = (value << 8) | u64::from(x);
    }
    let all_ones = (1u64 << (7 * len)) - 1;
    Some((if value == all_ones { None } else { Some(value) }, len))
}

fn video_track_in(tracks: &[u8]) -> Option<u64> {
    let mut p = 0;
    while let Some((id, Some(size), hl)) = element_header(&tracks[p..]) {
        let end = p + hl + size as usize;
        if end > tracks.len() {
            return None;
        }
        if id == EBML_TRACK_ENTRY {
            let entry = &tracks[p + hl..end];
            let (mut number, mut kind, mut q) = (None, None, 0);
            while let Some((cid, Some(csize), chl)) = element_header(&entry[q..]) {
                let cend = q + chl + csize as usize;
                if cend > entry.len() {
                    break;
                }
                let value = entry[q + chl..cend]
                    .iter()
                    .fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
                match cid {
                    EBML_TRACK_NUMBER => number = Some(value),
                    EBML_TRACK_TYPE => kind = Some(value),
                    _ => {}
                }
                q = cend;
            }
            if kind == Some(TRACK_TYPE_VIDEO) {
                return number;
            }
        }
        p = end;
    }
    None
}

impl WebmReplay {
    pub fn feed(&mut self, data: &[u8]) {
        if self.failed {
            return;
        }
        self.buf.extend_from_slice(data);
        self.parse();
        if self.buf.len() > MAX_GROUP_BYTES {
            if self.header.is_none() {
                self.failed = true;
                self.buf = Vec::new();
                return;
            }
            let cut = self.pos.min(self.buf.len());
            self.buf.drain(..cut);
            self.pos -= cut;
            self.cluster_start = None;
            self.valid = false;
        }
    }

    /// The header and the group since the newest keyframe, when both exist.
    pub fn snapshot(&self) -> Option<(Bytes, Bytes)> {
        if !self.valid || self.buf.is_empty() {
            return None;
        }
        Some((self.header.clone()?, Bytes::copy_from_slice(&self.buf)))
    }

    fn parse(&mut self) {
        while self.pos < self.buf.len() {
            let Some((id, size, hl)) = element_header(&self.buf[self.pos..]) else {
                return;
            };
            let body = self.pos + hl;
            match (id, size) {
                (EBML_SEGMENT, _) => self.pos = body,
                (EBML_CLUSTER, _) => {
                    if self.header.is_none() {
                        self.header = Some(Bytes::copy_from_slice(&self.buf[..self.pos]));
                    }
                    self.cluster_start = Some(self.pos);
                    self.seen_video_in_cluster = false;
                    self.pos = body;
                }
                (EBML_TRACKS, Some(size)) => {
                    let end = body + size as usize;
                    if end > self.buf.len() {
                        return;
                    }
                    self.video_track = video_track_in(&self.buf[body..end]);
                    self.pos = end;
                }
                (EBML_SIMPLE_BLOCK, Some(size)) => {
                    if let (Some(start), false) = (self.cluster_start, self.seen_video_in_cluster) {
                        let Some((Some(track), tl)) = vint(&self.buf[body..]) else {
                            return;
                        };
                        let flags_at = body + tl + 2;
                        if flags_at >= self.buf.len() {
                            return;
                        }
                        if self.video_track.is_none_or(|v| v == track) {
                            self.seen_video_in_cluster = true;
                            if self.buf[flags_at] & 0x80 != 0 && self.header.is_some() {
                                self.buf.drain(..start);
                                self.pos -= start;
                                self.cluster_start = Some(0);
                                self.valid = true;
                            }
                        }
                    }
                    self.pos += hl + size as usize;
                }
                (_, Some(size)) => self.pos = body + size as usize,
                (_, None) => {
                    self.failed = true;
                    self.valid = false;
                    self.buf = Vec::new();
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(id: &[u8], body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 0x4000);
        let mut v = id.to_vec();
        v.extend_from_slice(&[0x40 | (body.len() >> 8) as u8, body.len() as u8]);
        v.extend_from_slice(body);
        v
    }

    fn block(track: u8, key: bool, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x80 | track, 0, 0, if key { 0x80 } else { 0 }];
        b.extend_from_slice(payload);
        el(&[0xA3], &b)
    }

    fn cluster(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![
            0x1F, 0x43, 0xB6, 0x75, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        v.extend(el(&[0xE7], &[0]));
        for b in blocks {
            v.extend_from_slice(b);
        }
        v
    }

    /// Header with an audio track 1 and a video track 2.
    fn header() -> Vec<u8> {
        let mut v = el(&[0x1A, 0x45, 0xDF, 0xA3], &[0x42, 0x86, 0x81, 0x01]);
        v.extend_from_slice(&[
            0x18, 0x53, 0x80, 0x67, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        let audio = el(&[0xAE], &[el(&[0xD7], &[1]), el(&[0x83], &[2])].concat());
        let video = el(&[0xAE], &[el(&[0xD7], &[2]), el(&[0x83], &[1])].concat());
        v.extend(el(&[0x16, 0x54, 0xAE, 0x6B], &[audio, video].concat()));
        v
    }

    fn feed_in_slices(r: &mut WebmReplay, bytes: &[u8], step: usize) {
        for part in bytes.chunks(step) {
            r.feed(part);
        }
    }

    #[test]
    fn keeps_the_header_and_the_newest_keyframe_cluster() {
        let h = header();
        // The audio block leads each cluster: only the video block decides.
        let c1 = cluster(&[
            block(1, true, b"a"),
            block(2, true, b"k1"),
            block(2, false, b"d1"),
        ]);
        let c2 = cluster(&[block(1, true, b"a"), block(2, false, b"d2")]);
        let c3 = cluster(&[
            block(1, true, b"a"),
            block(2, true, b"k3"),
            block(2, false, b"d3"),
        ]);
        let stream = [h.clone(), c1, c2, c3.clone()].concat();
        for step in [1, 3, 7, 64, stream.len()] {
            let mut r = WebmReplay::default();
            feed_in_slices(&mut r, &stream, step);
            let (got_header, group) = r.snapshot().expect("a keyframe was seen");
            assert_eq!(&got_header[..], &h[..], "step {step}");
            assert_eq!(&group[..], &c3[..], "step {step}");
        }
    }

    #[test]
    fn a_cluster_without_a_keyframe_extends_the_group() {
        let h = header();
        let c1 = cluster(&[block(2, true, b"k1")]);
        let c2 = cluster(&[block(2, false, b"d2")]);
        let mut r = WebmReplay::default();
        feed_in_slices(&mut r, &[h, c1.clone(), c2.clone()].concat(), 5);
        assert_eq!(&r.snapshot().unwrap().1[..], &[c1, c2].concat()[..]);
    }

    #[test]
    fn nothing_before_the_first_keyframe() {
        let mut r = WebmReplay::default();
        r.feed(&[header(), cluster(&[block(2, false, b"d")])].concat());
        assert!(r.snapshot().is_none());
    }

    #[test]
    fn bytes_that_are_not_webm_replay_nothing() {
        let mut r = WebmReplay::default();
        r.feed(b"WEBM_INIT");
        r.feed(b"more bytes that are not an element tree");
        assert!(r.snapshot().is_none());
    }
}
