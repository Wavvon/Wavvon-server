//! Server-side check of a `.wavvonlang` package (language-packs.md §1).
//!
//! Only the envelope: a zip holding `lang.json` and nothing else, the format
//! and version, a BCP-47 code, a name, string-only `strings`, 512 KB cap.
//! Which strings a client takes (locked keys, ICU, placeholders) is the
//! client's call (`packages/i18n/packs.ts` in Wavvon-clients), whatever the
//! source. Keep the envelope rules in step with `languages/langPack.ts` there.

use std::io::{Cursor, Read};

pub const MAX_LANG_BYTES: u64 = 512 * 1024;
const MANIFEST: &str = "lang.json";

pub struct LangCheck {
    /// Canonical case: `sc`, `zh-Hant`, `it-CH`.
    pub code: String,
    pub name: String,
}

/// A BCP-47 tag in its canonical case, or None. A shape check, not the full
/// registry: primary 2-3 letters, then subtags of 1-8 alphanumerics.
pub fn canonical_code(raw: &str) -> Option<String> {
    if raw.len() > 35 {
        return None;
    }
    let mut out = Vec::new();
    for (i, sub) in raw.split(['-', '_']).enumerate() {
        let ok = if i == 0 {
            (2..=3).contains(&sub.len()) && sub.chars().all(|c| c.is_ascii_alphabetic())
        } else {
            (1..=8).contains(&sub.len()) && sub.chars().all(|c| c.is_ascii_alphanumeric())
        };
        if !ok {
            return None;
        }
        out.push(match (i, sub.len()) {
            (0, _) => sub.to_ascii_lowercase(),
            (_, 4) if sub.chars().all(|c| c.is_ascii_alphabetic()) => {
                let mut s = sub.to_ascii_lowercase();
                s[..1].make_ascii_uppercase();
                s
            }
            (_, 2) => sub.to_ascii_uppercase(),
            _ => sub.to_ascii_lowercase(),
        });
    }
    Some(out.join("-"))
}

pub fn validate(bytes: &[u8]) -> Result<LangCheck, String> {
    let mut ar =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|_| "Not a valid zip file".to_string())?;
    let mut manifest = None;
    for i in 0..ar.len() {
        let f = ar.by_index(i).map_err(|_| "Not a valid zip file")?;
        let name = f.name().map_err(|_| "Not a valid zip file")?.to_string();
        if name.ends_with('/') && !f.is_symlink() {
            continue;
        }
        if name != MANIFEST || f.is_symlink() {
            return Err(format!(
                "File \"{name}\" has a type that is not allowed in a package"
            ));
        }
        let too_big = || format!("File \"{name}\" is larger than 512 KB");
        if f.size() > MAX_LANG_BYTES {
            return Err(too_big());
        }
        // The declared size can lie; read one byte past the limit to know.
        let mut data = Vec::new();
        f.take(MAX_LANG_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|_| "Not a valid zip file")?;
        if data.len() as u64 > MAX_LANG_BYTES {
            return Err(too_big());
        }
        manifest = Some(data);
    }
    let manifest = manifest.ok_or_else(|| format!("Missing {MANIFEST}"))?;
    let m: serde_json::Value =
        serde_json::from_slice(&manifest).map_err(|_| format!("{MANIFEST} is not valid JSON"))?;
    let m = m
        .as_object()
        .ok_or_else(|| format!("{MANIFEST} is not an object"))?;
    if m.get("format").and_then(|v| v.as_str()) != Some("wavvon.lang") {
        return Err("Invalid format field".into());
    }
    if m.get("version").and_then(|v| v.as_f64()) != Some(1.0) {
        return Err("Unsupported version".into());
    }
    let code = m
        .get("code")
        .and_then(|v| v.as_str())
        .and_then(canonical_code)
        .ok_or("Invalid code (must be a BCP-47 language tag)")?;
    let name = m
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.encode_utf16().count() <= 48)
        .ok_or("Invalid name (must be 1-48 characters)")?;
    let strings = m
        .get("strings")
        .and_then(|v| v.as_object())
        .ok_or("Missing strings block")?;
    if let Some((key, _)) = strings.iter().find(|(_, v)| !v.is_string()) {
        return Err(format!("strings.{key}: expected text"));
    }
    Ok(LangCheck {
        code,
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_checked_and_canonicalized() {
        assert_eq!(canonical_code("sc").as_deref(), Some("sc"));
        assert_eq!(canonical_code("IT-ch").as_deref(), Some("it-CH"));
        assert_eq!(canonical_code("zh-hant-tw").as_deref(), Some("zh-Hant-TW"));
        assert!(canonical_code("not a tag").is_none());
        assert!(canonical_code("e").is_none());
        assert!(canonical_code("en--US").is_none());
    }
}
