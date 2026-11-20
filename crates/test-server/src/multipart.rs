//! `multipart/form-data` bodies for [`crate::TestRequest::multipart`].

use std::fmt::Display;

use bytes::Bytes;

pub struct Part {
    bytes: Bytes,
    file_name: Option<String>,
    mime_type: Option<String>,
}

impl Part {
    pub fn bytes(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: bytes.into(),
            file_name: None,
            mime_type: None,
        }
    }

    pub fn text(text: impl Display) -> Self {
        Self::bytes(text.to_string())
    }

    pub fn file_name(mut self, name: impl Display) -> Self {
        self.file_name = Some(name.to_string());
        self
    }

    pub fn mime_type(mut self, mime: impl Display) -> Self {
        self.mime_type = Some(mime.to_string());
        self
    }
}

#[derive(Default)]
pub struct MultipartForm {
    parts: Vec<(String, Part)>,
}

impl MultipartForm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_part(mut self, name: impl Display, part: Part) -> Self {
        self.parts.push((name.to_string(), part));
        self
    }

    pub fn add_text(self, name: impl Display, text: impl Display) -> Self {
        self.add_part(name, Part::text(text))
    }

    /// The `Content-Type` header (with its boundary) and the encoded body.
    pub(crate) fn encode(self) -> (String, Bytes) {
        const BOUNDARY: &str = "wavvon-test-boundary-7d1f0c";
        let mut body = Vec::new();
        for (name, part) in self.parts {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            let mut disposition = format!("Content-Disposition: form-data; name=\"{name}\"");
            if let Some(file) = &part.file_name {
                disposition.push_str(&format!("; filename=\"{file}\""));
            }
            body.extend_from_slice(disposition.as_bytes());
            body.extend_from_slice(b"\r\n");
            if let Some(mime) = &part.mime_type {
                body.extend_from_slice(format!("Content-Type: {mime}\r\n").as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(&part.bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        (
            format!("multipart/form-data; boundary={BOUNDARY}"),
            body.into(),
        )
    }
}
