//! In-process HTTP test client for the hub and farm routers.
//!
//! Requests go straight into the `Router` through `tower::ServiceExt::oneshot`:
//! no socket, no network. The API mirrors the subset of `axum-test` the test
//! suites used, so call sites read the same.

use std::fmt::{Debug, Display};
use std::future::{Future, IntoFuture};
use std::pin::Pin;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::Router;
use bytes::Bytes;
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tower::ServiceExt;

pub mod multipart;

#[derive(Clone)]
pub struct TestServer {
    app: Router,
}

impl TestServer {
    pub fn new(app: Router) -> Self {
        Self { app }
    }

    pub fn get(&self, path: &str) -> TestRequest {
        self.request(Method::GET, path)
    }

    pub fn post(&self, path: &str) -> TestRequest {
        self.request(Method::POST, path)
    }

    pub fn put(&self, path: &str) -> TestRequest {
        self.request(Method::PUT, path)
    }

    pub fn patch(&self, path: &str) -> TestRequest {
        self.request(Method::PATCH, path)
    }

    pub fn delete(&self, path: &str) -> TestRequest {
        self.request(Method::DELETE, path)
    }

    pub fn method(&self, method: Method, path: &str) -> TestRequest {
        self.request(method, path)
    }

    fn request(&self, method: Method, path: &str) -> TestRequest {
        TestRequest {
            app: self.app.clone(),
            method,
            path: path.to_string(),
            query: Vec::new(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }
}

#[must_use = "a request does nothing until awaited"]
pub struct TestRequest {
    app: Router,
    method: Method,
    path: String,
    query: Vec<String>,
    headers: HeaderMap,
    body: Bytes,
}

impl TestRequest {
    pub fn json<J: ?Sized + Serialize>(self, body: &J) -> Self {
        let bytes = serde_json::to_vec(body).expect("JSON body should serialize");
        self.bytes(bytes.into()).content_type("application/json")
    }

    pub fn text<T: Display>(self, text: T) -> Self {
        self.bytes(text.to_string().into())
            .content_type("text/plain")
    }

    pub fn bytes(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }

    pub fn multipart(self, form: multipart::MultipartForm) -> Self {
        let (content_type, body) = form.encode();
        self.bytes(body).content_type(&content_type)
    }

    pub fn content_type(self, value: &str) -> Self {
        self.add_header(CONTENT_TYPE, value)
    }

    pub fn authorization_bearer<T: Display>(self, token: T) -> Self {
        self.add_header(AUTHORIZATION, format!("Bearer {token}"))
    }

    pub fn add_header<N, V>(mut self, name: N, value: V) -> Self
    where
        N: TryInto<HeaderName>,
        N::Error: Debug,
        V: TryInto<HeaderValue>,
        V::Error: Debug,
    {
        let name = name.try_into().expect("valid header name");
        let value = value.try_into().expect("valid header value");
        self.headers.insert(name, value);
        self
    }

    pub fn add_query_param<V: Serialize>(mut self, key: &str, value: V) -> Self {
        let pair = serde_urlencoded::to_string([(key, value)]).expect("query param should encode");
        self.query.push(pair);
        self
    }

    async fn send(self) -> TestResponse {
        let mut uri = self.path;
        if !self.query.is_empty() {
            uri.push(if uri.contains('?') { '&' } else { '?' });
            uri.push_str(&self.query.join("&"));
        }
        let mut request = Request::builder()
            .method(self.method.clone())
            .uri(&uri)
            .body(Body::from(self.body))
            .expect("request should build");
        *request.headers_mut() = self.headers;
        let response = self
            .app
            .oneshot(request)
            .await
            .expect("router is infallible");
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .expect("response body should read")
            .to_bytes();
        TestResponse {
            method: self.method,
            uri,
            status: parts.status,
            headers: parts.headers,
            body,
        }
    }
}

impl IntoFuture for TestRequest {
    type Output = TestResponse;
    type IntoFuture = Pin<Box<dyn Future<Output = TestResponse> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.send())
    }
}

pub struct TestResponse {
    method: Method,
    uri: String,
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl TestResponse {
    pub fn status_code(&self) -> StatusCode {
        self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The header's value; panics when it is missing.
    pub fn header(&self, name: &str) -> HeaderValue {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("{} has no header {name}", self.describe()))
            .clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.body
    }

    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    #[track_caller]
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "{} body is not the expected JSON ({e}): {}",
                self.describe(),
                self.text()
            )
        })
    }

    #[track_caller]
    pub fn assert_status(&self, expected: StatusCode) {
        assert_eq!(
            self.status,
            expected,
            "{} returned {}, body: {}",
            self.describe(),
            self.status,
            self.text()
        );
    }

    #[track_caller]
    pub fn assert_status_ok(&self) {
        self.assert_status(StatusCode::OK);
    }

    #[track_caller]
    pub fn assert_status_success(&self) {
        assert!(
            self.status.is_success(),
            "{} returned {}, body: {}",
            self.describe(),
            self.status,
            self.text()
        );
    }

    #[track_caller]
    pub fn assert_status_bad_request(&self) {
        self.assert_status(StatusCode::BAD_REQUEST);
    }

    #[track_caller]
    pub fn assert_status_unauthorized(&self) {
        self.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[track_caller]
    pub fn assert_status_forbidden(&self) {
        self.assert_status(StatusCode::FORBIDDEN);
    }

    #[track_caller]
    pub fn assert_status_not_found(&self) {
        self.assert_status(StatusCode::NOT_FOUND);
    }

    #[track_caller]
    pub fn assert_status_internal_server_error(&self) {
        self.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn describe(&self) -> String {
        format!("{} {}", self.method, self.uri)
    }
}
