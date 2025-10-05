# Code Review Report

## Overview
- Reviewed the Rust workspace containing the `novnc_recorder` and `kasmvnc-oauth` crates.
- Attempted to build and run the automated test suite via `cargo test`.

## Build & Test Results
- `cargo test` fails because the OAuth binary does not compile. See the detailed findings below for root causes. Command output is captured in the test log (chunk `bd69c6`).

## Findings

### 1. Missing `cookie` dependency prevents compilation (high severity)
The OAuth callback handler relies on `cookie::Cookie`, but the `cookie` crate is not declared in `oauth/Cargo.toml`. As a result, `cargo test`/`cargo build` fail with `E0432/E0433` unresolved import errors.【F:oauth/src/main.rs†L156-L181】【F:oauth/Cargo.toml†L1-L71】

**Suggested fix:** Add `cookie = "0.18"` (or the desired version) to `oauth/Cargo.toml` and enable the required features. Alternatively, use `axum_extra::extract::cookie::Cookie` if that crate is already in use.

### 2. Incorrect response body type in callback handler (high severity)
The same callback handler attempts to call `axum::body::Empty::new()`, but `axum 0.7` does not expose an `Empty` type in that module, producing `E0433`. The intention is to send an empty body, which should be done with `axum::body::Body::empty()` or by returning a tuple that implements `IntoResponse` instead of manually building the response.【F:oauth/src/main.rs†L176-L182】

**Suggested fix:** Replace `.body(axum::body::Empty::new())` with `.body(axum::body::Body::empty())`, or refactor the branch to return `(StatusCode::FOUND, [(header::LOCATION, "/vnc"), (header::SET_COOKIE, cookie.to_string())])`.

### 3. Audience claim deserialisation is brittle (medium severity)
`Claims` models the `aud` claim strictly as `Vec<String>`. In practice, many providers return a single string for `aud`, which will cause deserialisation failures and, consequently, token validation failures even when the token is otherwise valid.【F:oauth/src/jwt.rs†L8-L31】

**Suggested fix:** Use a custom deserialiser that accepts both string and array forms (e.g. `#[serde(deserialize_with = "deserialize_audience")]` that normalises into `Vec<String>`).

### 4. Session activity tracking is effectively a no-op (low severity)
`SessionManager::update_activity` is intended to refresh `last_activity`, but because sessions are stored inside an `Arc<Session>`, the method cannot mutate the stored session and therefore silently does nothing. This defeats idle timeout enforcement.【F:oauth/src/session.rs†L92-L113】

**Suggested fix:** Store sessions as `Arc<RwLock<Session>>` or similar so that mutable fields such as `last_activity` can be updated.

### 5. JWKS cache ignores EC/other key types (medium severity)
`JwksCache::jwk_to_decoding_key` only supports RSA keys and drops EC and symmetric keys silently. Providers that rotate to EC (`ES256`, etc.) will fail with `JwksKeyNotFound` despite publishing valid keys.【F:oauth/src/jwks.rs†L38-L93】

**Suggested fix:** Implement EC key support (e.g. via `DecodingKey::from_ec_components`) or surface a configuration error when encountering unsupported algorithms, so operators are not left with unexplained authentication failures.

## Conclusion
Addressing the compilation blockers in Findings 1–2 is necessary before any end-to-end validation can pass. Findings 3–5 highlight robustness gaps that will affect real-world deployments once the build issues are fixed.
