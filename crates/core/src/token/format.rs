// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Token format detection (ADR 0049 section 1)
//!
//! Tells Fernet, legacy JWS and OAuth2 JWT credentials apart by their shape.
//! The result only selects the verifier: it is never trusted, and a
//! credential is verified by exactly that format, with no fallthrough.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// `typ` JOSE header of an OAuth2 JWT access token (RFC 9068).
pub const OAUTH2_ACCESS_TOKEN_TYP: &str = "at+jwt";

/// Wire format of a token credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenFormat {
    /// Fernet token: no `.` in the credential.
    Fernet,
    /// Python compatible JWS token.
    Jws,
    /// OAuth2 JWT access token.
    OAuth2,
}

/// Detect the format of the credential.
///
/// - no `.` → Fernet;
/// - three segments and a header with `typ: at+jwt` → OAuth2 JWT;
/// - any other three segment credential → JWS.
///
/// Anything with another number of segments is treated as Fernet, so that the
/// Fernet verifier produces the (uniform) invalid token error.
#[must_use]
pub fn detect_format(credential: &str) -> TokenFormat {
    let mut segments = credential.split('.');
    let (Some(header), Some(_), Some(_), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return TokenFormat::Fernet;
    };
    let is_oauth2 = URL_SAFE_NO_PAD
        .decode(header)
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|h| {
            h.get("typ")
                .and_then(|t| t.as_str())
                .map(|t| t.eq_ignore_ascii_case(OAUTH2_ACCESS_TOKEN_TYP))
        })
        .unwrap_or(false);
    if is_oauth2 {
        TokenFormat::OAuth2
    } else {
        TokenFormat::Jws
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(header: &str) -> String {
        format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode(header))
    }

    #[test]
    fn test_fernet() {
        assert_eq!(detect_format("gAAAAABk-abc_def=="), TokenFormat::Fernet);
        assert_eq!(detect_format(""), TokenFormat::Fernet);
    }

    #[test]
    fn test_jws() {
        assert_eq!(
            detect_format(&jwt(r#"{"alg":"ES256","kid":"k"}"#)),
            TokenFormat::Jws
        );
        assert_eq!(
            detect_format(&jwt(r#"{"alg":"ES256","typ":"JWT"}"#)),
            TokenFormat::Jws
        );
    }

    #[test]
    fn test_oauth2() {
        assert_eq!(
            detect_format(&jwt(r#"{"alg":"ES256","typ":"at+jwt","kid":"k"}"#)),
            TokenFormat::OAuth2
        );
    }

    #[test]
    fn test_malformed() {
        assert_eq!(detect_format("a.b"), TokenFormat::Fernet);
        assert_eq!(detect_format("a.b.c.d"), TokenFormat::Fernet);
        // Not base64/JSON header: left to the JWS verifier to reject.
        assert_eq!(detect_format("!!.e30.c2ln"), TokenFormat::Jws);
    }
}
