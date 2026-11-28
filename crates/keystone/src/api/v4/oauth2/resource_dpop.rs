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
//! Resource-side handling of DPoP-bound access tokens (RFC 9449 §7, ADR 0043
//! §4) for the Keystone endpoints that take an access token as their
//! credential.
//!
//! The binding rule itself is [`enforce_token_binding`]; this module reads
//! the credential from the request and verifies the `DPoP` proof against it.
//! Resource servers do not use server nonces in this version, so a proof
//! needs none.

use axum::http::{HeaderMap, header};

use openstack_keystone_core::oauth2_client::dpop::SUPPORTED_ALGORITHMS;

/// Authorization scheme an access token was presented with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Scheme {
    /// RFC 6750 `Bearer`.
    Bearer,
    /// RFC 9449 `DPoP`.
    Dpop,
}

/// Extract the access token and its scheme from the `Authorization` header.
/// Any other scheme, or an empty token, is no credential.
pub(super) fn presented_credential(headers: &HeaderMap) -> Option<(Scheme, &str)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let scheme = if scheme.eq_ignore_ascii_case("Bearer") {
        Scheme::Bearer
    } else if scheme.eq_ignore_ascii_case("DPoP") {
        Scheme::Dpop
    } else {
        return None;
    };
    Some(scheme).zip(Some(token.trim()).filter(|t| !t.is_empty()))
}

/// The `algs` challenge parameter: the proof algorithms the server accepts.
pub(super) fn challenge_algs() -> String {
    SUPPORTED_ALGORITHMS.join(" ")
}

pub(super) use openstack_keystone_core::oauth2_client::dpop_resource::{
    ProofRefusal, verify_resource_proof,
};

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(authorization: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(authorization).unwrap(),
        );
        headers
    }

    #[test]
    fn test_presented_credential_schemes() {
        assert_eq!(
            presented_credential(&headers("Bearer abc")),
            Some((Scheme::Bearer, "abc"))
        );
        assert_eq!(
            presented_credential(&headers("bearer abc")),
            Some((Scheme::Bearer, "abc"))
        );
        assert_eq!(
            presented_credential(&headers("DPoP abc")),
            Some((Scheme::Dpop, "abc"))
        );
        assert_eq!(
            presented_credential(&headers("dpop  abc ")),
            Some((Scheme::Dpop, "abc"))
        );
    }

    #[test]
    fn test_presented_credential_rejects_other_input() {
        assert!(presented_credential(&headers("Basic abc")).is_none());
        assert!(presented_credential(&headers("DPoP ")).is_none());
        assert!(presented_credential(&headers("DPoP")).is_none());
        assert!(presented_credential(&HeaderMap::new()).is_none());
    }

    #[test]
    fn test_challenge_algs() {
        assert_eq!(challenge_algs(), "ES256 RS256");
    }
}
