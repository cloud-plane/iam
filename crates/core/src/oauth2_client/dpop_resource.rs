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
//! HTTP-level DPoP rules shared by the `/token` endpoint and the resource
//! endpoints (RFC 9449, ADR 0043): reading the proof header, charging a
//! per-key throttle and classifying the refusals of the replay cache. Keeping
//! them in one place stops the two sides from drifting apart in what they
//! accept and how they report it.

use governor::{DefaultKeyedRateLimiter, clock::Clock as _};
use http::HeaderMap;

use crate::keystone::ServiceState;
use crate::oauth2_client::dpop::{DpopProofContext, DpopProofError, verify_dpop_proof};
use crate::oauth2_client::dpop_replay::DpopReplayError;
use openstack_keystone_core_types::oauth2_client::Confirmation;
use url::Url;

/// Name of the proof header.
const DPOP_HEADER: &str = "dpop";

/// Why the `DPoP` header of a request cannot be used.
#[derive(Debug, PartialEq, Eq)]
pub enum HeaderRefusal {
    /// More than one `DPoP` header.
    Multiple,
    /// The value is not text.
    NotText,
}

impl HeaderRefusal {
    /// Description for the error response.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Multiple => "exactly one DPoP header is allowed",
            Self::NotText => "the DPoP header is not valid text",
        }
    }
}

/// The proof of a request: `None` when there is no `DPoP` header, an error
/// when there is more than one or the value is not text.
pub fn proof_header(headers: &HeaderMap) -> Result<Option<&str>, HeaderRefusal> {
    let mut proofs = headers.get_all(DPOP_HEADER).iter();
    let Some(proof) = proofs.next() else {
        return Ok(None);
    };
    if proofs.next().is_some() {
        return Err(HeaderRefusal::Multiple);
    }
    proof.to_str().map(Some).map_err(|_| HeaderRefusal::NotText)
}

/// Charge `key`, the verified thumbprint of a proof key, against `limiter`.
/// On refusal the number of seconds to wait is returned.
pub fn charge_key(limiter: &DefaultKeyedRateLimiter<String>, key: &str) -> Result<(), u64> {
    limiter.check_key(&key.to_string()).map_err(|not_until| {
        not_until
            .wait_time_from(limiter.clock().now())
            .as_secs()
            .max(1)
    })
}

/// Seconds to wait before retrying when the replay cache refused a proof
/// for lack of room, `None` when the proof was a replay.
///
/// A replay is the client's fault. A full cache or an exhausted per-key
/// share is not: it clears once the entries age out, which takes at most one
/// proof lifetime, so the caller is told to retry after that instead of
/// being sent a final-looking `invalid_dpop_proof`.
pub fn replay_retry_after(error: &DpopReplayError, proof_lifetime_secs: u64) -> Option<u64> {
    match error {
        DpopReplayError::Replayed => None,
        DpopReplayError::CacheFull | DpopReplayError::KeyQuotaExceeded => {
            tracing::warn!(%error, "DPoP replay cache refused a proof");
            Some(proof_lifetime_secs.max(1))
        }
    }
}

/// Why a proof presented with an access token was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ProofRefusal {
    /// The proof is missing, malformed, stale, replayed or for another
    /// request or token.
    Invalid(String),
    /// Throttled; retry after the given number of seconds.
    RateLimited(u64),
}

/// Verify the `DPoP` proof of a request that presents `token` and return the
/// thumbprint of the proof key.
///
/// `uri` is the external URL of the endpoint (`htu`), `method` its HTTP
/// method (`htm`). The caller has rate limited the source already, which
/// bounds the signature checks; this adds the per-key throttle (ADR 0022) on
/// the verified key thumbprint, in its own pool apart from `/token`.
/// `bound_jkt` is the `cnf` of the token.
pub fn verify_resource_proof(
    state: &ServiceState,
    headers: &HeaderMap,
    method: &str,
    uri: &Url,
    token: &str,
    bound_jkt: &Confirmation,
) -> Result<String, ProofRefusal> {
    let proof = proof_header(headers)
        .map_err(|e| ProofRefusal::Invalid(e.description().into()))?
        .ok_or_else(|| ProofRefusal::Invalid("a DPoP proof is required".into()))?;

    let now = chrono::Utc::now().timestamp();
    let verified = verify_dpop_proof(
        proof,
        &DpopProofContext {
            access_token: Some(token),
            accepted_nonces: None,
            max_skew_secs: state.dpop.proof_lifetime_secs,
            method,
            now,
            uri,
        },
    )
    .map_err(|e: DpopProofError| ProofRefusal::Invalid(e.to_string()))?;
    // Only the key the token is bound to may use the replay cache: a proof
    // from any other key is refused before it takes an entry, so a holder of
    // a valid token cannot fill the cache with fresh keys.
    if !bound_jkt.matches(&verified.jkt) {
        return Err(ProofRefusal::Invalid(
            "the DPoP proof key does not match the token".into(),
        ));
    }
    // Throttled on the verified thumbprint: an unverified one is attacker
    // chosen, so a flood of forged proofs naming a victim's key could drain
    // the victim's bucket. A pool apart from `/token`, so reading with a
    // token cannot starve issuing or refreshing one.
    charge_key(&state.dpop.resource_throttle, &verified.jkt).map_err(ProofRefusal::RateLimited)?;
    state
        .dpop
        .replay
        .check_and_insert(&verified, now)
        .map_err(
            |e| match replay_retry_after(&e, state.dpop.proof_lifetime_secs) {
                Some(retry_after) => ProofRefusal::RateLimited(retry_after),
                None => ProofRefusal::Invalid(e.to_string()),
            },
        )?;
    Ok(verified.jkt)
}

/// Verify the `DPoP` proof sent with a request that issues a token (ADR 0049
/// section 4) and return the thumbprint of its key, or `None` when the request
/// carries no proof.
///
/// A proof here has no `ath`: no access token exists yet. It is replay
/// protected and throttled like the proof of a resource request.
pub fn verify_issuance_proof(
    state: &ServiceState,
    headers: &HeaderMap,
    method: &str,
    uri: &Url,
) -> Result<Option<String>, ProofRefusal> {
    let Some(proof) =
        proof_header(headers).map_err(|e| ProofRefusal::Invalid(e.description().into()))?
    else {
        return Ok(None);
    };
    let now = chrono::Utc::now().timestamp();
    let verified = verify_dpop_proof(
        proof,
        &DpopProofContext {
            access_token: None,
            accepted_nonces: None,
            max_skew_secs: state.dpop.proof_lifetime_secs,
            method,
            now,
            uri,
        },
    )
    .map_err(|e: DpopProofError| ProofRefusal::Invalid(e.to_string()))?;
    charge_key(&state.dpop.resource_throttle, &verified.jkt).map_err(ProofRefusal::RateLimited)?;
    state
        .dpop
        .replay
        .check_and_insert(&verified, now)
        .map_err(
            |e| match replay_retry_after(&e, state.dpop.proof_lifetime_secs) {
                Some(retry_after) => ProofRefusal::RateLimited(retry_after),
                None => ProofRefusal::Invalid(e.to_string()),
            },
        )?;
    Ok(Some(verified.jkt))
}

/// A signed `DPoP` proof for tests, made with a fresh P-256 key.
///
/// Returns the proof and the thumbprint of its key. `ath` is the access token
/// the proof is bound to.
#[cfg(test)]
pub(crate) fn test_proof(
    key: &openstack_keystone_key_repository::asymmetric::KeyMaterial,
    method: &str,
    uri: &str,
    jti: &str,
    access_token: Option<&str>,
) -> (String, String) {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use openstack_keystone_key_repository::asymmetric::{ActiveKeys, to_encoding_key};
    use serde_json::{Map, Value, json};

    use crate::oauth2_client::dpop::{access_token_hash, jwk_thumbprint};
    use crate::oauth2_key::jwks::active_keys_to_jwk_set;

    openstack_keystone_jwt_crypto::install().expect("crypto provider");
    let jwks = active_keys_to_jwk_set(&ActiveKeys {
        primary: key.clone(),
        previous: None,
    })
    .expect("jwks");
    let full = serde_json::to_value(&jwks).expect("jwks json")["keys"][0].clone();
    let jwk: Map<String, Value> = ["kty", "crv", "x", "y"]
        .into_iter()
        .filter_map(|k| full.get(k).map(|v| (k.to_string(), v.clone())))
        .collect();
    let jkt = jwk_thumbprint(&jwk).expect("thumbprint");
    let mut claims = json!({
        "jti": jti,
        "htm": method,
        "htu": uri,
        "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(token) = access_token {
        claims["ath"] = json!(access_token_hash(token));
    }
    let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &to_encoding_key(key).expect("signing key"),
        jsonwebtoken::Algorithm::ES256,
    )
    .expect("sign");
    (format!("{message}.{signature}"), jkt)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use governor::{Quota, RateLimiter};

    use super::*;

    #[test]
    fn test_proof_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(proof_header(&headers), Ok(None));
        headers.append("dpop", HeaderValue::from_static("a.b.c"));
        assert_eq!(proof_header(&headers), Ok(Some("a.b.c")));
        headers.append("DPoP", HeaderValue::from_static("d.e.f"));
        assert_eq!(proof_header(&headers), Err(HeaderRefusal::Multiple));
    }

    #[test]
    fn test_proof_header_must_be_text() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "dpop",
            HeaderValue::from_bytes(&[0xff, 0xfe]).expect("opaque bytes are a valid value"),
        );
        assert_eq!(proof_header(&headers), Err(HeaderRefusal::NotText));
    }

    #[test]
    fn test_replay_is_no_retry_but_exhaustion_is() {
        assert_eq!(replay_retry_after(&DpopReplayError::Replayed, 60), None);
        for exhausted in [
            DpopReplayError::CacheFull,
            DpopReplayError::KeyQuotaExceeded,
        ] {
            assert_eq!(replay_retry_after(&exhausted, 60), Some(60));
        }
        assert_eq!(replay_retry_after(&DpopReplayError::CacheFull, 0), Some(1));
    }

    #[test]
    fn test_charge_key_is_per_key_and_reports_a_wait() {
        let limiter: DefaultKeyedRateLimiter<String> =
            RateLimiter::keyed(Quota::per_minute(std::num::NonZeroU32::MIN));
        assert_eq!(charge_key(&limiter, "k1"), Ok(()));
        assert!(matches!(charge_key(&limiter, "k1"), Err(wait) if wait >= 1));
        // Another key has a bucket of its own.
        assert_eq!(charge_key(&limiter, "k2"), Ok(()));
    }

    fn state_with_endpoint() -> impl std::future::Future<Output = ServiceState> {
        let mut config = openstack_keystone_config::Config::default();
        config.default.public_endpoint = Some("https://ks.example".parse().unwrap());
        crate::tests::get_mocked_state(Some(config), None)
    }

    fn key() -> openstack_keystone_key_repository::asymmetric::KeyMaterial {
        openstack_keystone_key_repository::asymmetric::generate_keypair(
            openstack_keystone_key_repository::asymmetric::SigningAlgorithm::Es256,
        )
        .unwrap()
    }

    fn headers_with(proof: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("dpop", HeaderValue::from_str(proof).unwrap());
        headers
    }

    const URI: &str = "https://ks.example/v3/projects";

    #[tokio::test]
    async fn test_resource_proof_of_the_bound_key_is_accepted_once() {
        let state = state_with_endpoint().await;
        let key = key();
        let uri = Url::parse(URI).unwrap();
        let (proof, jkt) = test_proof(&key, "GET", URI, "j1", Some("tok"));
        let bound = Confirmation { jkt: jkt.clone() };
        let headers = headers_with(&proof);
        assert_eq!(
            verify_resource_proof(&state, &headers, "GET", &uri, "tok", &bound),
            Ok(jkt)
        );
        // The same proof is a replay.
        assert!(matches!(
            verify_resource_proof(&state, &headers, "GET", &uri, "tok", &bound),
            Err(ProofRefusal::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn test_resource_proof_of_another_key_is_refused() {
        let state = state_with_endpoint().await;
        let uri = Url::parse(URI).unwrap();
        let (_, victim) = test_proof(&key(), "GET", URI, "x", None);
        let (proof, _) = test_proof(&key(), "GET", URI, "j2", Some("tok"));
        let bound = Confirmation { jkt: victim };
        assert!(matches!(
            verify_resource_proof(&state, &headers_with(&proof), "GET", &uri, "tok", &bound),
            Err(ProofRefusal::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn test_resource_proof_must_name_the_request_and_token() {
        let state = state_with_endpoint().await;
        let key = key();
        let uri = Url::parse(URI).unwrap();
        let (_, jkt) = test_proof(&key, "GET", URI, "x", None);
        let bound = Confirmation { jkt };
        let cases = [
            ("POST", URI, Some("tok")),
            ("GET", "https://ks.example/v3/users", Some("tok")),
            ("GET", URI, Some("other-token")),
            ("GET", URI, None),
        ];
        for (n, (method, htu, ath)) in cases.into_iter().enumerate() {
            let (proof, _) = test_proof(&key, method, htu, &format!("c{n}"), ath);
            assert!(
                matches!(
                    verify_resource_proof(
                        &state,
                        &headers_with(&proof),
                        "GET",
                        &uri,
                        "tok",
                        &bound
                    ),
                    Err(ProofRefusal::Invalid(_))
                ),
                "case {n}"
            );
        }
        assert!(matches!(
            verify_resource_proof(&state, &HeaderMap::new(), "GET", &uri, "tok", &bound),
            Err(ProofRefusal::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn test_issuance_proof() {
        let state = state_with_endpoint().await;
        let uri = Url::parse("https://ks.example/v3/auth/tokens").unwrap();
        assert_eq!(
            verify_issuance_proof(&state, &HeaderMap::new(), "POST", &uri),
            Ok(None)
        );
        let (proof, jkt) = test_proof(&key(), "POST", uri.as_str(), "i1", None);
        assert_eq!(
            verify_issuance_proof(&state, &headers_with(&proof), "POST", &uri),
            Ok(Some(jkt))
        );
        // A proof for another endpoint is not an issuance proof.
        let (other, _) = test_proof(&key(), "POST", URI, "i2", None);
        assert!(matches!(
            verify_issuance_proof(&state, &headers_with(&other), "POST", &uri),
            Err(ProofRefusal::Invalid(_))
        ));
    }
}
