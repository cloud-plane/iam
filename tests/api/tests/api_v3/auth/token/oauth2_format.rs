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
//! The OAuth2 JWT as a Keystone token (ADR 0049) against a live server.
//!
//! The server is started with `KEYSTONE_TEST_TOKEN_PROVIDER` (default
//! `fernet`). Tests that are about the OAuth2 format run against
//! `KEYSTONE_TEST_TOKEN_PROVIDER=oauth2` (a dedicated CI step) and return at
//! once for another provider; the tests that state what a provider refuses
//! assert the matching behaviour for each one.

use std::env;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use eyre::{OptionExt, Result};
use reqwest::{RequestBuilder, Response, StatusCode};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use test_api::common::{TestClient, http_client};

/// Fixed proof key of these tests (the one of the v4 DPoP tests).
const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0mBL+Hphh8GGUGdi
gmBwdXtr0cZMOm/ZXd7WQelR3umhRANCAASxIa1qgs06aj9LNbZGgn5Mf+pjqf/q
u9kjxPUBs14LLJlWTBwQxPJ6GLO+UoZswTJWTmawRuC2EyKWhJaSPxwA
-----END PRIVATE KEY-----
";
const KEY_X: &str = "sSGtaoLNOmo_SzW2RoJ-TH_qY6n_6rvZI8T1AbNeCyw";
const KEY_Y: &str = "mVZMHBDE8noYs75ShmzBMlZOZrBG4LYTIpaElpI_HAA";

fn provider() -> String {
    env::var("KEYSTONE_TEST_TOKEN_PROVIDER").unwrap_or_else(|_| "fernet".into())
}

fn is_oauth2() -> bool {
    provider() == "oauth2"
}

/// RFC 7638 thumbprint of the proof key.
fn jkt() -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{KEY_X}","y":"{KEY_Y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The URL a proof names: `[DEFAULT] public_endpoint` of the server, which
/// can differ from the address the tests reach it at.
fn public_url(path: &str) -> Result<String> {
    let base = env::var("KEYSTONE_PUBLIC_URL")
        .or_else(|_| env::var("KEYSTONE_URL"))?
        .parse::<url::Url>()?;
    Ok(base.join(path)?.to_string())
}

fn keystone_url(path: &str) -> Result<url::Url> {
    Ok(env::var("KEYSTONE_URL")?.parse::<url::Url>()?.join(path)?)
}

/// A fresh proof. `token` binds it (`ath`) to the access token it is sent
/// with.
fn proof(method: &str, htu: &str, token: Option<&str>) -> Result<String> {
    let header = json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": {"kty": "EC", "crv": "P-256", "x": KEY_X, "y": KEY_Y},
    });
    let mut claims = json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": method,
        "htu": htu,
        "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(token) = token {
        claims["ath"] = URL_SAFE_NO_PAD
            .encode(Sha256::digest(token.as_bytes()))
            .into();
    }
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    openstack_keystone_jwt_crypto::install()?;
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &jsonwebtoken::EncodingKey::from_ec_pem(KEY_PEM.as_bytes())?,
        jsonwebtoken::Algorithm::ES256,
    )?;
    Ok(format!("{message}.{signature}"))
}

fn segment(token: &str, index: usize) -> Result<Value> {
    let part = token
        .split('.')
        .nth(index)
        .ok_or_eyre("the token has no such segment")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part)?)?)
}

fn password_body() -> Value {
    json!({"auth": {
        "identity": {"methods": ["password"], "password": {"user": {
            "name": "admin",
            "domain": {"id": "default"},
            "password": env::var("OPENSTACK_ADMIN_PASSWORD").unwrap_or("password".into()),
        }}},
        "scope": {"project": {"name": "admin", "domain": {"id": "default"}}},
    }})
}

/// `POST /v3/auth/tokens` as admin, optionally with a `DPoP` header.
async fn login(dpop: Option<&str>) -> Result<Response> {
    let mut req = http_client()
        .post(keystone_url("v3/auth/tokens")?)
        .json(&password_body());
    if let Some(dpop) = dpop {
        req = req.header("DPoP", dpop);
    }
    Ok(req.send().await?)
}

async fn bound_token() -> Result<String> {
    let proof = proof("POST", &public_url("v3/auth/tokens")?, None)?;
    let rsp = login(Some(&proof)).await?;
    assert_eq!(rsp.status(), StatusCode::CREATED);
    Ok(rsp
        .headers()
        .get("X-Subject-Token")
        .ok_or_eyre("no subject token")?
        .to_str()?
        .to_string())
}

/// `GET /v3/projects` with the headers `f` adds.
async fn list_projects(f: impl FnOnce(RequestBuilder) -> RequestBuilder) -> Result<StatusCode> {
    Ok(f(http_client().get(keystone_url("v3/projects")?))
        .send()
        .await?
        .status())
}

#[tokio::test]
async fn test_oauth2_token_claims() -> Result<()> {
    if !is_oauth2() {
        return Ok(());
    }
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let token = client
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();
    let header = segment(&token, 0)?;
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["alg"], "ES256");
    let claims = segment(&token, 1)?;
    assert_eq!(claims["aud"], "keystone");
    assert!(
        claims["iss"]
            .as_str()
            .is_some_and(|i| i.contains("/v4/oauth2/"))
    );
    assert!(claims["jti"].is_string());
    assert!(claims["ks_scope"]["project"].is_string());
    assert!(
        claims["amr"]
            .as_array()
            .is_some_and(|a| a.iter().any(|m| m == "password"))
    );
    // The compact claim set: nothing of the Python layout, no roles.
    for absent in ["nbf", "token_use", "roles", "cnf", "chain"] {
        assert!(claims.get(absent).is_none(), "unexpected `{absent}`");
    }
    assert!(
        !claims
            .as_object()
            .ok_or_eyre("claims are an object")?
            .keys()
            .any(|k| k.starts_with("openstack_"))
    );
    Ok(())
}

/// `Authorization: Bearer` carries an OAuth2 JWT only; Fernet and JWS tokens
/// travel in `X-Auth-Token`.
#[tokio::test]
async fn test_bearer_carries_only_the_oauth2_format() -> Result<()> {
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let token = client
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();
    let expected = if is_oauth2() {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    };
    assert_eq!(
        list_projects(|r| r.bearer_auth(&token)).await?,
        expected,
        "provider {}",
        provider()
    );
    // The same token in `X-Auth-Token` works for every provider.
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &token)).await?,
        StatusCode::OK
    );
    // `X-Auth-Token` wins over a bearer that is not a token.
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &token).bearer_auth("garbage")).await?,
        StatusCode::OK
    );
    assert_eq!(
        list_projects(|r| r.header("Authorization", "Basic dXNlcjpwdw==")).await?,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}

/// A proof sent to a deployment that cannot bind tokens is refused: the
/// client would take the unbound token it gets for a sender-constrained one.
#[tokio::test]
async fn test_dpop_proof_on_login_binds_or_is_refused() -> Result<()> {
    let proof = proof("POST", &public_url("v3/auth/tokens")?, None)?;
    let rsp = login(Some(&proof)).await?;
    if is_oauth2() {
        assert_eq!(rsp.status(), StatusCode::CREATED);
        let token = rsp
            .headers()
            .get("X-Subject-Token")
            .ok_or_eyre("no subject token")?
            .to_str()?
            .to_string();
        assert_eq!(segment(&token, 1)?["cnf"]["jkt"], jkt());
        // A login without a proof is unbound.
        let plain = login(None).await?;
        assert_eq!(plain.status(), StatusCode::CREATED);
        let plain = plain
            .headers()
            .get("X-Subject-Token")
            .ok_or_eyre("no subject token")?
            .to_str()?
            .to_string();
        assert!(segment(&plain, 1)?.get("cnf").is_none());
        // The issuance proof is single use.
        assert_eq!(login(Some(&proof)).await?.status(), StatusCode::BAD_REQUEST);
    } else {
        assert_eq!(rsp.status(), StatusCode::BAD_REQUEST);
    }
    // A malformed proof is refused whatever the provider.
    assert_eq!(
        login(Some("not-a-proof")).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn test_bound_token_needs_its_proof() -> Result<()> {
    if !is_oauth2() {
        return Ok(());
    }
    let token = bound_token().await?;
    let url = public_url("v3/projects")?;
    // No proof.
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &token)).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        list_projects(|r| r.bearer_auth(&token)).await?,
        StatusCode::UNAUTHORIZED
    );
    // A proof for this request and token, in each presentation.
    let valid = proof("GET", &url, Some(&token))?;
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &token).header("DPoP", &valid)).await?,
        StatusCode::OK
    );
    // The same proof again is a replay.
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &token).header("DPoP", &valid)).await?,
        StatusCode::UNAUTHORIZED
    );
    let fresh = proof("GET", &url, Some(&token))?;
    assert_eq!(
        list_projects(|r| r
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", &fresh))
        .await?,
        StatusCode::OK
    );
    let fresh = proof("GET", &url, Some(&token))?;
    assert_eq!(
        list_projects(|r| r.bearer_auth(&token).header("DPoP", &fresh)).await?,
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn test_bound_token_rejects_misdirected_proofs() -> Result<()> {
    if !is_oauth2() {
        return Ok(());
    }
    let token = bound_token().await?;
    let url = public_url("v3/projects")?;
    let cases = [
        // Another method, another URL, another token, no `ath`.
        ("POST", url.clone(), Some(token.as_str())),
        ("GET", public_url("v3/users")?, Some(token.as_str())),
        ("GET", url.clone(), Some("another-token")),
        ("GET", url.clone(), None),
    ];
    for (n, (method, htu, ath)) in cases.into_iter().enumerate() {
        let wrong = proof(method, &htu, ath)?;
        assert_eq!(
            list_projects(|r| r.header("X-Auth-Token", &token).header("DPoP", &wrong)).await?,
            StatusCode::UNAUTHORIZED,
            "case {n}"
        );
    }
    Ok(())
}

/// An unbound token cannot be presented as `DPoP`, and a proof does not make
/// it bound.
#[tokio::test]
async fn test_unbound_token_is_not_a_dpop_token() -> Result<()> {
    if !is_oauth2() {
        return Ok(());
    }
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let token = client
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();
    let url = public_url("v3/projects")?;
    let p = proof("GET", &url, Some(&token))?;
    assert_eq!(
        list_projects(|r| r
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", &p))
        .await?,
        StatusCode::UNAUTHORIZED
    );
    // As a bearer it works, and the proof is not consumed or needed.
    assert_eq!(
        list_projects(|r| r.bearer_auth(&token)).await?,
        StatusCode::OK
    );
    Ok(())
}

/// A bound token is not a credential value: exchanged in the body of
/// `POST /v3/auth/tokens` there is no proof of its key, and the result would
/// be an unbound token.
#[tokio::test]
async fn test_bound_token_cannot_be_exchanged_in_the_body() -> Result<()> {
    if !is_oauth2() {
        return Ok(());
    }
    let bound = bound_token().await?;
    let body =
        |id: &str| json!({"auth": {"identity": {"methods": ["token"], "token": {"id": id}}}});
    let rsp = http_client()
        .post(keystone_url("v3/auth/tokens")?)
        .json(&body(&bound))
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);
    assert!(rsp.headers().get("X-Subject-Token").is_none());

    // The same exchange of an unbound token works.
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let plain = client
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();
    let rsp = http_client()
        .post(keystone_url("v3/auth/tokens")?)
        .json(&body(&plain))
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::CREATED);
    Ok(())
}

/// Every format is checked against the format the token is detected as.
#[tokio::test]
async fn test_oauth2_credentials_that_do_not_verify_are_unauthorized() -> Result<()> {
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let token = client
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();
    if is_oauth2() {
        // A tampered payload: same header and signature, other claims.
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        let mut claims = segment(&token, 1)?;
        claims["sub"] = "someone-else".into();
        parts[1] = URL_SAFE_NO_PAD.encode(claims.to_string());
        assert_eq!(
            list_projects(|r| r.header("X-Auth-Token", parts.join("."))).await?,
            StatusCode::UNAUTHORIZED
        );
        // An unknown issuer has no keys.
        let mut claims = segment(&token, 1)?;
        claims["iss"] = "http://localhost:8080/v4/oauth2/no-such-domain".into();
        parts[1] = URL_SAFE_NO_PAD.encode(claims.to_string());
        assert_eq!(
            list_projects(|r| r.header("X-Auth-Token", parts.join("."))).await?,
            StatusCode::UNAUTHORIZED
        );
        // `alg: none` is not accepted.
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"at+jwt"}"#);
        let unsigned = format!("{header}.{}.", parts[1]);
        assert_eq!(
            list_projects(|r| r.header("X-Auth-Token", unsigned)).await?,
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

/// The token is revoked as any other: its audit chain is.
#[tokio::test]
async fn test_oauth2_token_is_revocable() -> Result<()> {
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let mut victim = TestClient::new()?;
    victim.auth_admin().await?;
    let victim_token = victim
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &victim_token)).await?,
        StatusCode::OK
    );
    let rsp = client
        .client
        .delete(keystone_url("v3/auth/tokens")?)
        .header("X-Subject-Token", &victim_token)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        list_projects(|r| r.header("X-Auth-Token", &victim_token)).await?,
        StatusCode::UNAUTHORIZED
    );
    Ok(())
}
