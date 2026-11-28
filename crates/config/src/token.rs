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
//! # Keystone configuration
//!
//! Parsing of the Keystone configuration file implementation.
use std::fmt;

use serde::Deserialize;

/// Token provider.
#[derive(Debug, Deserialize, Clone)]
pub struct TokenProvider {
    /// Token provider driver.
    #[serde(default)]
    pub provider: TokenProviderDriver,
    /// The amount of time that a token should remain valid (in seconds).
    /// Drastically reducing this value may break "long-running" operations
    /// that involve multiple services to coordinate together, and will
    /// force users to authenticate with keystone more frequently. Drastically
    /// increasing this value will increase the number of tokens that will be
    /// simultaneously valid. Keystone tokens are also bearer tokens, so a
    /// shorter duration will also reduce the potential security impact of a
    /// compromised token.
    #[serde(default = "default_token_expiration")]
    pub expiration: usize,
    /// Token formats that are accepted for validation in addition to the
    /// format issued by `provider` (ADR 0049). Lets a deployment switch the
    /// issuing format while tokens of the previous one are still alive.
    ///
    /// A comma-separated list in the configuration file, as in
    /// `accepted = fernet, jws`.
    #[serde(default, deserialize_with = "drivers_from_csv_or_seq")]
    pub accepted: Vec<TokenProviderDriver>,
    /// Maximum number of mapped groups an OAuth2 format token carries
    /// (ADR 0049). A federated login that resolves more groups fails; the
    /// list is never truncated.
    #[serde(default = "default_max_federation_groups")]
    pub max_federation_groups: usize,
}

impl TokenProvider {
    /// Whether tokens of the given format are accepted for validation: the
    /// issuing `provider` is always accepted.
    #[must_use]
    pub fn accepts(&self, driver: &TokenProviderDriver) -> bool {
        self.provider == *driver || self.accepted.contains(driver)
    }
}

fn default_token_expiration() -> usize {
    3600
}

fn default_max_federation_groups() -> usize {
    50
}

impl Default for TokenProvider {
    fn default() -> Self {
        Self {
            provider: TokenProviderDriver::Fernet,
            expiration: default_token_expiration(),
            accepted: Vec::new(),
            max_federation_groups: default_max_federation_groups(),
        }
    }
}

/// A list of drivers, either a sequence or the comma-separated string an INI
/// file holds (a single value reaches serde as a plain string).
fn drivers_from_csv_or_seq<'de, D>(deserializer: D) -> Result<Vec<TokenProviderDriver>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, IntoDeserializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Seq(Vec<TokenProviderDriver>),
        Csv(String),
    }
    match Repr::deserialize(deserializer)? {
        Repr::Seq(seq) => Ok(seq),
        Repr::Csv(csv) => csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                TokenProviderDriver::deserialize(IntoDeserializer::<D::Error>::into_deserializer(s))
                    .map_err(|e: D::Error| D::Error::custom(format!("accepted: {e}")))
            })
            .collect(),
    }
}

/// Token provider driver.
#[derive(Debug, Default, Deserialize, Clone, PartialEq, Eq)]
pub enum TokenProviderDriver {
    /// Fernet.
    #[default]
    #[serde(rename = "fernet")]
    Fernet,
    /// Asymmetric ES256/RS256-signed JWS tokens, wire-compatible with
    /// Python Keystone's `[token] provider = jws` (ADR 0026 §10, Phase 0).
    #[serde(rename = "jws")]
    Jws,
    /// OAuth2 JWT signed with the key of the user's domain (ADR 0049).
    #[serde(rename = "oauth2")]
    Oauth2,
}

impl TokenProviderDriver {
    /// The name of the driver as used in the configuration and as the metric
    /// label.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fernet => "fernet",
            Self::Jws => "jws",
            Self::Oauth2 => "oauth2",
        }
    }
}

impl fmt::Display for TokenProviderDriver {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_provider_driver_default_is_fernet() {
        assert_eq!(TokenProviderDriver::default(), TokenProviderDriver::Fernet);
    }

    #[test]
    fn test_token_provider_accepts() {
        let cfg: TokenProvider =
            serde_json::from_str(r#"{"provider":"jws","accepted":["fernet"]}"#).unwrap();
        assert!(cfg.accepts(&TokenProviderDriver::Jws));
        assert!(cfg.accepts(&TokenProviderDriver::Fernet));
        assert!(!TokenProvider::default().accepts(&TokenProviderDriver::Jws));
        assert!(TokenProvider::default().accepts(&TokenProviderDriver::Fernet));
    }

    #[test]
    fn test_token_provider_accepted_from_ini_strings() {
        for (value, expected) in [
            ("fernet", vec![TokenProviderDriver::Fernet]),
            (
                "fernet, jws,oauth2",
                vec![
                    TokenProviderDriver::Fernet,
                    TokenProviderDriver::Jws,
                    TokenProviderDriver::Oauth2,
                ],
            ),
            ("", vec![]),
        ] {
            let cfg: TokenProvider =
                serde_json::from_value(serde_json::json!({"accepted": value})).unwrap();
            assert_eq!(cfg.accepted, expected, "{value:?}");
        }
        assert!(
            serde_json::from_value::<TokenProvider>(serde_json::json!({"accepted": "pgp"}))
                .is_err()
        );
    }

    #[test]
    fn test_token_driver_display() {
        assert_eq!(TokenProviderDriver::Fernet.to_string(), "fernet");
        assert_eq!(TokenProviderDriver::Jws.to_string(), "jws");
    }

    #[test]
    fn test_token_provider_driver_deserialize_jws() {
        let parsed: TokenProviderDriver = serde_json::from_str("\"jws\"").unwrap();
        assert_eq!(parsed, TokenProviderDriver::Jws);
    }
}
