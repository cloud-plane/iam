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
//! # OAuth2 subcommand of the keystone-manage cli.
//!
//! Every subcommand talks to the admin API over the admin Unix socket via
//! [`build_admin_client`]. Each one splits its work into a `*_with_client`
//! method that takes the HTTP client and base URL, so it can be unit tested
//! against a mock server, and a `take_action` that wires in the real admin
//! client.

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::eyre};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::Response;

use openstack_keystone_config::LoadedConfig;

mod client;
mod confirm_rotate_signing_key;
mod ensure_signing_key;
mod list_local_emergency_candidates;
mod reconcile_local_emergency_key;
mod revoke;
mod rotate_signing_key;
mod sessions;

use crate::PerformAction;
use crate::oauth2::client::ClientCommand;
use crate::oauth2::confirm_rotate_signing_key::ConfirmRotateSigningKeyCommand;
use crate::oauth2::ensure_signing_key::EnsureSigningKeyCommand;
use crate::oauth2::list_local_emergency_candidates::ListLocalEmergencyCandidatesCommand;
use crate::oauth2::reconcile_local_emergency_key::ReconcileLocalEmergencyKeyCommand;
use crate::oauth2::revoke::RevokeCommand;
use crate::oauth2::rotate_signing_key::RotateSigningKeyCommand;
use crate::oauth2::sessions::SessionsCommand;

/// OAuth2/OIDC provider administration (ADR 0026).
#[derive(Parser)]
pub struct Oauth2Command {
    #[command(subcommand)]
    command: Oauth2Commands,
}

#[async_trait]
impl PerformAction for Oauth2Command {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        match self.command {
            Oauth2Commands::Client(e) => e.take_action(config).await,
            Oauth2Commands::Revoke(e) => e.take_action(config).await,
            Oauth2Commands::Sessions(e) => e.take_action(config).await,
            Oauth2Commands::RotateSigningKey(e) => e.take_action(config).await,
            Oauth2Commands::ConfirmRotateSigningKey(e) => e.take_action(config).await,
            Oauth2Commands::EnsureSigningKey(e) => e.take_action(config).await,
            Oauth2Commands::ListLocalEmergencyCandidates(e) => e.take_action(config).await,
            Oauth2Commands::ReconcileLocalEmergencyKey(e) => e.take_action(config).await,
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Subcommand)]
enum Oauth2Commands {
    Client(ClientCommand),
    Revoke(RevokeCommand),
    Sessions(SessionsCommand),
    RotateSigningKey(RotateSigningKeyCommand),
    ConfirmRotateSigningKey(ConfirmRotateSigningKeyCommand),
    EnsureSigningKey(EnsureSigningKeyCommand),
    ListLocalEmergencyCandidates(ListLocalEmergencyCandidatesCommand),
    ReconcileLocalEmergencyKey(ReconcileLocalEmergencyKeyCommand),
}

/// Characters escaped inside one URL path segment.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'\\');

/// Build `{base_url}/v4/oauth2/{domain}/{segments...}`, percent-encoding every
/// path segment so that operator input cannot alter the request path or
/// query.
fn domain_url(base_url: &str, domain: &str, segments: &[&str]) -> String {
    let mut url = format!(
        "{base_url}/v4/oauth2/{}",
        utf8_percent_encode(domain, PATH_SEGMENT)
    );
    for segment in segments {
        url.push('/');
        url.extend(utf8_percent_encode(segment, PATH_SEGMENT));
    }
    url
}

/// Turn a non-2xx admin API response into an error that carries the status
/// and the response body. `action` names the operation in the message.
async fn ensure_success(res: Response, action: &str) -> Result<Response, Report> {
    let status = res.status();
    if status.is_success() {
        return Ok(res);
    }
    let body = res
        .text()
        .await
        .unwrap_or_else(|e| format!("<unreadable response body: {e}>"));
    Err(eyre!("{action} failed: {status} ({body})"))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use openstack_keystone_config::Config;

    use super::*;
    use crate::common::build_admin_client;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: Oauth2Commands,
    }

    #[test]
    fn test_parses_rotate_signing_key_subcommand() {
        let wrapper = Wrapper::parse_from(["oauth2", "rotate-signing-key", "--domain", "domain-1"]);
        assert!(matches!(
            wrapper.command,
            Oauth2Commands::RotateSigningKey(_)
        ));
    }

    #[test]
    fn test_parses_confirm_rotate_signing_key_subcommand() {
        let wrapper = Wrapper::parse_from([
            "oauth2",
            "confirm-rotate-signing-key",
            "--domain",
            "domain-1",
            "--rotation-id",
            "rot-1",
        ]);
        assert!(matches!(
            wrapper.command,
            Oauth2Commands::ConfirmRotateSigningKey(_)
        ));
    }

    #[test]
    fn test_domain_url_encodes_segments() {
        assert_eq!(
            domain_url("https://localhost", "d1", &[]),
            "https://localhost/v4/oauth2/d1"
        );
        assert_eq!(
            domain_url("https://localhost", "d/1?x", &["clients", "p#1"]),
            "https://localhost/v4/oauth2/d%2F1%3Fx/clients/p%231"
        );
        assert_eq!(
            domain_url("https://localhost", "d", &["../x"]),
            "https://localhost/v4/oauth2/d/..%2Fx"
        );
    }

    #[tokio::test]
    async fn test_admin_client_requires_admin_interface() {
        let err = build_admin_client(&Config::default()).await.unwrap_err();
        assert!(
            err.to_string().contains("admin interface not configured"),
            "unexpected error: {err}"
        );
    }
}
