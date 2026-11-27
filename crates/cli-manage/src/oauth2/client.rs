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
//! # OAuth2 client registration commands (ADR 0026 §5).
//!
//! Thin wrappers over the `/v4/oauth2/{domain_id}/clients` API sent over the
//! admin UDS, so the Rego policy still applies. Each subcommand lives in its
//! own module under `client/`; this module holds the shared pieces.

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr};
use reqwest::{Client, Method};
use serde::Serialize;
use serde_json::Value;

use openstack_keystone_api_types::v4::oauth2_client::{GrantType, OAuth2Client};
use openstack_keystone_config::LoadedConfig;

use super::{domain_url, ensure_success};
use crate::PerformAction;
use crate::common::{OutputFormat, print_attribute_table};

mod create;
mod delete;
mod list;
mod rotate_secret;
mod show;
mod update;

use crate::oauth2::client::create::CreateCommand;
use crate::oauth2::client::delete::DeleteCommand;
use crate::oauth2::client::list::ListCommand;
use crate::oauth2::client::rotate_secret::RotateSecretCommand;
use crate::oauth2::client::show::ShowCommand;
use crate::oauth2::client::update::UpdateCommand;

/// Options shared by every client command.
#[derive(Args)]
pub(crate) struct Common {
    /// Domain owning the client.
    #[arg(long)]
    domain: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

/// Manage OAuth2 clients (relying parties and machine identities).
#[derive(Parser)]
pub(super) struct ClientCommand {
    #[command(subcommand)]
    command: ClientCommands,
}

#[derive(Subcommand)]
enum ClientCommands {
    /// Register a client. Prints the one-time secret of confidential clients.
    Create(CreateCommand),
    /// List the clients of a domain.
    List(ListCommand),
    /// Show one client.
    Show(ShowCommand),
    /// Update mutable client settings.
    Update(UpdateCommand),
    /// Delete a client and revoke its refresh-token families.
    Delete(DeleteCommand),
    /// Replace the secret of a confidential client.
    RotateSecret(RotateSecretCommand),
}

#[async_trait]
impl PerformAction for ClientCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        match self.command {
            ClientCommands::Create(c) => c.take_action(config).await,
            ClientCommands::List(c) => c.take_action(config).await,
            ClientCommands::Show(c) => c.take_action(config).await,
            ClientCommands::Update(c) => c.take_action(config).await,
            ClientCommands::Delete(c) => c.take_action(config).await,
            ClientCommands::RotateSecret(c) => c.take_action(config).await,
        }
    }
}

fn parse_grant_type(s: &str) -> Result<GrantType, String> {
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| format!("unknown grant type `{s}`"))
}

fn parse_claim(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got `{s}`"))
}

/// Build the clients API URL under `base_url`, percent-encoding every path
/// segment.
fn clients_url(base_url: &str, domain: &str, segments: &[&str]) -> String {
    let mut tail = vec!["clients"];
    tail.extend_from_slice(segments);
    domain_url(base_url, domain, &tail)
}

/// Send one request to the clients API through a pre-built admin client and
/// return the parsed JSON body (`Null` for an empty body).
async fn call(
    client: &Client,
    base_url: &str,
    method: Method,
    domain: &str,
    segments: &[&str],
    query: &[(&str, String)],
    body: Option<&impl Serialize>,
) -> Result<Value, Report> {
    let mut req = client
        .request(method, clients_url(base_url, domain, segments))
        .query(query);
    if let Some(body) = body {
        req = req.json(body);
    }
    let res = req.send().await.wrap_err("oauth2 client request failed")?;
    let res = ensure_success(res, "oauth2 client request").await?;
    let text = res
        .text()
        .await
        .wrap_err("reading oauth2 client response body failed")?;
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).wrap_err("invalid response body")
}

/// Print one client as an attribute table.
fn print_client(c: &OAuth2Client) {
    let grant_types: Vec<String> = c
        .grant_types
        .iter()
        .map(|g| {
            serde_json::to_value(g)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| format!("{g:?}"))
        })
        .collect();
    print_attribute_table(vec![
        ("Provider ID", c.provider_id.to_string()),
        ("Client ID", c.client_id.to_string()),
        ("Name", c.name.to_string()),
        ("Enabled", c.enabled.to_string()),
        ("Confidential", c.confidential.to_string()),
        ("Require PKCE", c.require_pkce.to_string()),
        ("Grant Types", grant_types.join(", ")),
        ("Redirect URIs", c.redirect_uris.join(", ")),
    ]);
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: ClientCommands,
    }

    #[test]
    fn test_parses_every_subcommand() {
        for args in [
            vec![
                "client",
                "create",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--name",
                "n",
            ],
            vec!["client", "list", "--domain", "d"],
            vec!["client", "show", "--domain", "d", "--provider-id", "p"],
            vec![
                "client",
                "update",
                "--domain",
                "d",
                "--provider-id",
                "p",
                "--enabled",
                "false",
            ],
            vec!["client", "delete", "--domain", "d", "--provider-id", "p"],
            vec![
                "client",
                "rotate-secret",
                "--domain",
                "d",
                "--provider-id",
                "p",
            ],
        ] {
            assert!(Wrapper::try_parse_from(args).is_ok());
        }
    }

    #[test]
    fn test_parse_grant_type_rejects_unknown() {
        assert!(parse_grant_type("bogus").is_err());
        assert_eq!(
            parse_grant_type("authorization_code").unwrap(),
            GrantType::AuthorizationCode
        );
    }

    #[test]
    fn test_clients_url_encodes_segments() {
        assert_eq!(
            clients_url("https://localhost", "d1", &[]),
            "https://localhost/v4/oauth2/d1/clients"
        );
        assert_eq!(
            clients_url("https://localhost", "d/1?x", &["p#1", "rotate-secret"]),
            "https://localhost/v4/oauth2/d%2F1%3Fx/clients/p%231/rotate-secret"
        );
    }
}
