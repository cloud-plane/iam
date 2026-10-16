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
//! # OAuth2 session triage (ADR 0026 §9).

use async_trait::async_trait;
use clap::{Parser, Subcommand};
use color_eyre::{Report, eyre::WrapErr, eyre::eyre};

use openstack_keystone_api_types::v4::oauth2_revocation::{Oauth2Session, Oauth2SessionList};
use openstack_keystone_config::LoadedConfig;

use super::client::OutputFormat;
use super::get_admin_client;
use crate::PerformAction;
use crate::common::print_list_table;

/// Table headers of the session listing.
const SESSION_HEADERS: [&str; 6] = [
    "Family ID",
    "Client",
    "Issued At",
    "Last Rotated",
    "Revoked At",
    "Reason",
];

/// One table row per session.
fn session_rows(sessions: Vec<Oauth2Session>) -> Vec<Vec<String>> {
    sessions
        .into_iter()
        .map(|s| {
            vec![
                s.family_id,
                s.client_id,
                s.issued_at.to_string(),
                s.last_rotated.to_string(),
                s.revoked_at
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "-".into()),
                s.revocation_reason.unwrap_or_else(|| "-".into()),
            ]
        })
        .collect()
}

/// Inspect OAuth2 sessions.
#[derive(Parser)]
pub(super) struct SessionsCommand {
    #[command(subcommand)]
    command: SessionsCommands,
}

#[derive(Subcommand)]
enum SessionsCommands {
    /// List the sessions (refresh token families) of a user.
    List(ListCommand),
}

#[async_trait]
impl PerformAction for SessionsCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        match self.command {
            SessionsCommands::List(c) => c.take_action(config).await,
        }
    }
}

/// List the sessions of a user.
#[derive(Parser)]
pub(super) struct ListCommand {
    /// Domain of the user.
    #[arg(long)]
    domain: String,
    /// User whose sessions are listed.
    #[arg(long)]
    user: String,
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[async_trait]
impl PerformAction for ListCommand {
    async fn take_action(self, config: &LoadedConfig) -> Result<(), Report> {
        let client = get_admin_client(config).await?;
        // Build the URL by segments so the domain is percent-encoded.
        let mut url = reqwest::Url::parse("https://localhost/")?;
        url.path_segments_mut()
            .map_err(|_| eyre!("invalid base URL"))?
            .extend(["v4", "oauth2", self.domain.as_str(), "sessions"]);
        let res = client
            .get(url)
            .query(&[("user_id", &self.user)])
            .send()
            .await
            .wrap_err("sessions request failed")?;
        let status = res.status();
        if !status.is_success() {
            let detail = match res.text().await {
                Ok(body) => body,
                Err(e) => format!("<unreadable response body: {e}>"),
            };
            return Err(eyre!("listing sessions failed: {status} ({detail})"));
        }
        let body: Oauth2SessionList = res.json().await?;
        match self.format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
            OutputFormat::Text => {
                print_list_table(SESSION_HEADERS.to_vec(), session_rows(body.oauth2_sessions));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Wrapper {
        #[command(subcommand)]
        command: SessionsCommands,
    }

    #[test]
    fn test_parses_list() {
        let w = Wrapper::parse_from(["sessions", "list", "--domain", "d", "--user", "u"]);
        let SessionsCommands::List(c) = w.command;
        assert_eq!(c.user, "u");
        assert!(Wrapper::try_parse_from(["sessions", "list", "--domain", "d"]).is_err());
    }

    #[test]
    fn test_session_rows() {
        let rows = session_rows(vec![
            Oauth2Session {
                client_id: "c1".into(),
                family_id: "f1".into(),
                issued_at: 10,
                last_rotated: 20,
                revocation_reason: None,
                revoked_at: None,
                user_id: "u".into(),
            },
            Oauth2Session {
                client_id: "c2".into(),
                family_id: "f2".into(),
                issued_at: 30,
                last_rotated: 40,
                revocation_reason: Some("user_logout".into()),
                revoked_at: Some(50),
                user_id: "u".into(),
            },
        ]);
        let expected: Vec<Vec<String>> = vec![
            ["f1", "c1", "10", "20", "-", "-"]
                .map(String::from)
                .to_vec(),
            ["f2", "c2", "30", "40", "50", "user_logout"]
                .map(String::from)
                .to_vec(),
        ];
        assert_eq!(rows, expected);
    }

    #[tokio::test]
    async fn test_rejects_missing_admin_interface_config() {
        let cfg = LoadedConfig::new(Default::default());
        let cmd = ListCommand {
            domain: "d".into(),
            user: "u".into(),
            format: OutputFormat::Text,
        };
        let err = cmd.take_action(&cfg).await.unwrap_err();
        assert!(err.to_string().contains("admin interface not configured"));
    }
}
