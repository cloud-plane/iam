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
use crate::common::TlsConfiguration;
use eyre::{WrapErr, eyre};
use oslo_config::{ConfigError, ConfigSection, LoadCtx};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::path::PathBuf;
use validator::Validate;

/// Database configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct DatabaseSection {
    /// Database URL.
    pub connection: SecretString,

    /// SQL query logging verbosity, `0`-`100` (mirrors oslo_db's
    /// `connection_debug`). `0` disables query logging (default); higher
    /// values enable it at increasingly verbose tracing levels.
    #[serde(default)]
    pub connection_debug: u8,

    /// Maximum number of connections the pool keeps open (mirrors oslo_db's
    /// `max_pool_size`). Unset uses the driver default of 10. Every in-flight
    /// request holds a connection per query, so a small pool makes requests
    /// queue behind each other long before the database is busy.
    #[serde(default)]
    pub max_pool_size: Option<u32>,

    /// TLS material for the DB connection: client cert/key for mTLS and the
    /// CA used to validate the DB server's certificate. Populated either by
    /// an external process (SPIRE Helper, cert-manager, manual ops rotating
    /// the files in place) or by Keystone's own SPIFFE writer task
    /// (`spiffe_managed` below) pointed at the same paths. Rotation of any
    /// of these files is detected by `reconnect_db_on_config_change`
    /// regardless of who wrote them - see `crates/keystone/src/db_reload.rs`.
    /// Distinct from TLS parameters embedded in the DSN query string (e.g.
    /// `sslrootcert=...`), which are static for the process lifetime unless
    /// the DSN itself changes.
    #[serde(flatten)]
    pub tls: TlsConfiguration,

    /// Run a background task that sources Keystone's own SPIFFE X.509 SVID
    /// and the SPIRE trust bundle, writing them to `tls.tls_cert_file`/
    /// `tls_key_file`/`tls_client_ca_file` above whenever SPIRE rotates them
    /// (see `crates/keystone/src/db_spiffe.rs`). Requires all three paths to
    /// be set; validated in `Config::finish_load`. This is coarser-grained
    /// than the per-handshake SPIFFE mTLS used for Raft/HTTP listeners -
    /// sqlx has no API to inject a live rustls config per DB handshake, so
    /// rotation here is bounded by write + reconnect-detection latency, not
    /// per-connection. See `db_spiffe`'s module doc for the full disclosure.
    #[serde(default)]
    pub spiffe_managed: bool,

    /// Interval in milliseconds between two polls of the `table_version`
    /// watermark table. Defaults to 1000; `0` disables the poller, and with
    /// it every projection cache of the SQL drivers (all reads go to the
    /// database).
    ///
    /// The SQL drivers of the identity and resource providers keep a
    /// version counter per table in `table_version`, bumped by database
    /// triggers, and cache small non-secret projections (user options,
    /// password expiry, project domain and parents) validated against the
    /// counters. Readers that tolerate staleness use the polled counters
    /// (a change made by another process is noticed within one interval);
    /// linearizable readers read the counters with one query first. When a
    /// poll fails, or the triggers are not installed, every read goes to
    /// the database. Requires a SQL backend with the watermark triggers
    /// installed (`keystone-manage db sync` or `db up`).
    #[serde(default = "default_table_watermark_interval_ms")]
    pub table_watermark_interval_ms: u64,

    /// How stale (in milliseconds) the non-secret projections the SQL
    /// drivers cache may be for the reads of the token validation path
    /// (the options and the password expiry of the user, the domain of a
    /// project). `0` (default) disables the projections that tolerate
    /// staleness: every read goes to the database. Without the watermark
    /// poller (`table_watermark_interval_ms = 0`) a projection that
    /// tolerates staleness is served by the age of the entry alone, up to
    /// this value.
    ///
    /// The projections are validated against the table watermarks (see
    /// `table_watermark_interval_ms`). A value below the watermark poll
    /// interval cannot be guaranteed and results in a database read, as
    /// does an unhealthy poller. Authentication, password verification and
    /// every write path always read the database. The value must not
    /// exceed 300000 (5 minutes).
    #[serde(default)]
    #[validate(range(max = 300_000))]
    pub projection_max_staleness_ms: u64,

    /// Upper bound, in MiB, of the memory of all the projection caches of
    /// the SQL drivers together (like `memcached -m`). The budget is split
    /// among the individual caches by the `projection_cache_weight_*`
    /// options, and every entry is charged its approximate size. When a
    /// cache is full expired entries are dropped first, then arbitrary
    /// ones. The budget applies to every driver instance: with several
    /// named SQL drivers each one gets the share of its own caches.
    /// Defaults to 64, at most 16384; `0` disables the projection caches.
    #[serde(default = "default_projection_cache_max_memory_mib")]
    #[validate(range(max = 16_384))]
    pub projection_cache_max_memory_mib: u64,

    /// Maximum age, in milliseconds, of an entry of the projection caches,
    /// whatever the watermarks and the staleness of the reader say. Bounds
    /// the damage of a missed invalidation (e.g. a cascade delete on
    /// MySQL, which fires no triggers). Defaults to 300000 (5 minutes), at
    /// most 86400000 (a day); `0` disables the projection caches.
    #[serde(default = "default_projection_cache_ttl_ms")]
    #[validate(range(max = 86_400_000))]
    pub projection_cache_ttl_ms: u64,

    /// How long, in milliseconds, an entry is trusted by a reader that
    /// accepts any staleness when there is no watermark poller to say that
    /// it is outdated. Defaults to 60000, between 1 and 3600000.
    #[serde(default = "default_projection_any_ttl_without_poller_ms")]
    #[validate(range(min = 1, max = 3_600_000))]
    pub projection_any_ttl_without_poller_ms: u64,

    /// Share of the user options cache in the projection memory budget.
    /// The share of a cache is its weight divided by the sum of all the
    /// `projection_cache_weight_*` options; `0` gives the cache no memory
    /// (disabled). At most 1000.
    #[serde(default = "default_weight_2")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_user_options: u32,

    /// Share of the password expiry cache, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_password_expiry: u32,

    /// Share of the cache of the domain of a project, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_project_domain: u32,

    /// Share of the cache of the domain of a user, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_user_domain: u32,

    /// Share of the cache of the parents of a project, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_2")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_project_parents: u32,

    /// Share of the project reference cache, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_2")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_project_ref: u32,

    /// Share of the domain reference cache, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_domain_ref: u32,

    /// Share of the cache of the groups of a user, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_2")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_user_groups: u32,

    /// Share of the role assignments cache, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_4")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_assignments: u32,

    /// Share of the cache of the user record, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_2")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_user: u32,

    /// Share of the cache of the local user row, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_local_user: u32,

    /// Share of the cache of the token revocation check, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_2")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_revocation: u32,

    /// Share of the cache of the role names, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_role_names: u32,

    /// Share of the cache of the resolved role inference, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_role_inference: u32,

    /// Share of the service catalog cache, see
    /// `projection_cache_weight_user_options`.
    #[serde(default = "default_weight_1")]
    #[validate(range(max = 1000))]
    pub projection_cache_weight_catalog: u32,
}

fn default_projection_cache_max_memory_mib() -> u64 {
    64
}

fn default_table_watermark_interval_ms() -> u64 {
    1_000
}

fn default_projection_cache_ttl_ms() -> u64 {
    300_000
}

fn default_projection_any_ttl_without_poller_ms() -> u64 {
    60_000
}

fn default_weight_1() -> u32 {
    1
}

fn default_weight_2() -> u32 {
    2
}

fn default_weight_4() -> u32 {
    4
}

impl Default for DatabaseSection {
    fn default() -> Self {
        Self {
            connection: SecretString::default(),
            connection_debug: 0,
            max_pool_size: None,
            tls: TlsConfiguration::default(),
            spiffe_managed: false,
            table_watermark_interval_ms: default_table_watermark_interval_ms(),
            projection_max_staleness_ms: 0,
            projection_cache_max_memory_mib: default_projection_cache_max_memory_mib(),
            projection_cache_ttl_ms: default_projection_cache_ttl_ms(),
            projection_any_ttl_without_poller_ms: default_projection_any_ttl_without_poller_ms(),
            projection_cache_weight_user_options: default_weight_2(),
            projection_cache_weight_password_expiry: default_weight_1(),
            projection_cache_weight_project_domain: default_weight_1(),
            projection_cache_weight_user_domain: default_weight_1(),
            projection_cache_weight_project_parents: default_weight_2(),
            projection_cache_weight_project_ref: default_weight_2(),
            projection_cache_weight_domain_ref: default_weight_1(),
            projection_cache_weight_user_groups: default_weight_2(),
            projection_cache_weight_assignments: default_weight_4(),
            projection_cache_weight_user: default_weight_2(),
            projection_cache_weight_local_user: default_weight_1(),
            projection_cache_weight_revocation: default_weight_2(),
            projection_cache_weight_role_names: default_weight_1(),
            projection_cache_weight_role_inference: default_weight_1(),
            projection_cache_weight_catalog: default_weight_1(),
        }
    }
}

impl DatabaseSection {
    /// The sum of the `projection_cache_weight_*` options.
    pub fn projection_cache_weight_total(&self) -> u64 {
        [
            self.projection_cache_weight_user_options,
            self.projection_cache_weight_password_expiry,
            self.projection_cache_weight_project_domain,
            self.projection_cache_weight_user_domain,
            self.projection_cache_weight_project_parents,
            self.projection_cache_weight_project_ref,
            self.projection_cache_weight_domain_ref,
            self.projection_cache_weight_user_groups,
            self.projection_cache_weight_assignments,
            self.projection_cache_weight_user,
            self.projection_cache_weight_local_user,
            self.projection_cache_weight_revocation,
            self.projection_cache_weight_role_names,
            self.projection_cache_weight_role_inference,
            self.projection_cache_weight_catalog,
        ]
        .into_iter()
        .map(u64::from)
        .sum()
    }

    /// Whether SQL query logging should be enabled for the configured
    /// `connection_debug` verbosity.
    pub fn sqlx_logging_enabled(&self) -> bool {
        self.connection_debug > 0
    }

    /// Tracing level to log SQL queries at for the configured
    /// `connection_debug` verbosity.
    pub fn sqlx_logging_level(&self) -> log::LevelFilter {
        match self.connection_debug {
            0 => log::LevelFilter::Off,
            1..=33 => log::LevelFilter::Warn,
            34..=66 => log::LevelFilter::Info,
            _ => log::LevelFilter::Debug,
        }
    }

    pub fn get_connection(&self) -> SecretString {
        let val = self.connection.expose_secret();
        if let Some(slash_pos) = val.find("://") {
            let scheme = &val[..slash_pos];
            if let Some(plus_pos) = scheme.find('+') {
                let base = &scheme[..plus_pos];
                return SecretString::from(format!("{}://{}", base, &val[slash_pos + 3..]));
            }
        }
        self.connection.clone()
    }
}

impl ConfigSection for DatabaseSection {
    const NAME: &'static str = "database";

    fn finish(&mut self, _ctx: &LoadCtx) -> Result<(), ConfigError> {
        self.tls
            .read_certs()
            .wrap_err("reading database TLS configuration")?;
        if self.spiffe_managed
            && (self.tls.tls_cert_file.is_none()
                || self.tls.tls_key_file.is_none()
                || self.tls.tls_client_ca_file.is_none())
        {
            return Err(eyre!(
                "[database] spiffe_managed = true requires tls_cert_file, tls_key_file, \
                 and tls_client_ca_file to all be set"
            ));
        }
        Ok(())
    }

    fn watch_files(&self) -> Vec<PathBuf> {
        [
            &self.tls.tls_cert_file,
            &self.tls.tls_key_file,
            &self.tls.tls_client_ca_file,
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_db_connection() {
        // No driver suffix – no change
        let sot = DatabaseSection {
            connection: "mysql://u:p@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());

        // Driver suffix stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());
    }

    #[test]
    fn test_db_connection_multiple_scheme_delimiters() {
        // :// in password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p://x@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p://x@h", sot.get_connection().expose_secret());

        // Multiple :// in password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u://x:p://y@h".into(),
            ..Default::default()
        };
        assert_eq!(
            "mysql://u://x:p://y@h",
            sot.get_connection().expose_secret()
        );
    }

    #[test]
    fn test_db_connection_plus_in_password() {
        // Single + in password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:p+q@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p+q@h", sot.get_connection().expose_secret());

        // Multiple + in password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:a+b+c@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:a+b+c@h", sot.get_connection().expose_secret());

        // Only + as password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:+@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:+@h", sot.get_connection().expose_secret());

        // + at end of password, no driver – unchanged
        let sot = DatabaseSection {
            connection: "mysql://u:pass+@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:pass+@h", sot.get_connection().expose_secret());

        // Driver suffix + single + in password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p+q@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p+q@h", sot.get_connection().expose_secret());

        // Driver suffix + multiple + in password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:a+b+c@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:a+b+c@h", sot.get_connection().expose_secret());

        // Driver suffix + only + as password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:+@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:+@h", sot.get_connection().expose_secret());

        // Driver suffix + :// and + in password
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p+q://r@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p+q://r@h", sot.get_connection().expose_secret());

        // + in username and password, no driver
        let sot = DatabaseSection {
            connection: "mysql://u+v:p+w@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u+v:p+w@h", sot.get_connection().expose_secret());

        // Driver suffix + + in username and password
        let sot = DatabaseSection {
            connection: "mysql+driver://u+v:p+w@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u+v:p+w@h", sot.get_connection().expose_secret());

        // Empty password, no driver
        let sot = DatabaseSection {
            connection: "mysql://u:@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:@h", sot.get_connection().expose_secret());

        // Empty password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u:@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:@h", sot.get_connection().expose_secret());

        // No password, no driver
        let sot = DatabaseSection {
            connection: "mysql://u@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u@h", sot.get_connection().expose_secret());

        // No password, driver stripped
        let sot = DatabaseSection {
            connection: "mysql+driver://u@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u@h", sot.get_connection().expose_secret());

        // Special chars in password: @, /, ?, #
        let sot = DatabaseSection {
            connection: "mysql+driver://u:p@ss/w?_r#k@h".into(),
            ..Default::default()
        };
        assert_eq!(
            "mysql://u:p@ss/w?_r#k@h",
            sot.get_connection().expose_secret()
        );

        // % encoded + in password (literal %2B)
        let sot = DatabaseSection {
            connection: "mysql+driver://u:%2B@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:%2B@h", sot.get_connection().expose_secret());
    }

    #[test]
    fn test_db_connection_edge_cases() {
        // Multiple consecutive +
        let sot = DatabaseSection {
            connection: "mysql+driver+extra://u:p@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql://u:p@h", sot.get_connection().expose_secret());

        // No scheme separator – passthrough
        let sot = DatabaseSection {
            connection: "mysql+driver/u:p@h".into(),
            ..Default::default()
        };
        assert_eq!("mysql+driver/u:p@h", sot.get_connection().expose_secret());

        // Empty connection
        let sot = DatabaseSection {
            connection: "".into(),
            ..Default::default()
        };
        assert_eq!("", sot.get_connection().expose_secret());
    }
}

#[cfg(test)]
mod projection_tests {
    use validator::Validate;

    use super::*;

    #[test]
    fn defaults_are_valid() {
        let db = DatabaseSection::default();
        assert!(db.validate().is_ok());
        assert_eq!(db.projection_cache_max_memory_mib, 64);
        assert_eq!(db.projection_cache_ttl_ms, 300_000);
        assert_eq!(db.table_watermark_interval_ms, 1_000);
        assert_eq!(db.projection_any_ttl_without_poller_ms, 60_000);
        assert_eq!(db.projection_cache_weight_total(), 24);
    }

    #[test]
    fn caps_are_enforced() {
        let ok = DatabaseSection::default();
        for broken in [
            DatabaseSection {
                projection_max_staleness_ms: 300_001,
                ..ok.clone()
            },
            DatabaseSection {
                projection_cache_max_memory_mib: 16_385,
                ..ok.clone()
            },
            DatabaseSection {
                projection_cache_ttl_ms: 86_400_001,
                ..ok.clone()
            },
            DatabaseSection {
                projection_any_ttl_without_poller_ms: 0,
                ..ok.clone()
            },
            DatabaseSection {
                projection_cache_weight_revocation: 1001,
                ..ok.clone()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
        let edge = DatabaseSection {
            projection_max_staleness_ms: 300_000,
            projection_cache_max_memory_mib: 0,
            projection_cache_weight_user: 0,
            ..ok
        };
        assert!(edge.validate().is_ok());
    }
}
