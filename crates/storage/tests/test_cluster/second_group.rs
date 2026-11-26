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
//! A second Raft group in the same process (ADR 0045 section 4,
//! reservation group): own listener, database and DEK, nothing shared with
//! the primary group.

use openstack_keystone_config::{Config, ConfigManager, LoadedConfig};
use openstack_keystone_distributed_storage::app::init_reservation_storage;
use openstack_keystone_distributed_storage::config::ReservationStorageConfiguration;
use oslo_config::SectionBag;

use super::harness::*;
use super::*;

const SECOND_GROUP_PORT_BASE: u16 = 3000;

#[serial_test::serial]
#[test]
fn test_two_groups_share_nothing() {
    TypeConfig::run(test_two_groups_inner()).unwrap();
}

#[allow(unsafe_code)]
async fn test_two_groups_inner() -> Result<()> {
    let tls = common::make_certificates()?;

    // Primary group: node 1.
    let (primary, mut primary_admin) =
        start_single_node_cluster(SECOND_GROUP_PORT_BASE, &tls).await?;

    // Reservation group: its own node 1 on another port and database.
    let group_dir = TempDir::new()?;
    let group_config = get_ds_config_with_port(
        1,
        SECOND_GROUP_PORT_BASE + 10,
        group_dir.path().into(),
        tls.clone(),
    );
    let mut sections = SectionBag::default();
    sections.insert(ReservationStorageConfiguration(group_config.clone()));
    let manager: Arc<ConfigManager> =
        ConfigManager::not_watched_loaded(LoadedConfig::with_sections(Config::default(), sections));
    // SAFETY: nodes are initialised sequentially, see `InstanceHolder`.
    unsafe {
        std::env::set_var("KEYSTONE_DEV_KEK", TEST_KEK_HEX);
        std::env::set_var("KEYSTONE_ALLOW_ENV_KEK", "1");
    }
    let group = init_reservation_storage(&manager).await?;
    {
        let (config, storage) = (group_config.clone(), group.clone());
        let _ = thread::spawn(move || {
            let mut rt = AsyncRuntimeOf::<TypeConfig>::new(1);
            let _ = rt.block_on(start_raft_app(&config, &storage));
        });
    }
    wait_for_listener(group_config.node_listener_addr).await;
    let mut group_admin = new_admin_client(
        group_config.node_cluster_addr.clone(),
        &get_client_tls_config(&group_config)?,
    )
    .await?;
    group_admin
        .init(pb::raft::InitRequest {
            nodes: vec![new_node_with_port(1, SECOND_GROUP_PORT_BASE + 10)],
        })
        .await?;
    wait_for_leader(&mut group_admin, 1).await;
    // The primary stays led.
    wait_for_leader(&mut primary_admin, 1).await;

    // The same key holds a different value in each group.
    set_value_retrying(&primary.storage, "k", "primary").await?;
    set_value_retrying(&group, "k", "reservation").await?;
    let p = get_by_key_retrying(&primary.storage, b"k", None)
        .await?
        .ok_or_else(|| eyre::eyre!("primary lost its write"))?;
    let g = get_by_key_retrying(&group, b"k", None)
        .await?
        .ok_or_else(|| eyre::eyre!("group lost its write"))?;
    assert_eq!("primary", p.try_deserialize::<String>()?.data);
    assert_eq!("reservation", g.try_deserialize::<String>()?.data);
    Ok(())
}
