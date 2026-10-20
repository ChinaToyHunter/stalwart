/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    IterateParams, RegistryStore, RegistryStoreInner, Store, U16_LEN, U32_LEN, U64_LEN, ValueKey,
    backend::ephemeral::EphemeralStore,
    registry::local::RegistryInit,
    write::{
        BatchBuilder, ValueClass,
        assert::AssertValue,
        key::{DeserializeBigEndian, KeySerializer},
        now,
    },
};
use rand::{RngExt, distr::Alphanumeric, rng};
use registry::{
    schema::{enums::ClusterNodeStatus, structs::ClusterNode},
    types::datetime::UTCDateTime,
};
use std::{path::PathBuf, time::Duration};
use trc::AddContext;

const STALE_NODE_TIMEOUT: u64 = 60 * 60; // 1 hour
const DEAD_NODE_TIMEOUT: u64 = 60 * 60 * 24; // 24 hours

impl RegistryStore {
    pub async fn init(local: PathBuf) -> Result<Self, String> {
        Self::init_with_mode(local, false).await
    }

    pub async fn init_for_import(local: PathBuf) -> Result<Self, String> {
        Self::init_with_mode(local, true).await
    }

    async fn init_with_mode(local: PathBuf, import_mode: bool) -> Result<Self, String> {
        // Create inner store
        let mut inner = RegistryStoreInner::new(local);

        // Build store
        inner.store = match inner.read_data_store().await {
            RegistryInit::Ok(data_store) => Store::build(data_store).await?,
            RegistryInit::Err(err) => return Err(err),
            RegistryInit::Bootstrap => {
                if import_mode {
                    return Err(
                        "Import requires an existing persistent data store configuration"
                            .to_string(),
                    );
                }
                inner.env_recovery_mode = true;

                if inner.env_recovery_admin.is_none() {
                    let password = rng()
                        .sample_iter(Alphanumeric)
                        .take(16)
                        .map(char::from)
                        .collect::<String>();
                    eprintln!();
                    eprintln!("════════════════════════════════════════════════════════════");
                    eprintln!("🔑 Stalwart bootstrap mode - temporary administrator account");
                    eprintln!();
                    eprintln!("   username: admin");
                    eprintln!("   password: {password}");
                    eprintln!();
                    eprintln!("Use these credentials to complete the initial setup at the");
                    eprintln!("/admin web UI. Once setup is done, Stalwart will provision a");
                    eprintln!("permanent administrator and this temporary account will no");
                    eprintln!("longer apply.");
                    eprintln!();
                    eprintln!("This password is shown only once. To pin a credential");
                    eprintln!("instead, set STALWART_RECOVERY_ADMIN=admin:<password> in the");
                    eprintln!("env file.");
                    eprintln!("════════════════════════════════════════════════════════════");
                    eprintln!();
                    inner.env_recovery_admin = Some(("admin".to_string(), password));
                }

                EphemeralStore::open()
            }
        };

        if import_mode && inner.store.is_ephemeral() {
            return Err("Import requires a configured persistent data store".to_string());
        }
        Self::from_inner_with_mode(inner, import_mode).await
    }

    pub fn from_inner_bootstrapped(inner: RegistryStoreInner) -> Self {
        Self(inner.into())
    }

    pub async fn from_inner(inner: RegistryStoreInner) -> Result<Self, String> {
        Self::from_inner_with_mode(inner, false).await
    }

    async fn from_inner_with_mode(
        mut inner: RegistryStoreInner,
        import_mode: bool,
    ) -> Result<Self, String> {
        // Create tables (SQL only)
        inner
            .store
            .create_tables()
            .await
            .map_err(|err| format!("Failed to create tables: {err}"))?;

        // Import startup must leave registry primary-key subspace untouched. The restore
        // command applies the same non-empty target guard before writing its first record.
        if import_mode {
            return Ok(Self(inner.into()));
        }

        // Obtain node id
        let mut retry_count = 0;
        loop {
            let mut found_node_id = false;
            let mut batch = BatchBuilder::new();
            let now = now();
            let mut node_ids = Vec::new();
            inner
                .store
                .iterate(
                    IterateParams::new(
                        ValueKey::from(ValueClass::NodeId(0)),
                        ValueKey::from(ValueClass::NodeId(u16::MAX)),
                    )
                    .ascending(),
                    |key, value| {
                        if key.len() == U16_LEN * 3 {
                            let node_id = key.deserialize_be_u16(U32_LEN)?;
                            let last_renewal = now.saturating_sub(value.deserialize_be_u64(0)?);
                            let hostname = value
                                .get(U64_LEN..)
                                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                .filter(|text| !text.is_empty())
                                .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())?;
                            let hash = xxhash_rust::xxh3::xxh3_64(value);

                            if hostname == inner.env_hostname || last_renewal > STALE_NODE_TIMEOUT {
                                if !found_node_id {
                                    inner.node_id = node_id;
                                    batch
                                        .assert_value(
                                            ValueClass::NodeId(node_id),
                                            AssertValue::Hash(hash),
                                        )
                                        .set(
                                            ValueClass::NodeId(node_id),
                                            KeySerializer::new(hostname.len() + U64_LEN)
                                                .write(now)
                                                .write(hostname)
                                                .finalize(),
                                        );
                                    found_node_id = true;
                                } else if last_renewal > DEAD_NODE_TIMEOUT {
                                    batch
                                        .assert_value(
                                            ValueClass::NodeId(node_id),
                                            AssertValue::Hash(hash),
                                        )
                                        .clear(ValueClass::NodeId(node_id));
                                }
                            } else {
                                node_ids.push(node_id);
                            }
                        }
                        Ok(true)
                    },
                )
                .await
                .map_err(|err| format!("Failed to iterate store: {err}"))?;

            if !found_node_id {
                if !node_ids.is_empty() {
                    node_ids.sort_unstable();
                    let mut last_node_id = 0;
                    for node_id in node_ids {
                        if node_id > last_node_id {
                            break;
                        }
                        last_node_id = node_id + 1;
                    }
                    inner.node_id = last_node_id;
                } else {
                    inner.node_id = 0;
                }

                batch
                    .assert_value(ValueClass::NodeId(inner.node_id), ())
                    .set(
                        ValueClass::NodeId(inner.node_id),
                        KeySerializer::new(inner.env_hostname.len() + U64_LEN)
                            .write(now)
                            .write(&inner.env_hostname)
                            .finalize(),
                    );
            }

            match inner.store.write(batch.build_all()).await {
                Ok(_) => break,
                Err(err) => {
                    if err.is_assertion_failure() && retry_count < 5 {
                        retry_count += 1;
                        continue;
                    } else {
                        return Err(format!("Failed to write node id to store: {err}"));
                    }
                }
            }
        }

        Ok(Self(inner.into()))
    }

    pub fn node_id(&self) -> u16 {
        self.0.node_id
    }

    pub fn refresh_node_id_interval(&self) -> Duration {
        Duration::from_secs(STALE_NODE_TIMEOUT / 2)
    }

    pub async fn cluster_node_list(&self) -> trc::Result<Vec<ClusterNode>> {
        let mut results = Vec::new();
        let now = now();

        self.0
            .store
            .iterate(
                IterateParams::new(
                    ValueKey::from(ValueClass::NodeId(0)),
                    ValueKey::from(ValueClass::NodeId(u16::MAX)),
                )
                .ascending(),
                |key, value| {
                    if key.len() == U16_LEN * 3 {
                        let node_id = key.deserialize_be_u16(U32_LEN)?;
                        let last_renewal = value.deserialize_be_u64(0)?;
                        let last_renewal_since_now = now.saturating_sub(last_renewal);
                        let hostname = value
                            .get(U64_LEN..)
                            .and_then(|bytes| std::str::from_utf8(bytes).ok())
                            .filter(|text| !text.is_empty())
                            .ok_or_else(|| trc::StoreEvent::DataCorruption.into_err())?;

                        results.push(ClusterNode {
                            hostname: hostname.to_string(),
                            last_renewal: UTCDateTime::from_timestamp(last_renewal.cast_signed()),
                            node_id: node_id as u64,
                            status: if last_renewal_since_now > DEAD_NODE_TIMEOUT {
                                ClusterNodeStatus::Inactive
                            } else if last_renewal_since_now > STALE_NODE_TIMEOUT {
                                ClusterNodeStatus::Stale
                            } else {
                                ClusterNodeStatus::Active
                            },
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .map(|_| results)
    }

    pub async fn refresh_node_id_lease(&self) -> trc::Result<()> {
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::NodeId(self.0.node_id),
            KeySerializer::new(self.0.env_hostname.len() + U64_LEN)
                .write(now())
                .write(&self.0.env_hostname)
                .finalize(),
        );
        self.0
            .store
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())
            .map(|_| ())
    }

    #[inline(always)]
    pub fn recovery_admin(&self) -> Option<&(String, String)> {
        self.0.env_recovery_admin.as_ref()
    }

    #[inline(always)]
    pub fn cluster_role(&self) -> Option<&str> {
        self.0.env_cluster_role.as_deref()
    }

    #[inline(always)]
    pub fn cluster_push_shard(&self) -> u32 {
        self.0.env_push_shard_id
    }

    #[inline(always)]
    pub fn local_hostname(&self) -> &str {
        &self.0.env_hostname
    }

    #[inline(always)]
    pub fn public_url(&self) -> Option<&str> {
        self.0.env_public_url.as_deref()
    }

    #[inline(always)]
    pub fn is_recovery_mode(&self) -> bool {
        self.0.env_recovery_mode
    }

    #[inline(always)]
    pub fn is_bootstrap_mode(&self) -> bool {
        self.0.store.is_ephemeral()
    }

    #[inline(always)]
    pub fn path(&self) -> &PathBuf {
        &self.0.local_path
    }

    #[inline(always)]
    pub fn store(&self) -> &Store {
        &self.0.store
    }

    pub fn initialize_inner(&self, store: Store) -> RegistryStoreInner {
        let mut inner = self.0.as_ref().clone();
        inner.store = store;
        inner
    }

    #[cfg(feature = "test_mode")]
    pub fn clone_with_public_url(&self, url: String) -> Self {
        let mut inner = self.0.as_ref().clone();
        inner.env_public_url = Some(url);
        Self(inner.into())
    }

    #[cfg(feature = "test_mode")]
    pub async fn new(
        path: &str,
        store: Store,
        hostname: String,
        push_shard_id: u32,
        cluster_role: Option<String>,
    ) -> Self {
        Self::from_inner(RegistryStoreInner {
            local_path: PathBuf::from(path),
            store,
            node_id: 0,
            env_recovery_mode: false,
            env_recovery_admin: Some(("admin".to_string(), "popolna_zapora".to_string())),
            env_cluster_role: cluster_role,
            env_push_shard_id: push_shard_id,
            env_hostname: hostname,
            env_public_url: None,
            id_generator: utils::snowflake::SnowflakeIdGenerator::new(),
        })
        .await
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SUBSPACE_REGISTRY_PK, write::AnyKey};

    async fn registry_records(store: &Store) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut records = Vec::new();
        store
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace: SUBSPACE_REGISTRY_PK,
                        key: vec![0],
                    },
                    AnyKey {
                        subspace: SUBSPACE_REGISTRY_PK,
                        key: vec![u8::MAX; 32],
                    },
                ),
                |key, value| {
                    records.push((key.to_vec(), value.to_vec()));
                    Ok(true)
                },
            )
            .await
            .unwrap();
        records
    }

    fn test_inner() -> RegistryStoreInner {
        let mut inner = RegistryStoreInner::new(PathBuf::from("unused-test-config"));
        inner.store = EphemeralStore::open();
        inner.env_hostname = "test-host".to_string();
        inner
    }

    #[tokio::test]
    async fn import_mode_leaves_empty_registry_primary_key_subspace_empty() {
        let inner = test_inner();
        let registry = RegistryStore::from_inner_with_mode(inner, true)
            .await
            .unwrap();
        assert!(registry_records(registry.store()).await.is_empty());
    }

    #[tokio::test]
    async fn import_mode_preserves_existing_registry_primary_key_entries() {
        let inner = test_inner();
        let store = inner.store.clone();
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::NodeId(7),
            KeySerializer::new(8 + "existing-host".len())
                .write(1234u64)
                .write("existing-host")
                .finalize(),
        );
        store.write(batch.build_all()).await.unwrap();
        let before = registry_records(&store).await;

        let registry = RegistryStore::from_inner_with_mode(inner, true)
            .await
            .unwrap();
        assert_eq!(registry_records(registry.store()).await, before);
    }

    #[tokio::test]
    async fn normal_mode_creates_and_refreshes_node_lease() {
        let inner = test_inner();
        let registry = RegistryStore::from_inner_with_mode(inner, false)
            .await
            .unwrap();
        let before = registry_records(registry.store()).await;
        assert_eq!(before.len(), 1);
        assert!(before[0].1.ends_with(b"test-host"));

        registry.refresh_node_id_lease().await.unwrap();
        let after = registry_records(registry.store()).await;
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].0, before[0].0);
        assert!(after[0].1.ends_with(b"test-host"));
        let renewal = |value: &[u8]| u64::from_be_bytes(value[..U64_LEN].try_into().unwrap());
        assert!(renewal(&after[0].1) >= renewal(&before[0].1));
    }
}
