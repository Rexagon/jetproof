use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytesize::ByteSize;
use everscale_types::cell::HashBytes;
use everscale_types::models::StdAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub cache_capacity: ByteSize,
}

pub struct Storage {
    db: Arc<rocksdb::DB>,
    snapshot: OwnedSnapshot,
    #[allow(unused)]
    block_cache: rocksdb::Cache,
    version: u32,
    start_from: u64,
    expire_at: u64,
    root_hash: HashBytes,
}

impl Storage {
    pub fn new(config: StorageConfig) -> Result<Self> {
        let block_cache = rocksdb::Cache::new_lru_cache(std::cmp::max(
            config.cache_capacity.as_u64() as usize,
            MIN_CACHE_CAPACITY,
        ));

        let db = {
            let mut options = rocksdb::Options::default();

            options.set_level_compaction_dynamic_level_bytes(true);

            options.set_log_level(rocksdb::LogLevel::Error);
            options.set_keep_log_file_num(2);
            options.set_recycle_log_file_num(2);

            let mut block_factory = rocksdb::BlockBasedOptions::default();
            block_factory.set_block_cache(&block_cache);
            block_factory.set_data_block_index_type(rocksdb::DataBlockIndexType::BinaryAndHash);

            rocksdb::DB::open_cf_for_read_only(&options, config.path, &["default"], true)
                .map(Arc::new)
                .context("failed to open RocksDB")?
        };

        let version;
        let start_from;
        let expire_at;
        let root_hash;
        {
            let Some(value) = db.get([0])? else {
                anyhow::bail!("general info not found");
            };
            anyhow::ensure!(
                value.len() == (4 + 8 + 8 + 32),
                "invalid value for general info"
            );

            version = u32::from_le_bytes(value[..4].try_into().unwrap());
            anyhow::ensure!(version == 0, "invalid version for general info");

            start_from = u64::from_le_bytes(value[4..12].try_into().unwrap());
            expire_at = u64::from_le_bytes(value[12..20].try_into().unwrap());
            root_hash = HashBytes::from_slice(&value[20..]);
        }

        let snapshot = OwnedSnapshot::new(db.clone());

        Ok(Self {
            db,
            snapshot,
            block_cache,
            version,
            start_from,
            expire_at,
            root_hash,
        })
    }

    pub fn count_addresses(&self) -> Result<u64> {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_snapshot(&self.snapshot);

        let mut iterator = self.db.raw_iterator_opt(readopts);
        iterator.seek([0u8; 33]);

        let mut result = 0;
        while iterator.key().is_some() {
            result += 1;
            iterator.next();
        }

        iterator.status()?;

        Ok(result)
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn start_from(&self) -> u64 {
        self.start_from
    }

    pub fn expire_at(&self) -> u64 {
        self.expire_at
    }

    pub fn root_hash(&self) -> &HashBytes {
        &self.root_hash
    }

    pub fn get_proof(&self, address: &StdAddr) -> Option<UserProof<rocksdb::DBPinnableSlice<'_>>> {
        let mut key = [0u8; 33];
        key[0] = address.workchain as u8;
        key[1..].copy_from_slice(address.address.as_array());

        self.db.get_pinned(key).unwrap().map(UserProof)
    }

    pub fn get_proofs(&self, from: &StdAddr) -> UserProofsIterBuilder<'_> {
        let mut readopts = rocksdb::ReadOptions::default();
        readopts.set_snapshot(&self.snapshot);

        let mut key = [0u8; 33];
        key[0] = from.workchain as u8;
        key[1..].copy_from_slice(from.address.as_array());

        let mut iterator = self.db.raw_iterator_opt(readopts);
        iterator.seek(key);

        UserProofsIterBuilder { inner: iterator }
    }
}

pub struct UserProof<T>(T);

impl<T> UserProof<T>
where
    T: AsRef<[u8]>,
{
    pub fn read(&self) -> (u128, &'_ str) {
        let data = self.0.as_ref();
        let (amount_bytes, proof_str) = data.split_first_chunk::<16>().unwrap();
        let amount = u128::from_le_bytes(*amount_bytes);
        let proof_boc = unsafe { std::str::from_utf8_unchecked(proof_str) };
        (amount, proof_boc)
    }
}

pub struct UserProofsIterBuilder<'a> {
    inner: rocksdb::DBRawIterator<'a>,
}

impl<'a> UserProofsIterBuilder<'a> {
    pub fn is_valid(&self) -> bool {
        self.inner.valid()
    }

    pub fn map<F, R>(self, map: F) -> UserProofsIter<'a, F>
    where
        for<'s> F: FnMut(StdAddr, UserProof<&'s [u8]>) -> R,
    {
        UserProofsIter {
            inner: self.inner,
            map,
        }
    }
}

pub struct UserProofsIter<'a, F> {
    inner: rocksdb::DBRawIterator<'a>,
    map: F,
}

impl<F> UserProofsIter<'_, F> {
    pub fn into_next_from(self) -> Option<StdAddr> {
        self.inner
            .key()
            .map(|key| StdAddr::new(key[0] as i8, HashBytes::from_slice(&key[1..])))
    }
}

impl<F, R> Iterator for UserProofsIter<'_, F>
where
    for<'s> F: FnMut(StdAddr, UserProof<&'s [u8]>) -> R,
{
    type Item = R;

    fn next(&mut self) -> Option<Self::Item> {
        let (key, value) = self.inner.item()?;
        let address = StdAddr::new(key[0] as i8, HashBytes::from_slice(&key[1..]));

        let result = Some((self.map)(address, UserProof(value)));
        self.inner.next();
        result
    }
}

/// RocksDB snapshot bounded to a [`rocksdb::DB`] instance.
pub struct OwnedSnapshot {
    inner: rocksdb::Snapshot<'static>,
    _db: Arc<rocksdb::DB>,
}

impl OwnedSnapshot {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        use rocksdb::Snapshot;

        unsafe fn extend_lifetime<'a>(r: Snapshot<'a>) -> Snapshot<'static> {
            std::mem::transmute::<Snapshot<'a>, Snapshot<'static>>(r)
        }

        // SAFETY: `Snapshot` requires the same lifetime as `rocksdb::DB` but
        // `tokio::task::spawn` requires 'static. This object ensures
        // that `rocksdb::DB` object lifetime will exceed the lifetime of the snapshot
        let inner = unsafe { extend_lifetime(db.as_ref().snapshot()) };
        Self { inner, _db: db }
    }
}

impl std::ops::Deref for OwnedSnapshot {
    type Target = rocksdb::Snapshot<'static>;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

const MIN_CACHE_CAPACITY: usize = 64 * 1024 * 1024; // 64 MB
