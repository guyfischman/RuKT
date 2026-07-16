// Start src/db.rs
use anyhow::{Context, Result};
use rocksdb::{ColumnFamilyDescriptor, DB, IngestExternalFileOptions, Options, SstFileWriter};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuditorTreeHead {
    pub tree_size: u64,
    pub timestamp: i64,
    pub signature: Vec<u8>,
    pub root_value: Vec<u8>,
    pub consistency: Vec<Vec<u8>>,
}

pub trait TransparencyStore: Send + Sync {
    fn get_log(&self, key: u64) -> Result<Option<Vec<u8>>>;
    fn put_log_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()>;

    fn get_prefix(&self, key: u64) -> Result<Option<Vec<u8>>>;
    fn put_prefix(&self, key: u64, val: Vec<u8>) -> Result<()>;
    fn put_prefix_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()>;
    fn batch_get_prefix(&self, keys: &[u64]) -> Result<Vec<(u64, Vec<u8>)>>;

    fn get_value(&self, key: u64) -> Result<Option<Vec<u8>>>;
    fn put_value(&self, key: u64, val: Vec<u8>) -> Result<()>;
    fn put_value_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()>;
    fn delete_value(&self, key: u64) -> Result<()>;

    fn get_opening(&self, key: u64) -> Result<Option<Vec<u8>>>;
    fn put_opening(&self, key: u64, opening: Vec<u8>) -> Result<()>;
    fn put_opening_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()>;
    fn delete_opening(&self, key: u64) -> Result<()>;

    fn get_head(&self) -> Result<Option<Vec<u8>>>;
    fn set_head(&self, data: Vec<u8>) -> Result<()>;

    fn get_label_history(&self, label: &[u8]) -> Result<Vec<(u32, u64)>>;
    fn append_label_history(&self, label: &[u8], version: u32, pos: u64) -> Result<()>;
    fn put_history_batch(&self, entries: Vec<(Vec<u8>, u32, u64)>) -> Result<()>;

    fn get_audit_blob(&self, log_index: u64) -> Result<Option<Vec<u8>>>;
    fn put_audit_blob(&self, log_index: u64, data: Vec<u8>) -> Result<()>;
}

pub struct RocksDbStore {
    db: Arc<DB>,
    path: PathBuf,
}

impl RocksDbStore {
    const CF_LOG: &'static str = "log";
    const CF_PREFIX: &'static str = "prefix";
    const CF_META: &'static str = "meta";
    const CF_VALUE: &'static str = "value";
    const CF_HISTORY: &'static str = "history";
    const CF_AUDIT: &'static str = "audit";
    const CF_OPENINGS: &'static str = "openings";

    pub fn new(path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // === HIGH PERFORMANCE TUNING FOR BENCHMARKS ===
        opts.increase_parallelism(8);
        opts.set_max_background_jobs(6);
        opts.set_write_buffer_size(128 * 1024 * 1024); // 128MB MemTable
        opts.set_max_write_buffer_number(4);
        opts.set_bytes_per_sync(1048576 * 2); // 2MB

        let cfs = vec![
            ColumnFamilyDescriptor::new(Self::CF_LOG, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_PREFIX, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_META, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_VALUE, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_HISTORY, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_AUDIT, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_OPENINGS, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs).context("Failed to open RocksDB")?;

        Ok(Self {
            db: Arc::new(db),
            path: PathBuf::from(path),
        })
    }

    /// Returns the filesystem path of this database.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create a RocksDB checkpoint (hard-link snapshot) at the given path.
    pub fn checkpoint(&self, dest: &str) -> Result<()> {
        let cp = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .context("Failed to create checkpoint object")?;
        cp.create_checkpoint(dest)
            .context("Failed to create checkpoint")?;
        Ok(())
    }

    /// Bulk-load sorted entries into a column family via SST file ingestion.
    /// Entries must be sorted by key in ascending order.
    /// This bypasses the WAL and memtable for maximum write throughput.
    pub fn ingest_sst(&self, cf_name: &str, sorted_entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<()> {
        if sorted_entries.is_empty() {
            return Ok(());
        }

        let sst_path = self.path.join(format!("_bulk_{}.sst", cf_name));
        let sst_str = sst_path.to_str().unwrap();

        let env_opts = Options::default();
        let mut writer = SstFileWriter::create(&env_opts);
        writer.open(sst_str).context("Failed to open SST writer")?;

        for (key, value) in &sorted_entries {
            writer.put(key, value).context("SST put failed")?;
        }
        writer.finish().context("SST finish failed")?;

        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown column family: {}", cf_name))?;
        let mut opts = IngestExternalFileOptions::default();
        opts.set_move_files(true);
        self.db
            .ingest_external_file_cf_opts(cf, &opts, vec![sst_str])
            .context("SST ingest failed")?;

        Ok(())
    }

    /// Column family name constants for use with ingest_sst.
    pub const fn cf_prefix() -> &'static str {
        Self::CF_PREFIX
    }
    pub const fn cf_value() -> &'static str {
        Self::CF_VALUE
    }
    pub const fn cf_history() -> &'static str {
        Self::CF_HISTORY
    }
    pub const fn cf_openings() -> &'static str {
        Self::CF_OPENINGS
    }
    pub const fn cf_log() -> &'static str {
        Self::CF_LOG
    }
    pub const fn cf_audit() -> &'static str {
        Self::CF_AUDIT
    }
    pub const fn cf_meta() -> &'static str {
        Self::CF_META
    }
}

impl TransparencyStore for RocksDbStore {
    fn get_log(&self, key: u64) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_LOG).unwrap();
        Ok(self.db.get_cf(cf, key.to_be_bytes())?)
    }

    fn put_log_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_LOG).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in entries {
            batch.put_cf(cf, k.to_be_bytes(), v);
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn get_prefix(&self, key: u64) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_PREFIX).unwrap();
        Ok(self.db.get_cf(cf, key.to_be_bytes())?)
    }

    fn put_prefix(&self, key: u64, val: Vec<u8>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_PREFIX).unwrap();
        self.db.put_cf(cf, key.to_be_bytes(), val)?;
        Ok(())
    }

    fn put_prefix_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_PREFIX).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in entries {
            batch.put_cf(cf, k.to_be_bytes(), v);
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn batch_get_prefix(&self, keys: &[u64]) -> Result<Vec<(u64, Vec<u8>)>> {
        let cf = self.db.cf_handle(Self::CF_PREFIX).unwrap();
        let keys_bytes: Vec<_> = keys.iter().map(|k| k.to_be_bytes()).collect();
        let results = self.db.multi_get_cf(keys_bytes.iter().map(|k| (cf, k)));
        let mut out = Vec::new();
        for (i, res) in results.into_iter().enumerate() {
            if let Ok(Some(val)) = res {
                out.push((keys[i], val));
            }
        }
        Ok(out)
    }

    fn get_value(&self, key: u64) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_VALUE).unwrap();
        Ok(self.db.get_cf(cf, key.to_be_bytes())?)
    }

    fn put_value(&self, key: u64, val: Vec<u8>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_VALUE).unwrap();
        self.db.put_cf(cf, key.to_be_bytes(), val)?;
        Ok(())
    }

    fn put_value_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_VALUE).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in entries {
            batch.put_cf(cf, k.to_be_bytes(), v);
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn delete_value(&self, key: u64) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_VALUE).unwrap();
        self.db.delete_cf(cf, key.to_be_bytes())?;
        Ok(())
    }

    fn get_opening(&self, key: u64) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_OPENINGS).unwrap();
        Ok(self.db.get_cf(cf, key.to_be_bytes())?)
    }

    fn put_opening(&self, key: u64, opening: Vec<u8>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_OPENINGS).unwrap();
        self.db.put_cf(cf, key.to_be_bytes(), opening)?;
        Ok(())
    }

    fn put_opening_batch(&self, entries: Vec<(u64, Vec<u8>)>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_OPENINGS).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        for (k, v) in entries {
            batch.put_cf(cf, k.to_be_bytes(), v);
        }
        self.db.write(batch)?;
        Ok(())
    }

    fn delete_opening(&self, key: u64) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_OPENINGS).unwrap();
        self.db.delete_cf(cf, key.to_be_bytes())?;
        Ok(())
    }

    fn get_head(&self) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_META).unwrap();
        Ok(self.db.get_cf(cf, b"head")?)
    }

    fn set_head(&self, data: Vec<u8>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_META).unwrap();
        self.db.put_cf(cf, b"head", data)?;
        Ok(())
    }

    fn get_label_history(&self, label: &[u8]) -> Result<Vec<(u32, u64)>> {
        let cf = self.db.cf_handle(Self::CF_HISTORY).unwrap();
        if let Some(bytes) = self.db.get_cf(cf, label)? {
            let mut out = Vec::new();
            let mut cursor = 0;
            while cursor + 12 <= bytes.len() {
                let ver = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into()?);
                let pos = u64::from_be_bytes(bytes[cursor + 4..cursor + 12].try_into()?);
                out.push((ver, pos));
                cursor += 12;
            }
            Ok(out)
        } else {
            Ok(Vec::new())
        }
    }

    fn append_label_history(&self, label: &[u8], version: u32, pos: u64) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_HISTORY).unwrap();
        let mut history = self.get_label_history(label)?;
        history.push((version, pos));

        let mut bytes = Vec::with_capacity(history.len() * 12);
        for (v, p) in history {
            bytes.extend_from_slice(&v.to_be_bytes());
            bytes.extend_from_slice(&p.to_be_bytes());
        }
        self.db.put_cf(cf, label, bytes)?;
        Ok(())
    }

    fn put_history_batch(&self, entries: Vec<(Vec<u8>, u32, u64)>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_HISTORY).unwrap();
        let mut batch = rocksdb::WriteBatch::default();
        let mut cache: HashMap<Vec<u8>, Vec<(u32, u64)>> = HashMap::new();

        for (label, ver, pos) in entries {
            let history = if let Some(h) = cache.get_mut(&label) {
                h
            } else {
                let h = self.get_label_history(&label)?;
                cache.insert(label.clone(), h);
                cache.get_mut(&label).unwrap()
            };
            history.push((ver, pos));
        }

        for (label, history) in cache {
            let mut bytes = Vec::with_capacity(history.len() * 12);
            for (v, p) in history {
                bytes.extend_from_slice(&v.to_be_bytes());
                bytes.extend_from_slice(&p.to_be_bytes());
            }
            batch.put_cf(cf, label, bytes);
        }

        self.db.write(batch)?;
        Ok(())
    }

    fn get_audit_blob(&self, log_index: u64) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_AUDIT).unwrap();
        Ok(self.db.get_cf(cf, log_index.to_be_bytes())?)
    }

    fn put_audit_blob(&self, log_index: u64, data: Vec<u8>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_AUDIT).unwrap();
        self.db.put_cf(cf, log_index.to_be_bytes(), data)?;
        Ok(())
    }
}
// End src/db.rs
