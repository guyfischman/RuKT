use anyhow::{Result, Context};
use rocksdb::{DB, Options, ColumnFamilyDescriptor};
use std::sync::Arc;
use crate::proto::transparency;

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

    fn get_opening(&self, key: u64) -> Result<Option<Vec<u8>>>;
    fn put_opening(&self, key: u64, opening: Vec<u8>) -> Result<()>;
    fn delete_opening(&self, key: u64) -> Result<()>;

    fn get_head(&self) -> Result<Option<Vec<u8>>>;
    fn set_head(&self, data: Vec<u8>) -> Result<()>;

    fn get_label_history(&self, label: &[u8]) -> Result<Vec<(u32, u64)>>;
    fn append_label_history(&self, label: &[u8], version: u32, pos: u64) -> Result<()>;

    fn get_audit_blob(&self, log_index: u64) -> Result<Option<Vec<u8>>>;
    fn put_audit_blob(&self, log_index: u64, data: Vec<u8>) -> Result<()>;
}

pub struct RocksDbStore {
    db: Arc<DB>,
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

        let cfs = vec![
            ColumnFamilyDescriptor::new(Self::CF_LOG, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_PREFIX, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_META, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_VALUE, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_HISTORY, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_AUDIT, Options::default()),
            ColumnFamilyDescriptor::new(Self::CF_OPENINGS, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .context("Failed to open RocksDB")?;

        Ok(Self { db: Arc::new(db) })
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

    fn get_opening(&self, key: u64) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(Self::CF_OPENINGS).unwrap();
        Ok(self.db.get_cf(cf, key.to_be_bytes())?)
    }

    fn put_opening(&self, key: u64, opening: Vec<u8>) -> Result<()> {
        let cf = self.db.cf_handle(Self::CF_OPENINGS).unwrap();
        self.db.put_cf(cf, key.to_be_bytes(), opening)?;
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
                let ver = u32::from_be_bytes(bytes[cursor..cursor+4].try_into()?);
                let pos = u64::from_be_bytes(bytes[cursor+4..cursor+12].try_into()?);
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