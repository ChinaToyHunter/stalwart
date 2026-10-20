/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::backup::{Family, MAGIC_MARKER, MAX_RECORD_LEN};
use crate::DATABASE_SCHEMA_VERSION;
use lz4_flex::frame::FrameDecoder;
use registry::schema::enums::CompressionAlgo;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::File,
    io::{BufReader, ErrorKind, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use store::{
    BlobStore, IterateParams, LEGACY_SUBSPACE_BITMAP_TAG, LEGACY_SUBSPACE_BITMAP_TEXT,
    SUBSPACE_ACL, SUBSPACE_BLOB_LINK, SUBSPACE_BLOBS, SUBSPACE_COUNTER, SUBSPACE_DELETED_ITEMS,
    SUBSPACE_DIRECTORY, SUBSPACE_IN_MEMORY_COUNTER, SUBSPACE_IN_MEMORY_VALUE, SUBSPACE_INDEXES,
    SUBSPACE_LOGS, SUBSPACE_PROPERTY, SUBSPACE_QUEUE_EVENT, SUBSPACE_QUEUE_MESSAGE, SUBSPACE_QUOTA,
    SUBSPACE_REGISTRY, SUBSPACE_REGISTRY_IDX, SUBSPACE_REGISTRY_PK, SUBSPACE_REPORT_IN,
    SUBSPACE_REPORT_OUT, SUBSPACE_SEARCH_INDEX, SUBSPACE_SPAM_SAMPLES, SUBSPACE_TASK_QUEUE,
    SUBSPACE_TELEMETRY_METRIC, SUBSPACE_TELEMETRY_SPAN, Store, U32_LEN,
    write::{AnyClass, AnyKey, BatchBuilder, ValueClass, key::DeserializeBigEndian},
};
use types::{blob_hash::BLOB_HASH_LEN, collection::Collection, field::Field};
use utils::failed;

/// Every subspace holding persistent state, including those a backup does not
/// export: any entry means the target is not a fresh installation.
const TARGET_SUBSPACES: [u8; 26] = [
    SUBSPACE_ACL,
    SUBSPACE_INDEXES,
    SUBSPACE_QUOTA,
    SUBSPACE_COUNTER,
    SUBSPACE_PROPERTY,
    SUBSPACE_BLOBS,
    SUBSPACE_BLOB_LINK,
    SUBSPACE_REGISTRY,
    SUBSPACE_REGISTRY_IDX,
    SUBSPACE_REGISTRY_PK,
    SUBSPACE_DIRECTORY,
    SUBSPACE_LOGS,
    SUBSPACE_QUEUE_MESSAGE,
    SUBSPACE_QUEUE_EVENT,
    SUBSPACE_REPORT_OUT,
    SUBSPACE_REPORT_IN,
    SUBSPACE_TELEMETRY_SPAN,
    SUBSPACE_TELEMETRY_METRIC,
    SUBSPACE_TASK_QUEUE,
    SUBSPACE_DELETED_ITEMS,
    SUBSPACE_SPAM_SAMPLES,
    SUBSPACE_IN_MEMORY_VALUE,
    SUBSPACE_IN_MEMORY_COUNTER,
    SUBSPACE_SEARCH_INDEX,
    LEGACY_SUBSPACE_BITMAP_TEXT,
    LEGACY_SUBSPACE_BITMAP_TAG,
];

/// Every key that does not start with this many 0xFF bytes, including the
/// empty key, sorts between `[]` and `[0xFF; TARGET_SCAN_END_LEN]`.
const TARGET_SCAN_END_LEN: usize = 4096;

// LZ4 frame format: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
const LZ4_MAGIC: u32 = 0x184D_2204;
const LZ4_FLG_VERSION_MASK: u8 = 0b1100_0000;
const LZ4_FLG_VERSION: u8 = 0b0100_0000;
const LZ4_FLG_BLOCK_CHECKSUM: u8 = 0b0001_0000;
const LZ4_FLG_CONTENT_SIZE: u8 = 0b0000_1000;
const LZ4_FLG_CONTENT_CHECKSUM: u8 = 0b0000_0100;
const LZ4_FLG_RESERVED: u8 = 0b0000_0010;
const LZ4_FLG_DICT_ID: u8 = 0b0000_0001;
const LZ4_BD_RESERVED: u8 = 0b1000_1111;
const LZ4_BLOCK_UNCOMPRESSED: u32 = 0x8000_0000;

pub async fn restore(store: Store, blob_store: BlobStore, src: PathBuf) {
    if let Err(err) = import_backup(&store, &blob_store, &src).await {
        failed(&format!("Import failed: {err}"));
    }
}

/// Imports a backup written by `Core::backup` into a fresh data store.
///
/// Nothing is written until the target is known to be empty and every dump has
/// been read in full: the directory must hold exactly one regular
/// `subspace_<id>` file per exported subspace, each one a complete LZ4 frame
/// with a content checksum, holding well-formed records in strictly increasing
/// key order, and the exported blobs must match the exported blob links.
/// A failure during the write pass can still leave partial state, so retry only
/// against a new, empty target. Dumps are read again for the write pass and
/// must not change while an import runs.
async fn import_backup(store: &Store, blob_store: &BlobStore, src: &Path) -> Result<(), String> {
    ensure_blobs_in_data_store(store, blob_store)?;
    ensure_target_empty(store).await?;
    for dump in validate_backup(src)? {
        println!("Importing database dump from {}.", dump.path.display());
        let path = dump.path.display().to_string();
        write_dump(store, blob_store, dump)
            .await
            .map_err(|err| format!("{path}: {err}"))?;
    }
    Ok(())
}

fn ensure_blobs_in_data_store(store: &Store, blob_store: &BlobStore) -> Result<(), String> {
    match blob_store {
        BlobStore::Store(blob_data) if blob_data.is_same(store) => Ok(()),
        _ => Err(
            "blobs must be kept in the data store: a separate blob store cannot be \
             verified to be empty"
                .to_string(),
        ),
    }
}

async fn ensure_target_empty(store: &Store) -> Result<(), String> {
    for subspace in TARGET_SUBSPACES {
        // SQL backends have no tables for the legacy bitmap subspaces.
        if store.is_sql()
            && matches!(
                subspace,
                LEGACY_SUBSPACE_BITMAP_TEXT | LEGACY_SUBSPACE_BITMAP_TAG
            )
        {
            continue;
        }

        let mut has_data = false;
        store
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: Vec::new(),
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; TARGET_SCAN_END_LEN],
                    },
                )
                .no_values(),
                |_, _| {
                    has_data = true;
                    Ok(false)
                },
            )
            .await
            .map_err(|err| format!("failed to inspect target database: {err}"))?;
        if has_data {
            return Err(format!(
                "target database is not empty (subspace {:?})",
                char::from(subspace)
            ));
        }
    }
    Ok(())
}

struct ValidatedDump {
    path: PathBuf,
    file: File,
    len: u64,
    subspace: u8,
    records: u64,
}

#[derive(Default)]
struct BlobReferences {
    stored: HashSet<Vec<u8>>,
    linked: HashSet<Vec<u8>>,
}

fn validate_backup(src: &Path) -> Result<Vec<ValidatedDump>, String> {
    let entries = std::fs::read_dir(src)
        .map_err(|err| format!("failed to read backup directory {}: {err}", src.display()))?;
    let mut dumps = BTreeMap::new();
    let mut blobs = BlobReferences::default();
    for entry in entries {
        let entry = entry
            .map_err(|err| format!("failed to read backup directory {}: {err}", src.display()))?;
        let path = entry.path();
        let is_file = entry
            .file_type()
            .map_err(|err| format!("{}: {err}", path.display()))?
            .is_file();
        if !is_file {
            return Err(format!(
                "{}: backup entries must be regular files",
                path.display()
            ));
        }

        let dump = validate_dump(path, &mut blobs)?;
        if let Some(previous) = dumps.insert(dump.subspace, dump) {
            return Err(format!(
                "{}: duplicate subspace dump",
                previous.path.display()
            ));
        }
    }

    let expected = Family::ALL
        .iter()
        .flat_map(|family| family.subspaces())
        .copied()
        .collect::<BTreeSet<_>>();
    let found = dumps.keys().copied().collect::<BTreeSet<_>>();
    if found != expected {
        let names = |subspaces: std::collections::btree_set::Difference<'_, u8>| {
            subspaces
                .map(|subspace| char::from(*subspace))
                .collect::<String>()
        };
        return Err(format!(
            "backup must contain exactly one dump per exported subspace \
             (missing {:?}, unexpected {:?})",
            names(expected.difference(&found)),
            names(found.difference(&expected))
        ));
    }
    if blobs.stored != blobs.linked {
        return Err(format!(
            "backup blobs do not match blob links ({} linked blobs missing, {} blobs without links)",
            blobs.linked.difference(&blobs.stored).count(),
            blobs.stored.difference(&blobs.linked).count()
        ));
    }

    Ok(dumps.into_values().collect())
}

fn validate_dump(path: PathBuf, blobs: &mut BlobReferences) -> Result<ValidatedDump, String> {
    match read_dump(&path, blobs) {
        Ok((file, len, subspace, records)) => Ok(ValidatedDump {
            path,
            file,
            len,
            subspace,
            records,
        }),
        Err(err) => Err(format!("{}: {err}", path.display())),
    }
}

fn read_dump(path: &Path, blobs: &mut BlobReferences) -> Result<(File, u64, u8, u64), String> {
    let mut file = File::open(path).map_err(|err| format!("failed to open dump: {err}"))?;
    let len = verify_lz4_frame(&mut file)?;
    let mut reader = DumpReader::open(file)?;
    let subspace = reader.subspace;
    let expected_name = format!("subspace_{}", char::from(subspace));
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
        return Err("file name does not match the subspace it contains".to_string());
    }

    let mut records = 0u64;
    let mut last_key: Option<Vec<u8>> = None;
    while let Some((key, value)) = reader.next_record()? {
        validate_record(subspace, &key, &value)?;
        if last_key.as_ref().is_some_and(|last| key <= *last) {
            return Err("keys are not in strictly increasing order".to_string());
        }
        match subspace {
            SUBSPACE_BLOBS => {
                blobs.stored.insert(key.clone());
            }
            SUBSPACE_BLOB_LINK => {
                blobs.linked.insert(key[..BLOB_HASH_LEN].to_vec());
            }
            _ => {}
        }
        records += 1;
        last_key = Some(key);
    }

    let mut file = reader.finish(len)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|err| format!("failed to rewind dump: {err}"))?;
    Ok((file, len, subspace, records))
}

fn validate_record(subspace: u8, key: &[u8], value: &[u8]) -> Result<(), String> {
    let valid = match subspace {
        SUBSPACE_COUNTER | SUBSPACE_QUOTA => value.len() == size_of::<u64>(),
        SUBSPACE_INDEXES => key.len() >= U32_LEN * 2 + 2,
        SUBSPACE_BLOBS => key.len() == BLOB_HASH_LEN,
        SUBSPACE_BLOB_LINK => key.len() >= BLOB_HASH_LEN,
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "malformed record for subspace {:?}",
            char::from(subspace)
        ))
    }
}

/// lz4_flex treats end-of-file where the next block header belongs as the end
/// of the stream, so a dump cut at a block boundary decodes as a shorter dump
/// without any error. Walk the frame layout first and require the end mark and
/// the content checksum written by `spawn_writer`; the decoder then verifies the
/// checksum. Returns the file length.
fn verify_lz4_frame(file: &mut File) -> Result<u64, String> {
    let len = file
        .metadata()
        .map_err(|err| format!("failed to read dump metadata: {err}"))?
        .len();
    let mut frame = FrameCursor {
        file: &mut *file,
        position: 0,
        len,
    };

    if u32::from_le_bytes(frame.read()?) != LZ4_MAGIC {
        return Err("not an LZ4 frame".to_string());
    }
    let [flags, block_descriptor] = frame.read()?;
    if flags & LZ4_FLG_VERSION_MASK != LZ4_FLG_VERSION
        || flags & (LZ4_FLG_RESERVED | LZ4_FLG_DICT_ID) != 0
        || block_descriptor & LZ4_BD_RESERVED != 0
    {
        return Err("unsupported LZ4 frame descriptor".to_string());
    }
    if flags & LZ4_FLG_CONTENT_CHECKSUM == 0 {
        return Err(
            "LZ4 frame has no content checksum, it was not written by a verified export"
                .to_string(),
        );
    }
    let max_block_len = match block_descriptor >> 4 {
        id @ 4..=7 => 1u64 << (8 + 2 * u32::from(id)),
        _ => return Err("unsupported LZ4 block size".to_string()),
    };
    // Optional content size, then the header checksum verified by the decoder.
    let content_size_len = if flags & LZ4_FLG_CONTENT_SIZE != 0 {
        8
    } else {
        0
    };
    frame.skip(content_size_len + 1)?;
    let block_checksum_len = if flags & LZ4_FLG_BLOCK_CHECKSUM != 0 {
        4
    } else {
        0
    };

    loop {
        if frame.position == frame.len {
            return Err("truncated dump: LZ4 end mark is missing".to_string());
        }
        let block = u32::from_le_bytes(frame.read()?);
        if block == 0 {
            break;
        }
        let block_len = u64::from(block & !LZ4_BLOCK_UNCOMPRESSED);
        if block_len == 0 || block_len > max_block_len {
            return Err("invalid LZ4 block length".to_string());
        }
        frame.skip(block_len + block_checksum_len)?;
    }
    frame.skip(4)?;
    if frame.position != frame.len {
        return Err("unexpected data after the LZ4 frame".to_string());
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|err| format!("failed to rewind dump: {err}"))?;
    Ok(len)
}

struct FrameCursor<'x> {
    file: &'x mut File,
    position: u64,
    len: u64,
}

impl FrameCursor<'_> {
    fn read<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.ensure(N as u64)?;
        let mut bytes = [0u8; N];
        self.file
            .read_exact(&mut bytes)
            .map_err(|err| format!("failed to read dump: {err}"))?;
        self.position += N as u64;
        Ok(bytes)
    }

    fn skip(&mut self, count: u64) -> Result<(), String> {
        self.ensure(count)?;
        self.file
            .seek(SeekFrom::Current(count as i64))
            .map_err(|err| format!("failed to read dump: {err}"))?;
        self.position += count;
        Ok(())
    }

    fn ensure(&self, count: u64) -> Result<(), String> {
        if self.len - self.position >= count {
            Ok(())
        } else {
            Err("truncated dump".to_string())
        }
    }
}

async fn write_dump(
    store: &Store,
    blob_store: &BlobStore,
    dump: ValidatedDump,
) -> Result<(), String> {
    let mut reader = DumpReader::open(dump.file)?;
    let subspace = reader.subspace;
    let mut batch = BatchBuilder::new();
    let mut records = 0u64;

    while let Some((key, value)) = reader.next_record()? {
        validate_record(subspace, &key, &value)?;
        records += 1;

        match subspace {
            SUBSPACE_BLOBS => {
                blob_store
                    .put_blob(&key, &value, CompressionAlgo::Lz4)
                    .await
                    .map_err(|err| format!("failed to write blob: {err}"))?;
            }
            SUBSPACE_COUNTER | SUBSPACE_QUOTA => {
                let value: [u8; 8] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| "malformed counter value".to_string())?;
                batch.add(
                    ValueClass::Any(AnyClass { subspace, key }),
                    u64::from_le_bytes(value) as i64,
                );
            }
            SUBSPACE_INDEXES => {
                let account_id = key
                    .as_slice()
                    .deserialize_be_u32(0)
                    .map_err(|err| format!("malformed index key: {err}"))?;
                let document_id = key
                    .as_slice()
                    .deserialize_be_u32(key.len() - U32_LEN)
                    .map_err(|err| format!("malformed index key: {err}"))?;
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::from(key[U32_LEN]))
                    .with_document(document_id)
                    .index(
                        Field::new(key[U32_LEN + 1]),
                        key[U32_LEN + 2..key.len() - U32_LEN].to_vec(),
                    );
            }
            _ => {
                batch.set(ValueClass::Any(AnyClass { subspace, key }), value);
            }
        }

        if batch.is_large_batch() {
            store
                .write(batch.build_all())
                .await
                .map_err(|err| format!("failed to write batch: {err}"))?;
            batch = BatchBuilder::new();
        }
    }

    if !batch.is_empty() {
        store
            .write(batch.build_all())
            .await
            .map_err(|err| format!("failed to write batch: {err}"))?;
    }

    reader.finish(dump.len)?;
    if records != dump.records {
        return Err("dump changed while it was being imported".to_string());
    }
    Ok(())
}

struct DumpReader {
    subspace: u8,
    decoder: FrameDecoder<BufReader<File>>,
}

impl DumpReader {
    fn open(file: File) -> Result<Self, String> {
        let mut decoder = FrameDecoder::new(BufReader::new(file));
        let mut header = [0u8; 6];
        decoder
            .read_exact(&mut header)
            .map_err(|err| format!("failed to read dump header: {err}"))?;
        if header[0] != MAGIC_MARKER {
            return Err("invalid magic marker".to_string());
        }
        let version = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
        if version != DATABASE_SCHEMA_VERSION {
            return Err(format!(
                "invalid database schema version: expected {DATABASE_SCHEMA_VERSION}, found {version}"
            ));
        }

        Ok(Self {
            subspace: header[1],
            decoder,
        })
    }

    fn next_record(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
        let Some(first) = self.read_byte()? else {
            return Ok(None);
        };
        let key = self.read_field(first)?;
        let first = self
            .read_byte()?
            .ok_or_else(|| "truncated record".to_string())?;
        let value = self.read_field(first)?;
        Ok(Some((key, value)))
    }

    /// Reads a canonical LEB128 length starting with `byte`, then that many bytes.
    fn read_field(&mut self, mut byte: u8) -> Result<Vec<u8>, String> {
        let mut len = 0usize;
        for shift in [0, 7, 14, 21, 28] {
            if (shift == 28 && byte > 0x0F) || (shift > 0 && byte == 0) {
                return Err("invalid record length encoding".to_string());
            }
            len |= usize::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            byte = self
                .read_byte()?
                .ok_or_else(|| "truncated record".to_string())?;
        }
        if len > MAX_RECORD_LEN {
            return Err("record exceeds the size limit".to_string());
        }

        let mut bytes = vec![0; len];
        self.decoder.read_exact(&mut bytes).map_err(|err| {
            if err.kind() == ErrorKind::UnexpectedEof {
                "truncated record".to_string()
            } else {
                format!("failed to read dump: {err}")
            }
        })?;
        Ok(bytes)
    }

    fn read_byte(&mut self) -> Result<Option<u8>, String> {
        let mut byte = [0u8; 1];
        loop {
            match self.decoder.read(&mut byte) {
                Ok(0) => return Ok(None),
                Ok(_) => return Ok(Some(byte[0])),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                Err(err) => return Err(format!("failed to read dump: {err}")),
            }
        }
    }

    /// Requires the decoder to have consumed the whole file: lz4_flex also
    /// reports end-of-stream after a block that decompresses to nothing.
    fn finish(mut self, len: u64) -> Result<File, String> {
        let position = self
            .decoder
            .get_mut()
            .stream_position()
            .map_err(|err| format!("failed to read dump position: {err}"))?;
        if position != len {
            return Err("records end before the end of the LZ4 frame".to_string());
        }
        Ok(self.decoder.into_inner().into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::backup::spawn_writer, *};
    use lz4_flex::frame::{FrameEncoder, FrameInfo};
    use std::{
        io::Write,
        time::{SystemTime, UNIX_EPOCH},
    };
    use store::backend::ephemeral::EphemeralStore;

    const HASH: [u8; BLOB_HASH_LEN] = [7; BLOB_HASH_LEN];

    type Records = Vec<(Vec<u8>, Vec<u8>)>;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "stalwart-restore-{name}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn dump(&self, subspace: u8) -> PathBuf {
            self.0.join(format!("subspace_{}", char::from(subspace)))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn sample_backup() -> BTreeMap<u8, Records> {
        let mut index = 1u32.to_be_bytes().to_vec();
        index.extend_from_slice(&[0, 1]);
        index.extend_from_slice(b"abc");
        index.extend_from_slice(&7u32.to_be_bytes());
        let mut link = HASH.to_vec();
        link.extend_from_slice(&[1, 2, 3]);
        // Incompressible data spanning several 64 KiB LZ4 blocks.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let blob = (0..300_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect::<Vec<_>>();

        BTreeMap::from([
            (SUBSPACE_PROPERTY, vec![(vec![0], vec![1, 2, 3, 4])]),
            (
                SUBSPACE_ACL,
                vec![
                    (b"acl-a".to_vec(), b"x".to_vec()),
                    (b"acl-b".to_vec(), b"y".to_vec()),
                ],
            ),
            (
                SUBSPACE_COUNTER,
                vec![(b"counter".to_vec(), 42u64.to_le_bytes().to_vec())],
            ),
            (SUBSPACE_INDEXES, vec![(index, Vec::new())]),
            (SUBSPACE_BLOBS, vec![(HASH.to_vec(), blob)]),
            (SUBSPACE_BLOB_LINK, vec![(link, Vec::new())]),
            (SUBSPACE_LOGS, vec![(b"log".to_vec(), b"entry".to_vec())]),
        ])
    }

    fn write_backup(dir: &TempDir, backup: &BTreeMap<u8, Records>) {
        for subspace in Family::ALL
            .iter()
            .flat_map(|family| family.subspaces())
            .copied()
        {
            let (handle, writer) =
                spawn_writer(dir.dump(subspace), subspace, DATABASE_SCHEMA_VERSION);
            for record in backup.get(&subspace).into_iter().flatten() {
                writer.send(record.clone()).unwrap();
            }
            drop(writer);
            handle.join().unwrap();
        }
    }

    fn write_raw_dump(path: &Path, subspace: u8, records: &[u8], info: FrameInfo, finish: bool) {
        let mut encoder = FrameEncoder::with_frame_info(info, Vec::new());
        encoder.write_all(&[MAGIC_MARKER, subspace]).unwrap();
        encoder
            .write_all(&DATABASE_SCHEMA_VERSION.to_le_bytes())
            .unwrap();
        encoder.write_all(records).unwrap();
        let bytes = if finish {
            encoder.finish().unwrap()
        } else {
            encoder.flush().unwrap();
            encoder.into_inner()
        };
        std::fs::write(path, bytes).unwrap();
    }

    /// Offsets of every data block header in a frame without a content size.
    fn block_offsets(frame: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut offset = 7;
        loop {
            let block = u32::from_le_bytes(frame[offset..offset + 4].try_into().unwrap());
            if block == 0 {
                return offsets;
            }
            offsets.push(offset);
            offset += 4 + (block & !LZ4_BLOCK_UNCOMPRESSED) as usize;
        }
    }

    fn assert_rejected(dir: &TempDir, expected: &str) {
        match validate_backup(&dir.0) {
            Ok(_) => panic!("backup was accepted, expected an error containing {expected:?}"),
            Err(err) => assert!(err.contains(expected), "unexpected error: {err}"),
        }
    }

    async fn subspace_records(store: &Store, subspace: u8) -> Records {
        let mut records = Vec::new();
        store
            .iterate(
                IterateParams::new(
                    AnyKey {
                        subspace,
                        key: Vec::new(),
                    },
                    AnyKey {
                        subspace,
                        key: vec![u8::MAX; TARGET_SCAN_END_LEN],
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

    async fn store_with(subspace: u8, key: Vec<u8>) -> Store {
        let store = EphemeralStore::open();
        let mut batch = BatchBuilder::new();
        batch.set(
            ValueClass::Any(AnyClass { subspace, key }),
            b"stale".to_vec(),
        );
        store.write(batch.build_all()).await.unwrap();
        store
    }

    #[tokio::test]
    async fn exported_backup_round_trips_into_empty_target() {
        let dir = TempDir::new("round-trip");
        let backup = sample_backup();
        write_backup(&dir, &backup);

        let store = EphemeralStore::open();
        let blob_store = BlobStore::Store(store.clone());
        import_backup(&store, &blob_store, &dir.0).await.unwrap();

        for subspace in [
            SUBSPACE_PROPERTY,
            SUBSPACE_ACL,
            SUBSPACE_LOGS,
            SUBSPACE_BLOB_LINK,
        ] {
            assert_eq!(subspace_records(&store, subspace).await, backup[&subspace]);
        }
        let index_keys = subspace_records(&store, SUBSPACE_INDEXES)
            .await
            .into_iter()
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        assert_eq!(index_keys, vec![backup[&SUBSPACE_INDEXES][0].0.clone()]);
        let counter = store
            .get_counter(ValueClass::Any(AnyClass {
                subspace: SUBSPACE_COUNTER,
                key: b"counter".to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(counter, 42);
        let blob = blob_store.get_blob(&HASH, 0..usize::MAX).await.unwrap();
        assert_eq!(
            blob.as_deref(),
            Some(backup[&SUBSPACE_BLOBS][0].1.as_slice())
        );
    }

    #[tokio::test]
    async fn non_empty_target_is_rejected_before_any_write() {
        let dir = TempDir::new("non-empty");
        write_backup(&dir, &sample_backup());
        // An empty key sorts below the `[0]` lower bound this check used before.
        let store = store_with(SUBSPACE_TASK_QUEUE, Vec::new()).await;

        let err = import_backup(&store, &BlobStore::Store(store.clone()), &dir.0)
            .await
            .unwrap_err();
        assert!(err.contains("target database is not empty"), "{err}");
        assert!(subspace_records(&store, SUBSPACE_ACL).await.is_empty());
    }

    #[tokio::test]
    async fn target_scan_covers_empty_and_long_keys() {
        assert!(ensure_target_empty(&EphemeralStore::open()).await.is_ok());
        for key in [Vec::new(), vec![u8::MAX; 64]] {
            let store = store_with(SUBSPACE_LOGS, key).await;
            assert!(ensure_target_empty(&store).await.is_err());
        }
    }

    #[test]
    fn separate_blob_store_is_rejected() {
        let store = EphemeralStore::open();
        assert!(ensure_blobs_in_data_store(&store, &BlobStore::Store(store.clone())).is_ok());
        assert!(
            ensure_blobs_in_data_store(&store, &BlobStore::Store(EphemeralStore::open())).is_err()
        );
    }

    #[test]
    fn dump_cut_between_records_at_block_boundary_is_rejected() {
        let dir = TempDir::new("block-boundary");
        let mut backup = sample_backup();
        // Header (6) + record framing (1 + 1 + 3) + value fill the first 64 KiB block.
        backup.insert(
            SUBSPACE_ACL,
            vec![
                (b"a".to_vec(), vec![0x5A; 65_525]),
                (b"b".to_vec(), b"lost".to_vec()),
            ],
        );
        write_backup(&dir, &backup);
        let path = dir.dump(SUBSPACE_ACL);
        let bytes = std::fs::read(&path).unwrap();
        let blocks = block_offsets(&bytes);
        assert_eq!(blocks.len(), 2);
        std::fs::write(&path, &bytes[..blocks[1]]).unwrap();

        // Without the frame check, the shortened dump reads as one clean record.
        let mut reader = DumpReader::open(File::open(&path).unwrap()).unwrap();
        assert!(reader.next_record().unwrap().is_some());
        assert!(reader.next_record().unwrap().is_none());

        assert_rejected(&dir, "end mark is missing");
    }

    #[test]
    fn truncated_or_corrupted_dumps_are_rejected() {
        let dir = TempDir::new("end-mark");
        write_backup(&dir, &sample_backup());
        let path = dir.dump(SUBSPACE_BLOBS);
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 8]).unwrap();
        assert_rejected(&dir, "end mark is missing");

        std::fs::write(&path, &bytes[..bytes.len() - 100]).unwrap();
        assert_rejected(&dir, "truncated dump");

        let mut corrupted = bytes.clone();
        corrupted[block_offsets(&bytes)[0] + 4 + 1_000] ^= 0x01;
        std::fs::write(&path, corrupted).unwrap();
        assert!(validate_backup(&dir.0).is_err());

        let mut trailing = bytes;
        trailing.push(0);
        std::fs::write(&path, trailing).unwrap();
        assert_rejected(&dir, "unexpected data after the LZ4 frame");
    }

    #[test]
    fn unterminated_dumps_are_rejected() {
        let dir = TempDir::new("unterminated");
        write_backup(&dir, &sample_backup());
        let path = dir.dump(SUBSPACE_LOGS);
        let records = b"\x03log\x05entry";

        // Written the way 0.16.18 exported dumps: no content checksum, no end mark.
        write_raw_dump(&path, SUBSPACE_LOGS, records, FrameInfo::new(), false);
        assert_rejected(&dir, "no content checksum");

        write_raw_dump(
            &path,
            SUBSPACE_LOGS,
            records,
            FrameInfo::new().content_checksum(true),
            false,
        );
        assert_rejected(&dir, "end mark is missing");

        write_raw_dump(
            &path,
            SUBSPACE_LOGS,
            records,
            FrameInfo::new().content_checksum(true),
            true,
        );
        assert!(validate_backup(&dir.0).is_ok());
    }

    #[test]
    fn malformed_record_encodings_are_rejected() {
        for (records, expected) in [
            (&[0x80, 0x00][..], "invalid record length encoding"),
            (
                &[0xFF, 0xFF, 0xFF, 0xFF, 0x7F][..],
                "invalid record length encoding",
            ),
            (&[0x81, 0x80, 0x80, 0x80, 0x01][..], "size limit"),
            (&[0x05, b'k', b'e'][..], "truncated record"),
            (&[0x01, b'k'][..], "truncated record"),
        ] {
            let dir = TempDir::new("malformed");
            write_backup(&dir, &sample_backup());
            write_raw_dump(
                &dir.dump(SUBSPACE_LOGS),
                SUBSPACE_LOGS,
                records,
                FrameInfo::new().content_checksum(true),
                true,
            );
            assert_rejected(&dir, expected);
        }
    }

    #[test]
    fn incomplete_or_mislabelled_backups_are_rejected() {
        let dir = TempDir::new("empty");
        assert_rejected(&dir, "exactly one dump per exported subspace");

        let dir = TempDir::new("missing");
        write_backup(&dir, &sample_backup());
        std::fs::remove_file(dir.dump(SUBSPACE_TASK_QUEUE)).unwrap();
        assert_rejected(&dir, "exactly one dump per exported subspace");

        let dir = TempDir::new("misnamed");
        write_backup(&dir, &sample_backup());
        std::fs::rename(dir.dump(SUBSPACE_TASK_QUEUE), dir.0.join("subspace_copy")).unwrap();
        assert_rejected(&dir, "file name does not match");

        let dir = TempDir::new("nested");
        write_backup(&dir, &sample_backup());
        std::fs::create_dir(dir.0.join("nested")).unwrap();
        assert_rejected(&dir, "regular files");
    }

    #[test]
    fn unordered_or_inconsistent_records_are_rejected() {
        let dir = TempDir::new("unordered");
        let mut backup = sample_backup();
        backup.insert(
            SUBSPACE_ACL,
            vec![(b"b".to_vec(), Vec::new()), (b"a".to_vec(), Vec::new())],
        );
        write_backup(&dir, &backup);
        assert_rejected(&dir, "strictly increasing");

        let dir = TempDir::new("dangling-link");
        let mut backup = sample_backup();
        let mut link = [9u8; BLOB_HASH_LEN].to_vec();
        link.push(0);
        backup
            .get_mut(&SUBSPACE_BLOB_LINK)
            .unwrap()
            .push((link, Vec::new()));
        write_backup(&dir, &backup);
        assert_rejected(&dir, "1 linked blobs missing");

        let dir = TempDir::new("counter");
        let mut backup = sample_backup();
        backup.insert(
            SUBSPACE_COUNTER,
            vec![(b"counter".to_vec(), vec![1, 2, 3, 4])],
        );
        write_backup(&dir, &backup);
        assert_rejected(&dir, "malformed record");
    }
}
