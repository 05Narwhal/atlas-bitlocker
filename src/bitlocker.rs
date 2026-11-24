// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! BitLocker (Windows 7 and later): reading the FVE metadata, finding the
//! volume key from a password or a recovery password, and mounting what is
//! inside.
//!
//! **Not yet verified against a real Windows-made volume.** The layout below
//! was written from the public libbde and Microsoft documentation; the
//! tests use a volume this module's test helper builds from the same
//! description, so they prove the code agrees with itself and with the RFC
//! 3610 and IEEE 1619 vectors, not that Windows agrees. The "unsure" items
//! are marked `UNVERIFIED` in the comments.
//!
//! The volume starts with a boot sector that carries `-FVE-FS-` at byte 3,
//! the FVE metadata GUID at byte 160 (or 424 on a BitLocker To Go volume) and
//! three byte offsets of metadata blocks. Each block is a 64-byte block
//! header (signature, version 2, encrypted-volume size, number of relocated
//! volume-header sectors, the offset they were moved to), a 48-byte metadata
//! header (size, version 1, encryption method) and a list of entries (size,
//! entry type, value type, version, data). The first copy that parses is used.
//!
//! Keys: a volume master key (VMK) is stored once per protector, wrapped with
//! AES-CCM under a key stretched from the password (or recovery password)
//! with a 0x100000-round SHA-256 chain. The full volume encryption key
//! (FVEK) is wrapped under the VMK. Protectors that need hardware or a key
//! file (TPM, startup key, clear key) are skipped.
//!
//! The volume is AES-CBC (IV is the sector's byte offset encrypted with the
//! FVEK) or AES-XTS (tweak is the sector number). The first sectors of the
//! volume (the original boot sector and its neighbours) were moved to
//! "volume header offset" and are read from there. Sectors past the
//! "encrypted volume size" are plain. The three metadata blocks sit inside
//! the volume and are not treated specially: they decrypt to noise, which no
//! filesystem reads. The elephant diffuser (`0x8000`, `0x8001`) and Windows
//! Vista volumes are not supported.
//!
//! The header is hostile input. Every size, offset and count is checked
//! before use, loops are bounded by the metadata size and an entry cap, and
//! the work an unlock does is capped ([`Limits`]). The password, the derived
//! keys, the VMK and the FVEK live in [`zeroize::Zeroizing`] buffers; no key
//! type implements `Debug`. (The SHA-256 state inside the hash crate is not
//! wiped.)

use std::sync::Arc;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use atlas_fs_core::error::{CorruptKind, Error, Result};
use atlas_fs_core::fs::{ContainerVolume, FileSystem, LockedVolume, VolumeState};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_luks::luks::Mounter;
use atlas_luks::source::{Decrypted, SectorCipher};

use super::ccm;
use super::{bad_field, corrupt, out_of_range};

const HEADER: &str = "BitLocker volume header";
const BLOCK: &str = "BitLocker metadata block";
const ENTRY: &str = "BitLocker metadata entry";
const KEY: &str = "BitLocker key";

/// `-FVE-FS-`, at byte 3 of the boot sector and at byte 0 of a metadata block.
const SIGNATURE: [u8; 8] = *b"-FVE-FS-";
/// The OEM name of a BitLocker To Go (FAT) boot sector.
const TOGO_OEM: [u8; 8] = *b"MSWIN4.1";
/// 4967D63B-2E29-4AD8-8399-F6A339E3D001 as stored (the first three fields
/// little-endian).
const FVE_GUID: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];
/// Where the GUID sits in a Windows 7 boot sector and in a To Go boot sector
/// (UNVERIFIED for To Go); the three metadata offsets follow it.
const GUID_AT: [usize; 2] = [160, 424];

/// The metadata block header and the metadata header, before the entries.
const BLOCK_HEADER: usize = 64;
const META_HEADER: usize = 48;
/// The most metadata (header plus entries) read from one block.
const MAX_METADATA: u32 = 1 << 20;
/// The most entries examined in one metadata block, and in one key protector.
const MAX_ENTRIES: usize = 4096;
const MAX_PROPERTIES: usize = 256;
/// Most key protectors (VMK entries) kept.
const MAX_VMKS: usize = 32;
/// The most bytes of one wrapped key.
const MAX_WRAPPED: usize = 1024;
/// The most bytes of relocated volume header.
const MAX_HEADER_BYTES: u64 = 16 << 20;
/// Most distinct key stretches one unlock runs.
const MAX_STRETCHES: usize = 4;

/// Protection types of a VMK entry.
const PROTECTION_RECOVERY: u16 = 0x0800;
const PROTECTION_PASSWORD: u16 = 0x2000;

/// Encryption methods of the metadata header (the FVEK entry repeats it).
const METHOD_CBC128_DIFFUSER: u16 = 0x8000;
const METHOD_CBC256_DIFFUSER: u16 = 0x8001;
const METHOD_CBC128: u16 = 0x8002;
const METHOD_CBC256: u16 = 0x8003;
const METHOD_XTS128: u16 = 0x8004;
const METHOD_XTS256: u16 = 0x8005;

/// The stretch of a BitLocker password: SHA-256 rounds, fixed by the format.
pub const STRETCH_ROUNDS: u32 = 0x10_0000;

/// Caps on the work a header may ask of an unlock.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// SHA-256 rounds of one key stretch. The format fixes it at
    /// [`STRETCH_ROUNDS`]; only a test or the fuzz target lowers it (a volume
    /// made by Windows does not unlock with a lower value).
    pub stretch_rounds: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            stretch_rounds: STRETCH_ROUNDS,
        }
    }
}

fn le16(buf: &[u8], at: usize) -> Option<u16> {
    let b = buf.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(<[u8; 2]>::try_from(b).ok()?))
}

fn le32(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(<[u8; 4]>::try_from(b).ok()?))
}

fn le64(buf: &[u8], at: usize) -> Option<u64> {
    let b = buf.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes(<[u8; 8]>::try_from(b).ok()?))
}

fn truncated(structure: &'static str, needed: u64, available: u64) -> Error {
    corrupt(structure, CorruptKind::Truncated { needed, available })
}

/// Where the metadata GUID sits in `head`, if it does.
fn guid_at(head: &[u8]) -> Option<usize> {
    GUID_AT.iter().copied().find(|&at| {
        at.checked_add(16)
            .and_then(|end| head.get(at..end))
            .is_some_and(|g| g == FVE_GUID)
    })
}

/// True when `head` (the start of a source) is a BitLocker boot sector: the
/// `-FVE-FS-` signature, or a To Go `MSWIN4.1` sector that carries the FVE
/// metadata GUID.
pub fn is_bitlocker(head: &[u8]) -> bool {
    match head.get(3..11) {
        Some(oem) if oem == SIGNATURE => true,
        Some(oem) if oem == TOGO_OEM => guid_at(head).is_some(),
        _ => false,
    }
}

/// Mounts a source that starts with a BitLocker boot sector: one locked
/// volume. Its `unlock` decrypts the payload and hands it to `mounter`.
///
/// A header that cannot be used (damaged, or a method or version this reader
/// does not have) is a volume in the `Failed` state; a read error is an
/// error.
pub fn mount(source: Arc<dyn BlockSource>, mounter: Mounter) -> Result<Vec<ContainerVolume>> {
    match open(source) {
        Ok(volume) => Ok(vec![ContainerVolume::new(
            "",
            None,
            VolumeState::Locked(Arc::new(LockedBitLocker { volume, mounter })),
        )]),
        Err(e @ (Error::Io { .. } | Error::AccessDenied { .. })) => Err(e),
        Err(e) => Ok(vec![ContainerVolume::new("", None, VolumeState::Failed(e))]),
    }
}

/// Reads the BitLocker metadata of `source` with the default [`Limits`].
pub fn open(source: Arc<dyn BlockSource>) -> Result<BitLocker> {
    open_with_limits(source, Limits::default())
}

/// Reads the BitLocker metadata of `source`.
pub fn open_with_limits(source: Arc<dyn BlockSource>, limits: Limits) -> Result<BitLocker> {
    let header = read_header(&*source)?;
    Ok(BitLocker {
        source,
        header,
        limits,
    })
}

/// A key protector: a VMK wrapped under a key made from a secret.
struct Protector {
    /// The protection type (`0x2000` password, `0x0800` recovery password,
    /// others are not usable).
    protection: u16,
    /// The stretch salt, when the protector has one.
    salt: Option<[u8; 16]>,
    /// The wrapped VMK.
    vmk: Wrapped,
}

/// An AES-CCM wrapped key: nonce, tag and the encrypted key structure.
struct Wrapped {
    nonce: [u8; 12],
    tag: [u8; 16],
    data: Vec<u8>,
}

impl Wrapped {
    /// Reads `nonce (12) | tag (16) | data` from a value of type 5.
    fn parse(value: &[u8]) -> Option<Self> {
        let nonce = <[u8; 12]>::try_from(value.get(..12)?).ok()?;
        let tag = <[u8; 16]>::try_from(value.get(12..28)?).ok()?;
        let data = value.get(28..)?;
        // A key structure is a 12-byte header and at least one key byte.
        (data.len() > 12 && data.len() <= MAX_WRAPPED).then(|| Self {
            nonce,
            tag,
            data: data.to_vec(),
        })
    }

    /// The key structure, when `key` is the key it was wrapped with.
    fn unwrap(&self, key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        ccm::decrypt(key, &self.nonce, &[], &self.data, &self.tag)
    }
}

/// The parsed metadata of the first good copy.
struct Header {
    /// Bytes per sector of the encryption (the boot sector's value).
    sector_size: u32,
    /// Size of the decrypted volume: the source rounded down to whole sectors.
    volume_len: u64,
    /// The encryption method of the metadata header.
    method: u16,
    /// Bytes from the start that are encrypted; the rest is plain.
    encrypted_len: u64,
    /// Where the first `header_len` bytes of the volume were moved to.
    header_off: u64,
    header_len: u64,
    protectors: Vec<Protector>,
    fvek: Wrapped,
}

/// A BitLocker volume waiting for its password or recovery password. Holds
/// the parsed metadata and the source, never a secret or a key.
pub struct BitLocker {
    source: Arc<dyn BlockSource>,
    header: Header,
    limits: Limits,
}

impl BitLocker {
    /// The encryption method as Windows names it.
    pub fn method_name(&self) -> &'static str {
        method_name(self.header.method)
    }

    /// The size of the decrypted volume in bytes.
    pub fn volume_len(&self) -> u64 {
        self.header.volume_len
    }

    /// The decrypted volume, when `secret` opens a key protector: a
    /// 48-digit recovery password (digits, hyphens allowed) or a password.
    /// The secret and every key made on the way are wiped before this
    /// returns, except the key inside the returned source.
    ///
    /// `Error::WrongPassword` when no protector the secret fits opens, or the
    /// secret has the shape of a recovery password but is not a valid one;
    /// `Error::Unsupported` when the volume has no protector of that kind
    /// that can be used without hardware.
    pub fn unlock_source(&self, secret: &str) -> Result<Arc<dyn BlockSource>> {
        let h = &self.header;
        // What to try, in order: (protection type, hash the stretch starts from).
        let mut plan: Vec<(u16, Zeroizing<[u8; 32]>)> = Vec::new();
        match recovery_key(secret)? {
            Some(key) => {
                plan.push((PROTECTION_RECOVERY, sha256(&*key)));
                if !h
                    .protectors
                    .iter()
                    .any(|p| p.protection == PROTECTION_RECOVERY)
                {
                    plan.push((PROTECTION_PASSWORD, password_hash(secret)));
                }
            }
            None => plan.push((PROTECTION_PASSWORD, password_hash(secret))),
        }

        let mut stretched: Vec<([u8; 16], Zeroizing<[u8; 32]>)> = Vec::new();
        let mut tried = false;
        let mut vmk: Option<Zeroizing<Vec<u8>>> = None;
        'plan: for (kind, initial) in &plan {
            for protector in h.protectors.iter().filter(|p| p.protection == *kind) {
                let Some(salt) = protector.salt else { continue };
                let cached = stretched.iter().position(|(s, _)| *s == salt);
                let at = match cached {
                    Some(at) => at,
                    None if stretched.len() < MAX_STRETCHES => {
                        let key = stretch(initial, &salt, self.limits.stretch_rounds);
                        stretched.push((salt, key));
                        stretched.len().saturating_sub(1)
                    }
                    None => continue,
                };
                let Some((_, key)) = stretched.get(at) else {
                    continue;
                };
                tried = true;
                if let Some(plain) = protector.vmk.unwrap(&**key) {
                    vmk = Some(plain);
                    break 'plan;
                }
            }
            // The cache is keyed by salt only, and the next kind starts from
            // another hash: it must not reuse these.
            stretched.clear();
        }

        let Some(vmk) = vmk else {
            return Err(if tried {
                Error::WrongPassword
            } else {
                no_usable_protector(h, plan.iter().map(|(k, _)| *k))
            });
        };
        let vmk_key = key_of(&vmk, Some(32))?;
        let fvek_plain = h
            .fvek
            .unwrap(vmk_key)
            .ok_or_else(|| corrupt(KEY, CorruptKind::Other("the volume key does not verify")))?;
        let method = le32(&fvek_plain, 8)
            .and_then(|m| u16::try_from(m).ok())
            .filter(|m| (METHOD_CBC128_DIFFUSER..=METHOD_XTS256).contains(m))
            .unwrap_or(h.method);
        let fvek = key_of(&fvek_plain, None)?;
        let (cipher, iv_step) = build_cipher(method, fvek, h.sector_size)?;
        let decrypted = Decrypted::new(
            Arc::clone(&self.source),
            cipher,
            0,
            h.volume_len,
            h.sector_size,
            0,
            iv_step,
        )?;
        Ok(Arc::new(BitLockerSource {
            raw: Arc::clone(&self.source),
            data: decrypted,
            len: h.volume_len,
            sector_size: h.sector_size,
            header_off: h.header_off,
            header_len: h.header_len,
            encrypted_len: h.encrypted_len,
        }))
    }
}

/// A [`BitLocker`] volume with the mounter that opens what is inside it.
struct LockedBitLocker {
    volume: BitLocker,
    mounter: Mounter,
}

impl LockedVolume for LockedBitLocker {
    fn hint(&self) -> Option<String> {
        None
    }

    fn unlock(&self, password: &str) -> Result<Arc<dyn FileSystem>> {
        let payload = self.volume.unlock_source(password)?;
        (self.mounter)(payload)
    }
}

/// Names the protection types of a volume for the "cannot unlock" message.
fn protection_name(protection: u16) -> &'static str {
    match protection {
        0x0000 => "a clear key (protection suspended)",
        0x0100 => "the TPM",
        0x0200 => "a startup key",
        0x0500 => "the TPM and a PIN",
        0x0600 => "the TPM and a startup key",
        0x0700 => "the TPM, a PIN and a startup key",
        PROTECTION_RECOVERY => "a recovery password",
        PROTECTION_PASSWORD => "a password",
        _ => "a protector of an unknown kind",
    }
}

fn method_name(method: u16) -> &'static str {
    match method {
        METHOD_CBC128_DIFFUSER => "AES-128-CBC with the elephant diffuser",
        METHOD_CBC256_DIFFUSER => "AES-256-CBC with the elephant diffuser",
        METHOD_CBC128 => "AES-128-CBC",
        METHOD_CBC256 => "AES-256-CBC",
        METHOD_XTS128 => "AES-128-XTS",
        METHOD_XTS256 => "AES-256-XTS",
        _ => "an unknown method",
    }
}

fn no_usable_protector(h: &Header, asked: impl Iterator<Item = u16>) -> Error {
    let asked: Vec<u16> = asked.collect();
    let mut present: Vec<&'static str> = Vec::new();
    for p in &h.protectors {
        let name = protection_name(p.protection);
        if !present.contains(&name) {
            present.push(name);
        }
    }
    let wanted = if asked.contains(&PROTECTION_RECOVERY) {
        "a recovery password"
    } else {
        "a password"
    };
    Error::unsupported(format!(
        "this BitLocker volume has no protector that {wanted} opens; it is protected by {} (only a password or a recovery password can be used)",
        present.join(", ")
    ))
}

/// The key bytes of a decrypted key structure: a 12-byte header (size,
/// type, value type, version, method) and the key. `want` fixes the key's
/// length.
fn key_of(structure: &[u8], want: Option<usize>) -> Result<&[u8]> {
    let size = le16(structure, 0)
        .map(usize::from)
        .filter(|&s| s > 12 && s <= structure.len())
        .ok_or_else(|| corrupt(KEY, CorruptKind::Other("key structure size")))?;
    let key = structure
        .get(12..size)
        .ok_or_else(|| corrupt(KEY, CorruptKind::Other("key structure size")))?;
    match want {
        Some(n) if key.len() != n => Err(bad_field(KEY, "key length", key.len() as u64)),
        _ => Ok(key),
    }
}

/// The sector cipher for `method` and the IV number step per sector.
fn build_cipher(method: u16, key: &[u8], sector_size: u32) -> Result<(SectorCipher, u64)> {
    let short = |needed: usize| truncated(KEY, needed as u64, key.len() as u64);
    match method {
        METHOD_CBC128 => {
            let k = key.get(..16).ok_or_else(|| short(16))?;
            Ok((SectorCipher::cbc_eboiv(k)?, u64::from(sector_size)))
        }
        METHOD_CBC256 => {
            let k = key.get(..32).ok_or_else(|| short(32))?;
            Ok((SectorCipher::cbc_eboiv(k)?, u64::from(sector_size)))
        }
        METHOD_XTS128 => {
            let k = key.get(..32).ok_or_else(|| short(32))?;
            Ok((SectorCipher::parse("aes-xts-plain64", k)?, 1))
        }
        METHOD_XTS256 => {
            let k = key.get(..64).ok_or_else(|| short(64))?;
            Ok((SectorCipher::parse("aes-xts-plain64", k)?, 1))
        }
        METHOD_CBC128_DIFFUSER | METHOD_CBC256_DIFFUSER => Err(Error::unsupported(
            "BitLocker with the elephant diffuser is not supported",
        )),
        other => Err(Error::unsupported(format!(
            "BitLocker encryption method {other:#06x}"
        ))),
    }
}

// ------------------------------------------------------------ key derivation

fn sha256(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    for (dst, src) in out.iter_mut().zip(Sha256::digest(data).iter()) {
        *dst = *src;
    }
    out
}

/// SHA-256 of SHA-256 of the UTF-16LE password: the hash the stretch starts
/// from for a password protector.
fn password_hash(password: &str) -> Zeroizing<[u8; 32]> {
    let mut utf16 = Zeroizing::new(Vec::with_capacity(password.len().saturating_mul(2)));
    for unit in password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let once = sha256(&utf16);
    sha256(&*once)
}

/// The 16-byte intermediate key of a recovery password: `Ok(None)` when
/// `secret` does not have the shape of one (48 digits, hyphens allowed);
/// `Error::WrongPassword` when it does but a group is not a multiple of 11 or
/// is too large (a typing mistake: no stretch is run for it).
fn recovery_key(secret: &str) -> Result<Option<Zeroizing<[u8; 16]>>> {
    let text = secret.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        return Ok(None);
    }
    let digits: Zeroizing<Vec<u8>> =
        Zeroizing::new(text.bytes().filter(|b| b.is_ascii_digit()).collect());
    if digits.len() != 48 {
        return Ok(None);
    }
    let mut key = Zeroizing::new([0u8; 16]);
    let groups = digits.as_chunks::<6>().0.iter();
    for (group, out) in groups.zip(key.as_chunks_mut::<2>().0.iter_mut()) {
        let mut value: u32 = 0;
        for digit in group {
            value = value
                .saturating_mul(10)
                .saturating_add(u32::from(digit.saturating_sub(b'0')));
        }
        if !value.is_multiple_of(11) {
            return Err(Error::WrongPassword);
        }
        let word = value
            .checked_div(11)
            .and_then(|w| u16::try_from(w).ok())
            .ok_or(Error::WrongPassword)?;
        out.copy_from_slice(&word.to_le_bytes());
    }
    Ok(Some(key))
}

/// The BitLocker key stretch: `rounds` of SHA-256 over
/// `last hash (32) | initial (32) | salt (16) | round number (u64 LE)`,
/// starting from a zero `last hash`. The final hash is the key.
pub(crate) fn stretch(initial: &[u8; 32], salt: &[u8; 16], rounds: u32) -> Zeroizing<[u8; 32]> {
    let mut last = Zeroizing::new([0u8; 32]);
    for count in 0..u64::from(rounds) {
        let mut hasher = Sha256::new();
        hasher.update(*last);
        hasher.update(initial);
        hasher.update(salt);
        hasher.update(count.to_le_bytes());
        for (dst, src) in last.iter_mut().zip(hasher.finalize().iter()) {
            *dst = *src;
        }
    }
    last
}

// ------------------------------------------------------------------ metadata

/// One metadata entry: its types and the bytes after its 8-byte header.
struct Entry<'a> {
    kind: u16,
    value: u16,
    data: &'a [u8],
}

/// Walks a run of metadata entries, spending one unit of `budget` per entry.
struct Entries<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Entries<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The next entry, `Ok(None)` at the end (or at zero padding), an error
    /// for a size that is under 8 or past the end of the run.
    fn next(&mut self, budget: &mut usize) -> Result<Option<Entry<'a>>> {
        let rest = self.buf.get(self.pos..).unwrap_or_default();
        if rest.is_empty() {
            return Ok(None);
        }
        let size = usize::from(le16(rest, 0).unwrap_or(0));
        if size < 8 || size > rest.len() {
            if size == 0 && rest.iter().all(|&b| b == 0) {
                self.pos = self.buf.len();
                return Ok(None);
            }
            return Err(if size < 8 {
                bad_field(ENTRY, "entry size", size as u64)
            } else {
                out_of_range(
                    ENTRY,
                    "entry size",
                    size as u64,
                    "bytes left",
                    rest.len() as u64,
                )
            });
        }
        *budget = budget.checked_sub(1).ok_or_else(|| {
            corrupt(
                ENTRY,
                CorruptKind::LimitExceeded {
                    what: "metadata entries",
                    limit: MAX_ENTRIES as u64,
                },
            )
        })?;
        let (Some(kind), Some(value), Some(data)) =
            (le16(rest, 2), le16(rest, 4), rest.get(8..size))
        else {
            return Err(bad_field(ENTRY, "entry size", size as u64));
        };
        self.pos = self.pos.checked_add(size).ok_or_else(|| {
            corrupt(
                ENTRY,
                CorruptKind::Overflow {
                    field: "entry size",
                },
            )
        })?;
        Ok(Some(Entry { kind, value, data }))
    }
}

/// A key protector from the data of a VMK entry (type 2, value type 8):
/// identifier (16), modification time (8), unknown (2), protection type (2),
/// then properties.
fn parse_protector(data: &[u8]) -> Option<Protector> {
    let protection = le16(data, 26)?;
    let mut entries = Entries::new(data.get(28..)?);
    let mut budget = MAX_PROPERTIES;
    let mut salt = None;
    let mut direct = None;
    let mut nested = None;
    // A property that does not parse ends the scan; what came before it counts.
    while let Ok(Some(e)) = entries.next(&mut budget) {
        match e.value {
            // Stretch key: method (4), salt (16), then properties of its own.
            3 => {
                if salt.is_none() {
                    salt = e.data.get(4..20).and_then(|s| <[u8; 16]>::try_from(s).ok());
                }
                if nested.is_none() {
                    nested = e.data.get(20..).and_then(wrapped_in);
                }
            }
            // AES-CCM encrypted key.
            5 if direct.is_none() => direct = Wrapped::parse(e.data),
            _ => {}
        }
    }
    Some(Protector {
        protection,
        salt,
        vmk: direct.or(nested)?,
    })
}

/// The first wrapped key among the entries of `buf`.
fn wrapped_in(buf: &[u8]) -> Option<Wrapped> {
    let mut entries = Entries::new(buf);
    let mut budget = 16usize;
    while let Ok(Some(e)) = entries.next(&mut budget) {
        if e.value == 5 {
            return Wrapped::parse(e.data);
        }
    }
    None
}

/// Reads the volume header and the first good metadata block.
fn read_header(source: &dyn BlockSource) -> Result<Header> {
    let src_len = source.len();
    let mut head = [0u8; 512];
    if src_len < 512 {
        return Err(truncated(HEADER, 512, src_len));
    }
    source.read_at(0, &mut head)?;
    if !is_bitlocker(&head) {
        return Err(corrupt(
            HEADER,
            CorruptKind::BadSignature {
                expected: u64::from_le_bytes(SIGNATURE),
                found: head
                    .get(3..11)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map_or(0, u64::from_le_bytes),
            },
        ));
    }
    let Some(guid) = guid_at(&head) else {
        return Err(Error::unsupported(
            "BitLocker volumes made by Windows Vista are not supported",
        ));
    };
    let sector_size = le16(&head, 11)
        .filter(|s| matches!(s, 512 | 1024 | 2048 | 4096))
        .ok_or_else(|| {
            bad_field(
                HEADER,
                "bytes per sector",
                u64::from(le16(&head, 11).unwrap_or(0)),
            )
        })?;
    let sector = u64::from(sector_size);
    let volume_len = src_len
        .checked_div(sector)
        .and_then(|n| n.checked_mul(sector))
        .filter(|&n| n > 0)
        .ok_or_else(|| truncated(HEADER, sector, src_len))?;

    let first = guid.checked_add(16).ok_or_else(|| {
        corrupt(
            HEADER,
            CorruptKind::Overflow {
                field: "metadata offsets",
            },
        )
    })?;
    let mut first_error = None;
    let mut seen: Vec<u64> = Vec::new();
    for i in 0..3usize {
        let at = first.saturating_add(i.saturating_mul(8));
        let Some(offset) = le64(&head, at) else {
            continue;
        };
        if offset == 0 || seen.contains(&offset) {
            continue;
        }
        seen.push(offset);
        match read_block(source, offset, sector, volume_len) {
            Ok(header) => return Ok(header),
            Err(e @ (Error::Io { .. } | Error::AccessDenied { .. })) => return Err(e),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    Err(first_error
        .unwrap_or_else(|| corrupt(HEADER, CorruptKind::Other("no metadata block offsets"))))
}

/// Reads and checks the metadata block at `offset`.
fn read_block(
    source: &dyn BlockSource,
    offset: u64,
    sector: u64,
    volume_len: u64,
) -> Result<Header> {
    let src_len = source.len();
    let fixed_len = BLOCK_HEADER + META_HEADER;
    check_range(offset, fixed_len, src_len)?;
    let mut fixed = [0u8; BLOCK_HEADER + META_HEADER];
    source.read_at(offset, &mut fixed)?;

    if fixed.get(..8) != Some(&SIGNATURE[..]) {
        return Err(corrupt(
            BLOCK,
            CorruptKind::BadSignature {
                expected: u64::from_le_bytes(SIGNATURE),
                found: fixed
                    .get(..8)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map_or(0, u64::from_le_bytes),
            },
        ));
    }
    // UNVERIFIED: the block header fields (version 2): version at 10,
    // encrypted volume size at 16, relocated header sectors at 28, relocated
    // header offset at 56.
    let version = le16(&fixed, 10).unwrap_or(0);
    if version != 2 {
        return Err(bad_field(BLOCK, "version", u64::from(version)));
    }
    let encrypted = le64(&fixed, 16).unwrap_or(0);
    let header_sectors = le32(&fixed, 28).unwrap_or(0);
    let header_off = le64(&fixed, 56).unwrap_or(0);

    // The metadata header: size, version 1, header size 48, size again,
    // volume GUID (16), nonce counter (4), method, creation time.
    let meta_size = le32(&fixed, 64).unwrap_or(0);
    let meta_version = le32(&fixed, 68).unwrap_or(0);
    let meta_header = le32(&fixed, 72).unwrap_or(0);
    let meta_copy = le32(&fixed, 76).unwrap_or(0);
    if meta_version != 1 {
        return Err(bad_field(
            BLOCK,
            "metadata version",
            u64::from(meta_version),
        ));
    }
    if meta_header as usize != META_HEADER {
        return Err(bad_field(
            BLOCK,
            "metadata header size",
            u64::from(meta_header),
        ));
    }
    if meta_copy != meta_size {
        return Err(bad_field(BLOCK, "metadata size copy", u64::from(meta_copy)));
    }
    if (meta_size as usize) < META_HEADER || meta_size > MAX_METADATA {
        return Err(out_of_range(
            BLOCK,
            "metadata size",
            u64::from(meta_size),
            "maximum",
            u64::from(MAX_METADATA),
        ));
    }
    let method = le16(&fixed, 100).unwrap_or(0);
    match method {
        METHOD_CBC128 | METHOD_CBC256 | METHOD_XTS128 | METHOD_XTS256 => {}
        METHOD_CBC128_DIFFUSER | METHOD_CBC256_DIFFUSER => {
            return Err(Error::unsupported(
                "BitLocker with the elephant diffuser is not supported",
            ));
        }
        other => {
            return Err(Error::unsupported(format!(
                "BitLocker encryption method {other:#06x}"
            )));
        }
    }

    // The relocated volume header must lie inside the volume.
    let header_len = u64::from(header_sectors)
        .checked_mul(sector)
        .filter(|&n| n <= MAX_HEADER_BYTES && n <= volume_len)
        .ok_or_else(|| {
            out_of_range(
                BLOCK,
                "volume header sectors",
                u64::from(header_sectors),
                "volume size",
                volume_len,
            )
        })?;
    if header_len > 0 {
        header_off
            .checked_add(header_len)
            .filter(|&e| e <= volume_len && header_off.is_multiple_of(sector))
            .ok_or_else(|| {
                out_of_range(
                    BLOCK,
                    "volume header offset",
                    header_off,
                    "volume size",
                    volume_len,
                )
            })?;
    }
    // UNVERIFIED: an encrypted size of zero is taken to mean the whole volume.
    // A sector is encrypted whole or not at all: round down to one.
    let encrypted_len = if encrypted == 0 {
        volume_len
    } else {
        let whole = encrypted.min(volume_len);
        whole.saturating_sub(whole.checked_rem(sector).unwrap_or(0))
    }
    .max(header_len);

    // The entries, after the metadata header.
    let meta_start = offset.checked_add(BLOCK_HEADER as u64).ok_or_else(|| {
        corrupt(
            BLOCK,
            CorruptKind::Overflow {
                field: "metadata offset",
            },
        )
    })?;
    let meta_len = meta_size as usize;
    check_range(meta_start, meta_len, src_len)?;
    let mut meta = vec![0u8; meta_len];
    source.read_at(meta_start, &mut meta)?;
    let entries = meta.get(META_HEADER..).unwrap_or_default();

    let mut walker = Entries::new(entries);
    let mut budget = MAX_ENTRIES;
    let mut protectors = Vec::new();
    let mut fvek = None;
    while let Some(e) = walker.next(&mut budget)? {
        match (e.kind, e.value) {
            (2, 8) if protectors.len() < MAX_VMKS => {
                protectors.extend(parse_protector(e.data));
            }
            (3, 5) if fvek.is_none() => fvek = Wrapped::parse(e.data),
            _ => {}
        }
    }
    let fvek =
        fvek.ok_or_else(|| corrupt(BLOCK, CorruptKind::Other("no full volume encryption key")))?;
    if protectors.is_empty() {
        return Err(corrupt(BLOCK, CorruptKind::Other("no volume master key")));
    }
    Ok(Header {
        sector_size: u32::try_from(sector)
            .map_err(|_| bad_field(HEADER, "bytes per sector", sector))?,
        volume_len,
        method,
        encrypted_len,
        header_off,
        header_len,
        protectors,
        fvek,
    })
}

// ----------------------------------------------------------- decrypted view

/// The decrypted volume: the relocated header for the first sectors,
/// decrypted sectors up to the encrypted size, plain bytes after it.
struct BitLockerSource {
    raw: Arc<dyn BlockSource>,
    /// The cipher over the whole raw source; the IV follows the position on
    /// disk (UNVERIFIED for the relocated header, which is decrypted as the
    /// sectors it is stored in).
    data: Decrypted,
    len: u64,
    sector_size: u32,
    header_off: u64,
    header_len: u64,
    encrypted_len: u64,
}

impl BlockSource for BitLockerSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let total = buf.len();
        let oob = || Error::OutOfBounds {
            offset,
            len: u64::try_from(total).unwrap_or(u64::MAX),
            size: self.len,
        };
        let mut done = 0usize;
        while done < total {
            let at = offset
                .checked_add(u64::try_from(done).map_err(|_| oob())?)
                .ok_or_else(oob)?;
            let left =
                u64::try_from(total.checked_sub(done).ok_or_else(oob)?).map_err(|_| oob())?;
            enum Part {
                Header,
                Cipher,
                Plain,
            }
            let (end, part) = if at < self.header_len {
                (self.header_len, Part::Header)
            } else if at < self.encrypted_len {
                (self.encrypted_len, Part::Cipher)
            } else {
                (self.len, Part::Plain)
            };
            let n = end.checked_sub(at).ok_or_else(oob)?.min(left);
            let n = usize::try_from(n).map_err(|_| oob())?;
            let stop = done.checked_add(n).ok_or_else(oob)?;
            let target = buf.get_mut(done..stop).ok_or_else(oob)?;
            match part {
                Part::Header => {
                    let from = self.header_off.checked_add(at).ok_or_else(oob)?;
                    self.data.read_at(from, target)?;
                }
                Part::Cipher => self.data.read_at(at, target)?,
                Part::Plain => self.raw.read_at(at, target)?,
            }
            done = stop;
        }
        Ok(())
    }
}
