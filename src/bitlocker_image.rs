// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! A small synthetic BitLocker volume, built the way the format describes it
//! (the encryptor side of `bitlocker.rs`). It is written from the same
//! public description as the reader, not from a Windows-made volume, so the
//! tests that use it prove the reader agrees with the description. The key
//! stretch, the recovery-password text and the sector ciphers are written
//! out again here instead of calling the reader's.
//!
//! Layout (bytes, whatever the sector size): the boot sector in sector 0;
//! metadata blocks of 4096 bytes at 12288, 16384 and 20480; the relocated
//! volume header (8192 bytes) at 49152; 128 KiB in all.

use sha2::{Digest, Sha256};

use super::ccm;
use atlas_luks::xts::{AesKey, Xts, tweak_of};

/// The password of the password protector.
pub const PASSWORD: &str = "atlas-test";
/// The eight 16-bit words of the recovery password's intermediate key.
pub const RECOVERY_WORDS: [u16; 8] = [1234, 22222, 3, 65535, 40000, 7, 999, 31337];
/// Size of the volume.
pub const VOLUME_LEN: usize = 128 << 10;
/// Where the three metadata blocks are, and how much room each has.
pub const META_OFFSETS: [usize; 3] = [12288, 16384, 20480];
pub const META_REGION: usize = 4096;
/// Where the first 8192 bytes of the volume were moved to.
pub const HEADER_OFF: usize = 49152;
pub const HEADER_LEN: usize = 8192;

pub const METHOD_CBC128: u16 = 0x8002;
pub const METHOD_CBC256: u16 = 0x8003;
pub const METHOD_XTS128: u16 = 0x8004;
pub const METHOD_XTS256: u16 = 0x8005;

/// How to build a volume.
#[derive(Clone)]
pub struct Spec {
    pub method: u16,
    /// Bytes per sector: 512 or 4096.
    pub sector: usize,
    /// SHA-256 rounds of the stretch (the format says 0x100000).
    pub rounds: u32,
    pub password: bool,
    pub recovery: bool,
    /// A TPM-only protector (no stretch key).
    pub tpm: bool,
    /// The wrapped key sits inside the stretch-key entry instead of beside it.
    pub nested: bool,
    /// Bytes from the start that are encrypted; 0 means all of them.
    pub encrypted_len: usize,
}

impl Spec {
    pub fn new(method: u16) -> Self {
        Self {
            method,
            sector: 512,
            rounds: 16,
            password: true,
            recovery: true,
            tpm: false,
            nested: false,
            encrypted_len: 0,
        }
    }
}

/// A built volume and what it holds when decrypted.
pub struct Built {
    pub image: Vec<u8>,
    pub plain: Vec<u8>,
}

/// The recovery password as Windows prints it: eight groups of six digits.
pub fn recovery_text() -> String {
    RECOVERY_WORDS
        .iter()
        .map(|w| format!("{:06}", u32::from(*w) * 11))
        .collect::<Vec<_>>()
        .join("-")
}

/// What the volume holds: a recognisable NTFS-looking boot sector in the
/// first 8192 bytes, a pattern after it, and the same first 8192 bytes again
/// where the relocated header is stored.
pub fn plain_volume() -> Vec<u8> {
    let mut plain: Vec<u8> = (0..VOLUME_LEN)
        .map(|i| (i.wrapping_mul(31) ^ (i >> 9).wrapping_mul(17)) as u8)
        .collect();
    plain[3..11].copy_from_slice(b"NTFS    ");
    plain[510..512].copy_from_slice(&[0x55, 0xAA]);
    let head = plain[..HEADER_LEN].to_vec();
    plain[HEADER_OFF..HEADER_OFF + HEADER_LEN].copy_from_slice(&head);
    plain
}

/// The key stretch, written out again.
pub fn stretch_ref(initial: [u8; 32], salt: [u8; 16], rounds: u32) -> [u8; 32] {
    let mut last = [0u8; 32];
    for count in 0..u64::from(rounds) {
        let mut buf = Vec::with_capacity(88);
        buf.extend_from_slice(&last);
        buf.extend_from_slice(&initial);
        buf.extend_from_slice(&salt);
        buf.extend_from_slice(&count.to_le_bytes());
        last.copy_from_slice(&Sha256::digest(&buf));
    }
    last
}

fn sha(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// The hash a password protector's stretch starts from.
pub fn password_initial(password: &str) -> [u8; 32] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    sha(&sha(&utf16))
}

/// The hash a recovery protector's stretch starts from.
pub fn recovery_initial() -> [u8; 32] {
    let key: Vec<u8> = RECOVERY_WORDS
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    sha(&key)
}

pub fn entry(kind: u16, value: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((8 + data.len()) as u16).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&value.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(data);
    out
}

/// A decrypted key structure: a 12-byte header (size, type, value type,
/// version, method) and the key.
fn key_structure(method: u32, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((12 + key.len()) as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(key);
    out
}

/// `nonce | tag | encrypted` of `plain` under `key`.
pub fn wrap(key: &[u8], seed: u8, plain: &[u8]) -> Vec<u8> {
    let nonce = [seed; 12];
    let (ct, tag) = ccm::encrypt(key, &nonce, &[], plain, 16).unwrap();
    let mut out = nonce.to_vec();
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    out
}

fn vmk_entry(
    protection: u16,
    seed: u8,
    stretch: Option<([u8; 16], &[u8; 32])>,
    vmk: &[u8],
    nested: bool,
) -> Vec<u8> {
    let mut data = vec![0x70 + seed; 16];
    data.extend_from_slice(&[0u8; 8]);
    data.extend_from_slice(&[0u8; 2]);
    data.extend_from_slice(&protection.to_le_bytes());
    let wrapped_plain = key_structure(0x2003, vmk);
    match stretch {
        Some((salt, key)) => {
            let ccm = entry(0, 5, &wrap(key, seed, &wrapped_plain));
            let mut stretch_data = 0x1000u32.to_le_bytes().to_vec();
            stretch_data.extend_from_slice(&salt);
            if nested {
                stretch_data.extend_from_slice(&ccm);
                data.extend_from_slice(&entry(0, 3, &stretch_data));
            } else {
                data.extend_from_slice(&entry(0, 3, &stretch_data));
                data.extend_from_slice(&ccm);
            }
        }
        None => {
            // No secret opens it: wrapped under a key nobody has.
            data.extend_from_slice(&entry(0, 5, &wrap(&[0x5A; 32], seed, &wrapped_plain)));
        }
    }
    entry(2, 8, &data)
}

fn encrypt_sector(method: u16, key: &[u8], index: usize, sector: usize, data: &mut [u8]) {
    match method {
        METHOD_XTS128 | METHOD_XTS256 => {
            let n = if method == METHOD_XTS128 { 32 } else { 64 };
            Xts::new(&key[..n])
                .unwrap()
                .encrypt_with_tweak(tweak_of(index as u64), data);
        }
        _ => {
            let n = if method == METHOD_CBC128 { 16 } else { 32 };
            let aes = AesKey::new(&key[..n]).unwrap();
            let mut iv = tweak_of((index * sector) as u64);
            aes.encrypt(&mut iv);
            for block in data.as_chunks_mut::<16>().0.iter_mut() {
                for (b, p) in block.iter_mut().zip(&iv) {
                    *b ^= *p;
                }
                aes.encrypt(block);
                iv.copy_from_slice(block);
            }
        }
    }
}

/// The FVEK bytes of `method`: more than the cipher uses, so a reader that
/// takes the wrong slice is caught.
pub fn fvek_bytes(method: u16) -> Vec<u8> {
    let n = if method == METHOD_XTS256 { 64 } else { 32 };
    (0..n).map(|i| 0xC0u8.wrapping_add(i as u8 * 3)).collect()
}

/// The volume master key.
pub fn vmk_bytes() -> Vec<u8> {
    (0..32).map(|i| 0x40u8 + i as u8).collect()
}

/// Builds the metadata block (block header, metadata header, entries) for
/// `spec`, `META_REGION` bytes with the rest zero.
pub fn metadata_block(spec: &Spec) -> Vec<u8> {
    let vmk = vmk_bytes();
    let mut entries = Vec::new();
    if spec.password {
        let salt = [0xA1u8; 16];
        let key = stretch_ref(password_initial(PASSWORD), salt, spec.rounds);
        entries.extend(vmk_entry(0x2000, 1, Some((salt, &key)), &vmk, spec.nested));
    }
    if spec.recovery {
        let salt = [0xB2u8; 16];
        let key = stretch_ref(recovery_initial(), salt, spec.rounds);
        entries.extend(vmk_entry(0x0800, 2, Some((salt, &key)), &vmk, spec.nested));
    }
    if spec.tpm {
        entries.extend(vmk_entry(0x0100, 3, None, &vmk, false));
    }
    let fvek = key_structure(u32::from(spec.method), &fvek_bytes(spec.method));
    entries.extend(entry(3, 5, &wrap(&vmk, 9, &fvek)));
    entries.extend(entry(0, 0, &[]));

    let meta_size = 48 + entries.len();
    let mut block = Vec::new();
    // Block header: signature, size in 16-byte units, version 2, encrypted
    // volume size, relocated header sectors, metadata offsets, relocated
    // header offset.
    block.extend_from_slice(b"-FVE-FS-");
    block.extend_from_slice(&(((64 + meta_size) / 16) as u16).to_le_bytes());
    block.extend_from_slice(&2u16.to_le_bytes());
    block.extend_from_slice(&[0u8; 4]);
    let encrypted = if spec.encrypted_len == 0 {
        VOLUME_LEN
    } else {
        spec.encrypted_len
    };
    block.extend_from_slice(&(encrypted as u64).to_le_bytes());
    block.extend_from_slice(&[0u8; 4]);
    block.extend_from_slice(&((HEADER_LEN / spec.sector) as u32).to_le_bytes());
    for o in META_OFFSETS {
        block.extend_from_slice(&(o as u64).to_le_bytes());
    }
    block.extend_from_slice(&(HEADER_OFF as u64).to_le_bytes());
    assert_eq!(block.len(), 64);
    // Metadata header.
    block.extend_from_slice(&(meta_size as u32).to_le_bytes());
    block.extend_from_slice(&1u32.to_le_bytes());
    block.extend_from_slice(&48u32.to_le_bytes());
    block.extend_from_slice(&(meta_size as u32).to_le_bytes());
    block.extend_from_slice(&[0x33u8; 16]);
    block.extend_from_slice(&5u32.to_le_bytes());
    block.extend_from_slice(&spec.method.to_le_bytes());
    block.extend_from_slice(&0u16.to_le_bytes());
    block.extend_from_slice(&[0u8; 8]);
    assert_eq!(block.len(), 112);
    block.extend_from_slice(&entries);
    assert!(block.len() <= META_REGION);
    block.resize(META_REGION, 0);
    block
}

/// The boot sector's 512 bytes.
pub fn boot_sector(sector: usize) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    b[3..11].copy_from_slice(b"-FVE-FS-");
    b[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
    b[13] = 8;
    b[160..176].copy_from_slice(&[
        0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0,
        0x01,
    ]);
    for (i, o) in META_OFFSETS.iter().enumerate() {
        b[176 + 8 * i..184 + 8 * i].copy_from_slice(&(*o as u64).to_le_bytes());
    }
    b[510..512].copy_from_slice(&[0x55, 0xAA]);
    b
}

/// Builds the whole volume.
pub fn build(spec: &Spec) -> Built {
    let plain = plain_volume();
    let key = fvek_bytes(spec.method);
    let encrypted = if spec.encrypted_len == 0 {
        VOLUME_LEN
    } else {
        spec.encrypted_len
    };
    let mut image = plain.clone();
    for (i, sector) in image.chunks_exact_mut(spec.sector).enumerate() {
        if i * spec.sector < encrypted {
            encrypt_sector(spec.method, &key, i, spec.sector, sector);
        }
    }
    // The relocated header: the first sectors, encrypted where they now sit.
    for j in 0..HEADER_LEN / spec.sector {
        let from = j * spec.sector;
        let at = HEADER_OFF + from;
        let mut s = plain[from..from + spec.sector].to_vec();
        encrypt_sector(spec.method, &key, at / spec.sector, spec.sector, &mut s);
        image[at..at + spec.sector].copy_from_slice(&s);
    }
    let boot = boot_sector(spec.sector);
    image[..512].copy_from_slice(&boot);
    let block = metadata_block(spec);
    for o in META_OFFSETS {
        image[o..o + META_REGION].copy_from_slice(&block);
    }
    Built { image, plain }
}
