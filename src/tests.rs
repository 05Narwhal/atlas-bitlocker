// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! BitLocker tests: AES-CCM against RFC 3610, the recovery-password
//! conversion, a synthetic volume (`bitlocker_image`) unlocked with a
//! password and with a recovery password in every cipher, and hostile
//! headers. No test here has seen a volume Windows made.

use std::sync::Arc;
use std::time::Instant;

use super::bitlocker::{self, BitLocker, Limits, STRETCH_ROUNDS};
use super::bitlocker_image::{
    self as img, HEADER_LEN, HEADER_OFF, META_OFFSETS, META_REGION, PASSWORD, Spec, VOLUME_LEN,
    entry, recovery_text,
};
use super::ccm;
use atlas_fs_core::error::Error;
use atlas_fs_core::io::block::{BlockSource, MemSource};

type Source = Arc<dyn BlockSource>;

const FAST: Limits = Limits { stretch_rounds: 16 };

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn mem(bytes: Vec<u8>) -> Source {
    Arc::new(MemSource::new(bytes))
}

fn open(bytes: Vec<u8>) -> Result<BitLocker, Error> {
    bitlocker::open_with_limits(mem(bytes), FAST)
}

fn volume(spec: &Spec) -> (BitLocker, Vec<u8>) {
    let built = img::build(spec);
    (open(built.image).unwrap(), built.plain)
}

fn unlock(v: &BitLocker, secret: &str) -> Result<Source, Error> {
    v.unlock_source(secret)
}

fn err(r: Result<Source, Error>) -> Error {
    match r {
        Err(e) => e,
        Ok(_) => panic!("expected an error"),
    }
}

fn read_all(s: &Source) -> Vec<u8> {
    let mut out = vec![0u8; usize::try_from(s.len()).unwrap()];
    s.read_at(0, &mut out).unwrap();
    out
}

/// `got` equals `plain` everywhere except the metadata blocks, which decrypt
/// to noise.
fn assert_plain(got: &[u8], plain: &[u8]) {
    let meta = META_OFFSETS[0]..META_OFFSETS[2] + META_REGION;
    assert_eq!(got.len(), plain.len());
    assert!(got[..meta.start] == plain[..meta.start], "before metadata");
    assert!(got[meta.end..] == plain[meta.end..], "after metadata");
}

fn put(image: &mut [u8], at: usize, bytes: &[u8]) {
    image[at..at + bytes.len()].copy_from_slice(bytes);
}

const ALL_METHODS: [u16; 4] = [
    img::METHOD_CBC128,
    img::METHOD_CBC256,
    img::METHOD_XTS128,
    img::METHOD_XTS256,
];

// ------------------------------------------------------------------- AES-CCM

#[test]
fn ccm_rfc_3610_packet_vector_1() {
    // RFC 3610 section 8: key C0..CF, a 13-byte nonce, 8 bytes of associated
    // data, 23 bytes of message, an 8-byte tag.
    let key = hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
    let nonce = hex("00000003020100A0A1A2A3A4A5");
    let aad = hex("0001020304050607");
    let plain = hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
    let ct = hex("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384");
    let tag = hex("17E8D12CFDF926E0");
    assert_eq!(
        ccm::encrypt(&key, &nonce, &aad, &plain, 8).unwrap(),
        (ct.clone(), tag.clone())
    );
    assert_eq!(*ccm::decrypt(&key, &nonce, &aad, &ct, &tag).unwrap(), plain);
}

#[test]
fn ccm_rejects_a_changed_tag_message_key_or_data() {
    let key = [7u8; 32];
    let nonce = [3u8; 12];
    let (ct, tag) = ccm::encrypt(
        &key,
        &nonce,
        &[],
        b"a wrapped key, 44 bytes of it, more or less",
        16,
    )
    .unwrap();
    assert!(ccm::decrypt(&key, &nonce, &[], &ct, &tag).is_some());
    let mut bad = tag.clone();
    bad[15] ^= 1;
    assert!(ccm::decrypt(&key, &nonce, &[], &ct, &bad).is_none());
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(ccm::decrypt(&key, &nonce, &[], &bad, &tag).is_none());
    assert!(ccm::decrypt(&[8u8; 32], &nonce, &[], &ct, &tag).is_none());
    // Parameters CCM does not allow: no panic, no answer.
    assert!(ccm::decrypt(&key, &nonce[..2], &[], &ct, &tag).is_none());
    assert!(ccm::decrypt(&key, &nonce, &[], &ct, &tag[..3]).is_none());
    assert!(ccm::decrypt(&key[..5], &nonce, &[], &ct, &tag).is_none());
    assert!(ccm::decrypt(&key, &nonce, &[], &[], &tag).is_none());
}

// ------------------------------------------------------------ recovery key

#[test]
fn recovery_password_text_makes_the_intermediate_key() {
    // Each group is eleven times a 16-bit word; the words are the key, little-endian.
    let text = [
        "000011", "000022", "720885", "000000", "000011", "000011", "000011", "000011",
    ]
    .join("-");
    let (v, _) = volume(&Spec::new(img::METHOD_XTS128));
    // 000011 -> 1, 000022 -> 2, 720885 -> 65535, 000000 -> 0: not a real key, so it
    // is a wrong password, but it parsed.
    assert!(matches!(err(unlock(&v, &text)), Error::WrongPassword));
    // The helper writes words the same way the reader reads them.
    let words = recovery_text();
    assert_eq!(words.split('-').count(), 8);
    assert!(
        words
            .split('-')
            .all(|g| g.len() == 6 && g.parse::<u32>().unwrap() % 11 == 0)
    );
}

#[test]
fn recovery_password_with_a_bad_group_is_refused_without_a_stretch() {
    let (v, _) = volume(&Spec::new(img::METHOD_XTS128));
    // 000012 is not a multiple of 11; 720896 is 65536 * 11, one word too many.
    for bad in ["000012", "720896", "999999"] {
        let mut groups = ["000011"; 8];
        groups[3] = bad;
        let started = Instant::now();
        assert!(matches!(
            err(unlock(&v, &groups.join("-"))),
            Error::WrongPassword
        ));
        assert!(started.elapsed().as_millis() < 500);
    }
}

// --------------------------------------------------------------------- header

#[test]
fn vista_style_header_is_unsupported() {
    // -FVE-FS- but no metadata GUID.
    let mut image = img::build(&Spec::new(img::METHOD_XTS128)).image;
    image[160..176].fill(0);
    assert!(matches!(open(image).err().unwrap(), Error::Unsupported(_)));
}

#[test]
fn bitlocker_to_go_header_with_the_guid_at_424_opens() {
    let built = img::build(&Spec::new(img::METHOD_XTS128));
    let mut image = built.image;
    let boot = image[..512].to_vec();
    image[3..11].copy_from_slice(b"MSWIN4.1");
    image[160..176].fill(0);
    image[176..200].fill(0);
    put(&mut image, 424, &boot[160..200]);
    let v = open(image).unwrap();
    assert_plain(&read_all(&unlock(&v, PASSWORD).unwrap()), &built.plain);
}

// ------------------------------------------------------------------- unlock

#[test]
fn password_unlocks_every_cipher_and_reads_the_plain_volume() {
    for method in ALL_METHODS {
        let (v, plain) = volume(&Spec::new(method));
        let source = unlock(&v, PASSWORD).unwrap();
        assert_eq!(source.len(), VOLUME_LEN as u64);
        assert_plain(&read_all(&source), &plain);
    }
}

#[test]
fn recovery_password_unlocks_with_and_without_hyphens() {
    for method in ALL_METHODS {
        let (v, plain) = volume(&Spec::new(method));
        let text = recovery_text();
        let bare: String = text.chars().filter(|c| *c != '-').collect();
        for secret in [text.clone(), bare, format!("  {text}\n")] {
            assert_plain(&read_all(&unlock(&v, &secret).unwrap()), &plain);
        }
    }
}

#[test]
fn the_first_sectors_come_from_the_relocated_header() {
    let (v, plain) = volume(&Spec::new(img::METHOD_XTS128));
    let source = unlock(&v, PASSWORD).unwrap();
    let mut head = vec![0u8; 512];
    source.read_at(0, &mut head).unwrap();
    assert_eq!(&head[3..11], b"NTFS    ");
    assert_eq!(head, plain[..512]);
}

#[test]
fn reads_that_cross_the_header_and_sector_boundaries() {
    let (v, plain) = volume(&Spec::new(img::METHOD_CBC128));
    let source = unlock(&v, PASSWORD).unwrap();
    for (offset, len) in [
        (HEADER_LEN - 3, 9),
        (HEADER_LEN - 512, 1024),
        (1, 12_000),
        (HEADER_OFF - 7, 8000),
        (HEADER_OFF + HEADER_LEN - 5, 40),
        (VOLUME_LEN - 1, 1),
        (VOLUME_LEN, 0),
        (24_576, 70_000),
    ] {
        let mut buf = vec![0u8; len];
        source.read_at(offset as u64, &mut buf).unwrap();
        assert!(buf == plain[offset..offset + len], "read {len} at {offset}");
    }
    let mut buf = [0u8; 2];
    assert!(source.read_at(VOLUME_LEN as u64 - 1, &mut buf).is_err());
    assert!(source.read_at(u64::MAX, &mut buf).is_err());
}

#[test]
fn a_volume_with_4096_byte_sectors_unlocks() {
    for method in [img::METHOD_XTS128, img::METHOD_CBC256] {
        let mut spec = Spec::new(method);
        spec.sector = 4096;
        let (v, plain) = volume(&spec);
        assert_plain(&read_all(&unlock(&v, PASSWORD).unwrap()), &plain);
    }
}

#[test]
fn sectors_past_the_encrypted_size_are_plain() {
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.encrypted_len = 32768;
    let built = img::build(&spec);
    let v = open(built.image.clone()).unwrap();
    let source = unlock(&v, PASSWORD).unwrap();
    let got = read_all(&source);
    assert!(got[..META_OFFSETS[0]] == built.plain[..META_OFFSETS[0]]);
    assert!(got[24_576..32768] == built.plain[24_576..32768]);
    // Past the encrypted size the bytes are the image's own.
    assert!(got[32768..] == built.image[32768..]);
}

#[test]
fn the_wrapped_key_inside_the_stretch_entry_is_found() {
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.nested = true;
    let (v, plain) = volume(&spec);
    assert_plain(&read_all(&unlock(&v, PASSWORD).unwrap()), &plain);
}

#[test]
fn the_full_stretch_of_1048576_rounds_runs() {
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.rounds = STRETCH_ROUNDS;
    spec.recovery = false;
    let built = img::build(&spec);
    let v = bitlocker::open(mem(built.image)).unwrap();
    let started = Instant::now();
    let source = unlock(&v, PASSWORD).unwrap();
    let took = started.elapsed();
    assert_plain(&read_all(&source), &built.plain);
    assert!(took.as_secs() < 20, "the stretch took {took:?}");
    // A wrong password costs the same and is refused.
    assert!(matches!(err(unlock(&v, "not it")), Error::WrongPassword));
}

#[test]
fn the_stretch_is_deterministic_and_depends_on_every_input() {
    let initial = img::password_initial(PASSWORD);
    let a = bitlocker::stretch(&initial, &[1u8; 16], 40);
    assert_eq!(*a, img::stretch_ref(initial, [1u8; 16], 40));
    assert_ne!(*a, *bitlocker::stretch(&initial, &[2u8; 16], 40));
    assert_ne!(*a, *bitlocker::stretch(&initial, &[1u8; 16], 41));
    assert_eq!(*bitlocker::stretch(&initial, &[1u8; 16], 0), [0u8; 32]);
}

#[test]
fn wrong_secrets_are_refused() {
    let (v, _) = volume(&Spec::new(img::METHOD_XTS128));
    for secret in [
        "",
        "atlas-tes",
        "Atlas-test",
        "atlas-test ",
        "000011-000011",
    ] {
        assert!(
            matches!(err(unlock(&v, secret)), Error::WrongPassword),
            "{secret:?}"
        );
    }
    // Well formed, every group a multiple of 11, but not this volume's.
    let other = ["000011"; 8].join("-");
    assert!(matches!(err(unlock(&v, &other)), Error::WrongPassword));
}

#[test]
fn a_recovery_password_falls_back_to_the_password_when_there_is_no_recovery_protector() {
    // A password that happens to be 48 digits.
    let digits = "000011000022000033000044000055000066000077000088";
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.recovery = false;
    let built = img::build(&spec);
    assert!(matches!(
        err(unlock(&open(built.image.clone()).unwrap(), digits)),
        Error::WrongPassword
    ));
}

#[test]
fn protectors_that_need_hardware_are_unsupported_with_a_plain_message() {
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.password = false;
    spec.recovery = false;
    spec.tpm = true;
    let (v, _) = volume(&spec);
    let Error::Unsupported(message) = err(unlock(&v, PASSWORD)) else {
        panic!("expected unsupported");
    };
    assert!(message.contains("TPM"), "{message}");
    // A password protector next to the TPM one is enough.
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.recovery = false;
    spec.tpm = true;
    let (v, _) = volume(&spec);
    assert!(unlock(&v, PASSWORD).is_ok());
    // Only the TPM and a recovery password: a password has nothing to open.
    let mut spec = Spec::new(img::METHOD_XTS128);
    spec.password = false;
    spec.tpm = true;
    let (v, _) = volume(&spec);
    assert!(matches!(err(unlock(&v, PASSWORD)), Error::Unsupported(_)));
    assert!(unlock(&v, &recovery_text()).is_ok());
}

#[test]
fn the_elephant_diffuser_and_unknown_methods_are_unsupported() {
    for method in [0x8000u16, 0x8001, 0x8006, 0x0000, 0xFFFF] {
        let mut spec = Spec::new(img::METHOD_XTS128);
        spec.method = method;
        let image = img::build(&spec).image;
        let Error::Unsupported(message) = open(image).err().unwrap() else {
            panic!("expected unsupported for {method:#x}");
        };
        if (0x8000..0x8002).contains(&method) {
            assert!(message.contains("diffuser"), "{message}");
        }
    }
}

#[test]
fn the_decrypted_source_and_the_volume_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<BitLocker>();
    let (v, _) = volume(&Spec::new(img::METHOD_XTS128));
    let source = unlock(&v, PASSWORD).unwrap();
    check::<Source>();
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                let mut b = [0u8; 600];
                source.read_at(100, &mut b).unwrap();
            });
        }
    });
}

// ------------------------------------------------------------ hostile input

#[test]
fn the_first_bad_metadata_copy_is_skipped() {
    let built = img::build(&Spec::new(img::METHOD_XTS128));
    let mut image = built.image;
    image[META_OFFSETS[0]] = b'X';
    image[META_OFFSETS[1] + 10] = 9; // version 9
    let v = open(image).unwrap();
    assert_plain(&read_all(&unlock(&v, PASSWORD).unwrap()), &built.plain);
}

#[test]
fn every_metadata_copy_bad_is_an_error() {
    let mut image = img::build(&Spec::new(img::METHOD_XTS128)).image;
    for o in META_OFFSETS {
        image[o] = 0;
    }
    assert!(open(image).is_err());
}

#[test]
fn truncated_sources_and_bad_boot_sectors_are_errors() {
    let image = img::build(&Spec::new(img::METHOD_XTS128)).image;
    for len in [0, 1, 3, 100, 511, 512, 600, 12_288, 12_400, 16_000, 20_600] {
        let _ = open(image[..len].to_vec()).err();
    }
    assert!(open(image[..511].to_vec()).is_err());
    assert!(open(image[..12_400].to_vec()).is_err());
    for bytes_per_sector in [0u16, 1, 511, 1000, 3000, 8192, 0xFFFF] {
        let mut bad = image.clone();
        put(&mut bad, 11, &bytes_per_sector.to_le_bytes());
        assert!(open(bad).is_err(), "bytes per sector {bytes_per_sector}");
    }
    let mut bad = image.clone();
    bad[3..11].copy_from_slice(b"NTFS    ");
    assert!(open(bad).is_err());
}

#[test]
fn metadata_offsets_past_the_source_or_on_each_other_are_errors() {
    let image = img::build(&Spec::new(img::METHOD_XTS128)).image;
    for offset in [
        VOLUME_LEN as u64,
        VOLUME_LEN as u64 - 50,
        u64::MAX,
        u64::MAX - 40,
        1 << 62,
    ] {
        let mut bad = image.clone();
        for i in 0..3 {
            put(&mut bad, 176 + 8 * i, &offset.to_le_bytes());
        }
        assert!(open(bad).is_err(), "offset {offset:#x}");
    }
    // Zero offsets: no copy at all.
    let mut bad = image.clone();
    bad[176..200].fill(0);
    assert!(open(bad).is_err());
    // All three the same place: read once, still fine.
    let mut same = image.clone();
    for i in 0..3 {
        put(
            &mut same,
            176 + 8 * i,
            &(META_OFFSETS[0] as u64).to_le_bytes(),
        );
    }
    assert!(open(same).is_ok());
    // Blocks that overlap each other and are not blocks where they start.
    let mut overlap = image.clone();
    for (i, o) in [
        META_OFFSETS[0] + 40,
        META_OFFSETS[0] + 80,
        META_OFFSETS[0] + 120,
    ]
    .iter()
    .enumerate()
    {
        put(&mut overlap, 176 + 8 * i, &(*o as u64).to_le_bytes());
    }
    assert!(open(overlap).is_err());
}

/// The image with every metadata offset moved to a block at `at`, which holds
/// `block`, and the room around it zero.
fn with_block(at: usize, block: &[u8]) -> Vec<u8> {
    let mut image = img::build(&Spec::new(img::METHOD_XTS128)).image;
    let need = at + block.len() + 4096;
    if image.len() < need {
        image.resize(need, 0);
    }
    put(&mut image, at, block);
    for i in 0..3 {
        put(&mut image, 176 + 8 * i, &(at as u64).to_le_bytes());
    }
    image
}

/// The entries of a good metadata block.
fn good_entries() -> Vec<u8> {
    let block = img::metadata_block(&Spec::new(img::METHOD_XTS128));
    let size = u32::from_le_bytes(block[64..68].try_into().unwrap()) as usize;
    block[112..64 + size].to_vec()
}

/// A good block header and metadata header around `entries`.
fn block_with(entries: &[u8], patch: impl Fn(&mut Vec<u8>)) -> Vec<u8> {
    let mut block = img::metadata_block(&Spec::new(img::METHOD_XTS128));
    block.truncate(112);
    let size = (48 + entries.len()) as u32;
    block[64..68].copy_from_slice(&size.to_le_bytes());
    block[76..80].copy_from_slice(&size.to_le_bytes());
    block.extend_from_slice(entries);
    patch(&mut block);
    block
}

#[test]
fn bad_entries_are_errors_not_panics() {
    let good_fvek = good_entries();
    let junk = [0xFFu8; 40];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("size 0 then junk", [vec![0u8; 8], junk.to_vec()].concat()),
        ("size 7", [7u8, 0, 0, 0, 0, 0, 0, 0].to_vec()),
        ("size 0xFFFF", {
            let mut e = entry(2, 8, &[0u8; 40]);
            e[0..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
            e
        }),
        ("size past the end", {
            let mut e = entry(2, 8, &[0u8; 40]);
            e[0] = 200;
            e
        }),
        ("one stray byte", vec![1u8]),
        ("VMK too short", entry(2, 8, &[0u8; 10])),
        ("VMK with a wrapped key too short", entry(2, 8, &[0u8; 40])),
        ("no entries at all", vec![]),
        ("only padding", vec![0u8; 64]),
        ("FVEK too short", entry(3, 5, &[1u8; 20])),
        ("wrapped key of 5000 bytes", entry(3, 5, &vec![1u8; 5000])),
        (
            "entries cut in half",
            good_fvek[..good_fvek.len() / 2].to_vec(),
        ),
    ];
    for (what, entries) in cases {
        let block = block_with(&entries, |_| {});
        let image = with_block(65_536, &block);
        let result = open(image);
        // None of these has both a protector and a key.
        assert!(result.is_err(), "{what}");
    }
    // The control: the good entries parse.
    let image = with_block(65_536, &block_with(&good_fvek, |_| {}));
    assert!(open(image).is_ok());
}

#[test]
fn too_many_entries_stop_the_walk() {
    // 5000 empty entries of 8 bytes: past the cap, and a loop that would run
    // out of the block if the cap were not there.
    let entries: Vec<u8> = (0..5000).flat_map(|_| entry(9, 9, &[])).collect();
    let block = block_with(&entries, |_| {});
    assert!(block.len() > 40_000);
    let image = with_block(65_536, &block);
    let Error::Corrupt(e) = open(image).err().unwrap() else {
        panic!("expected corruption");
    };
    assert!(e.to_string().contains("entries"), "{e}");
}

#[test]
fn bad_block_and_metadata_headers_are_errors() {
    let entries = good_entries();
    type Patch = Box<dyn Fn(&mut Vec<u8>)>;
    let cases: Vec<(&str, Patch)> = vec![
        ("signature", Box::new(|b| b[0] = 0)),
        ("block version 1", Box::new(|b| b[10] = 1)),
        ("block version 3", Box::new(|b| b[10] = 3)),
        ("metadata version", Box::new(|b| b[68] = 2)),
        ("metadata header size", Box::new(|b| b[72] = 49)),
        ("size copy", Box::new(|b| b[76] ^= 1)),
        ("size 0", Box::new(|b| b[64..68].fill(0))),
        (
            "size under the header",
            Box::new(|b| {
                b[64..68].copy_from_slice(&47u32.to_le_bytes());
                b[76..80].copy_from_slice(&47u32.to_le_bytes());
            }),
        ),
        (
            "size 4 GiB",
            Box::new(|b| {
                b[64..68].fill(0xFF);
                b[76..80].fill(0xFF);
            }),
        ),
        (
            "size past the source",
            Box::new(|b| {
                b[64..68].copy_from_slice(&900_000u32.to_le_bytes());
                b[76..80].copy_from_slice(&900_000u32.to_le_bytes());
            }),
        ),
        ("header sectors huge", Box::new(|b| b[28..32].fill(0xFF))),
        (
            "header offset past the volume",
            Box::new(|b| b[56..64].copy_from_slice(&(1u64 << 40).to_le_bytes())),
        ),
        ("header offset wraps", Box::new(|b| b[56..64].fill(0xFF))),
        (
            "header offset unaligned",
            Box::new(|b| b[56..64].copy_from_slice(&49_153u64.to_le_bytes())),
        ),
        ("method", Box::new(|b| b[100] = 0x77)),
    ];
    for (what, patch) in cases {
        let image = with_block(65_536, &block_with(&entries, &patch));
        assert!(open(image).is_err(), "{what}");
    }
}

#[test]
fn flipping_any_header_byte_never_panics() {
    let built = img::build(&Spec::new(img::METHOD_XTS128));
    let mut flipped = 0u32;
    let regions = [0..512usize, META_OFFSETS[0]..META_OFFSETS[0] + 420];
    for region in regions {
        for at in region {
            for mask in [0x01u8, 0x80, 0xFF] {
                let mut image = built.image.clone();
                image[at] ^= mask;
                if let Ok(v) = open(image) {
                    flipped += 1;
                    if let Ok(source) = unlock(&v, PASSWORD) {
                        let len = source.len();
                        let mut buf = vec![0u8; 3000];
                        for offset in [
                            0,
                            511,
                            HEADER_LEN as u64 - 5,
                            len / 2,
                            len.saturating_sub(100),
                        ] {
                            let take = usize::try_from(len.saturating_sub(offset))
                                .unwrap()
                                .min(buf.len());
                            let _ = source.read_at(offset, &mut buf[..take]);
                        }
                    }
                    let _ = unlock(&v, &recovery_text());
                }
            }
        }
    }
    assert!(flipped > 100, "only {flipped} flips still opened");
}

#[test]
fn the_decrypted_volume_is_read_only_and_bounds_checked() {
    let (v, _) = volume(&Spec::new(img::METHOD_XTS128));
    let source = unlock(&v, PASSWORD).unwrap();
    assert_eq!(source.sector_size(), 512);
    let mut one = [0u8; 1];
    assert!(source.read_at(source.len(), &mut one).is_err());
    assert!(source.read_at(source.len() - 1, &mut one).is_ok());
}

#[test]
fn a_source_with_a_partial_last_sector_loses_only_that_sector() {
    let built = img::build(&Spec::new(img::METHOD_XTS128));
    let mut image = built.image.clone();
    image.extend_from_slice(&[0xAB; 100]);
    let v = open(image).unwrap();
    assert_eq!(v.volume_len(), VOLUME_LEN as u64);
    assert_plain(&read_all(&unlock(&v, PASSWORD).unwrap()), &built.plain);
}

#[test]
fn is_bitlocker_checks_signature_and_guid() {
    let image = img::build(&Spec::new(img::METHOD_XTS128)).image;
    assert!(bitlocker::is_bitlocker(&image[..512]));
    assert!(!bitlocker::is_bitlocker(&image[..8]));
    assert!(!bitlocker::is_bitlocker(&[]));
    let mut togo = image[..512].to_vec();
    togo[3..11].copy_from_slice(b"MSWIN4.1");
    assert!(bitlocker::is_bitlocker(&togo));
    togo[160..176].fill(0);
    assert!(!bitlocker::is_bitlocker(&togo));
}
