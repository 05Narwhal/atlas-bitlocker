// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! AES-CCM (RFC 3610) over the `aes` block cipher, for the keys BitLocker
//! wraps in its metadata (a 12-byte nonce, a 16-byte tag, no associated data).
//!
//! The functions take the nonce and tag lengths from their arguments, so the
//! RFC's own test vectors (8-byte tag, 13-byte nonce, associated data) run
//! through the same code. Messages are short (a wrapped key): the length
//! limits below keep the counter and the length field inside the format.

use zeroize::Zeroizing;

use atlas_luks::kdf::ct_eq;
use atlas_luks::xts::AesKey;

/// The longest message accepted. A wrapped key is a few dozen bytes.
pub(crate) const MAX_MESSAGE: usize = 4096;

/// What `B0` and the counter blocks are made of for one message.
struct Params {
    /// Bytes of the length field and the counter, `15 - nonce length`.
    l: usize,
    /// Tag length in bytes.
    m: usize,
}

fn params(nonce: &[u8], tag_len: usize) -> Option<Params> {
    let l = 15usize.checked_sub(nonce.len())?;
    let ok = (2..=8).contains(&l) && (4..=16).contains(&tag_len) && tag_len.is_multiple_of(2);
    ok.then_some(Params { l, m: tag_len })
}

/// Counter block `A_i`: flags, nonce, the counter big-endian in `l` bytes.
fn counter_block(p: &Params, nonce: &[u8], counter: u64) -> Option<[u8; 16]> {
    let mut block = [0u8; 16];
    *block.first_mut()? = u8::try_from(p.l.checked_sub(1)?).ok()?;
    block
        .get_mut(1..1usize.checked_add(nonce.len())?)?
        .copy_from_slice(nonce);
    let be = counter.to_be_bytes();
    let tail = be.get(8usize.checked_sub(p.l)?..)?;
    block
        .get_mut(16usize.checked_sub(p.l)?..)?
        .copy_from_slice(tail);
    Some(block)
}

/// XORs the CTR keystream (blocks `A_1`, `A_2`, ...) into `data`.
fn apply_keystream(key: &AesKey, p: &Params, nonce: &[u8], data: &mut [u8]) -> Option<()> {
    for (n, chunk) in data.chunks_mut(16).enumerate() {
        let counter = u64::try_from(n).ok()?.checked_add(1)?;
        // A keystream block with the ciphertext gives the plaintext: wipe it.
        let mut stream = Zeroizing::new(counter_block(p, nonce, counter)?);
        key.encrypt(&mut *stream);
        for (b, s) in chunk.iter_mut().zip(stream.iter()) {
            *b ^= *s;
        }
    }
    Some(())
}

/// The CBC-MAC of `B0`, the associated data and the message, before it is
/// encrypted with `S0`.
fn cbc_mac(
    key: &AesKey,
    p: &Params,
    nonce: &[u8],
    aad: &[u8],
    message: &[u8],
) -> Option<Zeroizing<[u8; 16]>> {
    // The running value depends on the plaintext: wiped on drop.
    let mut x = Zeroizing::new([0u8; 16]);
    // B0: flags, nonce, message length in `l` bytes.
    let adata = u8::from(!aad.is_empty());
    let flags = (adata << 6)
        | (u8::try_from(p.m.checked_sub(2)?.checked_div(2)?).ok()? << 3)
        | u8::try_from(p.l.checked_sub(1)?).ok()?;
    let mut b0 = [0u8; 16];
    *b0.first_mut()? = flags;
    b0.get_mut(1..1usize.checked_add(nonce.len())?)?
        .copy_from_slice(nonce);
    let len = u64::try_from(message.len()).ok()?.to_be_bytes();
    b0.get_mut(16usize.checked_sub(p.l)?..)?
        .copy_from_slice(len.get(8usize.checked_sub(p.l)?..)?);
    absorb(key, &mut x, &b0);
    if !aad.is_empty() {
        // Only the two-byte length form: the associated data is short here.
        let n = u16::try_from(aad.len()).ok().filter(|&n| n < 0xFF00)?;
        let mut first = Vec::with_capacity(aad.len().checked_add(2)?);
        first.extend_from_slice(&n.to_be_bytes());
        first.extend_from_slice(aad);
        absorb_padded(key, &mut x, &first);
    }
    absorb_padded(key, &mut x, message);
    Some(x)
}

fn absorb(key: &AesKey, x: &mut [u8; 16], block: &[u8; 16]) {
    for (a, b) in x.iter_mut().zip(block) {
        *a ^= *b;
    }
    key.encrypt(x);
}

fn absorb_padded(key: &AesKey, x: &mut [u8; 16], data: &[u8]) {
    for chunk in data.chunks(16) {
        let mut block = Zeroizing::new([0u8; 16]);
        for (dst, src) in block.iter_mut().zip(chunk) {
            *dst = *src;
        }
        absorb(key, x, &block);
    }
}

/// `S0`, the keystream block that hides the tag.
fn tag_mask(key: &AesKey, p: &Params, nonce: &[u8]) -> Option<Zeroizing<[u8; 16]>> {
    let mut s0 = Zeroizing::new(counter_block(p, nonce, 0)?);
    key.encrypt(&mut *s0);
    Some(s0)
}

/// Decrypts `data` (a message encrypted with AES-CCM) and checks `tag`.
///
/// Returns the plaintext, or `None` when the tag does not match (the key or
/// the data is wrong) or an argument is outside what CCM allows. The tag is
/// compared in constant time.
pub(crate) fn decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
    tag: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let p = params(nonce, tag.len())?;
    if data.len() > MAX_MESSAGE {
        return None;
    }
    let aes = AesKey::new(key)?;
    let mut plain = Zeroizing::new(data.to_vec());
    apply_keystream(&aes, &p, nonce, &mut plain)?;
    let mac = cbc_mac(&aes, &p, nonce, aad, &plain)?;
    let mask = tag_mask(&aes, &p, nonce)?;
    let mut expected = Zeroizing::new([0u8; 16]);
    for (e, (m, s)) in expected.iter_mut().zip(mac.iter().zip(mask.iter())) {
        *e = *m ^ *s;
    }
    let expected = expected.get(..p.m)?;
    ct_eq(expected, tag).then_some(plain)
}

/// Encrypts `data` and returns it with its tag, for building test volumes.
#[cfg(any(test, feature = "test-util"))]
pub(crate) fn encrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
    tag_len: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let p = params(nonce, tag_len)?;
    let aes = AesKey::new(key)?;
    let mac = cbc_mac(&aes, &p, nonce, aad, data)?;
    let mask = tag_mask(&aes, &p, nonce)?;
    let tag: Vec<u8> = mac
        .iter()
        .zip(mask.iter())
        .map(|(m, s)| m ^ s)
        .take(tag_len)
        .collect();
    let mut out = data.to_vec();
    apply_keystream(&aes, &p, nonce, &mut out)?;
    Some((out, tag))
}
