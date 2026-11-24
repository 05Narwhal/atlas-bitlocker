// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! BitLocker volumes (Windows 7 and later): reading the FVE metadata, finding
//! the volume key from a password or a recovery password and decrypting the
//! volume as it is read (AES-XTS and AES-CBC). Reading only: nothing here
//! writes.
//!
//! The sector decryption, key derivation and AES-XTS come from `atlas-luks`;
//! the AES-CCM that wraps BitLocker's keys is private to this crate. The
//! secrets (password, derived keys, the volume and full-volume keys) live in
//! [`zeroize::Zeroizing`] buffers and no key-holding type derives `Debug`.
//!
//! ```no_run
//! use std::path::Path;
//! use std::sync::Arc;
//!
//! use atlas_fs_core::io::block::BlockSource;
//! use atlas_fs_core::io::file::FileSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let source: Arc<dyn BlockSource> = Arc::new(FileSource::open(Path::new("volume.img"))?);
//! let volume = atlas_bitlocker::bitlocker::open(source)?;
//! let payload = volume.unlock_source("password")?;
//! println!("{} bytes of decrypted volume", payload.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    any(test, feature = "test-util"),
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location};

pub mod bitlocker;
mod ccm;

/// A synthetic BitLocker volume builder for tests (`test-util` only).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod bitlocker_image;
#[cfg(test)]
mod tests;

/// A damaged-header error for `structure`, with no location.
pub(crate) fn corrupt(structure: &'static str, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(structure, Location::Unspecified, kind))
}

/// A field that is missing or holds a value the format does not allow.
pub(crate) fn bad_field(structure: &'static str, field: &'static str, value: u64) -> Error {
    corrupt(structure, CorruptKind::InvalidValue { field, value })
}

/// A field that points or counts past `limit`.
pub(crate) fn out_of_range(
    structure: &'static str,
    field: &'static str,
    value: u64,
    limit_name: &'static str,
    limit: u64,
) -> Error {
    corrupt(
        structure,
        CorruptKind::OutOfRange {
            field,
            value,
            limit_name,
            limit,
        },
    )
}
