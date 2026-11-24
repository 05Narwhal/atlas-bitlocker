# atlas-bitlocker

Reads BitLocker volumes (Windows 7 and later). `bitlocker::open` parses the FVE metadata, `BitLocker::unlock_source` finds the volume key from a password or a recovery password and returns a `BlockSource` that decrypts the volume sector by sector (AES-XTS, AES-CBC). Built on `atlas-luks`.

- **Not yet verified against a volume made by Windows**: the tests use a synthetic volume built from the public description, plus the RFC 3610 and IEEE 1619 vectors.
- `bitlocker::mount(source, mounter)` gives one locked volume whose `unlock` decrypts the volume and passes it to the `Mounter` you supply.
- Protectors that need hardware or a key file (TPM, startup key) are skipped; the elephant diffuser is not supported.
- Secrets live in `Zeroizing` buffers; no key-holding type derives `Debug`.
- No `unsafe`. Every length, offset and count read from the disk is checked; damage is an error, not a panic.

## Licence

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or MIT license
([LICENSE-MIT](LICENSE-MIT)) at your option.
