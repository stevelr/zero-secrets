# zero-secrets

[![License](https://img.shields.io/crates/l/zero-secrets.svg)](https://crates.io/crates/zero-secrets)
[![Latest version](https://img.shields.io/crates/v/zero-secrets.svg)](https://crates.io/crates/zero-secrets)
[![Latest Docs](https://docs.rs/zero-secrets/badge.svg)](https://docs.rs/zero-secrets/)
[![downloads-badge](https://img.shields.io/crates/d/zero-secrets.svg)](https://crates.io/crates/zero-secrets)

[API docs](https://docs.rs/zero-secrets/)

Simple lightweight secret wrappers that zeroize on drop and prevent accidental logging.
Built on RustCrypto [`zeroize`](https://crates.io/crates/zeroize)

Like `secrecy` but with fewer heap allocations.

# Usage

The crate provides three owned wrappers, each zeroizing its backing storage on
drop and redacting `Debug`:

- `SecretString` — owns a heap `String` (seeds, `.creds` text, invite codes).
- `SecretBytes` — owns a heap `Vec<u8>` (decrypted buffers, credential blobs).
- `SecretArray<N>` — owns a fixed-size `[u8; N]` (X25519 seeds, AEAD keys).

## Wrapping and reading a secret

Wrap an owned value, then borrow it through `expose_secret` for use. The borrow
never takes ownership, and the secret is still zeroized when the wrapper drops.

```rust
use zero_secrets::SecretString;

let secret = SecretString::new("hunter2".to_string());

// Borrow as &str without taking ownership.
assert_eq!(secret.expose_secret(), "hunter2");
assert_eq!(secret.len(), 7);
assert!(!secret.is_empty());

// The backing String is zeroized here, when `secret` is dropped.
```

`From` is implemented for ergonomic construction:

```rust
use zero_secrets::SecretString;

let secret: SecretString = "abc".to_string().into();
assert_eq!(secret.expose_secret(), "abc");
```

## Bytes and fixed-size keys

```rust
use zero_secrets::{SecretBytes, SecretArray};

// Heap-backed bytes (e.g. a decrypted plaintext buffer).
let blob = SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef]);
assert_eq!(blob.expose_secret(), &[0xde, 0xad, 0xbe, 0xef]);

// Stack-backed fixed-size key material (e.g. a 32-byte AEAD key).
let key = SecretArray::<32>::new([7u8; 32]);
assert_eq!(key.expose_secret(), &[7u8; 32]);
assert_eq!(key.len(), 32);
```

## Debug is redacted

`Debug` never prints the contents — or even the length — so a secret can't leak
through a stray `{:?}`. `Display` is intentionally not implemented, so `{}` does
not compile.

```rust
use zero_secrets::SecretString;

let secret = SecretString::new("super-secret-seed".to_string());
assert_eq!(format!("{secret:?}"), "SecretString(REDACTED)");
```

## Clone is an independent, independently-zeroized copy

A clone owns its own allocation; dropping one does not affect the other, and
both zeroize on their own drop. This holds for clones moved into async
blocks/tasks.

```rust
use zero_secrets::SecretBytes;

let original = SecretBytes::new(vec![10, 20, 30]);
let cloned = original.clone();

assert_eq!(original.expose_secret(), cloned.expose_secret());
drop(cloned); // independent allocation; `original` is untouched
assert_eq!(original.expose_secret(), &[10, 20, 30]);
```

## Handing ownership out of the library

When a secret must cross the library boundary, the `#[must_use]` extractors
return the plain owned value. The moved-out value is intentionally **not**
zeroized — that is the point of the handoff, and the caller then owns leak
prevention. The wrapper is consumed, so no wrapped copy lingers.

```rust
use zero_secrets::{SecretString, SecretBytes, SecretArray};

let s = SecretString::new("seed".to_string()).into_string(); // -> String
let v = SecretBytes::new(vec![1, 2, 3]).into_vec();          // -> Vec<u8>
let k = SecretArray::<4>::new([1, 2, 3, 4]).into_inner();    // -> [u8; 4]
```

## Recommended policy

These wrappers are designed to be **internal** to your crate around private fields.
Keep `Secret*` types out of your public API: accept `&str` / `&[u8]` in your inputs,
and return borrowed accessors via `expose_secret` for normal use. Use plain owned
extractors only when ownership must leave the boundary.
`serde::Serialize` / `Deserialize` are intentionally not implemented.
If serializing is needed, it should be in targeted, auditable call-sites.

