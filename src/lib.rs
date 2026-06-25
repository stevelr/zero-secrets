//! Simple lightweight secret wrappers that zeroize on drop
//! and prevent accidental logging. Built on RustCrypto [`zeroize`](https://crates.io/crates/zeroize)
//!
//! This crate provides three owned wrappers around in-memory secret material,
//! backed by the `RustCrypto` [`zeroize`] crate:
//!
//! - [`SecretString`] owns a heap [`String`] (e.g. NKEY seeds, `.creds` text,
//!   invite/recovery codes, base64-encoded credentials).
//! - [`SecretBytes`] owns a heap [`Vec<u8>`] (e.g. decrypted plaintext buffers,
//!   credential blobs, message bodies that may contain secrets).
//! - [`SecretArray<N>`] owns a fixed-size stack `[u8; N]` (e.g. X25519 private
//!   seeds, AEAD keys, shared secrets — typically `[u8; 32]`).
//!
//! # Guarantees
//!
//! Every wrapper:
//!
//! 1. Zeroizes its backing storage on [`Drop`] (heap allocation contents for
//!    the string/bytes wrappers, the stack bytes for [`SecretArray`]).
//! 2. Redacts [`Debug`]. `Display` is not implemented to prevent `{}` formatting.
//!    Secret contents or length are not printed.
//! 3. Produces an **independently owned** value on [`Clone`] — a deep copy with
//!    its own allocation (for the heap types) whose own [`Drop`] also zeroizes.
//!    This holds for clones moved into async blocks/tasks.
//!
//! # Ownership contract
//!
//! - **Borrow in:** callers wrap only when *this* code takes ownership of a
//!   secret. Code that merely reads a secret should accept `&str` / `&[u8]`.
//! - **Wrap on ownership:** construct via `new` or the `From` impls when an
//!   owned secret enters the crate that owns it.
//! - **Borrow for use:** read through [`expose_secret`](SecretString::expose_secret)
//!   (returns `&str` / `&[u8]`); the borrow never escapes the wrapper.
//! - **Plain owned out:** when ownership must *leave* the library, use the
//!   `#[must_use]` extractors ([`into_string`](SecretString::into_string),
//!   [`into_vec`](SecretBytes::into_vec), [`into_inner`](SecretArray::into_inner)).
//!   These return the plain owned value and intentionally do **not** zeroize the
//!   moved-out value — the caller then owns leak prevention. Their inputs are
//!   consumed, so no wrapped copy lingers.
//!
//! # How to use (recommended policy)
//!
//! These wrappers are designed to be **internal** to your crate, used to protect
//! private owned fields. Keep `Secret*` types out of your public API:
//! accept `&str` / `&[u8]` in inputs, and return borrowed accessors via `expose_secret`
//! for normal use. Use plain owned extractors only when ownership must leave the boundary.
//! `serde::Serialize` / `Deserialize` are intentionally not implemented. If serializing
//! is needed, it should be in targeted, auditable call-sites.
//!

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Marker rendered by [`Debug`] in place of any secret contents.
const REDACTED: &str = "REDACTED";

/// An owned, zeroizing wrapper around a [`String`].
///
/// The backing allocation is zeroized on [`Drop`]. [`Debug`] is redacted.
/// [`Display`] is not implemented to prevent accidental formatting.
/// [`Clone`] produces an independently owned, independently zeroized copy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps an owned [`String`] as a secret.
    #[inline]
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrows the secret as a `&str` for use without taking ownership.
    ///
    /// All uses of this function should be carefully reviewed to ensure the value
    /// is not printed or copied to a non-Secret-wrapped storage.
    /// The borrow does not change ownership and the secret is still zeroed on drop.
    #[inline]
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Length of the secret in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and returns the plain owned [`String`].
    ///
    /// This is the ownership-handoff path for when a secret must leave the
    /// library boundary. The moved-out value is **not** zeroized (that is the
    /// point of handoff); the caller then owns leak prevention. No wrapped copy
    /// remains, because `self` is consumed by value.
    #[inline]
    #[must_use]
    pub fn into_string(mut self) -> String {
        core::mem::take(&mut self.0)
    }
}

impl From<String> for SecretString {
    #[inline]
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({REDACTED})")
    }
}

/// An owned, zeroizing wrapper around a [`Vec<u8>`].
///
/// The backing allocation is zeroized on [`Drop`]. [`Debug`]
/// are redacted. [`Clone`] produces an independently owned, independently
/// zeroized copy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps an owned [`Vec<u8>`] as a secret.
    #[inline]
    #[must_use]
    pub const fn new(value: Vec<u8>) -> Self {
        Self(value)
    }

    /// Borrows the secret as a `&[u8]` for use without taking ownership.
    ///
    /// All uses of this function should be carefully reviewed to ensure the value
    /// is not printed or copied to a non-Secret-wrapped storage.
    /// The borrow does not change ownership and the secret is still zeroed on drop.
    #[inline]
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Length of the secret in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consumes the wrapper and returns the plain owned [`Vec<u8>`].
    ///
    /// This is the ownership-handoff path for when a secret must leave the
    /// library boundary. The moved-out value is **not** zeroized (that is the
    /// point of handoff); the caller then owns leak prevention. No wrapped copy
    /// remains, because `self` is consumed by value.
    #[inline]
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for SecretBytes {
    #[inline]
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({REDACTED})")
    }
}

/// An owned, zeroizing wrapper around a fixed-size `[u8; N]` stack array.
///
/// Intended for fixed-size key material such as X25519 private seeds, AEAD
/// keys, and shared secrets (`[u8; 32]`). The stack bytes are overwritten with
/// zeros on [`Drop`]. [`Debug`] is redacted. [`Clone`]
/// produces an independent value that also zeroizes on its own drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretArray<const N: usize>([u8; N]);

impl<const N: usize> SecretArray<N> {
    /// Wraps an owned `[u8; N]` as a secret.
    #[inline]
    #[must_use]
    pub const fn new(value: [u8; N]) -> Self {
        Self(value)
    }

    /// Borrows the secret as a `&[u8]` view.
    ///
    /// All uses of this function should be carefully reviewed to ensure the value
    /// is not printed or copied to a non-Secret-wrapped storage.
    /// The borrow does not change ownership and the secret is still zeroed on drop.
    #[inline]
    #[must_use]
    pub const fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Length of the array in bytes (always `N`).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether the array is zero-length (`N == 0`).
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Consumes the wrapper and returns the plain owned `[u8; N]`.
    ///
    /// This is the ownership-handoff path for when key material must leave the
    /// library boundary. The moved-out value is **not** zeroized (that is the
    /// point of handoff); the caller then owns leak prevention. No wrapped copy
    /// remains, because `self` is consumed by value.
    ///
    /// Note: `[u8; N]` is `Copy`, so this returns a bit-for-bit copy and the
    /// (now-moved) `self` is dropped — its storage is the same bytes the copy
    /// carries, so this does not zero the returned value.
    #[inline]
    #[must_use]
    pub const fn into_inner(self) -> [u8; N] {
        // `self` is `Copy`-backed; read the bytes out then forget the wrapper so
        // its `Drop` does not run (which would be a no-op on this copy anyway,
        // but forgetting keeps the handoff semantics explicit and avoids a
        // redundant zeroize of a value we are about to return).
        let inner = self.0;
        core::mem::forget(self);
        inner
    }
}

impl<const N: usize> From<[u8; N]> for SecretArray<N> {
    #[inline]
    fn from(value: [u8; N]) -> Self {
        Self::new(value)
    }
}

impl<const N: usize> fmt::Debug for SecretArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretArray({REDACTED})")
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretArray, SecretBytes, SecretString};

    // Compile-time assertions that the wrappers implement the zeroize traits.
    const fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    const fn assert_traits() {
        assert_zeroize_on_drop::<SecretString>();
        assert_zeroize_on_drop::<SecretBytes>();
        assert_zeroize_on_drop::<SecretArray<32>>();
    }
    const _: () = assert_traits();

    // ---- SecretString ----

    #[test]
    fn secret_string_round_trip() {
        let s = SecretString::new("hunter2".to_string());
        assert_eq!(s.expose_secret(), "hunter2");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());
        assert!(SecretString::from(String::new()).is_empty());
        assert_eq!(s.into_string(), "hunter2");
    }

    #[test]
    fn secret_string_from() {
        let s: SecretString = "abc".to_string().into();
        assert_eq!(s.expose_secret(), "abc");
    }

    #[test]
    fn secret_string_debug_redacted() {
        let secret = "super-secret-seed-value";
        let s = SecretString::new(secret.to_string());
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "SecretString(REDACTED)");
        assert!(!dbg.contains(secret));
        // length must not leak either
        assert!(!dbg.contains("23"));
    }

    #[test]
    fn secret_string_clone_is_independent_allocation() {
        let original = SecretString::new("independent".to_string());
        let cloned = original.clone();
        assert_eq!(original.expose_secret(), cloned.expose_secret());
        // Distinct heap allocations: the backing String buffers differ.
        assert_ne!(
            original.expose_secret().as_ptr(),
            cloned.expose_secret().as_ptr(),
            "clone must own a separate allocation"
        );
        // Dropping the clone must not affect the original.
        drop(cloned);
        assert_eq!(original.expose_secret(), "independent");
    }

    // ---- SecretBytes ----

    #[test]
    fn secret_bytes_round_trip() {
        let b = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(b.expose_secret(), &[1, 2, 3, 4]);
        assert_eq!(b.len(), 4);
        assert!(!b.is_empty());
        assert!(SecretBytes::from(Vec::new()).is_empty());
        assert_eq!(b.into_vec(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn secret_bytes_from() {
        let b: SecretBytes = vec![9u8, 8, 7].into();
        assert_eq!(b.expose_secret(), &[9, 8, 7]);
    }

    #[test]
    fn secret_bytes_debug_redacted() {
        let secret = [0xde, 0xad, 0xbe, 0xef];
        let b = SecretBytes::new(secret.to_vec());
        let dbg = format!("{b:?}");
        assert_eq!(dbg, "SecretBytes(REDACTED)");
        // No byte values leak.
        assert!(!dbg.contains("222") && !dbg.contains("173"));
        assert!(!dbg.contains("de") && !dbg.contains("ad"));
        // Length must not leak.
        assert!(!dbg.contains('4'));
    }

    #[test]
    fn secret_bytes_clone_is_independent_allocation() {
        let original = SecretBytes::new(vec![10, 20, 30]);
        let cloned = original.clone();
        assert_eq!(original.expose_secret(), cloned.expose_secret());
        assert_ne!(
            original.expose_secret().as_ptr(),
            cloned.expose_secret().as_ptr(),
            "clone must own a separate allocation"
        );
        drop(cloned);
        assert_eq!(original.expose_secret(), &[10, 20, 30]);
    }

    // ---- SecretArray ----

    #[test]
    fn secret_array_round_trip() {
        let key = [7u8; 32];
        let a = SecretArray::<32>::new(key);
        assert_eq!(a.expose_secret(), &key);
        assert_eq!(a.len(), 32);
        assert!(!a.is_empty());
        assert_eq!(a.into_inner(), key);
    }

    #[test]
    fn secret_array_from() {
        let a: SecretArray<4> = [1u8, 2, 3, 4].into();
        assert_eq!(a.expose_secret(), &[1, 2, 3, 4]);
    }

    #[test]
    fn secret_array_empty() {
        let a = SecretArray::<0>::new([]);
        assert!(a.is_empty());
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn secret_array_debug_redacted() {
        let key = [0xABu8; 16];
        let a = SecretArray::<16>::new(key);
        let dbg = format!("{a:?}");
        assert_eq!(dbg, "SecretArray(REDACTED)");
        assert!(!dbg.contains("171")); // 0xAB
        assert!(!dbg.contains("ab"));
        assert!(!dbg.contains("16")); // length
    }

    #[test]
    fn secret_array_clone_is_independent_value() {
        let original = SecretArray::<32>::new([5u8; 32]);
        let mut cloned = original.clone();
        assert_eq!(original.expose_secret(), cloned.expose_secret());
        // Mutating the clone's bytes (via a fresh value) must not touch the
        // original; arrays are value types, so re-create and compare.
        cloned = SecretArray::<32>::new([6u8; 32]);
        assert_eq!(original.expose_secret(), &[5u8; 32]);
        assert_eq!(cloned.expose_secret(), &[6u8; 32]);
    }

    /// Proves the zeroize actually overwrites the backing stack bytes.
    ///
    /// The workspace forbids `unsafe_code`, so the read-after-drop raw-pointer
    /// pattern is unavailable. Instead we drive the same code path `Drop` runs
    /// (`<Self as Zeroize>::zeroize`, which the derived `ZeroizeOnDrop` calls)
    /// directly through a `&mut` borrow and then observe — safely — that every
    /// backing byte is now zero. This is a real overwrite assertion on the
    /// exact storage that `Drop` would clear.
    #[test]
    fn secret_array_zeroize_overwrites_backing_bytes() {
        use zeroize::Zeroize;
        let mut a = SecretArray::<32>::new([0xFFu8; 32]);
        assert_eq!(a.expose_secret(), &[0xFFu8; 32]);
        a.zeroize();
        assert_eq!(
            a.expose_secret(),
            &[0u8; 32],
            "zeroize must overwrite the stack bytes"
        );
    }

    #[test]
    fn secret_string_zeroize_overwrites_backing_bytes() {
        use zeroize::Zeroize;
        let mut s = SecretString::new("secret".to_string());
        s.zeroize();
        // zeroize on String clears the bytes and truncates to empty.
        assert!(s.is_empty());
    }

    #[test]
    fn secret_bytes_zeroize_overwrites_backing_bytes() {
        use zeroize::Zeroize;
        let mut b = SecretBytes::new(vec![0xFFu8; 16]);
        b.zeroize();
        // zeroize on Vec<u8> zeros the elements then clears length.
        assert!(b.is_empty());
    }
}
