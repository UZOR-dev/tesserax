//! Key tree primitive. Contract header:
//!
//! ```text
//! Role:      primitive (key tree crypto, no policy)
//! Forbidden: built-in labels, salts, domains, hosts, keys or any product / consumer name.
//! ```
//!
//! Every salt, label and right name is chosen by the caller. The crate only guarantees the
//! mechanics: derivation, sealing, signing without export, capabilities and branch isolation.

use std::collections::BTreeMap;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

#[cfg(feature = "capabilities")]
mod capability;
#[cfg(feature = "capabilities")]
pub use capability::{attenuate, revocation_id, unverified_fact, Authority, Issued, Verified};

/// Errors of the key tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Sealed data could not be opened with this key.
    WrongKey,
    /// Sealed data shorter than a nonce.
    Truncated,
    /// Filesystem error (kind only, never a path or content).
    Io(String),
    /// Bad identifier (branch id, fact name).
    BadId,
    /// Token malformed, not signed by this authority, or failed a check.
    BadToken,
    /// Token valid but the operation is not granted.
    Denied,
    /// Sealing failed.
    Seal,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// A 32-byte secret node of the tree (root or branch). Zeroized on drop.
pub struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    /// Fresh random secret.
    pub fn random() -> Self {
        let mut b = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *b);
        Self(b)
    }

    /// Root from an authenticator PRF output (e.g. WebAuthn `prf`): HKDF(salt, prf).expand(info).
    pub fn from_prf(prf_output: &[u8], salt: &[u8], info: &[u8]) -> Self {
        Self(hkdf32(salt, prf_output, info))
    }

    /// Child secret: HKDF(salt, self).expand(label).
    pub fn derive(&self, salt: &[u8], label: &[u8]) -> Secret {
        Secret(hkdf32(salt, &*self.0, label))
    }

    /// Walk a path of `(salt, label)` steps from this secret.
    pub fn derive_path(&self, steps: &[(&[u8], &[u8])]) -> Secret {
        let mut cur = Secret(Zeroizing::new(*self.0));
        for (salt, label) in steps {
            cur = cur.derive(salt, label);
        }
        cur
    }

    /// Public tag (hex) of this secret under `(salt, label)`, for "same secret?" checks
    /// without storing the secret.
    pub fn tag(&self, salt: &[u8], label: &[u8]) -> String {
        let t = hkdf32(salt, &*self.0, label);
        t.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Raw bytes, for the caller's own sealed store only. Never log or transmit.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }

    /// Signing handle whose seed is this secret.
    pub fn signing_handle(&self) -> KeyHandle {
        KeyHandle::from_seed(&self.0)
    }
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out).expect("32 bytes is a valid HKDF length");
    out
}

/// ed25519 signing handle. Signs and reports its public key; there is no key getter.
pub struct KeyHandle(SigningKey);

impl KeyHandle {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

/// Strict ed25519 verification.
pub fn verify_signature(public_key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else { return false };
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(signature)).is_ok()
}

/// Domain-separated message: `domain || 0 || part1 || 0 || part2 ...` (no trailing 0).
pub fn domain_message(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut m = domain.to_vec();
    for p in parts {
        m.push(0);
        m.extend_from_slice(p);
    }
    m
}

/// Seal bytes: `nonce(24) || XChaCha20-Poly1305(key, plaintext)`.
pub fn seal(key: &Secret, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&*key.0).into())
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Seal)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open bytes made by [`seal`].
pub fn open(key: &Secret, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < 24 {
        return Err(Error::Truncated);
    }
    let (nonce, ct) = sealed.split_at(24);
    XChaCha20Poly1305::new((&*key.0).into())
        .decrypt(XNonce::from_slice(nonce), ct)
        .map(Zeroizing::new)
        .map_err(|_| Error::WrongKey)
}

/// [`seal`] into `path`: written to `path.tmp` with mode 0600, then renamed.
pub fn seal_file(path: &Path, key: &Secret, plaintext: &[u8]) -> Result<(), Error> {
    let out = seal(key, plaintext)?;
    let tmp = path.with_extension("tmp");
    write_private(&tmp, &out)?;
    std::fs::rename(&tmp, path).map_err(|e| Error::Io(e.kind().to_string()))
}

/// Read and [`open`] a sealed file.
pub fn open_file(path: &Path, key: &Secret) -> Result<Zeroizing<Vec<u8>>, Error> {
    let raw = std::fs::read(path).map_err(|e| Error::Io(e.kind().to_string()))?;
    open(key, &raw)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path).and_then(|mut f| f.write_all(bytes)).map_err(|e| Error::Io(e.kind().to_string()))
}

/// Validate a branch id for use as a file stem: 1..=128 of `[A-Za-z0-9._@-]`, not starting with '.'.
pub fn branch_id(id: &str) -> Result<&str, Error> {
    let ok = !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        && !id.starts_with('.');
    ok.then_some(id).ok_or(Error::BadId)
}

/// One isolated branch per root id. A branch is inserted only after the caller opened it with
/// that root's own secret, so one root never reaches another's branch through this map.
pub struct MultiRoot<B> {
    branches: BTreeMap<String, B>,
}

impl<B> Default for MultiRoot<B> {
    fn default() -> Self {
        Self { branches: BTreeMap::new() }
    }
}

impl<B> MultiRoot<B> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn insert(&mut self, id: &str, branch: B) -> Result<(), Error> {
        self.branches.insert(branch_id(id)?.to_owned(), branch);
        Ok(())
    }
    pub fn remove(&mut self, id: &str) -> Option<B> {
        self.branches.remove(id)
    }
    pub fn get(&self, id: &str) -> Option<&B> {
        self.branches.get(id)
    }
    pub fn get_mut(&mut self, id: &str) -> Option<&mut B> {
        self.branches.get_mut(id)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &B)> {
        self.branches.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let root = Secret::from_prf(b"prf-output", b"salt-a", b"info-a");
        let a = root.derive_path(&[(b"l1", b"x"), (b"l2", b"y")]);
        let b = root.derive(b"l1", b"x").derive(b"l2", b"y");
        assert_eq!(a.expose_secret(), b.expose_secret());
        assert_ne!(root.derive(b"l1", b"x").expose_secret(), root.derive(b"l1", b"z").expose_secret());
        assert_ne!(Secret::from_prf(b"prf-output", b"salt-b", b"info-a").expose_secret(), root.expose_secret());
    }

    #[test]
    fn handle_signs_and_verifies() {
        let h = Secret::random().signing_handle();
        let m = domain_message(b"dom", &[b"who", b"op", b"payload"]);
        assert_eq!(m, b"dom\0who\0op\0payload");
        let s = h.sign(&m);
        assert!(verify_signature(&h.public_key(), &m, &s));
        assert!(!verify_signature(&h.public_key(), b"other", &s));
    }

    #[test]
    fn sealed_file_roundtrip_and_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("b.sealed");
        let k = Secret::random();
        seal_file(&p, &k, b"hello").unwrap();
        assert_eq!(&*open_file(&p, &k).unwrap(), b"hello");
        assert_eq!(open_file(&p, &Secret::random()).unwrap_err(), Error::WrongKey);
        assert_eq!(open(&k, &[0u8; 3]).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn branch_ids() {
        assert!(branch_id("alice@x").is_ok());
        assert!(branch_id("../x").is_err());
        assert!(branch_id(".x").is_err());
        assert!(branch_id("").is_err());
        let mut m = MultiRoot::new();
        m.insert("a", 1).unwrap();
        assert!(m.insert("a/b", 2).is_err());
        assert_eq!(m.get("a"), Some(&1));
    }
}
