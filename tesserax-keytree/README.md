# tesserax-keytree

Key tree primitive for tesserax services.

- `Secret`: a 32-byte root (for example the output of a WebAuthn PRF evaluation) that derives
  branch secrets with HKDF-SHA256. All salts and labels come from the caller.
- `KeyHandle`: an ed25519 signing handle built from a branch secret. It signs and reports its
  public key; it never hands out the key.
- `seal_file` / `open_file`: XChaCha20-Poly1305 sealed files (`nonce || ciphertext`, mode 0600,
  atomic rename).
- `Authority` (feature `capabilities`): Biscuit tokens with caller-named facts and opaque
  rights, verification bound to a subject, attenuation to a subset of operations, and
  revocation ids for rotate / revoke.
- `MultiRoot`: one isolated branch per root; one root's secret never opens another's branch.

The crate has no policy. Which rights exist, what a branch is called and what a right unlocks is
decided by the consumer.

Licensed under either of MIT or Apache-2.0, at your option.
