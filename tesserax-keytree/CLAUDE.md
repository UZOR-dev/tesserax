# tesserax-keytree

Contract header. The crate docs mirror this block.

```text
Role:      primitive (key tree crypto, no policy)
Owns:      nothing persistent except sealed files it is told to write.
Exports:   Secret, KeyHandle, verify_signature, domain_message, seal_file, open_file, seal, open,
           MultiRoot, branch_id, Error; feature capabilities: Authority, Issued, Verified,
           attenuate, unverified_fact, revocation_id.
Imports:   ed25519-dalek, chacha20poly1305, hkdf, sha2, rand_core, zeroize;
           feature capabilities: biscuit-auth, hex.
Forbidden: built-in labels, salts, domains, hosts, keys or any product / consumer name. Every label
           is supplied by the caller. No getter returns a signing key.
```
