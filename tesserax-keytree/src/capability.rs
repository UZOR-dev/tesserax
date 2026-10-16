//! Biscuit capabilities with caller-named facts and opaque rights.
//!
//! A token carries `name(value)` facts and `right(op, subject)` facts. Verification checks the
//! signature against the authority's root, then `allow if right(op, subject)` where `subject`
//! is read from the token's own subject fact, so a holder cannot name another subject.
//! [`attenuate`] appends a block that limits the operations the token may be used for.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use biscuit_auth::builder::{AuthorizerBuilder, BlockBuilder, Fact, Term};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey, UnverifiedBiscuit};
use zeroize::Zeroizing;

use crate::Error;

fn ident(name: &str) -> Result<&str, Error> {
    let mut b = name.bytes();
    let ok = matches!(b.next(), Some(c) if c.is_ascii_lowercase())
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        && name.len() <= 64;
    ok.then_some(name).ok_or(Error::BadId)
}

/// Token issuer and verifier (an ed25519 root key pair).
pub struct Authority(KeyPair);

/// A freshly issued token.
#[derive(Debug, Clone)]
pub struct Issued {
    pub token: String,
    /// Hex revocation id of the token's authority block.
    pub revocation_id: String,
}

/// Result of a successful verification.
#[derive(Debug, Clone)]
pub struct Verified {
    /// Requested facts read from the token.
    pub facts: BTreeMap<String, String>,
    /// Hex revocation id of the authority block (compare with the current one to rotate).
    pub revocation_id: String,
}

impl Authority {
    pub fn generate() -> Self {
        Self(KeyPair::new())
    }

    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let pk = PrivateKey::from_bytes(bytes, biscuit_auth::Algorithm::Ed25519).map_err(|_| Error::BadToken)?;
        Ok(Self(KeyPair::from(&pk)))
    }

    /// Private bytes, for the caller's own sealed store only.
    pub fn private_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.private().to_bytes().to_vec())
    }

    pub fn public_key(&self) -> PublicKey {
        self.0.public()
    }

    /// Issue a token with `facts` (each `name(value)`) and `right(r, subject)` for every right.
    pub fn issue(&self, facts: &[(&str, &str)], subject: &str, rights: &BTreeSet<String>) -> Result<Issued, Error> {
        let mut b = Biscuit::builder();
        for (name, value) in facts {
            b = b.fact(Fact::new(ident(name)?.to_owned(), vec![Term::Str((*value).to_owned())])).map_err(|_| Error::BadToken)?;
        }
        for r in rights {
            b = b
                .fact(Fact::new("right".to_owned(), vec![Term::Str(r.clone()), Term::Str(subject.to_owned())]))
                .map_err(|_| Error::BadToken)?;
        }
        let t = b.build(&self.0).map_err(|_| Error::BadToken)?;
        let revocation_id = revocation_id_of(&t)?;
        Ok(Issued { token: t.to_base64().map_err(|_| Error::BadToken)?, revocation_id })
    }

    /// Verify `token` grants `op` to the subject named by its `subject_fact`, and read `read` facts.
    pub fn verify(&self, token: &str, op: &str, subject_fact: &str, read: &[&str]) -> Result<Verified, Error> {
        let t = Biscuit::from_base64(token, self.0.public()).map_err(|_| Error::BadToken)?;
        let revocation_id = revocation_id_of(&t)?;
        let subject_fact = ident(subject_fact)?;
        let mut facts = BTreeMap::new();
        {
            let mut q = AuthorizerBuilder::new().set_limits(limits()).build(&t).map_err(|_| Error::BadToken)?;
            for name in read.iter().copied().chain(std::iter::once(subject_fact)) {
                let rule = format!("data($x) <- {}($x)", ident(name)?);
                let rows: Vec<(String,)> = q.query(rule.as_str()).map_err(|_| Error::BadToken)?;
                if let Some((v,)) = rows.into_iter().next() {
                    facts.insert(name.to_owned(), v);
                }
            }
        }
        let subject = facts.get(subject_fact).cloned().ok_or(Error::BadToken)?;
        let mut params = HashMap::new();
        params.insert("op".to_owned(), Term::Str(op.to_owned()));
        params.insert("subject".to_owned(), Term::Str(subject));
        let mut az = AuthorizerBuilder::new()
            .set_limits(limits())
            .code_with_params("operation({op}); allow if right({op}, {subject});", params, HashMap::new())
            .map_err(|_| Error::BadToken)?
            .build(&t)
            .map_err(|_| Error::BadToken)?;
        az.authorize().map_err(|_| Error::Denied)?;
        Ok(Verified { facts, revocation_id })
    }
}

/// Append a block limiting the token to `ops`. Anyone holding the token may attenuate it; the
/// result can only do less. Needs no private key.
pub fn attenuate(token: &str, root: &PublicKey, ops: &BTreeSet<String>) -> Result<String, Error> {
    let t = Biscuit::from_base64(token, *root).map_err(|_| Error::BadToken)?;
    let set: BTreeSet<Term> = ops.iter().map(|o| Term::Str(o.clone())).collect();
    let mut params = HashMap::new();
    params.insert("ops".to_owned(), Term::Set(set));
    let blk = BlockBuilder::new()
        .code_with_params("check if operation($op), {ops}.contains($op);", params, HashMap::new())
        .map_err(|_| Error::BadToken)?;
    t.append(blk).map_err(|_| Error::BadToken)?.to_base64().map_err(|_| Error::BadToken)
}

/// Revocation id of the authority block, without verifying the signature.
pub fn revocation_id(token: &str) -> Result<String, Error> {
    let t = UnverifiedBiscuit::from_base64(token).map_err(|_| Error::BadToken)?;
    Ok(hex::encode(t.revocation_identifiers().first().ok_or(Error::BadToken)?))
}

/// First `name("value")` in the authority block, unverified. Routing only (e.g. which branch
/// should verify); never an authorization decision.
pub fn unverified_fact(token: &str, name: &str) -> Result<String, Error> {
    let t = UnverifiedBiscuit::from_base64(token).map_err(|_| Error::BadToken)?;
    let src = t.print_block_source(0).map_err(|_| Error::BadToken)?;
    let pat = format!("{}(\"", ident(name)?);
    let mut from = 0;
    while let Some(i) = src[from..].find(&pat) {
        let at = from + i;
        let boundary = at == 0 || !src.as_bytes()[at - 1].is_ascii_alphanumeric() && src.as_bytes()[at - 1] != b'_';
        let start = at + pat.len();
        if boundary {
            let end = src[start..].find('"').ok_or(Error::BadToken)? + start;
            return Ok(src[start..end].to_owned());
        }
        from = start;
    }
    Err(Error::BadToken)
}

/// Datalog run limits. The library default (1 ms) fails spuriously on loaded or debug hosts.
fn limits() -> biscuit_auth::AuthorizerLimits {
    biscuit_auth::AuthorizerLimits { max_time: std::time::Duration::from_millis(100), ..Default::default() }
}

fn revocation_id_of(t: &Biscuit) -> Result<String, Error> {
    Ok(hex::encode(t.revocation_identifiers().first().ok_or(Error::BadToken)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rights(r: &[&str]) -> BTreeSet<String> {
        r.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn issue_verify_deny() {
        let a = Authority::generate();
        let i = a.issue(&[("branch", "b1"), ("subject", "s-1")], "s-1", &rights(&["read", "write"])).unwrap();
        let v = a.verify(&i.token, "read", "subject", &["branch"]).unwrap();
        assert_eq!(v.facts["branch"], "b1");
        assert_eq!(v.revocation_id, i.revocation_id);
        assert_eq!(a.verify(&i.token, "admin", "subject", &[]).unwrap_err(), Error::Denied);
        assert_eq!(Authority::generate().verify(&i.token, "read", "subject", &[]).unwrap_err(), Error::BadToken);
        assert_eq!(unverified_fact(&i.token, "branch").unwrap(), "b1");
        assert_eq!(revocation_id(&i.token).unwrap(), i.revocation_id);
    }

    #[test]
    fn rights_bound_to_own_subject() {
        let a = Authority::generate();
        // right granted for another subject does not count
        let i = a.issue(&[("subject", "s-1")], "s-2", &rights(&["read"])).unwrap();
        assert_eq!(a.verify(&i.token, "read", "subject", &[]).unwrap_err(), Error::Denied);
    }

    #[test]
    fn attenuation_narrows() {
        let a = Authority::generate();
        let i = a.issue(&[("subject", "s")], "s", &rights(&["read", "write"])).unwrap();
        let t = attenuate(&i.token, &a.public_key(), &rights(&["read"])).unwrap();
        assert!(a.verify(&t, "read", "subject", &[]).is_ok());
        assert_eq!(a.verify(&t, "write", "subject", &[]).unwrap_err(), Error::Denied);
        // attenuation keeps the authority block's revocation id
        assert_eq!(revocation_id(&t).unwrap(), i.revocation_id);
    }

    #[test]
    fn private_bytes_roundtrip() {
        let a = Authority::generate();
        let b = Authority::from_private_bytes(&a.private_bytes()).unwrap();
        let i = a.issue(&[("subject", "s")], "s", &rights(&["x"])).unwrap();
        assert!(b.verify(&i.token, "x", "subject", &[]).is_ok());
    }

    #[test]
    fn bad_fact_names_rejected() {
        let a = Authority::generate();
        assert_eq!(a.issue(&[("Bad(", "v")], "s", &rights(&[])).unwrap_err(), Error::BadId);
    }
}
