//! Key generation, secret handling and encryption at rest.
//!
//! * Payment wallets are fresh sr25519 coldkeys derived from a 24-word BIP39 mnemonic whose
//!   256-bit entropy comes from the OS CSPRNG ([`rand_core::OsRng`] -> `getrandom`).
//! * Mnemonics live in [`zeroize::Zeroizing`] buffers and have no `Debug`/`Display`/`Serialize`.
//! * At rest they are sealed with XChaCha20-Poly1305 under a 256-bit master key. The payment id and
//!   deposit address are bound in as associated data, so a ciphertext cannot be swapped onto
//!   another record.

use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;
use zeroize::{Zeroize, Zeroizing};

/// SS58 address (generic substrate prefix 42, what Bittensor uses) of a public key.
pub fn ss58(account: &AccountId32) -> String {
    account.to_string()
}

/// Parse an SS58 address.
pub fn parse_ss58(s: &str) -> Result<AccountId32> {
    s.parse()
        .map_err(|e| Error::Config(format!("bad ss58 address {s:?}: {e:?}")))
}

/// A freshly generated payment wallet. Holds the mnemonic only in zeroizing memory.
pub struct PaymentWallet {
    phrase: Zeroizing<String>,
    keypair: Keypair,
}

impl std::fmt::Debug for PaymentWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentWallet")
            .field("address", &ss58(&self.account_id()))
            .finish_non_exhaustive()
    }
}

impl PaymentWallet {
    /// Generate a new wallet from 256 bits of OS randomness.
    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(entropy.as_mut());
        let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        Self::from_phrase(Zeroizing::new(mnemonic.to_string()))
    }

    /// Rebuild a wallet from a stored mnemonic.
    pub fn from_phrase(phrase: Zeroizing<String>) -> Result<Self> {
        let mnemonic =
            bip39::Mnemonic::parse(phrase.as_str()).map_err(|e| Error::Crypto(e.to_string()))?;
        let keypair =
            Keypair::from_phrase(&mnemonic, None).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Self { phrase, keypair })
    }

    pub fn account_id(&self) -> AccountId32 {
        self.keypair.public_key().to_account_id()
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Seal the mnemonic for storage.
    pub fn seal(&self, key: &MasterKey, aad: &[u8]) -> Result<SealedSecret> {
        key.seal(self.phrase.as_bytes(), aad)
    }

    /// Open a sealed mnemonic.
    pub fn unseal(key: &MasterKey, sealed: &SealedSecret, aad: &[u8]) -> Result<Self> {
        let bytes = key.open(sealed, aad)?;
        let phrase = String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::Crypto("sealed secret is not utf-8".into()))?;
        Self::from_phrase(Zeroizing::new(phrase))
    }
}

/// Associated data binding a sealed wallet secret to its payment record.
pub fn wallet_aad(payment_id: &str, address: &str) -> Vec<u8> {
    format!("bittensor-buyback/v1/{payment_id}/{address}").into_bytes()
}

/// 256-bit master key. Zeroized on drop, never printed.
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let k = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        k
    }

    /// Parse 64 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut buf = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(s.trim().trim_start_matches("0x"), buf.as_mut())
            .map_err(|_| Error::Config("master key must be 32 bytes of hex".into()))?;
        Ok(Self(buf))
    }

    /// Read from an env var holding 64 hex chars. KMS users: decrypt the data key in your
    /// entrypoint and export it here, or call [`MasterKey::from_bytes`] directly.
    pub fn from_env(var: &str) -> Result<Self> {
        let v = Zeroizing::new(
            std::env::var(var).map_err(|_| Error::Config(format!("{var} is not set")))?,
        );
        Self::from_hex(&v)
    }

    /// New random key (for `gen-master-key`).
    pub fn generate() -> Self {
        let mut buf = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(buf.as_mut());
        Self(buf)
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0.as_ref()))
    }

    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret> {
        let cipher = XChaCha20Poly1305::new(self.0.as_ref().into());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("encryption failed".into()))?;
        Ok(SealedSecret {
            v: 1,
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
        })
    }

    pub fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.v != 1 {
            return Err(Error::Crypto(format!(
                "unknown sealed version {}",
                sealed.v
            )));
        }
        let bad = || Error::Crypto("corrupt sealed secret".into());
        let nonce = hex::decode(&sealed.nonce).map_err(|_| bad())?;
        if nonce.len() != 24 {
            return Err(bad());
        }
        let ct = hex::decode(&sealed.ct).map_err(|_| bad())?;
        let cipher = XChaCha20Poly1305::new(self.0.as_ref().into());
        cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto("decryption failed (wrong key or tampered data)".into()))
    }
}

/// An encrypted secret as stored on disk / in the database.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub v: u8,
    pub nonce: String,
    pub ct: String,
}

impl std::fmt::Debug for SealedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedSecret(..)")
    }
}

/// Where the treasury coldkey comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreasuryKeySource {
    /// Env var holding a secret URI: a mnemonic, optionally with derivation (`<phrase>//hard/soft`),
    /// or a dev URI like `//Alice` (localnet only).
    EnvUri(String),
    /// File holding a secret URI / mnemonic (chmod 600).
    MnemonicFile(std::path::PathBuf),
    /// JSON file holding a [`SealedSecret`] of a secret URI, sealed with the master key
    /// (associated data `bittensor-buyback/v1/treasury`). Create with `buyback seal-treasury`.
    EncryptedKeystore(std::path::PathBuf),
}

pub const TREASURY_AAD: &[u8] = b"bittensor-buyback/v1/treasury";

impl TreasuryKeySource {
    pub fn load(&self, master: Option<&MasterKey>) -> Result<Keypair> {
        let uri: Zeroizing<String> = match self {
            Self::EnvUri(var) => Zeroizing::new(
                std::env::var(var).map_err(|_| Error::Config(format!("{var} is not set")))?,
            ),
            Self::MnemonicFile(p) => Zeroizing::new(
                std::fs::read_to_string(p)
                    .map_err(|e| Error::Config(format!("read {}: {e}", p.display())))?,
            ),
            Self::EncryptedKeystore(p) => {
                let master = master
                    .ok_or_else(|| Error::Config("encrypted keystore needs a master key".into()))?;
                let raw = Zeroizing::new(
                    std::fs::read_to_string(p)
                        .map_err(|e| Error::Config(format!("read {}: {e}", p.display())))?,
                );
                let sealed: SealedSecret = serde_json::from_str(&raw)
                    .map_err(|_| Error::Config("keystore is not a sealed secret".into()))?;
                let bytes = master.open(&sealed, TREASURY_AAD)?;
                Zeroizing::new(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| Error::Crypto("keystore is not utf-8".into()))?,
                )
            }
        };
        keypair_from_uri(uri.trim())
    }
}

/// Build an sr25519 keypair from a secret URI (mnemonic or `//Dev` path).
pub fn keypair_from_uri(uri: &str) -> Result<Keypair> {
    let uri: SecretUri = uri
        .parse()
        .map_err(|_| Error::Config("invalid secret uri".into()))?;
    Keypair::from_uri(&uri).map_err(|_| Error::Config("invalid secret uri".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn keygen_is_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let w = PaymentWallet::generate().unwrap();
            let addr = ss58(&w.account_id());
            assert!(addr.starts_with('5'), "prefix 42 addresses start with 5");
            assert_eq!(parse_ss58(&addr).unwrap(), w.account_id());
            assert_eq!(w.phrase.split_whitespace().count(), 24);
            assert!(seen.insert(addr));
        }
    }

    #[test]
    fn keygen_randomness_bit_balance() {
        // 200 public keys * 256 bits: the fraction of set bits must be close to 1/2.
        let ones: u32 = (0..200)
            .map(|_| PaymentWallet::generate().unwrap().account_id().0)
            .map(|k| k.iter().map(|b| b.count_ones()).sum::<u32>())
            .sum();
        let frac = ones as f64 / (200.0 * 256.0);
        assert!((0.47..0.53).contains(&frac), "bit balance {frac}");
    }

    #[test]
    fn debug_never_leaks_secret() {
        let w = PaymentWallet::generate().unwrap();
        let first_word = w.phrase.split_whitespace().next().unwrap().to_string();
        let dbg = format!("{w:?} {:?}", MasterKey::generate());
        assert!(!dbg.contains(&*w.phrase));
        assert!(!dbg.contains(&format!(" {first_word} ")));
    }

    #[test]
    fn seal_roundtrip_and_tamper_detection() {
        let key = MasterKey::generate();
        let w = PaymentWallet::generate().unwrap();
        let addr = ss58(&w.account_id());
        let aad = wallet_aad("id-1", &addr);
        let sealed = w.seal(&key, &aad).unwrap();
        assert!(!sealed.ct.contains(&hex::encode(w.phrase.as_bytes())));

        let back = PaymentWallet::unseal(&key, &sealed, &aad).unwrap();
        assert_eq!(back.account_id(), w.account_id());

        // wrong key
        assert!(PaymentWallet::unseal(&MasterKey::generate(), &sealed, &aad).is_err());
        // wrong record binding
        assert!(PaymentWallet::unseal(&key, &sealed, &wallet_aad("id-2", &addr)).is_err());
        // flipped ciphertext bit
        let mut t = sealed.clone();
        let mut ct = hex::decode(&t.ct).unwrap();
        ct[0] ^= 1;
        t.ct = hex::encode(ct);
        assert!(PaymentWallet::unseal(&key, &t, &aad).is_err());
        // nonces are random
        assert_ne!(w.seal(&key, &aad).unwrap().nonce, sealed.nonce);
    }

    #[test]
    fn master_key_hex() {
        let k = MasterKey::generate();
        let k2 = MasterKey::from_hex(&k.to_hex()).unwrap();
        let s = k.seal(b"x", b"a").unwrap();
        assert_eq!(&*k2.open(&s, b"a").unwrap(), b"x");
        assert!(MasterKey::from_hex("abcd").is_err());
    }

    #[test]
    fn dev_uri() {
        let alice = keypair_from_uri("//Alice").unwrap();
        assert_eq!(
            ss58(&alice.public_key().to_account_id()),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
    }
}
