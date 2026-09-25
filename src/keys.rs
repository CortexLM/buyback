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

/// A payment wallet. Holds its secret (a BIP39 mnemonic, or a 32-byte sr25519 mini secret for
/// derived wallets) only in zeroizing memory.
pub struct PaymentWallet {
    secret: Zeroizing<Vec<u8>>,
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
        Ok(Self {
            secret: Zeroizing::new(phrase.as_bytes().to_vec()),
            keypair,
        })
    }

    /// A wallet from a 32-byte sr25519 mini secret (what [`DerivationSeed`] produces).
    pub fn from_mini_secret(mini: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            secret: Zeroizing::new(mini.to_vec()),
            keypair: keypair_from_mini_secret(mini)?,
        })
    }

    /// Rebuild from sealed plaintext: 32 bytes is a mini secret, anything else a mnemonic (the
    /// shortest BIP39 phrase is longer than 32 bytes, so the two cannot be confused).
    pub fn from_secret_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self> {
        if let Ok(mini) = <[u8; 32]>::try_from(bytes.as_slice()) {
            let mini = Zeroizing::new(mini);
            return Self::from_mini_secret(&mini);
        }
        let phrase = String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::Crypto("sealed secret is not utf-8".into()))?;
        Self::from_phrase(Zeroizing::new(phrase))
    }

    pub fn account_id(&self) -> AccountId32 {
        self.keypair.public_key().to_account_id()
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Seal the wallet secret for storage.
    pub fn seal(&self, key: &MasterKey, aad: &[u8]) -> Result<SealedSecret> {
        key.seal(&self.secret, aad)
    }

    /// Seal under the keyring's active key (the key id is recorded in the result).
    pub fn seal_with(&self, keyring: &Keyring, aad: &[u8]) -> Result<SealedSecret> {
        keyring.seal(&self.secret, aad)
    }

    /// Open a sealed wallet secret.
    pub fn unseal(key: &MasterKey, sealed: &SealedSecret, aad: &[u8]) -> Result<Self> {
        Self::from_secret_bytes(key.open(sealed, aad)?)
    }

    /// Open a sealed wallet secret with whichever keyring key sealed it.
    pub fn unseal_with(keyring: &Keyring, sealed: &SealedSecret, aad: &[u8]) -> Result<Self> {
        Self::from_secret_bytes(keyring.open(sealed, aad)?)
    }
}

/// sr25519 keypair of a 32-byte mini secret (ed25519 expansion, as substrate does).
pub fn keypair_from_mini_secret(mini: &[u8; 32]) -> Result<Keypair> {
    Keypair::from_secret_key(*mini).map_err(|_| Error::Crypto("invalid mini secret".into()))
}

/// Root of deterministic wallets: every wallet is `<phrase><path>` with hard junctions only, so
/// any substrate tool regenerates it (`subkey inspect "<phrase>//opentype//deposit//7"`).
///
/// Only the root mini secret is kept (zeroized on drop), never the phrase.
pub struct DerivationSeed {
    root: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for DerivationSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DerivationSeed(<redacted>)")
    }
}

impl DerivationSeed {
    /// From a BIP39 mnemonic (no password), exactly as `Keypair::from_phrase`.
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let bad = || Error::Config("derivation seed is not a valid BIP39 mnemonic".into());
        let mnemonic = bip39::Mnemonic::parse(phrase.trim()).map_err(|_| bad())?;
        let (entropy, len) = mnemonic.to_entropy_array();
        let entropy = Zeroizing::new(entropy);
        let mut seed = Zeroizing::new([0u8; 64]);
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
            &entropy[..len],
            b"mnemonic",
            2048,
            seed.as_mut(),
        )
        .map_err(|_| bad())?;
        let mut root = Zeroizing::new([0u8; 32]);
        root.copy_from_slice(&seed[..32]);
        Ok(Self { root })
    }

    /// Mini secret of `path`, which must be hard junctions only (`//a//b//7`): hard derivation
    /// does not reveal siblings from a child key, and a hard-derived key is fully described by
    /// its 32-byte mini secret.
    pub fn derive_mini(&self, path: &str) -> Result<Zeroizing<[u8; 32]>> {
        use schnorrkel::derive::ChainCode;
        let junctions = hard_junctions(path)?;
        let mut mini = schnorrkel::MiniSecretKey::from_bytes(self.root.as_ref())
            .map_err(|_| Error::Crypto("invalid root".into()))?;
        for cc in junctions {
            let secret = mini.expand(schnorrkel::ExpansionMode::Ed25519);
            mini = secret.hard_derive_mini_secret_key(Some(ChainCode(cc)), b"").0;
        }
        Ok(Zeroizing::new(mini.to_bytes()))
    }

    pub fn wallet(&self, path: &str) -> Result<PaymentWallet> {
        PaymentWallet::from_mini_secret(&*self.derive_mini(path)?)
    }
}

/// Chain codes of `//a//b//7` (substrate `SecretUri` rules: a number is a SCALE u64, anything
/// else a SCALE string, blake2-hashed past 32 bytes). Soft junctions are refused.
fn hard_junctions(path: &str) -> Result<Vec<[u8; 32]>> {
    let bad = || Error::Config(format!("derivation path {path:?} must be //hard//junctions only"));
    let rest = path.strip_prefix("//").ok_or_else(bad)?;
    rest.split("//")
        .map(|j| {
            if j.is_empty() || j.contains('/') {
                return Err(bad());
            }
            let dj = subxt_signer::DeriveJunction::from(format!("/{j}"));
            if !dj.is_hard() {
                return Err(bad());
            }
            Ok(*dj.inner())
        })
        .collect()
}

/// Versioned data keys. Secrets are sealed under the active key and carry its id, so old
/// ciphertexts still open after a rotation and can be re-sealed ([`Keyring::reseal`]).
///
/// Provider-agnostic on purpose: plain XChaCha20-Poly1305 under keys from your own secret
/// store, so an encrypted table survives a move to any database.
pub struct Keyring {
    active: String,
    keys: std::collections::BTreeMap<String, MasterKey>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("active", &self.active)
            .field("ids", &self.keys.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Key id given to a bare [`MasterKey`] and assumed for a sealed secret without one.
pub const DEFAULT_KEY_ID: &str = "k0";

impl From<MasterKey> for Keyring {
    fn from(key: MasterKey) -> Self {
        Self {
            active: DEFAULT_KEY_ID.into(),
            keys: [(DEFAULT_KEY_ID.to_string(), key)].into(),
        }
    }
}

impl Keyring {
    pub fn new(active: &str, keys: impl IntoIterator<Item = (String, MasterKey)>) -> Result<Self> {
        let keys: std::collections::BTreeMap<_, _> = keys.into_iter().collect();
        if !keys.contains_key(active) {
            return Err(Error::Config(format!("active key id {active:?} is not in the keyring")));
        }
        if keys.keys().any(|k| k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')) {
            return Err(Error::Config("key ids are [A-Za-z0-9_-]+".into()));
        }
        Ok(Self {
            active: active.into(),
            keys,
        })
    }

    /// Parse `id:hex,id:hex` (the active id is given separately).
    pub fn parse(spec: &str, active: &str) -> Result<Self> {
        let mut keys = vec![];
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (id, hex) = part
                .split_once(':')
                .ok_or_else(|| Error::Config("keyring entries are id:hex".into()))?;
            keys.push((id.trim().to_string(), MasterKey::from_hex(hex)?));
        }
        Self::new(active, keys)
    }

    pub fn active_id(&self) -> &str {
        &self.active
    }

    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret> {
        let mut s = self.keys[&self.active].seal(plaintext, aad)?;
        s.kid = Some(self.active.clone());
        Ok(s)
    }

    pub fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let kid = sealed.kid.as_deref().unwrap_or(DEFAULT_KEY_ID);
        let key = self
            .keys
            .get(kid)
            .ok_or_else(|| Error::Crypto(format!("key id {kid:?} is not in the keyring")))?;
        key.open(sealed, aad)
    }

    /// Re-seal under the active key. `None` when it already is.
    pub fn reseal(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Option<SealedSecret>> {
        if sealed.kid.as_deref().unwrap_or(DEFAULT_KEY_ID) == self.active {
            return Ok(None);
        }
        let plain = self.open(sealed, aad)?;
        self.seal(&plain, aad).map(Some)
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
            kid: None,
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
    /// Keyring key id; `None` means [`DEFAULT_KEY_ID`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
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
            assert_eq!(std::str::from_utf8(&w.secret).unwrap().split_whitespace().count(), 24);
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
        let phrase = std::str::from_utf8(&w.secret).unwrap().to_string();
        let first_word = phrase.split_whitespace().next().unwrap().to_string();
        let dbg = format!("{w:?} {:?}", MasterKey::generate());
        assert!(!dbg.contains(&phrase));
        assert!(!dbg.contains(&format!(" {first_word} ")));
    }

    #[test]
    fn seal_roundtrip_and_tamper_detection() {
        let key = MasterKey::generate();
        let w = PaymentWallet::generate().unwrap();
        let addr = ss58(&w.account_id());
        let aad = wallet_aad("id-1", &addr);
        let sealed = w.seal(&key, &aad).unwrap();
        assert!(!sealed.ct.contains(&hex::encode(&*w.secret)));

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

    const PHRASE: &str = "bottom drive obey lake curtain smoke basket hold race lonely fit walk";

    #[test]
    fn derivation_matches_substrate_uris_and_is_deterministic() {
        let seed = DerivationSeed::from_phrase(PHRASE).unwrap();
        for path in ["//opentype//deposit//0", "//opentype//deposit//7", "//Alice", "//a//b//123456789"] {
            let ours = seed.wallet(path).unwrap().account_id();
            let uri = keypair_from_uri(&format!("{PHRASE}{path}")).unwrap();
            assert_eq!(ours, uri.public_key().to_account_id(), "{path}");
            // determinism: a second seed from the same phrase gives the same key
            let again = DerivationSeed::from_phrase(PHRASE).unwrap().wallet(path).unwrap();
            assert_eq!(again.account_id(), ours);
        }
        // `//Alice` from the dev phrase is the well-known Alice
        let dev = DerivationSeed::from_phrase(subxt_signer::DEV_PHRASE).unwrap();
        assert_eq!(
            ss58(&dev.wallet("//Alice").unwrap().account_id()),
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
        let a = seed.wallet("//opentype//deposit//1").unwrap().account_id();
        let b = seed.wallet("//opentype//deposit//2").unwrap().account_id();
        assert_ne!(a, b);
        // the mini secret alone rebuilds the key
        let mini = seed.derive_mini("//opentype//deposit//1").unwrap();
        assert_eq!(PaymentWallet::from_mini_secret(&mini).unwrap().account_id(), a);
    }

    #[test]
    fn derivation_refuses_soft_and_malformed_paths() {
        let seed = DerivationSeed::from_phrase(PHRASE).unwrap();
        for bad in ["", "/soft", "//a/soft", "//", "//a////b", "opentype"] {
            assert!(seed.derive_mini(bad).is_err(), "{bad:?}");
        }
        assert!(DerivationSeed::from_phrase("not a mnemonic").is_err());
        assert!(!format!("{seed:?}").contains("bottom"));
    }

    #[test]
    fn keyring_roundtrip_rotation_and_tamper() {
        let k1 = MasterKey::generate();
        let k1_hex = k1.to_hex();
        let old = Keyring::new("k1", [("k1".to_string(), k1)]).unwrap();
        let seed = DerivationSeed::from_phrase(PHRASE).unwrap();
        let w = seed.wallet("//opentype//deposit//3").unwrap();
        let aad = b"tenant-a/5Fxyz";
        let sealed = w.seal_with(&old, aad).unwrap();
        assert_eq!(sealed.kid.as_deref(), Some("k1"));
        assert_eq!(PaymentWallet::unseal_with(&old, &sealed, aad).unwrap().account_id(), w.account_id());
        // wrong AAD, tampered ciphertext, unknown key id
        assert!(PaymentWallet::unseal_with(&old, &sealed, b"tenant-b/5Fxyz").is_err());
        let mut t = sealed.clone();
        let mut ct = hex::decode(&t.ct).unwrap();
        ct[5] ^= 0x80;
        t.ct = hex::encode(ct);
        assert!(PaymentWallet::unseal_with(&old, &t, aad).is_err());
        let mut t = sealed.clone();
        t.kid = Some("k9".into());
        assert!(PaymentWallet::unseal_with(&old, &t, aad).is_err());

        // rotate: k2 active, k1 kept for reading
        let new = Keyring::parse(&format!("k1:{},k2:{}", *k1_hex, *MasterKey::generate().to_hex()), "k2").unwrap();
        assert_eq!(PaymentWallet::unseal_with(&new, &sealed, aad).unwrap().account_id(), w.account_id());
        let resealed = new.reseal(&sealed, aad).unwrap().expect("re-sealed");
        assert_eq!(resealed.kid.as_deref(), Some("k2"));
        assert!(new.reseal(&resealed, aad).unwrap().is_none(), "already current");
        // after dropping k1 only the re-sealed copy opens
        let only_k2 = Keyring::parse(&format!("k2:{}", *MasterKey::from_hex(&hex::encode([0u8;32])).unwrap().to_hex()), "k2").unwrap();
        assert!(PaymentWallet::unseal_with(&only_k2, &sealed, aad).is_err());
        assert!(Keyring::new("nope", []).is_err());
        assert!(!format!("{new:?}").contains(&*k1_hex));
    }

    #[test]
    fn legacy_sealed_without_kid_opens_with_default_key() {
        let k = MasterKey::generate();
        let hexk = k.to_hex();
        let w = PaymentWallet::generate().unwrap();
        let sealed = w.seal(&k, b"x").unwrap();
        assert!(sealed.kid.is_none());
        let ring: Keyring = MasterKey::from_hex(&hexk).unwrap().into();
        assert_eq!(PaymentWallet::unseal_with(&ring, &sealed, b"x").unwrap().account_id(), w.account_id());
        // serde: no kid field in the JSON of a legacy secret
        assert!(!serde_json::to_string(&sealed).unwrap().contains("kid"));
    }
}
