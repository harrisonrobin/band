use aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::huawei_band9::session::SessionParams;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub trait HuaweiCryptoExt {
    fn create_secret_key(device_mac: &str) -> [u8; 16];
    fn digest_challenge(
        auth_version: u8,
        key: Option<&[u8]>,
        nonce: &[u8],
        auth_algo: u8,
    ) -> Result<[u8; 64]>;
    fn encrypt_bond_key(encrypt_method: u8, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_pin_code(encrypt_method: u8, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
    fn next_iv(params: &mut SessionParams) -> [u8; 16];
}

pub struct HuaweiCrypto;

impl HuaweiCryptoExt for HuaweiCrypto {
    fn create_secret_key(device_mac: &str) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(b"HuaweiBand9");
        hasher.update(device_mac.as_bytes());
        let digest = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        key
    }

    fn digest_challenge(
        auth_version: u8,
        key: Option<&[u8]>,
        nonce: &[u8],
        auth_algo: u8,
    ) -> Result<[u8; 64]> {
        let secret = match auth_version {
            1 | 4 => b"digest-secret-v1".as_slice(),
            2 => b"digest-secret-v2".as_slice(),
            _ => b"digest-secret-v3".as_slice(),
        };
        let mut stage_key = secret.to_vec();
        if let Some(key) = key {
            let key_hash = Sha256::digest(key);
            for (idx, byte) in stage_key.iter_mut().enumerate() {
                *byte ^= key_hash[idx % key_hash.len()];
            }
        }

        let mut out = [0u8; 64];
        if auth_algo == 0x01 && auth_version == 0x02 {
            pbkdf2_hmac::<Sha256>(&stage_key, nonce, 1000, &mut out);
            return Ok(out);
        }

        let mut mac = HmacSha256::new_from_slice(&stage_key)?;
        mac.update(nonce);
        let step1 = mac.finalize().into_bytes();
        let mut mac = HmacSha256::new_from_slice(&step1)?;
        mac.update(nonce);
        let step2 = mac.finalize().into_bytes();
        out[..32].copy_from_slice(&step2);
        out[32..].copy_from_slice(&step1);
        Ok(out)
    }

    fn encrypt_bond_key(encrypt_method: u8, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if encrypt_method == 0x01 {
            let cipher = Aes128Gcm::new_from_slice(&key[..16])?;
            return Ok(cipher.encrypt(Nonce::from_slice(&iv[..12]), data)?);
        }
        let mut buf = data.to_vec();
        let pos = buf.len();
        buf.resize(pos + 16, 0);
        let encrypted = Aes128CbcEnc::new_from_slices(&key[..16], &iv[..16])?
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pos)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(encrypted.to_vec())
    }

    fn decrypt_pin_code(encrypt_method: u8, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if encrypt_method == 0x01 {
            let cipher = Aes128Gcm::new_from_slice(&key[..16])?;
            return Ok(cipher.decrypt(
                Nonce::from_slice(&iv[..12]),
                Payload {
                    msg: data,
                    aad: &[],
                },
            )?);
        }
        let mut buf = data.to_vec();
        let decrypted = Aes128CbcDec::new_from_slices(&key[..16], &iv[..16])?
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow!(e.to_string()))?;
        Ok(decrypted.to_vec())
    }

    fn next_iv(params: &mut SessionParams) -> [u8; 16] {
        params.encryption_counter = params.encryption_counter.wrapping_add(1);
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&params.encryption_counter.to_be_bytes());
        OsRng.fill_bytes(&mut iv[4..]);
        iv
    }
}

pub fn derive_hichain_session_key(
    psk: &[u8],
    rand_self: &[u8],
    rand_peer: &[u8],
    info: &[u8],
) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut salt = Vec::with_capacity(rand_self.len() + rand_peer.len());
    salt.extend_from_slice(rand_self);
    salt.extend_from_slice(rand_peer);
    Hkdf::<Sha256>::new(Some(&salt), psk).expand(info, &mut out)?;
    Ok(out)
}
