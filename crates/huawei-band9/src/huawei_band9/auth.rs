use anyhow::{anyhow, Context, Result};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;

use crate::{
    huawei_band9::session::{AuthFlow, HuaweiBand9Session, LinkParams, SessionParams},
    protocol::{
        crypto::{derive_hichain_session_key, HuaweiCrypto, HuaweiCryptoExt},
        tlv::Tlv,
    },
};

impl HuaweiBand9Session {
    pub async fn authenticate(&mut self) -> Result<AuthFlow> {
        let link = self.get_link_params().await?;
        self.params.apply_link_params(&link);
        let flow = self.select_auth_flow();
        match flow {
            AuthFlow::Normal => self.auth_normal(&link).await?,
            AuthFlow::HiChainLite => self.auth_hichain_lite(&link).await?,
            AuthFlow::HiChain => self.auth_hichain(&link).await?,
        }
        Ok(flow)
    }

    fn select_auth_flow(&self) -> AuthFlow {
        match self.params.device_support_type {
            0x02 => AuthFlow::HiChainLite,
            0x01 | 0x03 | 0x04 => AuthFlow::HiChain,
            _ => AuthFlow::Normal,
        }
    }

    async fn auth_normal(&mut self, link: &LinkParams) -> Result<()> {
        let device_mac = self.address.to_string();
        let bond_key = self
            .params
            .secret_key
            .clone()
            .unwrap_or_else(|| HuaweiCrypto::create_secret_key(&device_mac).to_vec());
        let mut client_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut client_nonce);
        let mut double_nonce = link.server_nonce.clone();
        double_nonce.extend_from_slice(&client_nonce);
        let digest = HuaweiCrypto::digest_challenge(
            self.params.auth_version,
            None,
            &double_nonce,
            self.params.auth_algo,
        )?;
        self.params.first_key = Some(digest[32..48].try_into().unwrap());
        let response = self.send_auth(&digest[..32], &client_nonce).await?;
        if response.get_first(0x01) != Some(&digest[..32]) {
            return Err(anyhow!("auth challenge response mismatch"));
        }
        let bond_params = self.get_bond_params().await?;
        self.params.encryption_counter = bond_params.encryption_counter;
        let iv = HuaweiCrypto::next_iv(&mut self.params);
        let encrypted = HuaweiCrypto::encrypt_bond_key(
            self.params.encrypt_method,
            &bond_key,
            &HuaweiCrypto::create_secret_key(&device_mac),
            &iv,
        )?;
        self.send_bond(&encrypted, &iv).await?;
        self.params.secret_key = Some(bond_key);
        Ok(())
    }

    async fn auth_hichain_lite(&mut self, link: &LinkParams) -> Result<()> {
        let negotiation = self.get_security_negotiation().await?;
        self.params.auth_mode = negotiation.auth_type;
        if self.params.auth_version != 0x02 && self.params.pin_code.is_none() {
            let pin = self.get_pin_code().await?;
            self.params.pin_code = Some(pin);
        }
        self.auth_normal(link).await
    }

    async fn auth_hichain(&mut self) -> Result<()> {
        let negotiation = self.get_security_negotiation().await?;
        self.params.auth_mode = negotiation.auth_type;
        if self.params.pin_code.is_none() {
            self.params.pin_code = Some(self.get_pin_code().await?);
        }

        let mut rand_self = [0u8; 16];
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut rand_self);
        OsRng.fill_bytes(&mut seed);
        let android_id = self.config.android_id.as_bytes();

        let request = json!({
            "isoSalt": rand_self,
            "peerAuthId": android_id,
            "peerUserType": 0,
            "operationCode": 1,
            "seed": seed,
        });
        let step1 = self.send_hichain_step(1, &request.to_string()).await?;
        let rand_peer = step1
            .get("randPeer")
            .and_then(|v| v.as_array())
            .context("missing randPeer")?
            .iter()
            .filter_map(|v| v.as_u64().map(|v| v as u8))
            .collect::<Vec<_>>();

        let pin = self.params.pin_code.clone().unwrap_or_default();
        let psk = derive_hichain_session_key(&pin, &rand_self, &rand_peer, b"hichain_psk")?;
        let session_key =
            derive_hichain_session_key(&psk, &rand_self, &rand_peer, b"hichain_iso_session_key")?;
        self.params.secret_key = Some(session_key.to_vec());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BondParams {
    pub encryption_counter: u32,
}

#[derive(Debug, Clone)]
pub struct SecurityNegotiation {
    pub auth_type: u8,
}

impl SessionParams {
    pub fn apply_link_params(&mut self, link: &LinkParams) {
        self.auth_version = link.auth_version;
        self.device_support_type = link.device_support_type;
        self.slice_size = link.slice_size as usize;
        self.mtu = link.mtu as usize;
        self.interval = link.interval;
        self.auth_algo = link.auth_algo;
        self.encrypt_method = link.encrypt_method;
    }
}

pub fn parse_security_negotiation(tlv: &Tlv) -> SecurityNegotiation {
    let auth_type = tlv.get_u8(0x02).or_else(|| tlv.get_u8(0x7f)).unwrap_or(0);
    SecurityNegotiation { auth_type }
}

pub fn parse_bond_params(tlv: &Tlv) -> BondParams {
    BondParams {
        encryption_counter: tlv.get_u32(0x09).unwrap_or_default(),
    }
}
