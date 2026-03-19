use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use bluer::{gatt::remote::Characteristic, Address};
use bytes::BytesMut;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, Mutex},
    task::JoinHandle,
    time::timeout,
};
use uuid::Uuid;

use crate::{
    ble::{
        adapter::HuaweiBleAdapter,
        device::connect,
        gatt::{HuaweiGatt, HUAWEI_NOTIFY_UUID, HUAWEI_WRITE_UUID},
    },
    capture::logging::FrameLog,
    huawei_band9::{
        auth::{parse_bond_params, parse_security_negotiation, BondParams, SecurityNegotiation},
        capabilities::{ExpandCapabilities, SupportedCommands, SupportedServices},
        notifications::{BatteryStatus, DeviceEvent, ProductInfo},
    },
    protocol::{
        frame::{encode_frame, parse_stream, SliceReassembler, TransportFrame},
        router::Router,
        tlv::Tlv,
    },
};

const DEVICE_CONFIG_SERVICE: u8 = 0x01;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuaweiBand9Config {
    pub adapter: Option<String>,
    pub android_id: String,
    pub client_serial: String,
    pub synthetic_mac: String,
    pub app_version: u32,
    pub android_version: String,
    pub request_timeout: Duration,
}

impl Default for HuaweiBand9Config {
    fn default() -> Self {
        Self {
            adapter: None,
            android_id: "ff-android-id".into(),
            client_serial: "linux-bluer".into(),
            synthetic_mac: "FF:FF:FF:12:34:56".into(),
            app_version: 1_600_008_300,
            android_version: "14".into(),
            request_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AuthFlow {
    Normal,
    HiChainLite,
    HiChain,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionParams {
    pub auth_version: u8,
    pub device_support_type: u8,
    pub secret_key: Option<Vec<u8>>,
    pub slice_size: usize,
    pub transactions_crypted: bool,
    pub mtu: usize,
    pub encryption_counter: u32,
    pub pin_code: Option<Vec<u8>>,
    pub interval: u8,
    pub auth_algo: u8,
    pub encrypt_method: u8,
    pub first_key: Option<[u8; 16]>,
    pub auth_mode: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LinkParams {
    pub protocol_version: u8,
    pub slice_size: u16,
    pub mtu: u16,
    pub interval: u8,
    pub auth_version: u8,
    pub server_nonce: Vec<u8>,
    pub device_support_type: u8,
    pub auth_algo: u8,
    pub bond_state: u8,
    pub encrypt_method: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub auth_flow: Option<AuthFlow>,
    pub params: SessionParams,
    pub product_info: Option<ProductInfo>,
    pub battery: Option<BatteryStatus>,
    pub supported_services: SupportedServices,
    pub supported_commands: SupportedCommands,
    pub expand_capabilities: Option<ExpandCapabilities>,
}

pub struct HuaweiBand9Session {
    pub address: Address,
    pub config: HuaweiBand9Config,
    pub params: SessionParams,
    router: Router,
    frame_logs: Arc<Mutex<Vec<FrameLog>>>,
    event_tx: broadcast::Sender<DeviceEvent>,
    reader_task: Option<JoinHandle<Result<()>>>,
    write: Option<Characteristic>,
    _notify: Option<Characteristic>,
    pub product_info: Option<ProductInfo>,
    pub battery: Option<BatteryStatus>,
    pub supported_services: SupportedServices,
    pub supported_commands: SupportedCommands,
    pub expand_capabilities: Option<ExpandCapabilities>,
    pub auth_flow: Option<AuthFlow>,
}

impl HuaweiBand9Session {
    pub fn new(address: Address, config: HuaweiBand9Config) -> Self {
        let (event_tx, _) = broadcast::channel(128);
        Self {
            address,
            config,
            params: SessionParams {
                slice_size: 20,
                mtu: 20,
                ..SessionParams::default()
            },
            router: Router::new(),
            frame_logs: Arc::new(Mutex::new(Vec::new())),
            event_tx,
            reader_task: None,
            write: None,
            _notify: None,
            product_info: None,
            battery: None,
            supported_services: SupportedServices::default(),
            supported_commands: SupportedCommands::default(),
            expand_capabilities: None,
            auth_flow: None,
        }
    }

    pub fn events(&self) -> broadcast::Receiver<DeviceEvent> {
        self.event_tx.subscribe()
    }

    pub async fn frame_logs(&self) -> Vec<FrameLog> {
        self.frame_logs.lock().await.clone()
    }

    pub async fn connect(&mut self) -> Result<()> {
        let adapter = HuaweiBleAdapter::new(self.config.adapter.as_deref()).await?;
        let device = connect(&adapter, self.address).await?;
        let gatt = HuaweiGatt::discover(&device).await?;
        let notify_stream = gatt.notify.notify().await.context("subscribe FE02")?;
        self.write = Some(gatt.write.clone());
        self._notify = Some(gatt.notify.clone());

        let router = self.router.clone();
        let logs = self.frame_logs.clone();
        let event_tx = self.event_tx.clone();
        self.reader_task = Some(tokio::spawn(async move {
            let mut notifications = notify_stream;
            let mut buf = BytesMut::new();
            let mut reassembler = SliceReassembler::default();
            while let Some(packet) = notifications.next().await {
                let packet = packet.context("read FE02 notification")?;
                logs.lock()
                    .await
                    .push(FrameLog::new("rx", "FE02", packet.clone(), "notify"));
                buf.extend_from_slice(&packet);
                for frame in parse_stream(&mut buf, &mut reassembler)? {
                    let _ = event_tx.send(DeviceEvent::Raw {
                        service_id: frame.service_id,
                        command_id: frame.command_id,
                        payload: frame.payload.clone(),
                    });
                    router.route(frame).await?;
                }
            }
            Ok(())
        }));
        Ok(())
    }

    pub async fn initialize(&mut self) -> Result<SessionSnapshot> {
        self.connect().await?;
        self.auth_flow = Some(self.authenticate().await?);
        let snapshot = self.bootstrap().await?;
        self.product_info = Some(snapshot.product_info.clone());
        self.battery = Some(snapshot.battery.clone());
        self.supported_services = snapshot.supported_services.clone();
        self.supported_commands = snapshot.supported_commands.clone();
        self.expand_capabilities = snapshot.expand_capabilities.clone();
        Ok(self.snapshot())
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            auth_flow: self.auth_flow,
            params: self.params.clone(),
            product_info: self.product_info.clone(),
            battery: self.battery.clone(),
            supported_services: self.supported_services.clone(),
            supported_commands: self.supported_commands.clone(),
            expand_capabilities: self.expand_capabilities.clone(),
        }
    }

    async fn send_request(
        &mut self,
        service_id: u8,
        command_id: u8,
        payload: Vec<u8>,
    ) -> Result<TransportFrame> {
        let rx = self.router.register(service_id, command_id).await;
        let frame = TransportFrame {
            service_id,
            command_id,
            payload,
        };
        let write = self.write.as_ref().context("session not connected")?;
        for slice in encode_frame(&frame, self.params.slice_size.max(20)) {
            self.frame_logs.lock().await.push(FrameLog::new(
                "tx",
                if write.uuid().await? == HUAWEI_WRITE_UUID {
                    "FE01"
                } else {
                    "UNKNOWN"
                },
                slice.bytes.clone(),
                format!("svc={service_id:#04x} cmd={command_id:#04x}"),
            ));
            write.write(&slice.bytes).await.context("write FE01")?;
        }
        timeout(self.config.request_timeout, rx)
            .await
            .context("request timeout")?
            .map_err(|_| anyhow!("response channel closed"))
    }

    pub async fn get_link_params(&mut self) -> Result<LinkParams> {
        let mut tlv = Tlv::default();
        for tag in [0x01u8, 0x02, 0x03, 0x04] {
            tlv.push_bytes(tag, Vec::<u8>::new());
        }
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x01, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        Ok(LinkParams {
            protocol_version: tlv.get_u8(0x01).unwrap_or_default(),
            slice_size: tlv.get_u16(0x02).unwrap_or(20),
            mtu: tlv.get_u16(0x03).unwrap_or(20),
            interval: tlv.get_u8(0x04).unwrap_or_default(),
            auth_version: tlv
                .get_first(0x05)
                .and_then(|bytes| bytes.first().copied())
                .unwrap_or_default(),
            server_nonce: tlv
                .get_first(0x05)
                .map(|bytes| bytes.get(1..).unwrap_or_default().to_vec())
                .unwrap_or_default(),
            device_support_type: tlv.get_u8(0x07).unwrap_or_default(),
            auth_algo: tlv.get_u8(0x08).unwrap_or_default(),
            bond_state: tlv.get_u8(0x09).unwrap_or_default(),
            encrypt_method: tlv.get_u8(0x0c).unwrap_or_default(),
        })
    }

    pub async fn get_security_negotiation(&mut self) -> Result<SecurityNegotiation> {
        let mut tlv = Tlv::default();
        tlv.push_u8(0x01, self.params.auth_mode.max(1));
        tlv.push_u8(0x03, 0x01);
        tlv.push_u8(0x04, 0x00);
        tlv.push_bytes(0x05, self.config.android_id.as_bytes().to_vec());
        if self.params.encrypt_method == 1 {
            tlv.push_u8(0x0d, 0x01);
        }
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x33, tlv.encode())
            .await?;
        Ok(parse_security_negotiation(&Tlv::decode(&frame.payload)?))
    }

    pub async fn get_pin_code(&mut self) -> Result<Vec<u8>> {
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, Vec::<u8>::new());
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x2c, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        Ok(tlv.get_first(0x01).unwrap_or_default().to_vec())
    }

    pub async fn send_auth(&mut self, digest: &[u8], client_nonce: &[u8; 16]) -> Result<Tlv> {
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, digest.to_vec());
        let mut version_and_nonce = vec![0x00, self.params.auth_version];
        version_and_nonce.extend_from_slice(client_nonce);
        tlv.push_bytes(0x02, version_and_nonce);
        if self.params.auth_mode == 0x02 {
            tlv.push_u8(0x03, self.params.auth_algo);
        }
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x13, tlv.encode())
            .await?;
        Tlv::decode(&frame.payload).map_err(Into::into)
    }

    pub async fn get_bond_params(&mut self) -> Result<BondParams> {
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, Vec::<u8>::new());
        tlv.push_bytes(0x03, self.config.client_serial.as_bytes().to_vec());
        tlv.push_u8(0x04, 0x02);
        tlv.push_bytes(0x05, Vec::<u8>::new());
        tlv.push_bytes(0x07, self.config.synthetic_mac.as_bytes().to_vec());
        tlv.push_bytes(0x09, Vec::<u8>::new());
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x0f, tlv.encode())
            .await?;
        Ok(parse_bond_params(&Tlv::decode(&frame.payload)?))
    }

    pub async fn send_bond(&mut self, encrypted_key: &[u8], iv: &[u8; 16]) -> Result<()> {
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, Vec::<u8>::new());
        tlv.push_u8(0x03, 0x00);
        tlv.push_bytes(0x05, self.config.client_serial.as_bytes().to_vec());
        tlv.push_bytes(0x06, encrypted_key.to_vec());
        tlv.push_bytes(0x07, iv.to_vec());
        let _ = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x0e, tlv.encode())
            .await?;
        Ok(())
    }

    pub async fn send_hichain_step(&mut self, step: u8, json: &str) -> Result<serde_json::Value> {
        let mut tlv = Tlv::default();
        tlv.push_u8(0x01, step);
        tlv.push_bytes(0x02, json.as_bytes().to_vec());
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x28, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        let raw = tlv.get_first(0x02).unwrap_or_default();
        Ok(serde_json::from_slice(raw).unwrap_or_else(|_| serde_json::json!({})))
    }

    pub async fn get_product_info(&mut self) -> Result<ProductInfo> {
        let mut tlv = Tlv::default();
        tlv.push_bytes(
            0x01,
            vec![
                0x01, 0x02, 0x07, 0x09, 0x0a, 0x11, 0x12, 0x16, 0x1a, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
                0x22, 0x23,
            ],
        );
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x07, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        let product = ProductInfo {
            hardware_version: tlv
                .get_first(0x03)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            software_version: tlv
                .get_first(0x07)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            serial_number: tlv
                .get_first(0x09)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            product_model: tlv
                .get_first(0x0a)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            package_name: tlv
                .get_first(0x0f)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            device_name: tlv
                .get_first(0x11)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            region_code: tlv
                .get_first(0x14)
                .map(|v| String::from_utf8_lossy(v).to_string()),
            ota_signature_length: tlv.get_u32(0x27),
        };
        let _ = self.event_tx.send(DeviceEvent::Product(product.clone()));
        Ok(product)
    }

    pub async fn sync_time(&mut self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        let mut tlv = Tlv::default();
        tlv.push_u32(0x01, now);
        tlv.push_u16(0x02, 0);
        let _ = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x05, tlv.encode())
            .await?;
        Ok(())
    }

    pub async fn get_battery(&mut self) -> Result<BatteryStatus> {
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, Vec::<u8>::new());
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x08, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        let battery = BatteryStatus {
            level: tlv.get_u8(0x01),
            component_levels: tlv.get_first(0x02).unwrap_or_default().to_vec(),
            component_states: tlv.get_first(0x03).unwrap_or_default().to_vec(),
        };
        let _ = self.event_tx.send(DeviceEvent::Battery(battery.clone()));
        Ok(battery)
    }

    pub async fn get_supported_services(&mut self) -> Result<SupportedServices> {
        let candidates: [u8; 38] = [
            0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1d, 0x20,
            0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2a, 0x2b, 0x2d, 0x2e,
        ];
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, candidates.to_vec());
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x02, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        let bits = tlv.get_first(0x02).unwrap_or_default();
        let mut ids = BTreeSet::from([DEVICE_CONFIG_SERVICE]);
        for (index, service_id) in candidates.iter().enumerate() {
            let byte = index / 8;
            let bit = index % 8;
            if bits
                .get(byte)
                .map(|value| (value & (1 << bit)) != 0)
                .unwrap_or(false)
            {
                ids.insert(*service_id);
            }
        }
        Ok(SupportedServices { ids })
    }

    pub async fn get_supported_commands(
        &mut self,
        services: &SupportedServices,
    ) -> Result<SupportedCommands> {
        let mut by_service = BTreeMap::new();
        for service_id in &services.ids {
            let mut inner = Tlv::default();
            inner.push_u8(0x02, *service_id);
            inner.push_bytes(0x03, (1u8..=0x40).collect::<Vec<_>>());
            let mut outer = Tlv::default();
            outer.push_bytes(0x81, inner.encode());
            let frame = self
                .send_request(DEVICE_CONFIG_SERVICE, 0x03, outer.encode())
                .await?;
            let outer = Tlv::decode(&frame.payload)?;
            let nested = outer.get_first(0x81).unwrap_or_default();
            let inner = Tlv::decode(nested)?;
            let bitmap = inner.get_first(0x04).unwrap_or_default();
            let mut commands = BTreeSet::new();
            for command_id in 1u8..=0x40 {
                let idx = (command_id - 1) as usize;
                let byte = idx / 8;
                let bit = idx % 8;
                if bitmap
                    .get(byte)
                    .map(|value| (value & (1 << bit)) != 0)
                    .unwrap_or(false)
                {
                    commands.insert(command_id);
                }
            }
            by_service.insert(*service_id, commands);
        }
        Ok(SupportedCommands { by_service })
    }

    pub async fn get_expand_capabilities(
        &mut self,
        commands: &SupportedCommands,
    ) -> Result<Option<ExpandCapabilities>> {
        if !commands.supports(DEVICE_CONFIG_SERVICE, 0x37) {
            return Ok(None);
        }
        let mut tlv = Tlv::default();
        tlv.push_bytes(0x01, Vec::<u8>::new());
        let frame = self
            .send_request(DEVICE_CONFIG_SERVICE, 0x37, tlv.encode())
            .await?;
        let tlv = Tlv::decode(&frame.payload)?;
        let bytes = tlv.get_first(0x01).unwrap_or_default().to_vec();
        let _ = self
            .event_tx
            .send(DeviceEvent::CapabilityBytes(bytes.clone()));
        Ok(Some(ExpandCapabilities { bytes }))
    }

    pub async fn disconnect(mut self) -> Result<()> {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        Ok(())
    }
}
