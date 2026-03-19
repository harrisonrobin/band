use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use bluer::{Address, Session};
use tokio::sync::broadcast;

use crate::{
    maestro::{
        channel::ChannelState,
        channels::{
            ch10_settings::{build_toggle, parse_snapshot, SettingId, SettingSnapshot},
            ch11_status::{parse_status, DeviceStatus},
            ch2_handshake::{build_init_payload, parse_ack_payload, HandshakeState},
            ch3_control::{parse_battery, BatteryUpdate, GestureClassifier, GestureEvent},
            ch5_conn_state::{parse_connection_state, ConnectionState},
            ch8_keepalive::KeepaliveState,
            ch9_wear_touch::{parse_wear_touch, EarState, WearTouchEvent},
        },
        frame::{encode_frame, MaestroFrame},
    },
    rfcomm::client::{connect_maestro, discover_maestro_descriptor, RfcommDescriptor},
};

#[derive(Debug, Clone)]
pub struct MaestroConfig {
    pub adapter: Option<String>,
    pub keepalive_interval: Duration,
}

impl Default for MaestroConfig {
    fn default() -> Self {
        Self {
            adapter: None,
            keepalive_interval: Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MaestroEvent {
    Handshake(HandshakeState),
    ConnectionState(ConnectionState),
    Battery(BatteryUpdate),
    WearTouch(WearTouchEvent),
    Gesture(GestureEvent),
    Setting(SettingSnapshot),
    Status(DeviceStatus),
    Frame(MaestroFrame),
}

pub struct PixelBudsASession {
    address: Address,
    pub config: MaestroConfig,
    pub descriptor: Option<RfcommDescriptor>,
    pub handshake: HandshakeState,
    pub connection_state: Option<ConnectionState>,
    pub last_ear_state: EarState,
    pub settings: HashMap<SettingId, u8>,
    channels: HashMap<u8, ChannelState>,
    keepalive: KeepaliveState,
    gesture_classifier: GestureClassifier,
    event_tx: broadcast::Sender<MaestroEvent>,
}

impl PixelBudsASession {
    pub fn new(address: Address, config: MaestroConfig) -> Self {
        let (event_tx, _) = broadcast::channel(128);
        Self {
            address,
            config,
            descriptor: None,
            handshake: HandshakeState::default(),
            connection_state: None,
            last_ear_state: EarState::BothOut,
            settings: HashMap::new(),
            channels: HashMap::new(),
            keepalive: KeepaliveState::default(),
            gesture_classifier: GestureClassifier::default(),
            event_tx,
        }
    }

    pub fn events(&self) -> broadcast::Receiver<MaestroEvent> {
        self.event_tx.subscribe()
    }

    pub async fn connect(&mut self) -> Result<()> {
        let session = Session::new().await.context("create BlueZ session")?;
        let adapter = if let Some(name) = self.config.adapter.as_deref() {
            session.adapter(name)?
        } else {
            session.default_adapter().await?
        };
        let device = adapter.device(self.address)?;
        if !device.is_connected().await? {
            device.connect().await?;
        }
        let descriptor = discover_maestro_descriptor(&device).await?;
        connect_maestro(&device, descriptor).await?;
        self.descriptor = Some(descriptor);
        Ok(())
    }

    pub fn build_handshake_frames(&mut self) -> Vec<Vec<u8>> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let init = build_init_payload(timestamp_ms, 0);
        let mut frames = vec![encode_frame(0x01, 2, 0, &init)];
        for channel in [5u8, 6, 7, 8, 9, 10, 11] {
            self.channels.insert(channel, ChannelState::OpenSent);
            frames.push(encode_frame(0x01, channel, 0, &[]));
        }
        frames
    }

    pub fn next_keepalive_frame(&mut self) -> Vec<u8> {
        encode_frame(0x09, 8, 0, &self.keepalive.next_ping())
    }

    pub fn set_in_ear_detection(&self, enabled: bool) -> Vec<u8> {
        encode_frame(
            0x03,
            10,
            0,
            &build_toggle(SettingId::InEarDetect, enabled as u8),
        )
    }

    pub fn ingest_frame(&mut self, frame: MaestroFrame) {
        let _ = self.event_tx.send(MaestroEvent::Frame(frame.clone()));
        match (frame.frame_type, frame.channel) {
            (0x02, 2) => {
                parse_ack_payload(&frame.payload, &mut self.handshake);
                let _ = self
                    .event_tx
                    .send(MaestroEvent::Handshake(self.handshake.clone()));
            }
            (0x02, channel) => {
                self.channels.insert(channel, ChannelState::Open);
            }
            (0x05, 3) | (0x10, 3) => {
                if let Some(update) = parse_battery(&frame.payload, self.last_ear_state) {
                    let _ = self.event_tx.send(MaestroEvent::Battery(update));
                } else {
                    self.gesture_classifier.note_ch3_payload(&frame.payload);
                }
            }
            (0x05, 5) | (0x87, 5) => {
                if let Some(state) = parse_connection_state(&frame.payload) {
                    self.connection_state = Some(state);
                    let _ = self.event_tx.send(MaestroEvent::ConnectionState(state));
                }
            }
            (0x05, 8) | (0x09, 8) => {
                let _ = crate::maestro::channels::ch8_keepalive::KeepaliveState::is_pong(
                    &frame.payload,
                );
            }
            (0x05, 9) | (0x87, 9) => {
                for event in parse_wear_touch(&frame.payload) {
                    if let WearTouchEvent::Ear(state) = event {
                        self.last_ear_state = state;
                    }
                    if let WearTouchEvent::GestureComplete(code) = event {
                        let gesture = self.gesture_classifier.classify_from_discriminator(code);
                        let _ = self.event_tx.send(MaestroEvent::Gesture(gesture));
                    }
                    let _ = self.event_tx.send(MaestroEvent::WearTouch(event));
                }
            }
            (0x87, 10) | (0x05, 10) => {
                if let Some(snapshot) = parse_snapshot(&frame.payload) {
                    self.settings.insert(snapshot.setting, snapshot.value);
                    let _ = self.event_tx.send(MaestroEvent::Setting(snapshot));
                }
            }
            (0x05, 11) => {
                if let Some(status) = parse_status(&frame.payload) {
                    let _ = self.event_tx.send(MaestroEvent::Status(status));
                }
            }
            _ => {}
        }
    }
}
