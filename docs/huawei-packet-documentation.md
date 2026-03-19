# Huawei packet documentation, auth flow, crypto stages, and Rust implementation notes

## Purpose and scope

This document consolidates the Huawei protocol details that can be extracted from the repository's packet model, request pipeline, and authentication logic. It is aimed at two audiences:

1. engineers who need a single reference for Huawei service IDs, command IDs, framing, and packet handling; and
2. engineers building a compatible Rust implementation that follows the same on-wire behavior used by Gadgetbridge.

The goal is not to restate every Java class line by line. Instead, it extracts the stable protocol facts, explains how the initialization and authentication phases fit together, and translates the implementation pattern into a clean Rust design.

## Evidence used inside this repository

The key protocol evidence for this document comes from:

- `HuaweiPacket.java`
- `HuaweiTLV.java`
- `HuaweiCrypto.java`
- `packets/DeviceConfig.java`
- `packets/*.java`
- `service/devices/huawei/HuaweiSupportProvider.java`
- `service/devices/huawei/requests/GetLinkParamsRequest.java`
- `service/devices/huawei/requests/GetSecurityNegotiationRequest.java`
- `service/devices/huawei/requests/GetPincodeRequest.java`
- `service/devices/huawei/requests/GetAuthRequest.java`
- `service/devices/huawei/requests/GetBondParamsRequest.java`
- `service/devices/huawei/requests/GetBondRequest.java`
- `service/devices/huawei/requests/GetHiChainRequest.java`

---

## 1. Transport and BLE layout

### 1.1 Huawei BLE service used by the protocol

The main Huawei BLE path uses the vendor service `FE86` and two vendor characteristics:

- service: `0000FE86-0000-1000-8000-00805F9B34FB`
- write characteristic: `0000FE01-0000-1000-8000-00805F9B34FB`
- read/notify characteristic: `0000FE02-0000-1000-8000-00805F9B34FB`

The operational sequence implemented in the repository is:

1. connect,
2. enable notifications on `FE02`,
3. send protocol frames to `FE01`,
4. parse every notification as one or more Huawei transport frames,
5. route replies to pending requests by `(service_id, command_id)`, and
6. route everything else through the asynchronous response manager.

### 1.2 Negotiated transport parameters

The `DeviceConfig.LinkParams` response is the first important packet in a session. It provides the parameters that shape the rest of the exchange:

- protocol version,
- slice size,
- MTU,
- auth version,
- server nonce,
- device support type,
- auth algorithm,
- bond state,
- connection interval,
- encryption method.

These values are stored into the shared `ParamsProvider` and then reused by auth, encryption, and write-splitting logic.

---

## 2. Huawei transport frame format

### 2.1 Core framing constants

The core transport implementation exposes the following fixed values:

- magic byte: `0x5A`
- protocol version constant used by packet logic: `0x02`
- success/result TLV tag: `0x7F`
- success value bytes: `00 01 86 A0`
- success integer form: `0x186A0`

### 2.2 Unsliced packet layout

When a packet fits in one BLE write, the frame structure is:

```text
0      magic                  0x5A
1..2   body_length_plus_1     u16
3      slice_marker           0x00
4      service_id             u8
5      command_id             u8
6..n   payload                TLV or command-specific bytes
n+1..n+2 crc16                u16
```

### 2.3 Sliced packet layout

Large packets are split into slices using a per-slice framing envelope:

```text
0      magic                  0x5A
1..2   slice_body_length      u16
3      slice_state            0x01 first, 0x02 middle, 0x03 last
4      slice_index_or_flag    incrementing per slice
5..    first slice: service_id, command_id, payload
       later slices: payload only
last2  crc16                  u16
```

### 2.4 Stream handling behavior

The parser in `HuaweiPacket` does all of the following:

- validates the magic byte,
- checks CRC16,
- buffers partial incoming notifications,
- supports multiple concatenated frames in one notification,
- reassembles sliced packets before higher-level parsing,
- dispatches replies to the request queue,
- falls back to async routing when no pending request matches.

### 2.5 Outgoing write splitting

The serializer uses the negotiated `sliceSize` from `LinkParams` and only includes `service_id` and `command_id` in the first slice of a sliced message. Every slice gets its own CRC16. `SupportedCommands` is especially conservative and computes a maximum TLV payload size so that the encrypted request stays under the slice limit after adding headers, TLV wrappers, IV, and block-size effects.

---

## 3. TLV format and packet body conventions

### 3.1 General TLV usage

Most Huawei packets carry a TLV body after `(service_id, command_id)`. The repository's `HuaweiTLV` implementation is responsible for:

- storing ordered TLV entries,
- serializing primitive values and nested TLVs,
- parsing TLVs back into typed accessors,
- decoding strings, integers, bytes, and container TLVs.

In practice, most request/response classes follow this pattern:

1. construct a TLV map,
2. serialize the transport frame,
3. parse a matching response TLV,
4. map tags into strongly typed fields.

### 3.2 Crypto-related TLV tags

The transport layer reserves these tags around encrypted payloads:

- `0x7C`: encryption marker / crypto metadata
- `0x7D`: IV / initialization vector
- `0x7E`: ciphertext
- `0x7F`: result / success field

Decryption is attempted when the encrypted marker tag is present and the packet class is not marked plaintext.

### 3.3 Known non-standard payload exceptions

The parser contains a small set of service/command pairs that should be treated as command-specific payloads rather than normal TLV bodies:

- `(0x0A, 0x05)`
- `(0x28, 0x06)`
- `(0x2C, 0x05)`
- `(0x1C, 0x05)`

Those should remain explicit exceptions in any Rust parser.

---

## 4. Session and initialization flow

### 4.1 High-level state machine

The repository's initialization logic uses this sequence:

```text
BLE connected
-> notifications enabled
-> GetLinkParams
-> decide auth family
-> optional GetSecurityNegotiation
-> one of:
     Normal auth
     HiChain Lite auth
     HiChain / HiChain3 auth
-> configure/init queue
-> GetProductInformation
-> SetTime
-> GetBatteryLevel
-> GetSupportedServices
-> GetSupportedCommands
-> dynamic service initialization
-> steady state
```

### 4.2 Auth mode selection

The decision process uses `deviceSupportType` from `LinkParams` and `authType` from `SecurityNegotiation`.

Observed meanings in the support provider are:

- support type `0x00`: normal mode
- support type `0x02`: HiChain Lite capable
- support type `0x01` or `0x03`: HiChain capable
- support type `0x04`: HiChain3-capable path

Internal `authMode` values used later are:

- `0x00`: no HiChain / normal path
- `0x02`: HiChain Lite path
- `0x04`: HiChain3 negotiation path

After `SecurityNegotiation`:

- `authType == 0x0186A0` means HiChain mode,
- `authType == 0x01` or `0x02` means HiChain Lite mode,
- `isHiChain3(authType)` also selects HiChain mode,
- otherwise the implementation falls back to normal mode if no HiChain path is active.

---

## 5. Authentication flows used by Gadgetbridge

## 5.1 Shared host-side state used during auth

The implementation persists or derives the following values across auth stages:

- real device MAC address,
- a synthetic host MAC alias,
- Android ID bytes,
- per-device secret key,
- optional decrypted PIN code,
- auth version,
- auth algorithm,
- encrypt method,
- encryption counter,
- `firstKey` extracted from the challenge digest,
- HiChain session materials like `seed`, `randSelf`, `randPeer`, `psk`, and `sessionKey`.

## 5.2 Normal mode flow

The normal BLE/AW flow is:

```text
GetLinkParams
-> createSecretKey (if needed)
-> GetAuth
-> GetBondParams
-> GetBond
-> device configuration queue
```

### Stage details

#### A. GetLinkParams

The host asks for the protocol parameters and receives:

- `serverNonce`
- `authVersion`
- `authAlgo`
- `deviceSupportType`
- `encryptMethod`
- `sliceSize`
- `mtu`
- `bondState`

#### B. createSecretKey

`HuaweiCrypto.createSecretKey(device_mac)` derives a 16-byte base secret from two embedded key arrays and the device MAC string. This key is used on the normal path as the encryption key protecting the bonded secret.

#### C. GetAuth

The host generates a random `clientNonce`, concatenates `serverNonce || clientNonce` into a 32-byte `doubleNonce`, then computes a challenge digest and sends:

- TLV `0x01`: 32-byte challenge,
- TLV `0x02`: `authVersion || clientNonce`.

The device replies with the challenge response in TLV `0x01`, and the host validates it against its locally computed expected digest.

#### D. GetBondParams

The host sends device/host identifiers and receives the current `encryptionCounter`. This counter seeds the transport IV generator for subsequent encrypted exchanges.

#### E. GetBond

The host encrypts the current per-device secret key and sends it with:

- serial,
- encrypted bonding key,
- IV.

If the encrypt method is `0x01`, AES-GCM is used. Otherwise AES-CBC with padding is used.

## 5.3 HiChain Lite flow

The HiChain Lite flow is an overlay on top of the normal auth exchange. The sequence is:

```text
GetLinkParams
-> GetSecurityNegotiation
-> optional GetPincode
-> createSecretKey
-> GetAuth
-> GetBondParams
-> GetBond
-> device configuration queue
```

Differences from normal mode:

- `authMode` is set to `0x02`.
- `GetAuth` includes TLV `0x03 = authAlgo`.
- If `authVersion != 0x02`, the host first fetches and decrypts a PIN code.
- The digest logic changes to `computeDigestHiChainLite(...)` or a special `authVersion == 0x02` HMAC path.
- The `GetBond` encryption key is not the MAC-derived key; it is `firstKey`, extracted from the challenge digest state.

## 5.4 PIN code stage

`DeviceConfig.PinCode` is command `0x2C` on service `0x01`. The response contains:

- TLV `0x01`: encrypted PIN bytes,
- TLV `0x02`: IV.

The PIN is decrypted using the digest-secret for the current auth version, not the per-device bonded secret. The cipher is selected by `encryptMethod`:

- `0x01`: AES-GCM
- otherwise: AES-CBC with padding

## 5.5 HiChain / HiChain3 flow

The HiChain path is a multi-step JSON-over-TLV exchange carried inside `DeviceConfig.HiChain` command `0x28`.

Sequence used by the repository:

```text
GetLinkParams
-> GetSecurityNegotiation
-> if first connection: GetPincode
-> GetHiChain step 1
-> GetHiChain step 2
-> GetHiChain step 3
-> GetHiChain step 4
-> if first connection: run second HiChain operation for bind
-> store resulting secret key
-> device configuration queue
```

Two operation codes are used:

- `0x01`: first connection / authenticate
- `0x02`: later bind-style stage

### HiChain step mechanics

#### Step 1

Host creates:

- `seed` = 32 random bytes,
- `randSelf` = 16 random bytes.

It sends JSON containing at least:

- `isoSalt` = `randSelf`
- `peerAuthId` = self Android ID
- `operationCode`
- `seed`
- `peerUserType = 0`

For operation `0x02`, it also sends package/service metadata.

#### Step 1 response processing

Host extracts:

- `authIdPeer`
- `randPeer`
- `peerToken`

It then derives the PSK:

- first connection: `key = SHA-256(hex(pinCode_bytes))`
- later stage: `key = stored_secret_key`
- `psk = HMAC-SHA256(key, seed)`

Token verification message order is:

```text
randPeer || randSelf || authIdSelf || authIdPeer
```

The host verifies:

```text
peerToken == HMAC-SHA256(psk, message)
```

#### Step 2

The host computes its own token over the reverse message order:

```text
randSelf || randPeer || authIdPeer || authIdSelf
```

and sends:

```text
selfToken = HMAC-SHA256(psk, message)
```

#### Step 2 response processing

Host validates:

```text
returnCodeMac == HMAC-SHA256(psk, 00 00 00 00)
```

#### Step 3

The host derives the 32-byte session key:

```text
salt = randSelf || randPeer
info = "hichain_iso_session_key"
sessionKey = HKDF-SHA256(psk, salt, info, 32)
```

On first connection it then:

- generates a 12-byte GCM nonce,
- generates a 16-byte random `challenge`,
- encrypts that challenge using AES-GCM with AAD `"hichain_iso_exchange"`,
- sends nonce + encrypted data.

If this is the later operation stage, the implementation skips directly toward step 4.

#### Step 3 response processing

On first connection, the host decrypts `encAuthToken` using:

- key = `sessionKey`
- IV = returned `nonce`
- AAD = original random `challenge`

The decrypted value becomes the persistent secret key.

#### Step 4

The host sends an AES-GCM encrypted four-byte zero result using:

- key = `sessionKey`
- nonce = random 12 bytes
- plaintext = `00 00 00 00`
- AAD = `"hichain_iso_result"`

#### Final bind key derivation

After the operation `0x02` HiChain completion, the host derives the stored long-term key as:

```text
salt = randSelf || randPeer
info = "hichain_return_key"
final_key = HKDF-SHA256(sessionKey, salt, info, 32)
```

That value is stored as the device secret key.

---

## 6. Crypto used at each stage

## 6.1 Digest secrets by auth version

The implementation contains version-specific digest secrets:

- `DIGEST_SECRET_v1`
- `DIGEST_SECRET_v2`
- `DIGEST_SECRET_v3`

Selection rules:

- auth version `1` and `4` use digest secret v1,
- auth version `2` uses digest secret v2,
- all other known versions use digest secret v3.

## 6.2 Normal challenge/response digest

For non-HiChain-Lite auth, the digest function is:

1. prepend the selected digest secret to the message marker,
2. HMAC-SHA256 that block with `nonce`,
3. HMAC-SHA256 the step-1 digest again with `nonce`,
4. return `challenge = step2 || step1`.

Message markers are:

- challenge: `01 00`
- response: `01 10`
- challenge v4: `04 00`

The first 32 bytes are sent/compared as the actual challenge material. Bytes 32..47 feed the `firstKey` value used later in HiChain Lite bonding.

## 6.3 HiChain Lite digest

For HiChain Lite the repository mutates the version-selected digest secret by XORing it with a hashed form of the current key. Then it computes the challenge as either:

- PBKDF2-SHA256 with 1000 iterations and 256-byte output when `authAlgo == 0x01`, or
- HMAC-SHA256 otherwise.

It then wraps the result in the same `step2 || step1` format described above.

## 6.4 Bond-key protection

`GetBond` encrypts the stored secret key using either:

- AES-GCM without padding when `encryptMethod == 0x01`, or
- AES-CBC with padding for the legacy path.

The encryption key depends on auth family:

- normal mode: MAC-derived secret from `createSecretKey(device_mac)`
- HiChain Lite: `firstKey`

## 6.5 PIN decryption

The encrypted PIN is decrypted using the digest-secret chosen by auth version, not the current bonded secret key. Again:

- AES-GCM when `encryptMethod == 0x01`
- AES-CBC otherwise

## 6.6 Session transport encryption

For general encrypted Huawei packets, `HuaweiPacket.ParamsProvider.getIv()` behaves differently by `deviceSupportType`:

- support type `0x04`: use a random 16-byte nonce,
- all other types: build a 16-byte IV from 12 random bytes plus a rolling 32-bit encryption counter.

When the counter reaches `0xFFFFFFFF`, it wraps back to `1`.

---

## 7. Packet service catalog

This section summarizes the service classes directly represented in `packets/*.java`.

| Service ID | Service name | Commands visible in repo | Main purpose |
|---|---|---|---|
| `0x01` | DeviceConfig | `0x01 LinkParams`, `0x02 SupportedServices`, `0x03 SupportedCommands`, `0x04 DateFormat`, `0x05 TimeRequest`, `0x07 ProductInfo`, `0x08 BatteryLevel`, `0x09 ActivateOnLift`, `0x0B DndDelete`, `0x0C DndAdd`, `0x0D FactoryReset`, `0x0E Bond`, `0x0F BondParams`, `0x10 PhoneInfo`, `0x12 ActivityType`, `0x13 Auth`, `0x16 DeviceStatus`, `0x1A WearLocation`, `0x1B NavigateOnRotate`, `0x1D DndLiftWristType`, `0x2C PinCode`, `0x30 AcceptAgreement`, `0x31 SettingRelated`, `0x33 SecurityNegotiation`, `0x35 ConnectStatus`, `0x37 ExpandCapability` | Bootstrap, auth, core settings, discovery |
| `0x02` | Notifications | `0x01 NotificationAction`, `0x02 NotificationConstraints`, `0x04 NotificationState`, `0x05 NotificationCapabilities`, `0x06 NotificationRemove`, `0x08 WearMessagePush`, `0x10 NotificationReply` | Notification upload and action handling |
| `0x03` | Contacts | `0x01 ContactsSet`, `0x02 ContactsCount` | Contact sync |
| `0x04` | Calls | `0x01 AnswerCallResponse` | Call control |
| `0x07` | FitnessData | `0x01 MotionGoal`, `0x02 UserInfo`, `0x03 FitnessTotals`, `0x07 ActivityReminder`, `0x0E DeviceReportThreshold`, `0x16 TruSleep`, `0x17 AutomaticHeartrate`, `0x1C RealtimeHeartRate`, `0x1D HighHeartRateAlert`, `0x22 LowHeartRateAlert`, `0x23 NotifyRestHeartRate`, `0x24 AutomaticSpo`, `0x25 LowSpoAlert`, `0x28 RunPaceConfig`, `0x29 MediumToStrengthThreshold`, `0x2A SkinTemperatureMeasurement` | User profile, goals, health settings |
| `0x08` | Alarms | `0x01 EventAlarmsRequest`, `0x02 SmartAlarmRequest`, `0x03 EventAlarmsList`, `0x04 SmartAlarmList` | Alarm management |
| `0x09` | OTA | `0x01 StartQuery`, `0x02 DataParams`, `0x03 DataChunkRequest`, `0x04 NextChunkSend`, `0x05 SizeReport`, `0x06 UpdateResult`, `0x07 DeviceError`, `0x09 SetStatus`, `0x0C SetAutoUpdate`, `0x0E NotifyNewVersion`, `0x0F DeviceRequest`, `0x12 Progress`, `0x13 GetMode`, `0x14 SetChangeLog`, `0x15 GetChangeLog` | Firmware and OTA transport |
| `0x0B` | FindPhone / DisconnectNotification | `FindPhone: 0x02 StopRequest`; `DisconnectNotification: 0x03 DisconnectNotificationSetting` | Find phone and disconnect behavior |
| `0x0C` | LocaleConfig | `0x01 SetLanguageSetting`, `0x05 Temperature/MeasurementSystem` | Locale and unit settings |
| `0x0F` | Weather | `0x01 CurrentWeather`, `0x02 WeatherSupport`, `0x04 WeatherDeviceRequest`, `0x05 WeatherUnit`, `0x06 ExtendedSupport`, `0x07 ErrorSimple`, `0x08 ForecastData`, `0x09 WeatherStart`, `0x0A SunMoonSupport`, `0x0C ErrorExtended` | Weather sync |
| `0x17` | Workout | `0x07 WorkoutCount`, `0x08 WorkoutTotals`, `0x0A WorkoutData`, `0x0C WorkoutPace`, `0x0E WorkoutSwimSegments`, `0x14 WorkoutSpO2`, `0x15 WorkoutCapability`, `0x16 WorkoutSections`, `0x17 NotifyHeartRate` | Workout history and metrics |
| `0x18` | GpsAndTime | `0x01 GpsParameters`, `0x02 GpsStatus`, `0x03 GpsData`, `0x07 CurrentGPSRequest` | GPS uploads and time-related GPS settings |
| `0x19` | HrRriTest | `0x01 OpenOrClose`, `0x05 RriData` | HR/RRI test mode |
| `0x1A` | AccountRelated | `0x01 SendAccount`, `0x05 SendExtendedAccount`, `0x0A SendCountryCode` | Account and region identity |
| `0x20` | Stress | `0x09 AutomaticStress` | Stress feature configuration |
| `0x23` | ECG | `0x10 SetECGOpen` | ECG enablement |
| `0x25` | MusicControl | `0x01 MusicStatus`, `0x02 MusicInfo`, `0x03 Control`, `0x04 MusicInfoParams`, `0x05 MusicList`, `0x06 MusicPlaylists`, `0x07 MusicPlaylistMusics`, `0x08 MusicOperation`, `0x09 UploadMusicFileInfo`, `0x0D ExtendedMusicInfoParams` | Music transport and controls |
| `0x26` | WorkMode | `0x01 ModeStatus`, `0x02 SwitchStatusRequest`, `0x03 FootWear` | Work mode / device mode control |
| `0x27` | Watchface | `0x01 WatchfaceParams`, `0x02 DeviceWatchInfo`, `0x03 WatchfaceOperation`, `0x05 WatchfaceConfirm`, `0x06 WatchfaceNameInfo` | Watchface management |
| `0x28` | FileUpload | `0x02 FileInfoSend`, `0x03 FileHashSend`, `0x04 FileUploadConsultAck`, `0x05 FileNextChunkParams`, `0x06 FileNextChunkSend`, `0x07 FileUploadResult`, `0x08 FileUploadDeviceResponse` | Generic file upload service |
| `0x2A` | App | `0x01 AppDelete`, `0x03 AppNames`, `0x06 AppInfoParams` | App metadata and deletion |
| `0x2B` | Earphones | `0x03 InEarState`, `0x04 Audio/ANC/VoiceBoost setters`, `0x10 PauseWhenRemovedFromEar`, `0x2A GetAudioMode` | Earbud controls |
| `0x2D` | Breath | `0x01 SleepBreath` | Sleep breathing data/feature |
| `0x32` | Menstrual | `0x02 ModifyTime`, `0x05 CapabilityRequest` | Menstrual feature settings |
| `0x34` | P2P | `0x01 P2PCommand` | Higher-level P2P multiplexed services |
| `0x37` | DataSync | `0x01 ConfigCommand`, `0x02 EventCommand`, `0x03 DataCommand`, `0x04 DictDataCommand` | Rich feature/data synchronization |

### 7.1 Supported-services and supported-commands discovery

The repository first sends a synthetic `SupportedServices` request containing a list of candidate service IDs. The device replies with the actual supported set. Then `SupportedCommands` iterates per service and builds command lists in a nested TLV container.

That discovery step is important because Huawei devices do not all expose the same command surface, even when they share the same basic transport.

---

## 8. Rust implementation strategy

## 8.1 Suggested crate stack

A Rust reimplementation can be built cleanly with these crate roles:

- `bluer` for BLE connection and GATT I/O
- `bytes` for frame assembly/disassembly
- `crc` or `crc16` for CRC16
- `aes`, `cbc`, `cipher`, `aes-gcm` for symmetric crypto
- `hmac`, `sha2`, `pbkdf2`, `hkdf` for auth primitives
- `serde_json` for HiChain JSON payloads
- `tokio` for async orchestration

## 8.2 Recommended module structure

```text
src/
  protocol/
    frame.rs          # 0x5A framing, slicing, CRC
    tlv.rs            # Huawei TLV encoding/decoding
    services.rs       # service/command enums
    parser.rs         # frame-to-packet dispatch
  crypto/
    mod.rs            # traits and shared helpers
    huawei.rs         # digest, key derivation, IV logic
    hichain.rs        # HKDF/HMAC/GCM flow
  session/
    state.rs          # ParamsProvider-like state
    init.rs           # bootstrap queue
    auth.rs           # normal, lite, hichain flows
  transport/
    ble.rs            # bluer adapter
```

## 8.3 Core state struct

A Rust equivalent of `ParamsProvider` should carry:

```rust
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
```

## 8.4 Frame parser outline

```rust
fn parse_stream(buf: &mut BytesMut) -> Result<Vec<TransportFrame>, ParseError> {
    let mut out = Vec::new();
    loop {
        if buf.len() < 3 {
            break;
        }
        if buf[0] != 0x5a {
            return Err(ParseError::BadMagic);
        }
        let body_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total_len = 3 + body_len + 2;
        if buf.len() < total_len {
            break;
        }
        let frame = buf.split_to(total_len);
        validate_crc(&frame)?;
        out.push(parse_one_frame(&frame)?);
    }
    Ok(out)
}
```

The `parse_one_frame` function should then:

- detect unsliced vs sliced frames,
- reassemble slices into complete packet bodies,
- decode `service_id` and `command_id`,
- detect encrypted TLV wrappers,
- dispatch to a typed parser.

## 8.5 Auth implementation outline

```rust
pub enum AuthFlow {
    Normal,
    HiChainLite,
    HiChain,
}

pub async fn authenticate(dev: &mut DeviceSession) -> Result<()> {
    let link = dev.get_link_params().await?;
    dev.params.apply_link_params(&link);

    match dev.select_auth_flow().await? {
        AuthFlow::Normal => dev.auth_normal(&link).await?,
        AuthFlow::HiChainLite => dev.auth_hichain_lite(&link).await?,
        AuthFlow::HiChain => dev.auth_hichain().await?,
    }

    dev.configure_after_auth().await?;
    Ok(())
}
```

## 8.6 Normal auth pseudocode

```rust
async fn auth_normal(&mut self, link: &LinkParams) -> Result<()> {
    let mac_key = create_secret_key(&self.device_mac, self.params.auth_version)?;
    let client_nonce = random_16();
    let double_nonce = concat(&link.server_nonce, &client_nonce);

    let digest = digest_challenge(self.params.auth_version, self.params.auth_mode, None, &double_nonce)?;
    self.params.first_key = Some(digest[32..48].try_into().unwrap());

    let auth_rsp = self.send_auth(&digest[..32], client_nonce).await?;
    verify_digest_response(..., auth_rsp.challenge_response)?;

    let bond_params = self.get_bond_params().await?;
    self.params.encryption_counter = bond_params.encryption_counter;

    let iv = next_iv(&mut self.params)?;
    let encrypted_secret = encrypt_bond_key(
        self.params.encrypt_method,
        self.params.secret_key.as_ref().unwrap(),
        &mac_key,
        &iv,
    )?;
    self.send_bond(encrypted_secret, iv).await?;
    Ok(())
}
```

## 8.7 HiChain notes for Rust

Model HiChain as a dedicated mini-protocol instead of mixing it into generic auth code. That usually means:

- a typed `HiChainState` struct,
- explicit methods for step 1/2/3/4 payload construction,
- separate functions for PSK derivation, token verification, session-key derivation, and final long-term key derivation,
- AES-GCM helpers that accept AAD exactly as required by each step.

## 8.8 Crypto API sketch

```rust
pub trait HuaweiCryptoExt {
    fn create_secret_key(&self, device_mac: &str) -> Result<[u8; 16]>;
    fn digest_challenge(&self, key: Option<&[u8]>, nonce: &[u8]) -> Result<[u8; 64]>;
    fn digest_response(&self, key: Option<&[u8]>, nonce: &[u8]) -> Result<[u8; 64]>;
    fn encrypt_bond_key(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_pin_code(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>>;
    fn next_iv(&self, counter: &mut u32, device_support_type: u8) -> [u8; 16];
}
```

## 8.9 Important Rust implementation cautions

- Preserve byte order exactly; several fields are built with Java `ByteBuffer` semantics.
- Keep the transport parser separate from decrypted payload parsing.
- Maintain a request/reply queue keyed by service + command so notifications and async packets do not race.
- Treat `HiChain`, `P2P`, and `DataSync` as separate sub-protocols.
- Preserve the message ordering in every HMAC input. Small ordering mistakes will break auth immediately.
- Preserve the exact AAD strings in HiChain:
  - `hichain_iso_session_key`
  - `hichain_iso_exchange`
  - `hichain_iso_result`
  - `hichain_return_key`

---

## 9. Recommended clean-room validation checklist

Before relying on a Rust implementation in production, validate these points with captures or controlled tests:

1. confirm CRC16 polynomial/endianness against device captures,
2. verify whether all target models use the same `encryptMethod` interpretation,
3. verify the legacy AES-CBC padding mode and IV rules on older models,
4. confirm which service/command pairs are truly non-TLV payloads,
5. compare `SupportedCommands` replies across multiple devices,
6. confirm whether HiChain3 introduces any payload differences beyond negotiation and IV behavior,
7. verify whether reconnect flows reuse stored keys identically across Band, Watch Fit, and FreeBuds families.

## 10. Practical takeaway

For a Rust port, the safest architecture is:

- implement `LinkParams` and frame parsing first,
- add TLV support second,
- implement normal auth end to end,
- layer in HiChain Lite,
- isolate HiChain as its own protocol module,
- only then add higher services such as notifications, weather, workout sync, file upload, P2P, and DataSync.

That mirrors the repository's own dependency order: transport first, auth second, service discovery third, feature traffic last.
