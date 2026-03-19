# Huawei Band 9 clean-room protocol spec template

## Purpose

This document is a **clean-room friendly protocol template** derived from the Huawei Band 9 support scaffolding present in this repository.
It is intended as a starting point for a **new Linux implementation using `bluer`**, not as a line-by-line restatement of Gadgetbridge internals.

Use it to separate:

- **Observed wire-level facts** that can be reimplemented safely.
- **Inferred session structure** that should be validated with packet captures.
- **Open questions** that still require independent confirmation.

## Provenance inside this repo

The template below is based on the Huawei Band 9 coordinator, generic Huawei BLE coordinator, core packet serializer/parser, Huawei constants, request/response lifecycle, initialization flow, async router, state/capability helpers, and packet definitions in this repository.

Primary evidence sources in this repo snapshot:

- `HuaweiBand9Coordinator.java`
- `HuaweiLECoordinator.java`
- `HuaweiCoordinator.java`
- `HuaweiConstants.java`
- `HuaweiPacket.java`
- `HuaweiState.java`
- `packets/DeviceConfig.java`
- `service/devices/huawei/HuaweiSupportProvider.java`
- `service/devices/huawei/ResponseManager.java`
- `service/devices/huawei/AsynchronousResponse.java`
- `service/devices/huawei/requests/*.java`

---

## 1. Device profile

### 1.1 Target device

- **Product family:** Huawei Band 9
- **Discovery name pattern:** `huawei band 9-.*` (case-insensitive)
- **Device kind:** fitness band
- **Connection type:** BLE
- **Bonding style in Gadgetbridge:** no platform bonding requirement
- **Scan filter:** BLE advertisements exposing Huawei service `FE86`
- **Support class selected by coordinator:** `HuaweiLESupport`
- **Current support flag in repo:** experimental

### 1.2 BLE services and characteristics

Known GATT structure used by the Huawei BLE implementation:

- Standard services may be present:
  - Generic Access
  - Generic Attribute
  - Device Information
  - Human Interface Device
- Huawei vendor service:
  - **Service UUID:** `0000FE86-0000-1000-8000-00805F9B34FB`
  - **Write characteristic:** `0000FE01-0000-1000-8000-00805F9B34FB`
  - **Read/notify characteristic:** `0000FE02-0000-1000-8000-00805F9B34FB`
- Additional SDP-like UUIDs present in constants for wider Huawei/Honor support, but not part of the Band 9 BLE request path:
  - `82FF3820-8411-400C-B85A-55BDB32CF060`
  - `C9770A18-4C3D-453A-8AAF-D7EC7BBD2785`

### 1.3 Connection setup notes

At session start the implementation should:

1. connect over BLE,
2. enable notifications on the Huawei read characteristic,
3. send initialization/authentication traffic over the Huawei write characteristic,
4. parse all notifications as Huawei protocol frames,
5. split outgoing writes to fit the negotiated slice size,
6. route complete frames by `(serviceId, commandId)`.

---

## 2. Packet framing

> **Status:** largely confirmed from `HuaweiPacket.java`; command-specific payload meanings still need capture-backed validation.

### 2.1 Confirmed transport constants

- **Magic byte:** `0x5A`
- **Protocol version constant:** `0x02`
- **Success/result TLV tag:** `0x7F`
- **Success value bytes:** `00 01 86 A0`
- **Success integer form:** `0x186A0`
- **Crypto TLV tags:**
  - `0x7C` = encryption marker/metadata
  - `0x7D` = IV / initialization vector
  - `0x7E` = ciphertext

### 2.2 Confirmed outer frame layout

Unsliced packet format as serialized by the repo:

```text
0      : 0x5A                      magic
1..2   : uint16                    body_length_plus_1
3      : 0x00                      unsliced marker
4      : service_id
5      : command_id
6..n   : TLV payload
n+1..n+2 : uint16 CRC16
```

Sliced packet format:

```text
0      : 0x5A                      magic
1..2   : uint16                    slice_body_length
3      : slice_state               0x01 first, 0x02 middle, 0x03 last
4      : slice_index/flag          increments per slice
5..    : on first slice: service_id, command_id, then payload bytes
         on later slices: payload bytes only
last 2 : uint16 CRC16
```

### 2.3 Stream handling rules confirmed by code

Incoming parser behavior:

- validates magic byte and CRC16,
- buffers incomplete packets until enough bytes arrive,
- reassembles sliced payloads across `0x01/0x02/0x03` slice states,
- supports concatenated packets in a single BLE notification by keeping `leftover` byte count,
- dispatches the first matching pending request, otherwise routes packet to async handling.

Outgoing serializer behavior:

- writes unsliced packets when payload fits,
- otherwise slices by negotiated `sliceSize`,
- sends service/command IDs only in the first slice,
- uses CRC16 on every slice,
- computes `SupportedCommands` request size conservatively to stay below the slice limit,
- keeps some commands explicitly unsliced even when request splitting is used at a higher level.

### 2.4 TLV/encryption behavior

- Many packets are logically TLV payloads starting immediately after `(serviceId, commandId)`.
- Transport-level parsing first identifies the packet subclass, then optional decryption is attempted.
- Decryption is triggered when TLV tag `0x7C` is present and true.
- Some packets are explicitly marked plaintext in code, especially early auth/bootstrap commands.
- A few services/commands are hard-coded as non-TLV payloads in the parser and should be treated separately during reverse engineering:
  - `(0x0A, 0x05)`
  - `(0x28, 0x06)`
  - `(0x2C, 0x05)`
  - `(0x1C, 0x05)`

---

## 3. Session state machine

> **Status:** strongly supported by `HuaweiSupportProvider.java`.

### 3.1 High-level phases

```text
Disconnected
  -> BLE connected
  -> notifications enabled on FE02
  -> GetLinkParams
  -> optional GetDeviceStatus (not taken on BLE path here)
  -> auth-mode decision
  -> optional GetSecurityNegotiation
  -> one of:
       normal auth flow
       HiChain Lite auth flow
       HiChain / HiChain3 flow
  -> post-auth bootstrap
  -> service discovery
  -> command discovery
  -> optional expand-capability query
  -> dynamic feature initialization
  -> initialized / steady state
```

### 3.2 Authentication mode selection visible in the code

The support code distinguishes these families:

- **Normal mode**
- **HiChain Lite**
- **HiChain**
- **HiChain3**

Observed decision points:

- `GetLinkParams` runs first and supplies `deviceSupportType`, `authVersion`, `authAlgo`, `bondState`, `mtu`, `sliceSize`, and `encryptMethod`.
- For BLE, the code proceeds directly into auth-mode handling without querying `GetDeviceStatus`.
- If the device is considered HiChain-capable, `GetSecurityNegotiation` is issued.
- Negotiation result handling in code is:
  - `0x0186A0` or a HiChain3-derived value => HiChain mode,
  - `0x01` or `0x02` => HiChain Lite mode,
  - otherwise the implementation falls back to normal mode when HiChain is not advertised.

### 3.3 Host identity and stored material

The repo creates and/or persists these host-side values before auth:

- real device MAC address from the connected band,
- synthetic client MAC alias beginning with `FF:FF:FF:...`,
- synthetic Android ID,
- locally persisted per-device secret key (`authkey`),
- optional decrypted PIN code,
- encryption counter after bond-parameter exchange.

### 3.4 Concrete auth chain templates

#### Normal mode

```text
1. GetLinkParams
2. createSecretKey if needed
3. GetAuth
4. GetBondParams        # BLE/AW path in this repo
5. GetBond              # BLE/AW path in this repo
6. continue to bootstrap
```

#### HiChain Lite mode

```text
1. GetLinkParams
2. GetSecurityNegotiation
3. createSecretKey if needed
4. optional GetPincode  # if no cached PIN and authVersion != 0x02
5. GetAuth
6. GetBondParams
7. GetBond
8. continue to bootstrap
```

#### HiChain / HiChain3 mode

```text
1. GetLinkParams
2. GetSecurityNegotiation
3. optional GetPincode on first connection
4. GetHiChain
5. continue to bootstrap
```

---

## 4. Confirmed core command IDs and payload structure

All commands below are in service `0x01` (`DeviceConfig`) unless noted otherwise.

### 4.1 Link parameters (`command 0x01`)

**Request TLVs**

- tag `0x01`
- tag `0x02`
- tag `0x03`
- tag `0x04`
- tag `0x06` only for AW device type

**Response TLVs parsed by code**

- `0x01` => protocol version
- `0x02` => slice size
- `0x03` => MTU
- `0x04` => interval
- `0x05` => authVersion + server nonce blob
- `0x07` => deviceSupportType
- `0x08` => authAlgo
- `0x09` => bondState
- `0x0C` => encryptMethod

**Important side effects**

- sets negotiated slice size for later writes,
- captures a 16-byte server nonce,
- establishes auth algorithm/version inputs,
- determines whether the device advertises HiChain support.

### 4.2 Supported services (`command 0x02`)

Request sends TLV `0x01` containing a host-known candidate service list.

The repo's current candidate list is:

```text
02 03 04 05 06 07 08 09 0A
0B 0C 0D 0E 0F 10 11 12 13 14
15 16 17 18 19 1A 1B 1D 20
22 23 24 25 26 27 2A 2B 2D 2E
30 32 33 34 35
```

Response TLV `0x02` is treated as a bitmap over that candidate list.
Service `0x01` is then force-added because the implementation assumes `DeviceConfig` always exists.

### 4.3 Supported commands (`command 0x03`)

This request is special:

- it can span multiple *requests* even though one request packet itself is not sliced at the protocol level for this command,
- the payload is wrapped inside TLV `0x81`,
- each requested service contributes:
  - `0x02` => service ID
  - `0x03` => candidate command list
- the response also uses nested TLV `0x81`, where:
  - `0x02` => service ID
  - `0x04` => bitmap of supported commands for that service.

The implementation loads commands per service from a static map and stores only the commands whose response bitmap bit is set.

### 4.4 Time sync (`command 0x05`)

**Request TLVs**

- `0x01` => device time as `int`
- `0x02` => timezone/offset short

**Response TLVs**

- `0x01` => device time as `int`

The repo compares device time to host time and immediately reissues the command once if the values differ.

### 4.5 Product info (`command 0x07`)

For BLE/Band-style devices, the request asks for tags:

```text
01 02 07 09 0A 11 12 16 1A 1D 1E 1F 20 21 22 23
```

Response tags parsed by code:

- `0x03` => hardware version
- `0x07` => software version
- `0x09` => serial number
- `0x0A` => product model
- `0x0F` => package name
- `0x11` => device name
- `0x14` => region code
- `0x27` => OTA signature length

### 4.6 Battery level (`command 0x08`, async change `0x27`)

**Request TLV**

- `0x01`

**Response TLVs**

- `0x01` => single battery level
- `0x02` => multi-battery levels array
- `0x03` => per-battery status array

The same response format is also used for async battery updates on command `0x27`.

### 4.7 Bonding commands

#### Bond (`command 0x0E`)

Plaintext request TLVs:

- `0x01`
- `0x03` => constant `0x00`
- `0x05` => client serial
- `0x06` => encrypted bonding key
- `0x07` => IV

#### Bond parameters (`command 0x0F`)

Plaintext request TLVs:

- `0x01`
- `0x03` => client serial
- `0x04` => constant `0x02`
- `0x05`
- `0x07` => synthetic MAC alias
- `0x09`

Response TLVs parsed by code:

- `0x01` => status
- `0x09` => encryption counter

### 4.8 Phone info (`command 0x10`)

The request populates a host capability/profile TLV set based on tags requested by the device. Hard-coded values include Android version string `14` and app version integer `1600008300` for tag `0x11`.

The response is treated either as:

- a simple success ACK using `0x7F == 0x186A0`, or
- a returned list of requested info tags.

### 4.9 Device status (`command 0x16`)

Request shape differs by mode:

- query status: TLV `0x01`
- notify form: TLV `0x02 => 0x00`

Response tag:

- `0x01` => status byte

### 4.10 Auth (`command 0x13`)

Request TLVs:

- `0x01` => 32-byte challenge digest
- `0x02` => `[authVersion(2 bytes)] + clientNonce(16 bytes)`
- `0x03` => authAlgo only in auth mode `0x02`

Response TLV:

- `0x01` => challenge response bytes

The repo derives `doubleNonce = serverNonce || clientNonce`, verifies the returned digest, and caches a `firstKey` used later in some bonding paths.

### 4.11 PIN code (`command 0x2C`)

Plaintext request TLV:

- `0x01`

Response TLVs:

- `0x01` => encrypted PIN payload
- `0x02` => IV

The PIN is decrypted using the negotiated auth/encryption parameters.

### 4.12 Security negotiation (`command 0x33`)

Plaintext request TLVs:

- `0x01` => auth mode
- `0x02` => constant `0x01` when auth mode is `0x02` or `0x04`
- `0x05` => synthetic Android/device UUID
- `0x03` => constant `0x01`
- `0x04` => constant `0x00`
- `0x06` + `0x07` only for auth mode `0x04` (includes phone model)
- `0x0D => 0x01` when `encryptMethod == 1`

Response parsing rules in code:

- tag `0x01 == 0x01` => interpret as `0x0186A0`
- tag `0x02` => auth type byte, optionally XOR-adjusted for HiChain3
- tag `0x7F` => fallback auth type byte

### 4.13 Expand capability (`command 0x37`)

Request TLV:

- `0x01`

Response TLV:

- `0x01` => raw expand capability bytes

This command is only issued if the supported-command map says service `0x01` supports command `0x37`.

---

## 5. Capability discovery and feature bootstrap

### 5.1 Early bootstrap sequence

After successful authentication, the fixed bootstrap chain is:

1. `GetProductInformationRequest`
2. `SetTimeRequest`
3. `GetBatteryLevelRequest`
4. `GetSupportedServicesRequest`

`GetSupportedServicesRequest` then chains into one or more `GetSupportedCommandsRequest` calls and optionally `GetExpandCapabilityRequest` before dynamic service initialization begins.

### 5.2 Dynamic initialization queue observed in the repo

Once service/command capabilities are known, the support code queues a broad post-bootstrap sequence including symbolic requests for:

- extended account sync,
- setting-related state,
- agreement acceptance,
- reverse capabilities,
- setup/device status,
- activity type, wear status, connect status,
- DND configuration,
- menstrual and heart-rate capability notifies,
- user info, run pace config, device report thresholds, heart-rate zones, fitness goals,
- notification capabilities/constraints,
- watchface parameters,
- camera remote enablement,
- app info and music info parameters,
- lift-to-wake, wear location, rotate navigation,
- notification push and message push,
- timezone, language, date format,
- activity reminder, TruSleep, sleep-breath,
- contacts count,
- OTA auto-update and change log,
- country code,
- workout capability,
- ECG-open setting,
- event and smart alarm list queries.

### 5.3 Feature gating implication

A clean-room implementation should model Huawei Band 9 support as:

1. **mandatory transport/auth/bootstrap**,
2. **service/command capability cache**,
3. **optional expand-capability cache**,
4. **feature modules enabled by capability checks**.

---

## 6. Response routing model

### 6.1 Synchronous replies

The request framework matches replies using:

- `serviceId`
- `commandId`

A pending request is completed when a fully parsed packet matches those fields.

### 6.2 Asynchronous / unsolicited traffic

If no pending request claims a complete packet, it is routed through `AsynchronousResponse`.

Observed async families explicitly handled in this repo snapshot include:

- find phone,
- music control,
- call control,
- phone info,
- menstrual updates,
- weather,
- GPS/time,
- file upload,
- watchface,
- camera remote,
- app management,
- P2P,
- ephemeris,
- battery updates,
- notifications/replies,
- permission checks,
- data sync,
- OTA,
- file download.

### 6.3 Clean-room design recommendation

Keep the Linux implementation split into three layers:

1. **Transport/framing**
   - BLE connect, notification subscription, CRC validation, slice reassembly, MTU/slice-aware writes.
2. **Core protocol router**
   - frame decode/encode, optional decrypt, pending-request matching, async dispatch.
3. **Feature modules**
   - auth, config, notifications, weather, data sync, OTA, file transfer, workouts, contacts, alarms.

---

## 7. Seed numeric command catalog

The following numeric service IDs are confirmed by packet classes in this repo and are good initial spec section anchors:

- `0x01` = `DeviceConfig`
- `0x02` = `Notifications`
- `0x03` = `Contacts`
- `0x07` = `FitnessData`
- `0x08` = `Workout`
- `0x09` = `Watchface`
- `0x0A` = `MusicControl`
- `0x0B` = `App`
- `0x16` = `DataSync`
- `0x17` = `P2P`
- `0x18` = `OTA`
- `0x19` = `FileDownloadService0A`
- `0x1A` = `FileDownloadService2C`
- `0x1B` = `FileUpload`
- `0x1D` = `Ephemeris`
- `0x20` = `CameraRemote`
- `0x23` = `GpsAndTime`
- `0x2A` = `Alarms`
- `0x2D` = `AccountRelated`

> These service IDs are code-backed for this repo snapshot, but specific Band 9 firmware support must still be confirmed through the supported-services / supported-commands handshake.

### 7.1 Service `0x01` candidate commands advertised by the host

The host-side candidate command list for `DeviceConfig` is:

```text
04 07 08 09 0A 0D 0E 10 11 12 13 14 1B 1A 1D 21 22 23 24 29 2A 2B 32 2E 31 30 35 36 37 2F
```

That list is particularly useful when correlating captures because it reveals the expected command namespace even before the device returns its bitmap.

### 7.2 Suggested documentation order

Document services in this order:

1. transport + framing,
2. auth + bond,
3. product/time/battery/bootstrap,
4. service and command capability discovery,
5. notifications + async events,
6. fitness/workout sync,
7. alarms/contacts/weather/camera remote,
8. bulk transfer services (OTA/file upload/file download/watchfaces),
9. P2P/data-sync extensions.

---

## 8. Linux `bluer` implementation skeleton template

### 8.1 Suggested crate/module layout

```text
src/
  ble/
    adapter.rs
    device.rs
    gatt.rs
  protocol/
    frame.rs
    tlv.rs
    crypto.rs
    router.rs
    pending.rs
  huawei_band9/
    session.rs
    auth.rs
    bootstrap.rs
    capabilities.rs
    notifications.rs
    weather.rs
    fitness.rs
    workouts.rs
    files.rs
    ota.rs
  capture/
    logging.rs
```

### 8.2 Suggested runtime phases

```text
connect()
  -> discover FE86 / FE01 / FE02
  -> subscribe FE02
  -> start frame reader task
  -> run GetLinkParams/auth state machine
  -> run product/time/battery bootstrap
  -> fetch supported services
  -> fetch supported commands
  -> optionally fetch expand capability
  -> register async handlers
  -> expose high-level API to callers
```

### 8.3 Packet logger template

For every frame, log:

- timestamp,
- BLE direction,
- characteristic UUID,
- raw bytes,
- parsed envelope fields,
- slice state / slice index,
- whether decryption succeeded,
- service/command symbolic name,
- request correlation result,
- remaining undecoded TLVs.

This is the fastest path to turning the symbolic template into a numeric/wire-accurate spec.

---

## 9. Open questions to resolve independently

These are not fully answerable from the files present in this repo snapshot alone:

1. Which of the generic Huawei services/commands are actually enabled on shipping Huawei Band 9 firmware.
2. Exact meaning of several request tags that are currently treated as constants/placeholders by the repo.
3. Exact cryptographic derivation details needed for a clean-room reimplementation without consulting Gadgetbridge logic directly.
4. The precise semantics of expand-capability indices for Band 9.
5. Which async packets are mandatory for a minimally usable Linux implementation versus optional quality-of-life features.
6. Firmware-specific quirks across Band 9 revisions.

---

## 10. Minimal viable spec for first clean-room milestone

### Phase A: connectivity and bootstrap

- connect to FE86,
- subscribe to FE02,
- implement CRC-checked frame parsing and slice reassembly,
- complete enough auth traffic to establish a session,
- fetch product info,
- fetch battery,
- sync time,
- enumerate supported services and commands,
- store optional expand capabilities.

### Phase B: user-visible basics

- notifications,
- weather,
- find phone / camera remote if desired,
- basic configuration settings,
- alarms and contacts if supported.

### Phase C: data sync

- steps,
- sleep,
- workouts,
- bulk file download support as needed.

---

## 11. Working notes section template

Use this section while converting captures into a final protocol spec.

```text
Observation ID:
Date:
Firmware version:
Band model:
Host stack:

Trigger action:
  e.g. connect, enable notifications, request battery, dismiss notification, start workout sync

Frames observed:
  1. host->device ...
  2. device->host ...

Decoded fields:
  - ...

Confidence:
  - confirmed from repeated capture
  - inferred from one capture
  - inferred from Gadgetbridge naming only

Next action:
  - verify on second firmware
  - identify tag meaning
  - confirm encryption boundary
```

---

## 12. Short implementation checklist

- [ ] Confirm FE86 / FE01 / FE02 on actual Huawei Band 9 hardware.
- [ ] Capture and decode `GetLinkParams` on Band 9.
- [ ] Confirm which auth branch the band takes on first pair and reconnect.
- [ ] Reimplement unsliced and sliced CRC16 frame handling.
- [ ] Reimplement pending-request matching keyed by `(serviceId, commandId)`.
- [ ] Confirm product-info, time, battery, supported-services sequence.
- [ ] Build a capture-backed Band 9 command matrix from supported-command responses.
- [ ] Correlate expand-capability bytes with user-visible features.
- [ ] Separate generic Huawei protocol pieces from Band 9-only quirks.
