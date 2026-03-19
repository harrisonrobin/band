# Huawei Band 9 clean-room protocol spec template

## Purpose

This document is a **clean-room friendly protocol template** derived from the Huawei Band 9 support scaffolding present in this repository.
It is intended as a starting point for a **new Linux implementation using `bluer`**, not as a line-by-line restatement of Gadgetbridge internals.

Use it to separate:

- **Observed wire-level facts** that can be reimplemented safely.
- **Inferred session structure** that should be validated with packet captures.
- **Open questions** that still require independent confirmation.

## Provenance inside this repo

The template below is based on the Huawei Band 9 coordinator, BLE support entrypoint, Huawei constants, request/response lifecycle, initialization flow, and Huawei request wrappers in this repository.

Primary evidence sources:

- `HuaweiBand9Coordinator.java`
- `HuaweiLECoordinator.java`
- `HuaweiConstants.java`
- `service/devices/huawei/HuaweiLESupport.java`
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

### 1.3 Connection setup notes

At session start the implementation should:

1. connect over BLE,
2. enable notifications on the Huawei read characteristic,
3. send initialization/authentication traffic over the Huawei write characteristic,
4. parse all notifications as Huawei protocol frames,
5. split outgoing writes to fit the negotiated MTU.

---

## 2. Packet framing template

> **Status:** partially confirmed from constants and request/response plumbing; exact byte layout still needs independent validation from captures or the missing packet classes.

### 2.1 Known constants

- **Magic byte:** `0x5A`
- **Protocol version:** `0x02`
- **Success/result TLV tag:** `127` / `0x7F`
- **Success value:** `00 01 86 A0`
- **Success integer form:** `0x186A0`

### 2.2 Known crypto-related TLV tags

- `124` / `0x7C` = encryption metadata
- `125` / `0x7D` = IV / initialization vector
- `126` / `0x7E` = ciphertext

### 2.3 Framing record template

Use the following placeholder for each confirmed frame type:

```text
Frame name:
Direction: host->device | device->host
Transport: BLE notify/write on FE86/FE01/FE02

Envelope:
  magic: 0x5A                          # confirmed
  version: 0x02                        # confirmed
  service_id: ??                       # symbolic ID known in many cases, numeric value often not present in this repo snapshot
  command_id: ??                       # symbolic ID known in many cases, numeric value often not present in this repo snapshot
  flags: ??
  sequence/correlation: ??
  payload_length: ??
  payload_encoding: TLV, possibly encrypted

Payload TLVs:
  tag 0x?? => <meaning>
  tag 0x?? => <meaning>

Result handling:
  tag 0x7F == 00 01 86 A0 means success  # confirmed at constant level

Notes:
  - Record whether frame is chunked across notifications.
  - Record whether payload is plaintext TLV or encrypted TLV.
  - Record whether a reply is synchronous or asynchronous.
```

### 2.4 Transport behavior template

```text
Incoming stream behavior:
  - notifications may contain full frames or concatenated frames
  - parser must retain partial state until a frame is complete
  - parser must also handle leftover bytes after one complete frame

Outgoing stream behavior:
  - split writes at negotiated MTU boundary
  - insert a short inter-request delay between chained requests
```

---

## 3. Session state machine

> **Status:** strongly suggested by initialization logic.

### 3.1 High-level phases

```text
Disconnected
  -> BLE connected
  -> notifications enabled on FE02
  -> link parameter exchange
  -> optional device status check
  -> security negotiation
  -> one of:
       normal auth flow
       HiChain Lite auth flow
       HiChain auth flow
  -> device configuration bootstrap
  -> capability discovery
  -> dynamic service initialization
  -> initialized / steady state
```

### 3.2 Authentication modes visible in the code

The Huawei support code distinguishes these families:

- **Normal mode**
- **HiChain Lite**
- **HiChain**
- **HiChain3**

Observed decision points:

- a preliminary **link-parameters** request is sent first,
- a **security negotiation** request is then used to determine the auth path,
- depending on mode, the flow may include:
  - PIN retrieval,
  - challenge/response authentication,
  - bond parameter fetch,
  - bond request.

### 3.3 Auth flow template

```text
Auth flow name:
Preconditions:
  - FE02 notifications enabled
  - link parameters available

Steps:
  1. GetLinkParams
  2. [optional] GetDeviceStatus
  3. GetSecurityNegotiation
  4. Branch on negotiated auth type
  5. [optional] GetPinCode
  6. GetAuth
  7. [optional] GetBondParams
  8. [optional] GetBond
  9. Continue into configuration bootstrap

Secrets/material:
  - per-device secret key persisted locally
  - nonce-based challenge material
  - IV used for bond key encryption
  - generated fake Android ID / synthetic MAC alias also participate in host identity

Validation artifacts to capture:
  - request/response pair bytes
  - nonce lengths
  - auth version and algorithm values
  - exact bond key encryption inputs/outputs
```

---

## 4. Known bootstrap sequence for Huawei Band 9 support

After authentication, the BLE Huawei support code performs a short fixed bootstrap and then a larger capability-driven initialization sequence.

### 4.1 Early bootstrap sequence

The request chain is:

1. `GetProductInformationRequest`
2. `SetTimeRequest`
3. `GetBatteryLevelRequest`
4. `GetSupportedServicesRequest`

### 4.2 Capability discovery implications

`GetSupportedServicesRequest` leads into per-service command discovery, then into dynamic service initialization.

The implementation should therefore treat **service discovery and command discovery as protocol-level capability negotiation**, not as optional diagnostics.

### 4.3 Dynamic initialization sequence observed in the repo

The support code queues a long post-bootstrap command chain that includes symbolic requests such as:

- extended account and setup/device-status related commands,
- activity type, wear status, and connect status,
- DND configuration,
- menstrual / heart-rate capability notifications,
- user info, run pace, report thresholds, heart-rate zones, fitness goals,
- notification capabilities and constraints,
- watchface parameters,
- camera remote enablement,
- app info and music info parameters,
- lift-to-wake, wear location, rotate navigation,
- notification push controls,
- timezone, language, date format,
- activity reminder, TruSleep, sleep-breath,
- contacts count,
- OTA auto-update and change-log,
- country code,
- workout capability,
- ECG-open setting,
- alarm list queries.

For clean-room work, this suggests the stack should be designed around:

- a **core mandatory handshake**,
- a **capability cache**,
- a **modular feature registry** that can enable services conditionally.

---

## 5. Response routing model

### 5.1 Synchronous replies

The request framework matches replies using:

- `serviceId`
- `commandId`

A pending request is completed when an incoming fully parsed packet matches those two fields.

### 5.2 Asynchronous / unsolicited traffic

The repo explicitly routes unmatched packets to a separate asynchronous handler.

Observed asynchronous service families include symbolic handling for:

- find phone,
- music control,
- call control,
- phone info,
- weather,
- GPS/time,
- file upload,
- watchface,
- camera remote,
- app management,
- P2P,
- ephemeris,
- battery updates,
- notifications / replies,
- permission checks,
- data sync,
- OTA,
- file download.

### 5.3 Clean-room design recommendation

Keep the Linux implementation split into three layers:

1. **Transport/framing**
   - BLE connect, notification subscription, MTU-aware write splitting, stream reassembly.
2. **Core protocol router**
   - frame decode/encode, pending request matching, async dispatch.
3. **Feature modules**
   - auth, config, notifications, weather, data sync, OTA, file transfer, etc.

---

## 6. Band 9 command catalog template

Use one record like this per command, even when only symbolic IDs are known.

```text
Command name:
Symbolic service: <e.g. DeviceConfig>
Symbolic command: <e.g. ProductInfo>
Numeric service ID: unknown | 0x??
Numeric command ID: unknown | 0x??
Direction: host->device request / device->host response / async
Phase: auth | bootstrap | feature-init | steady-state | file-transfer

Request payload:
  - plaintext or encrypted: ?
  - TLV tags:
      * 0x?? => ...

Response payload:
  - plaintext or encrypted: ?
  - TLV tags:
      * 0x?? => ...

Observed effects:
  - updates local capability cache / device metadata / feature state / user-visible event

Failure semantics:
  - timeout behavior:
  - explicit result TLV:

Evidence:
  - source files:
  - packet captures:
  - notes:
```

### 6.1 Seed command list for Band 9 work

Start by documenting these first because they sit on the critical path:

- `GetLinkParamsRequest`
- `GetDeviceStatusRequest`
- `GetSecurityNegotiationRequest`
- `GetPincodeRequest`
- `GetAuthRequest`
- `GetBondParamsRequest`
- `GetBondRequest`
- `GetProductInformationRequest`
- `SetTimeRequest`
- `GetBatteryLevelRequest`
- `GetSupportedServicesRequest`
- `GetSupportedCommandsRequest`

Then add commonly needed user-visible commands:

- notifications
- weather
- music control
- alarms
- activity / fitness sync
- workout sync
- contacts
- camera remote

---

## 7. Symbolic command families visible in this repo snapshot

This repo snapshot exposes many symbolic service/command names through request wrappers even where numeric IDs are not directly present.
That is useful for **naming the spec sections** before reverse-engineering exact byte values.

### 7.1 Core/config/auth families

- `DeviceConfig`
  - `LinkParams`
  - `DeviceStatus`
  - `SecurityNegotiation`
  - `PinCode`
  - `Auth`
  - `BondParams`
  - `Bond`
  - `ProductInfo`
  - `BatteryLevel`
  - `SupportedServices`
  - `SupportedCommands`
  - `ExpandCapability`
  - `SettingRelated`
  - `ActivityType`
  - `ConnectStatusRequest`
  - `DndLiftWristType`
  - `DndAddRequest`
  - `DndDeleteRequest`
  - `AcceptAgreement`
  - `TimeRequest`
  - `PhoneInfo`

### 7.2 Feature/service families

- `Notifications`
- `FitnessData`
- `Workout`
- `Watchface`
- `MusicControl`
- `App`
- `DataSync`
- `P2P`
- `OTA`
- `FileDownloadService0A`
- `FileDownloadService2C`
- `FileUpload`
- `Ephemeris`
- `EphemerisFileUpload`
- `CameraRemote`
- `GpsAndTime`
- `Contacts`
- `Alarms`
- `AccountRelated`

### 7.3 Suggested documentation order

Document services in this order:

1. transport + framing,
2. auth + bond,
3. product/time/battery/bootstrap,
4. capability discovery,
5. notifications + async events,
6. fitness/workout sync,
7. bulk transfer services (OTA/file upload/file download/watchfaces),
8. P2P/data-sync extensions.

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
  -> run auth state machine
  -> run bootstrap sequence
  -> fetch service/command capabilities
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
- whether decryption succeeded,
- service/command symbolic name,
- request correlation result,
- remaining undecoded TLVs.

This is the fastest path to turning the symbolic template into a numeric/wire-accurate spec.

---

## 9. Open questions to resolve independently

These are not fully answerable from the files present in this repo snapshot alone:

1. Exact numeric `serviceId` / `commandId` values for many symbolic packet classes.
2. Full envelope field order and sizes beyond the confirmed constants.
3. Exact TLV tag maps for each command payload.
4. Exact encryption boundaries per command.
5. Which feature modules are truly required on Huawei Band 9 versus shared Huawei watch support.
6. Whether any Band 9 specific quirks differ from Band 8 / Band 10 behavior.

---

## 10. Minimal viable spec for first clean-room milestone

A practical first milestone for a new Linux implementation would be:

### Phase A: connectivity and bootstrap

- connect to FE86,
- subscribe to FE02,
- send enough auth traffic to complete session setup,
- fetch product info,
- fetch battery,
- sync time,
- enumerate supported services/commands.

### Phase B: user-visible basics

- notifications,
- weather,
- find phone / camera remote if desired,
- basic configuration settings.

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
- [ ] Capture and decode link-parameter exchange.
- [ ] Confirm selected auth branch used by Band 9 firmware under Linux.
- [ ] Write frame reassembler for concatenated notify payloads.
- [ ] Implement pending-request matcher keyed by service/command.
- [ ] Confirm product-info, time, battery, supported-services sequence.
- [ ] Build numeric command catalog from captures.
- [ ] Separate generic Huawei protocol pieces from Band 9-only quirks.

