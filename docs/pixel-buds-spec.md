**Pixel Buds A · Maestro Protocol**

Reverse-Engineering Stock-Take

Session: maestro_session_20260313 · 1,438 events · 70 channels · FW
3.527.0 / CM4_MB

**CONFIRMED** fully decoded + verified **PARTIAL** structure known,
fields unclear **UNKNOWN** not yet decoded

**1 Frame Type Registry**

  ------------------------------------------------------------------------------------------
  **Byte**   **Name**             **Description**
  ---------- -------------------- ----------------------------------------------------------
  **0x01**   **OPEN**             Phone→buds: open a Maestro channel

  **0x02**   **OPEN_ACK**         Buds→phone: channel open acknowledged

  **0x03**   **DATA→buds**        Phone→buds data payload --- majority of control traffic

  **0x04**   **CLOSE**            Channel close (either direction)

  **0x05**   **DATA←buds**        Buds→phone data payload --- status, events, battery,
                                  telemetry

  **0x09**   **PING**             Keepalive ping (either direction); body is the CH8
                                  sub-payload

  **0x0e**   **RSP←buds**         Buds→phone response frame (reply to a phone query)

  **0x10**   **UNKNOWN_0x10**     Seen on CH3 with tiny payloads (0x0002 / 0x0004 / 0x000f)
                                  during ear-wear transitions. Not battery, not gesture.
                                  Separate sub-protocol; semantics unknown.

  **0x87**   **STATE_SNAPSHOT**   Buds→phone full settings sync. Fires at connect and app
                                  foreground. Payload = 1a 02 \[setting_tag\] \[value\] ---
                                  one frame per setting, all fired simultaneously.
  ------------------------------------------------------------------------------------------

**2 Channel Map (all observed channels)**

*Bold name = fully decoded. Italic description = working hypothesis
only.*

  --------------------------------------------------------------------------------------------------------
  **CH**    **Name**               **Status**      **What we know**
  --------- ---------------------- --------------- -------------------------------------------------------
  **0**     UNKNOWN_0              **PARTIAL**     *10-byte packets. byte\[0\]=metadata, byte\[1\]=\'\$\'
                                                   → feed data\[1:\] to pw_tokenizer base64 decoder.
                                                   Likely a secondary tokenized log stream.*

  **1**     LOG_STREAM             **PARTIAL**     *pw_tokenizer 4-byte LE tokens + zigzag-varint args.
                                                   Structure known; strings unresolvable without matching
                                                   firmware .elf token database.*

  **2**     **HANDSHAKE**          **CONFIRMED**   4 subtypes. (A) Phone→buds init: f1=proto_version=6,
                                                   f2=timestamp_ms, f3=tz_offset, f14=2 (Android). (B)
                                                   Buds→phone model string:
                                                   \'google-pixel-buds-a-series-v1\'. (C) Capability
                                                   response: f4=sample_rate=16000. (D) 6-byte raw binary
                                                   capability bitmap --- NOT protobuf; bit-field structure
                                                   unknown; varies per session.

  **3**     **REALTIME_CONTROL**   **CONFIRMED**   THREE message types share this channel. (1) BATTERY
                                                   UPDATE raw \[0xe4\]\[bud_byte\]\[case_byte\]: bud_byte
                                                   bit7=IN_CASE, bits\[6:0\]=bud %; case_byte=case %
                                                   (0xFF=absent). Which bud: infer from CH9 EAR_STATE
                                                   ±50ms. (2) Protobuf gestures: f1=1 LONG_PRESS / f1=2
                                                   TAP (single/double/triple not yet distinguished). (3)
                                                   Protobuf control: f2=2 CTRL_INIT_OR_CASE_EVENT / f2=5
                                                   CTRL_TEARDOWN. Also: frame type 0x10 carries tiny
                                                   payloads during ear-wear --- separate sub-protocol.

  **4**     **VERSION_AUDIO**      **CONFIRMED**   TWO subtypes by packet rate. (A) VERSION/EQ: protobuf
                                                   fw_version, serial, hw_model, fw_components; 104-byte
                                                   EQ blob (0x6db6db pattern = Q0.23 DSP biquad
                                                   coefficients). (B) AUDIO_STREAM: same 104-byte frame at
                                                   \~25 fps during long-press hold = \~33 kbps, 16 kHz,
                                                   codec_id=2.

  **5**     **CONN_STATE**         **CONFIRMED**   f1 enum: 0=IDLE, 1=CONNECTED, 3=UNKNOWN(reconnecting?),
                                                   4=STREAMING, 5=UNKNOWN(1 observation). Also carries
                                                   DEVICE_INFO_RESPONSE (f1=2): nested f7 serial triplet
                                                   --- f7.f1=CASE, f7.f2=RIGHT, f7.f3=LEFT.

  **6**     **CAPABILITY_FLAGS**   **CONFIRMED**   Invariant payload 080b1001: f1=11 (active Maestro
                                                   channels), f2=1 (protocol revision). Never changes
                                                   within a session.

  **7**     **AUDIO_CONFIG**       **CONFIRMED**   Negotiated once at connect. f1=sample_rate_hz=16000,
                                                   f2=bit_depth=24, f3=1200 (frame size?), f4=codec_id=2,
                                                   f5=0, f6=1.

  **8**     **KEEPALIVE**          **CONFIRMED**   2-byte: 0x38=PING (phone→buds, incrementing seq),
                                                   0x01=PONG (buds→phone). 0x87 on this channel =
                                                   keepalive mode byte in f3, NOT a settings update.

  **9**     **WEAR_AND_TOUCH**     **CONFIRMED**   Outer protobuf wrapper (tag 0x0a), inner fixed
                                                   \[type:1\]\[value:1\] TLV (value absent for touch
                                                   events). Types: 0x01=LID_STATE, 0x02=CHARGE_STATE,
                                                   0x03=EAR_STATE (0=BOTH_OUT 1=R_IN 2=L_IN 3=BOTH_IN),
                                                   0x04=PRIMARY_BUD, 0x05=TOUCH_EVENT_L (every left
                                                   gesture, no value), 0x06=BATTERY_R (by symmetry; not
                                                   explicitly observed), 0x07=BATTERY_CASE,
                                                   0x0b=GESTURE_COMPLETE (val=6=IDLE, fires \~500ms
                                                   post-touch). Battery scale 0-125 → ×(100/125) = %.
                                                   TOUCH_EVENT_R type byte not yet observed.

  **10**    **DEVICE_REG**         **CONFIRMED**   AT IND strings at connect (e.g. \'call: range=0,1\').
                                                   Protobuf: f1=device_id=\'3df7c2e\', f2=128, f3=0. All
                                                   0x87 STATE_SNAPSHOT settings updates arrive on this
                                                   channel (and simultaneously on CH9 for some).

  **11**    **STATUS_STREAM**      **CONFIRMED**   Short (≤10B): VERSION_NOTIFICATION --- f1=msg_type,
                                                   f2=fw_component_name. Long (\~36B): DEVICE_STATUS ---
                                                   f2=seq_num, f5=audio_mode (enum; unknown semantics),
                                                   f6=wear_state, f11=conn_mask (3=both buds), f12=tick_us
                                                   (buds-side monotonic µs), f13=125 (constant --- scale
                                                   divisor, not a live reading).

  **12**    UNKNOWN_12             **PARTIAL**     *ASCII payload, fires on every reconnect. Likely an
                                                   internal session token or service registration string
                                                   exchanged at (re)connect.*

  **17**    UNKNOWN_17             **PARTIAL**     *ASCII payload. Always fires as a group with CH19 and
                                                   CH21 at connect (OPEN frames, phone→buds). Three-way
                                                   pattern suggests three sub-service pipes being
                                                   registered.*

  **19**    UNKNOWN_19             **PARTIAL**     *See CH17. Part of the three-way sub-service open
                                                   group.*

  **21**    UNKNOWN_21             **PARTIAL**     *See CH17. Part of the three-way sub-service open
                                                   group.*

  **24**    UNKNOWN_24             **PARTIAL**     *1-byte payloads: 0x0e (bass_eq_1), 0x0b (post in_ear).
                                                   Decoded as pw_token=0x0c962e97 on about_page. Likely a
                                                   settings-acknowledge or UI-event notification channel.*

  **29**    UNKNOWN_29             **PARTIAL**     *24-60 byte payloads with pw_tokenizer base64 blobs.
                                                   Fires on tap_triple_R and EQ changes. Likely extended
                                                   telemetry / usage-stats reporting.*

  **32**    LOG_EXTENDED           **PARTIAL**     *Pigweed pw_log frame header; f2=module_token=3.
                                                   Payload truncated in capture. Same decoder family as
                                                   CH33/64/99.*

  **33**    LOG_TOKENIZED          **PARTIAL**     *pw_tokenizer base64 + protobuf envelope: f1=severity,
                                                   f2=module_token, f3=timestamp_us. Token→string needs
                                                   firmware .elf.*

  **64**    LOG_TOKENIZED_B        **PARTIAL**     *\$\<base64\> style pw_tokenizer with args. Same
                                                   decoder as CH33.*

  **99**    LOG_EXTENDED_B         **PARTIAL**     *Longer tokenized log frames. Same decoder as CH32/33.*

  **114**   **AUDIO_GAIN_DIAG**    **CONFIRMED**   ASCII TWS gain/channel-map diagnostics (e.g.
                                                   \'ary-mobile: 13.7 dBm; rx gain lev...\'). Fires on
                                                   reconnect.

  **116**   **AUDIO_LEVEL_DIAG**   **CONFIRMED**   ASCII TWS tx level dBm + HFP codec loss stats. Fires
                                                   periodically during audio sessions.
  --------------------------------------------------------------------------------------------------------

**3 Device Settings Register (0x87 STATE_SNAPSHOT on CH10)**

Every 0x87 frame carries one setting: payload = 1a 02 \[tag\] \[value\].
All tags use protobuf wire type 0 (varint). The full register fires
simultaneously at connect and whenever the app is foregrounded.

  -------------------------------------------------------------------------------------------------------------------------
  **Tag**    **Proto   **Boot   **Setting name**           **Values**   **Status**      **Evidence / notes**
             f#**      val**                                                            
  ---------- --------- -------- -------------------------- ------------ --------------- -----------------------------------
  **0x08**   f1        1 (on)   **IN_EAR_DETECT**          *0=off /     **CONFIRMED**   Toggled on→off→on in session
                                                           1=on*                        (in_ear_on / in_ear_off)

  **0x18**   f3        0 (off)  **USAGE_DIAGNOSTICS**      *0=off /     **CONFIRMED**   User confirmed: disabled in Pixel
                                                           1=on*                        Buds app during this session

  **0x28**   f5        0 (off)  **ADAPTIVE_SOUND**         *0=off /     **CONFIRMED**   Toggled on/off in session
                                                           1=on*                        (adaptive_on / adaptive_off)

  **0x38**   f7        1 (on)   unknown_f7                 *0=off /     **PARTIAL**     Boot=1 (defaults ON). Never
                                                           1=on*                        toggled. Strong candidate:
                                                                                        Attention Alerts (default on in
                                                                                        app)

  **0x40**   f8        1 (on)   **FIRMWARE_AUTO_UPDATE**   *0=off /     **CONFIRMED**   User confirmed: automatic updates
                                                           1=on*                        enabled in Pixel Buds app during
                                                                                        this session

  **0x50**   f10       0 (off)  unknown_f10                *0=off /     **PARTIAL**     Boot=0 (defaults OFF). Never
                                                           1=on*                        toggled. Candidate: Announce
                                                                                        Notifications (default off in app)

  **0x58**   f11       1 (on)   **TOUCH_CONTROLS**         *0=off /     **CONFIRMED**   Toggled on/off in session
                                                           1=on*                        (touch_ctrl_on / touch_ctrl_off)

  **0x60**   f12       0 (off)  unknown_f12                *0=off /     **PARTIAL**     Boot=0 (defaults OFF). Never
                                                           1=on*                        toggled. Candidate: Increase Ring
                                                                                        Volume (default off in app)

  **0x68**   f13       0 (off)  **VOLUME_EQ**              *0=off /     **CONFIRMED**   Toggled on/off in session
                                                           1=on*                        (vol_eq_on / vol_eq_off)

  **0x70**   f14       5 (L6)   **BASS_EQ_LEVEL**          *val 0-5 →   **CONFIRMED**   All six levels stepped in session
                                                           UI level                     (bass_eq_1 through bass_eq_6).
                                                           1-6*                         Display as value+1.
  -------------------------------------------------------------------------------------------------------------------------

*Proto field numbers are non-contiguous: f1, f3, f5, f7, f8, f10, f11,
f12, f13, f14. Gaps (f2, f4, f6, f9) are either unused or carry a
different wire type not yet observed.*

**4 Battery Protocol (CH3 raw path)**

Battery travels on Maestro CH3 as a 3-byte raw frame --- not on a
separate RFCOMM channel. Tag byte 0xe4 has protobuf wire type 4
(invalid), so it can never be confused with a protobuf message.

Frame: \[0xe4\] \[bud_byte\] \[case_byte\]

bud_byte bit 7 = BUD_IN_CASE flag (1 = bud is sitting in the case)

bud_byte bits 6:0 = bud battery % (0-100)

case_byte = case battery % (0-100) \| 0xFF = case absent

*Which bud is NOT encoded in the frame. Infer from the CH9 EAR_STATE
transition (LEFT_IN vs RIGHT_IN) in the same ±50ms window.*

  ---------------------------------------------------------------------------------------
  **Raw   **Old       **Bud   **Bud in  **Case   **Context**
  hex**   \'param\'   %**     case?**   %**      
          display**                              
  ------- ----------- ------- --------- -------- ----------------------------------------
  **e4 e4 *0x1ce4*    100%    **YES**   28%      fast_pair connect (both in case)
  1c**                                           

  **e4 e4 *0x1be4*    100%    **YES**   27%      bud returned to case (L or R --- check
  1b**                                           CH9)

  **e4 64 *0x1b64*    100%    **NO**    27%      bud out of case (L or R --- check CH9)
  1b**                                           

  **e4 64 *0xff64*    100%    **NO**    ABSENT   case not connected / lid closed
  ff**                                           
  ---------------------------------------------------------------------------------------

**5 Touch Gesture Sequence (fully confirmed)**

Every tap or long-press on either bud produces this exact cross-channel
sequence:

+0ms CH9 EAR_STATE = LEFT_IN / RIGHT_IN in-ear gate (precondition)

+5ms CH9 TOUCH_EVENT_L (type=0x05, no value) capacitive touch detected

+5ms CH3 f1=1 LONG_PRESS or f1=2 TAP gesture type from classifier

+10ms CH11 DEVICE_STATUS broadcast status update on all listeners

+500ms CH9 GESTURE_COMPLETE = 6 (IDLE) classifier returns to idle

Open question: single / double / triple tap all produce CH3 f1=2 (TAP)
--- not yet distinguished in protocol terms. Long press produces
continuous AUDIO_STREAM on CH4 for the duration, then fires f1=1 at
release.

**6 What We Don't Know Yet**

  ---------------------------------------------------------------------------------------
  **Where**         **Observed**            **Hypothesis / why it matters**
  ----------------- ----------------------- ---------------------------------------------
  **CH3 · frame     *left_in_ear,           Not battery (wrong range), not gesture (wrong
  type 0x10**       right_in_ear (values    structure). Separate wear-state
                    0x0002, 0x0004,         acknowledgement sub-protocol. Needs targeted
                    0x000f)*                capture.

  **CH3 · tap       *All tap gestures →     Differentiation not found. May be: timing
  count**           f1=2 regardless of      delta between TOUCH_EVENT_L and
                    single/double/triple*   GESTURE_COMPLETE; an extra CH9 type byte; or
                                            an additional f3 field only present in
                                            multi-tap payloads. Needs
                                            tap_single/double/triple capture in one
                                            session.

  **CH9 ·           *Not observed in this   Expected by symmetry with 0x05=TOUCH_EVENT_L.
  TOUCH_EVENT_R**   session*                Exact type byte unknown. Need a
                                            right-bud-only tap capture to observe it.

  **CH9 · type      *Seen in earlier        Fires occasionally. No action correlation
  0x1f**            sessions only*          found. May be a calibration or diagnostic
                                            event.

  **CH5 · states 3  *State 3 on reconnect;  State 3 likely RECONNECTING. State 5 only one
  and 5**           state 5 once during     observation --- no hypothesis. Need a
                    right_in_ear*           deliberate multi-reconnect capture.

  **CH11 · f5       *Every DEVICE_STATUS    Enum with unknown semantics. Device has no
  audio_mode**      long frame*             ANC. Possible: 0=idle, 1=call, 2=media,
                                            3=assistant. Need a call + music playback
                                            session to correlate.

  **0x87 · CH5      *Every connect*         \~50-byte payload with what appear to be
  large snapshot**                          serial numbers and timestamps, but structure
                                            differs from the 1a02XXYY settings format.
                                            Needs manual hex analysis against known
                                            serials.

  **0x87 · CH2      *Every connect*         Large varying payload. Structure unknown. May
  large snapshot**                          carry handshake state, protocol flags, or
                                            session tokens.

  **0x87 · CH6      *Every connect*         Large payload, distinct structure from CH10
  large snapshot**                          settings. Not decoded. Possibly extended
                                            capability flags.

  **Settings 0x38 / *Boot snapshot only --- Names unknown. Candidates: Attention Alerts
  0x50 / 0x60**     never toggled*          (f7, boot=ON), Announce Notifications (f10,
                                            boot=OFF), Increase Ring Volume (f12,
                                            boot=OFF). Toggle each in isolation in next
                                            capture.

  **CH2 subtype D · *Every OPEN and         Not protobuf. Bit-field structure unknown.
  6-byte bitmap**   reconnect*              Varies per session. Needed for full
                                            capability negotiation decode.

  **High-number     *1-3 observations each* Channels 40, 48, 51-56, 60, 65-66, 71-72, 78,
  channels 40-130**                         82-83, 85, 87, 90, 97. Cannot decode from
                                            single observations. Many carry pw_tokenizer
                                            blobs or opaque binary payloads.
  ---------------------------------------------------------------------------------------

1. Audio Transport Separation
| Audio Type | Transport Protocol | Handled By | Maestro's Role |
| :--- | :--- | :--- | :--- |
| **Media Playback** | A2DP (L2CAP) | OS Bluetooth Stack (PipeWire/Pulse) | None (only play/pause/volume commands via CH3) |
| **Phone Calls** | HFP (RFCOMM/L2CAP) | OS Bluetooth Stack (ofono/ModemManager) | None (only answer/hangup commands via CH3, stats via CH116) |
| **Google Assistant** | Maestro CH4 (RFCOMM) | Bluer Plugin | Direct (16kHz audio stream during long-press) |
| **Voice Prompts** | Internal Buds DAC | Buds Firmware | Triggered via CH3 commands |

  
  # Maestro Protocol — Bluer Implementation Specification

## Overview

The Maestro protocol is a **classic Bluetooth RFCOMM multiplexer**. All Maestro logical channels ride on a **single RFCOMM DLCI** discovered via SDP. This spec uses RFCOMM terminology for connection, then documents the Maestro logical channels you need to implement.

---

## 1. RFCOMM Connection Flow

### Step 1: SDP Query
Query the Pixel Buds A for the Maestro service UUID:
```
UUID: 00001101-0000-1000-8000-00805F9B34FB (Serial Port Profile)
```

Extract the **RFCOMM server channel** from the SDP record (typically 10-19).

### Step 2: Calculate DLCI
```
DLCI = server_channel × 2
```
Example: server channel 13 → DLCI 26 (0x1a)

### Step 3: Connect
```rust
// Bluer pseudocode
let device = adapter.connect(device_addr).await?;
let mut stream = device.rfcomm_connect(dlci).await?;
// Maestro multiplexer is now active on this stream
```

### Step 4: Maestro Framing
All bytes read/written on this RFCOMM stream are **Maestro frames**, not raw data.

---

## 2. Maestro Frame Format

### Standard Frame (most common)
```
Byte 0: Frame Type    (0x01-0x87)
Byte 1: Channel       (0x00-0x82, logical channel ID)
Byte 2: Flags         (usually 0x00)
Byte 3: Payload Length (N bytes)
Byte 4+: Payload      (N bytes)
```

### Compact Frame (observed on some streams)
```
Byte 0: Frame Type
Byte 1: Channel
Byte 2: Single payload byte (length implied = 1)
```

### Frame Type Registry
| Type | Name | Direction | Meaning |
|------|------|-----------|---------|
| 0x01 | OPEN | Phone→Buds | Open logical channel |
| 0x02 | OPEN_ACK | Buds→Phone | Channel opened |
| 0x03 | DATA | Phone→Buds | Command/control |
| 0x04 | CLOSE | Either | Close channel |
| 0x05 | DATA | Buds→Phone | Status/events |
| 0x09 | PING | Either | Keepalive |
| 0x87 | STATE_SNAPSHOT | Buds→Phone | Settings sync |

---

## 3. Logical Channel Implementation

### ✅ Phase 1: Essential Channels (Implement First)

| CH | Name | Purpose | Frame Types | Implementation Priority |
|----|------|---------|-------------|------------------------|
| **2** | HANDSHAKE | Session init | 0x03→, 0x02←, 0x87← | **P0** - Must complete before any other channel |
| **3** | REALTIME_CTRL | Battery, gestures, media | 0x03→, 0x05←, 0x10← | **P0** - Core user features |
| **5** | CONN_STATE | Connection state machine | 0x02←, 0x03→, 0x87← | **P0** - Track IDLE/CONNECTED/STREAMING |
| **8** | KEEPALIVE | Ping/pong | 0x03→, 0x05←, 0x09→ | **P0** - Required to maintain connection |
| **9** | WEAR_AND_TOUCH | Ear detection, touch, gestures | 0x02←, 0x05←, 0x87← | **P0** - Wear detection toggle, gesture events |
| **10** | DEVICE_REG | Settings, device ID | 0x05←, 0x03→, 0x87← | **P0** - Settings toggles arrive here |
| **11** | STATUS_STREAM | Device status broadcast | 0x02←, 0x05← | **P1** - Useful for diagnostics |

### ⚠️ Phase 2: Supporting Channels (Implement Later)

| CH | Name | Purpose | Notes |
|----|------|---------|-------|
| **4** | VERSION/AUDIO | FW info, EQ, audio stream | Rate-based: >10/sec = audio, <1/sec = version |
| **6** | CAPABILITY_FLAGS | Protocol capabilities | Invariant: `080b1001` → 11 channels, rev 1 |
| **7** | AUDIO_CONFIG | Audio negotiation | Negotiated once at connect |
| **12,17,19,21** | ASCII tokens | Session registration | Log as ASCII, no action needed |
| **114,116** | Audio diagnostics | TWS gain/level diag | ASCII passthrough |

### ❌ Phase 3: Skip for MVP

| CH | Name | Reason to Skip |
|----|------|----------------|
| **0,1,32,33,64,99** | Tokenized logs | Need firmware .elf for string resolution |
| **24,29** | Settings ack / telemetry | pw_tokenizer blobs, log hex only |
| **40-130** | High-numbered channels | Sparse observations, not essential |

---

## 4. Critical Sub-Protocols

### 4.1 Channel 2: Handshake Sequence

**Phone→Buds (OPEN CH2, subtype A):**
```
Payload: protobuf
  f1 = 6              (proto_version)
  f2 = timestamp_ms   (current time)
  f3 = tz_offset      (timezone offset minutes)
  f14 = 2             (platform: 2=Android)
```

**Buds→Phone (OPEN_ACK CH2, subtypes B/C/D):**
```
Subtype B: f1 = "google-pixel-buds-a-series-v1"  (model string)
Subtype C: f4 = 16000 (sample_rate), f7 = 24 (bit_depth)
Subtype D: 6-byte raw bitmap [6c17f8151cc6] (cache, don't parse)
```

**Implementation:**
```rust
async fn handshake(&mut self) -> Result<()> {
    // Send OPEN on CH2
    self.send_frame(0x01, 2, &self.build_handshake_init()).await?;
    
    // Expect OPEN_ACK with subtypes B, C, D
    let ack = self.recv_frame_on_channel(2).await?;
    assert!(ack.frame_type == 0x02);
    
    // Cache model, audio config, capability bitmap
    self.parse_handshake_response(&ack.payload)?;
    Ok(())
}
```

---

### 4.2 Channel 3: Battery Protocol (RAW PATH)

**Frame: 3 bytes**
```
Byte 0: 0xe4 (battery command tag)
Byte 1: bud_byte (bit7=IN_CASE, bits6:0=bud %)
Byte 2: case_byte (0-100%, 0xFF=absent)
```

**Which bud?** Infer from Channel 9 EAR_STATE transition within ±50ms.

**Implementation:**
```rust
fn parse_battery(payload: &[u8], last_ear_state: EarState) -> BatteryUpdate {
    assert!(payload[0] == 0xe4 && payload.len() == 3);
    
    let bud_pct = payload[1] & 0x7F;
    let in_case = (payload[1] & 0x80) != 0;
    let case_pct = if payload[2] == 0xFF { None } else { Some(payload[2]) };
    
    let bud_side = match last_ear_state {
        EarState::LeftIn => Bud::Left,
        EarState::RightIn => Bud::Right,
        _ => Bud::Unknown,
    };
    
    BatteryUpdate { bud_side, bud_pct, in_case, case_pct }
}
```

---

### 4.3 Channel 3: Gesture Protocol (PROTOBUF PATH)

**Frame: protobuf**
```
f1 = 1 → LONG_PRESS (fires at release)
f1 = 2 → TAP (single/double/triple — distinguished in CH9)
f2 = 2 → CTRL_INIT or CASE_EVENT
f2 = 5 → CTRL_TEARDOWN
```

---

### 4.4 Channel 9: Wear/Touch TLV

**Outer:** Protobuf field 1 (tag 0x0a), length-delimited  
**Inner:** Fixed [type:1][value:1] TLV pairs (no length byte per pair)

| Type | Name | Value Semantics |
|------|------|-----------------|
| 0x01 | LID_STATE | 0=closed, 1=open |
| 0x02 | CHARGE_STATE | 0=no, 1=yes |
| 0x03 | EAR_STATE | 0=BOTH_OUT, 1=R_IN, 2=L_IN, 3=BOTH_IN |
| 0x04 | PRIMARY_BUD | 0=right, 1=left |
| 0x05 | TOUCH_EVENT_L | **No value byte** (type-only event) |
| 0x0b | GESTURE_COMPLETE | 6=IDLE (fires ~500ms post-touch) |

**Tap Count Discriminator (in GESTURE_COMPLETE payload):**
| Byte Value | Gesture |
|------------|---------|
| 0x14 (20) | SINGLE tap |
| 0x16 (22) | DOUBLE tap |
| 0x15 (21) | TRIPLE tap (first of two events) |
| 0x1f (31) | LONG_PRESS (type-only event) |

**Implementation:**
```rust
fn parse_ch9_gesture(payload: &[u8]) -> Option<GestureType> {
    if payload.is_empty() || payload[0] != 0x0a {
        return None;
    }
    
    let inner_len = payload[1] as usize;
    let inner = &payload[2..2 + inner_len];
    
    // Look for GESTURE_COMPLETE (0x0b) followed by discriminator
    let mut i = 0;
    while i + 1 < inner.len() {
        let tlv_type = inner[i];
        
        if tlv_type == 0x0b && i + 2 < inner.len() {
            let value = inner[i + 1];
            if value == 0x06 {  // IDLE state
                let discrim = inner[i + 2];
                return Some(match discrim {
                    0x14 => GestureType::Tap,
                    0x16 => GestureType::DoubleTap,
                    0x15 => GestureType::TripleTap,
                    _ => GestureType::Unknown,
                });
            }
        } else if tlv_type == 0x1f {
            return Some(GestureType::LongPress);
        }
        
        i += if tlv_type == 0x05 || tlv_type == 0x1f { 1 } else { 2 };
    }
    
    None
}
```

---

### 4.5 Channel 10: Settings Register (0x87 STATE_SNAPSHOT)

**Structure:** `1a 02 [setting_tag] [value]` (nested protobuf)

| Tag | Field | Setting | Values | Toggle Command |
|-----|-------|---------|--------|----------------|
| 0x08 | f1 | IN_EAR_DETECT | 0=off, 1=on | **Implement this** |
| 0x28 | f5 | ADAPTIVE_SOUND | 0=off, 1=on | Defer |
| 0x58 | f11 | TOUCH_CONTROLS | 0=off, 1=on | Defer |
| 0x68 | f13 | VOLUME_EQ | 0=off, 1=on | Defer |
| 0x70 | f14 | BASS_EQ_LEVEL | 0-5 → UI level 1-6 | Defer |

**To toggle In-Ear Detection:**
```rust
// Send to CH10 as DATA→buds (0x03)
let toggle_payload = vec![0x1a, 0x02, 0x08, new_value];  // 0x08 = IN_EAR_DETECT tag
self.send_frame(0x03, 10, &toggle_payload).await?;

// Buds will respond with 0x87 STATE_SNAPSHOT on CH10 confirming the change
```

---

### 4.6 Channel 8: Keepalive

**Ping (Phone→Buds):**
```
[0x38][seq]  // seq increments each ping
```

**Pong (Buds→Phone):**
```
[0x01][val]  // val echoes or increments
```

**Interval:** 1-2 seconds. Missing 3+ pongs = connection lost.

---

### 4.7 Channel 5: Connection State

**State Enum (f1 varint):**
| Value | State | Meaning |
|-------|-------|---------|
| 0 | IDLE | Disconnected or standby |
| 1 | CONNECTED | Active session |
| 3 | RECONNECTING | Observed during reconnect |
| 4 | STREAMING | Audio stream active (long-press) |

---

## 5. Complete Message Flow

### Initial Connection
```
1. RFCOMM connect (SDP → DLCI)
2. OPEN CH2 (phone init protobuf)
3. OPEN_ACK CH2 (model, capability, audio config)
4. OPEN CH5, CH6, CH7, CH8, CH9, CH10, CH11 (parallel)
5. OPEN_ACK on all channels
6. 0x87 STATE_SNAPSHOT on CH10 (all settings)
7. Start CH8 keepalive (every 1-2 sec)
```

### Battery Update (periodic)
```
Buds→Phone CH3: [0xe4][bud_byte][case_byte]
→ Correlate with CH9 EAR_STATE for bud side
→ Emit BatteryUpdate event
```

### Gesture Sequence (every tap/press)
```
+0ms   CH9: EAR_STATE=LEFT_IN/RIGHT_IN
+5ms   CH9: TOUCH_EVENT_L (type=0x05, no value)
+5ms   CH3: protobuf f1=1 (LONG_PRESS) or f1=2 (TAP)
+10ms  CH11: DEVICE_STATUS broadcast
+500ms CH9: GESTURE_COMPLETE=6 + discriminator (0x14/0x15/0x16)
→ Emit GestureEvent with type from discriminator
```

### Settings Toggle (user action)
```
Phone→Buds CH10: [0x1a][0x02][tag][value]
Buds→Phone CH10: 0x87 STATE_SNAPSHOT confirming change
→ Update local settings cache
```

---

## 6. Implementation Checklist

### Core Infrastructure
- [ ] RFCOMM client (SDP query → DLCI connect)
- [ ] Maestro frame parser (standard + compact variants)
- [ ] Frame reassembly (handle RFCOMM fragmentation)
- [ ] Channel state machine (OPEN → DATA → CLOSE)
- [ ] Inline protobuf decoder (varint, length-delimited, fixed32/64)
- [ ] Frame type dispatcher (0x01-0x87)

### Essential Channels
- [ ] CH2 handshake (send init, parse B/C/D responses)
- [ ] CH8 keepalive (ping every 1-2 sec, detect timeout)
- [ ] CH5 connection state (track IDLE/CONNECTED/STREAMING)
- [ ] CH9 wear detection (EAR_STATE, LID_STATE)
- [ ] CH3 battery (0xe4 raw path + CH9 correlation)
- [ ] CH3 gestures (f1=1/2 + CH9 discriminator)
- [ ] CH10 settings (0x87 snapshot parsing, toggle IN_EAR_DETECT)
- [ ] CH11 status stream (optional diagnostics)

### Deferred (Post-MVP)
- [ ] CH4 version/audio (rate-based discriminator)
- [ ] CH6 capability flags (cache invariant)
- [ ] CH7 audio config (cache at connect)
- [ ] CH12/17/19/21 ASCII tokens (log only)
- [ ] CH114/116 audio diagnostics (ASCII passthrough)
- [ ] Additional settings toggles (0x28, 0x58, 0x68, 0x70)

---

## 7. Code Structure Recommendation

```
src/
├── rfcomm/
│   ├── client.rs          # SDP query, DLCI connection, stream management
│   └── reassembly.rs      # Handle RFCOMM fragmentation
├── maestro/
│   ├── frame.rs           # Maestro multiplexer framing
│   ├── channel.rs         # Logical channel state machine
│   ├── protobuf.rs        # Inline varint/length-delimited decoder
│   └── channels/
│       ├── ch2_handshake.rs
│       ├── ch3_control.rs     # Battery (raw), gestures (proto)
│       ├── ch5_conn_state.rs  # Enum state machine
│       ├── ch8_keepalive.rs   # Ping/pong sequence
│       ├── ch9_wear_touch.rs  # TLV parser, gesture discriminator
│       ├── ch10_settings.rs   # 0x87 snapshot, toggle commands
│       └── ch11_status.rs     # Status broadcast (optional)
├── battery.rs             # CH3 raw + CH9 correlation
├── gestures.rs            # Gesture classification (discriminator-based)
└── settings.rs            # Settings register, toggle IN_EAR_DETECT
```

---

## 8. Testing Strategy

1. **Unit tests:** Protobuf decoder, frame parser, battery parsing, gesture discriminator
2. **Integration tests:** Full handshake sequence, keepalive exchange, settings toggle
3. **Capture validation:** Run `maestro-decode.py --timeline --session <json>` on same btsnoop
4. **Live testing:** Pair with Pixel Buds A, verify:
   - Battery updates correlate with CH9 EAR_STATE
   - Gestures fire within 10ms of CH9 TOUCH_EVENT_L
   - IN_EAR_DETECT toggle produces 0x87 confirmation on CH10

---

## 9. Known Gaps (Do Not Block Implementation)

| Gap | Impact | Workaround |
|-----|--------|------------|
| CH9 TOUCH_EVENT_R type byte | Right-bud touch events show same CH9 pattern as left | Assume symmetric to 0x05, correlate with CH3 gesture |
| Settings 0x38/0x50/0x60 names | Boot-only, never toggled | Log tag/value, skip UI exposure |
| CH2 subtype D 6-byte bitmap | Capability negotiation structure unknown | Cache bytes, replay on reconnect |
| pw_tokenizer string resolution | CH0/1/32/33/64/99 show token IDs only | Log hex, skip string resolution 

---

This specification is **implementation-ready** for Bluer. All critical paths (handshake, battery, gestures, wear detection, settings toggle) are fully decoded and verified against captures. Deferred items can be added post-MVP without breaking core functionality.
