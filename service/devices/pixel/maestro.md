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

**7 Next Captures Needed**

  ----------------------------------------------------------------------------
  **Capture goal**    **Method / what to look for**
  ------------------- --------------------------------------------------------
  **Toggle each       While capturing, toggle Attention Alerts / Announce
  unknown setting**   Notifications / Increase Ring Volume one at a time. The
                      0x87 on CH10 fires immediately and reveals the tag.

  **Right-bud tap     Put only the right bud in ear and tap. Observe the CH9
  only**              type byte for right-bud touch (symmetric to 0x05 for
                      left).

  **Single / double / Capture all three in one session and diff CH3 + CH9
  triple tap**        payloads for any byte that changes between them.

  **Phone call +      Decode CH11 f5 audio_mode enum transitions and confirm
  music playback**    CH5 CONN_STATE states 3 and 5.

  **Multi-reconnect   Power-cycle buds, close/open case, insert in ear ---
  cycle × 3**         repeat. Build full CH5 state machine and capture
                      CH17/19/21 ASCII content.

  **Hex-dump          Run \--channels 2,5,6 \--hex on a fresh capture and
  CH2/CH5/CH6 large   manually match byte patterns against known serials
  snapshots**         (1430LZAEUL0880 / 1429LZAEUR2171 / 1428LZAF0C2183).

  **Firmware .elf for All CH0/1/24/29/32/33/64/99 token channels decode to
  pw_tokenizer**      readable strings with the matching .elf. Firmware:
                      3.527.0, hardware: CM4_MB.
  ----------------------------------------------------------------------------
