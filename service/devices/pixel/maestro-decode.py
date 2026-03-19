#!/usr/bin/env python3
"""
maestro-decode.py — Pixel Buds A Protocol Reverse Engineering Tool
===================================================================
Decodes the Maestro multiplexer protocol including:
  - Protobuf payloads (inline decoder, no external deps)
  - pw_tokenizer frames (both raw token and base64/$-prefix format)
  - AT command indicators (channel 10)
  - Audio diagnostics (channels 114, 116)
  - Version, handshake, keepalive, status, control frames

Usage:
  python maestro-decode.py                          # analyse btsnoop_hci.log
  python maestro-decode.py -r /path/to/capture.log  # specify capture file
  python maestro-decode.py --hex 0a020302 --ch 9    # decode a single hex payload
  python maestro-decode.py --full                   # show ALL samples (not just 5)

Bugs fixed vs original:
  - Multi-value channel fields split correctly
  - All channels named (including 5-9, 32, 33, 64, 99, 114, 116)
  - Payloads decoded semantically, not just hex-dumped
  - Sample limit raised and configurable
"""

import subprocess
import struct
import base64
import re
import sys
import json
import argparse
from collections import defaultdict
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# REGISTRY
# ─────────────────────────────────────────────

CHANNEL_NAMES = {
    1:   "LOG STREAM",          # pw_tokenizer tokens from buds firmware
    2:   "HANDSHAKE",           # timezone / proto version negotiation
    3:   "REALTIME CONTROL",    # gesture event delivery (f1=type) + ctrl init/teardown (f2)
    4:   "VERSION/AUDIO",       # VERSION/EQ config at connect; AUDIO STREAM during long-press
    5:   "CONN STATE",          # connection state enum (observed: 0/1/3/4)
    6:   "CAPABILITY FLAGS",    # always 080b1001 → f1=11(channels), f2=1(proto rev)
    7:   "AUDIO CONFIG",        # sample rate, codec, bit depth — negotiated at connect
    8:   "KEEPALIVE",           # ping/pong
    9:   "WEAR+TOUCH",          # in-ear detection AND capacitive touch / gesture events
    10:  "DEVICE REG",          # AT indicators + device registration protobuf
    11:  "STATUS STREAM",       # wear state, audio mode, timestamps, conn mask
    12:  "UNKNOWN_12",
    32:  "LOG EXTENDED",        # pw_tokenizer log frame header (truncated)
    33:  "LOG TOKENIZED",       # pw_tokenizer base64 + protobuf envelope
    64:  "LOG TOKENIZED B",     # $<base64> pw_tokenizer with args
    99:  "LOG EXTENDED B",      # longer tokenized log frames
    114: "AUDIO GAIN DIAG",     # gain level, TWS channel map
    116: "AUDIO LEVEL DIAG",    # dBm level, HFP codec loss stats
}

FRAME_TYPE_NAMES = {
    0x01: "OPEN",
    0x02: "OPEN_ACK",
    0x03: "DATA→buds",
    0x04: "CLOSE",
    0x05: "DATA→phone",
    0x09: "PING",
    0x0e: "RESPONSE",
    0x87: "STATE_SNAPSHOT",   # buds→phone bulk state sync (multi-channel snapshot at connect/foreground)
}

VALID_FTYPES = set(FRAME_TYPE_NAMES.keys())

# NOTE: Pixel Buds A have NO ANC, NO swipe gestures.
# Tap controls only: single=play/pause, double=next, triple=prev, long=assistant
# Channel 3 commands are touch/gesture configuration, not audio processing modes.
#
# CH3 gesture delivery (confirmed from timeline correlation):
#   Protobuf f1=1 → GESTURE_LONG_PRESS  (fires at release of long press)
#   Protobuf f1=2 → GESTURE_TAP         (fires for single/double/triple — not yet distinguished)
#   Protobuf f2=2 → CTRL_INIT           (connection setup)
#   Protobuf f2=5 → CTRL_TEARDOWN       (disconnect cleanup)
# Single/double/triple differentiation not yet decoded — may be timing-based
# or encoded in a CH9 field not yet identified.

CH3_GESTURE_TYPES = {
    1: "LONG_PRESS",
    2: "TAP",   # single/double/triple — not yet distinguished in this field
}
CH3_CTRL_SUBTYPES = {
    2: "CTRL_INIT_OR_CASE_EVENT",  # appears both at connect AND when bud enters/exits case
    5: "CTRL_TEARDOWN",
}

# CH3 battery update command byte (raw path).
# 0xe4 has wire type = (0xe4 & 7) = 4 (INVALID in protobuf).
# This ensures it always hits the raw decode path and can never be
# misinterpreted as a protobuf field tag.
#
# Battery packet format (3 bytes total, phone↔buds direction):
#   byte[0] = 0xe4   (battery update command tag)
#   byte[1] = bud battery: bit7 = BUD_IN_CASE flag, bits[6:0] = percentage (0–100)
#   byte[2] = case battery: 0–100%, 0xFF = case absent or disconnected
#
# Which bud is NOT explicitly encoded — infer from CH9 EAR_STATE transitions
# that occur in the same ~50ms window.
CH3_BATTERY_CMD = 0xe4
# ─────────────────────────────────────────────
# SESSION / TIMESTAMP HELPERS
# ─────────────────────────────────────────────

def load_session(path: str) -> list:
    """Load a maestro-guide session JSON.  Returns sorted list of window dicts."""
    with open(path) as f:
        s = json.load(f)
    return sorted(s.get("windows", []), key=lambda w: w["start_unix_us"])

def classify_timestamp(unix_us: int, windows: list) -> str:
    """Return the action label if unix_us falls inside a session window, else None."""
    for w in windows:
        if w["start_unix_us"] <= unix_us <= w["end_unix_us"]:
            return w["action_id"]
    return None

def fmt_ts(unix_us: int) -> str:
    """Format unix µs as HH:MM:SS.mmm local time."""
    dt = datetime.fromtimestamp(unix_us / 1e6)
    return dt.strftime("%H:%M:%S.%f")[:-3]

def fmt_ts_full(unix_us: int) -> str:
    """Format unix µs as YYYY-MM-DD HH:MM:SS.mmm local time."""
    dt = datetime.fromtimestamp(unix_us / 1e6)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


# Channel 5 connection states
CONN_STATES = {0: "IDLE", 1: "CONNECTED", 4: "STREAMING"}

# Channel 3 touch command codes (1-byte).
# 0x57/0x58 seen with param=0xffff → likely GET(=0x58) / SET(=0x57) for touch config.
# Ch3 encodes raw frames as [class:4 | cmd:4] [param_lo] [param_hi]
# (confirmed by independent Lua dissector with real-world captures)
# Protobuf frames also appear on ch3 — use full-parse discriminator to tell apart.
CH3_CLASSES = {
    0x5: "MEDIA",
    0xD: "ANC_MIC",  # microphone control class (exists even without ANC)
}
CH3_CMDS = {
    0x4: "PLAY_PAUSE",
    0x6: "NEXT_TRACK",
    0x7: "PREV_TRACK",
    0x8: "VOL_UP",
    0xe: "VOL_DOWN",
}

# ─────────────────────────────────────────────
# INLINE PROTOBUF DECODER  (no external deps)
# ─────────────────────────────────────────────

def _decode_varint(data: bytes, pos: int):
    """Decode a protobuf varint.  Raises ValueError on truncation (no terminal byte).
    The final byte of a varint must have MSB=0.  If we exhaust data with MSB still
    set, the varint is truncated — this should propagate as an error, not silent junk.
    All callers already use try/except so this is safe.
    """
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return result, pos
        if shift > 63:
            raise ValueError("varint too long (>10 bytes)")
    raise ValueError(f"truncated varint at pos {pos}")

def decode_protobuf(data: bytes, depth: int = 0):
    """Return list of (field_num, wire_type_str, value).
       wire_type_str: 'varint' | 'i64' | 'bytes' | 'string' | 'i32'
       Nested bytes are left as raw bytes; caller may recurse.
    """
    fields = []
    pos = 0
    while pos < len(data):
        try:
            tag, pos = _decode_varint(data, pos)
        except Exception:
            break
        if tag == 0 or pos > len(data):
            break
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num == 0:
            break
        try:
            if wire_type == 0:
                val, pos = _decode_varint(data, pos)
                fields.append((field_num, "varint", val))
            elif wire_type == 1:
                if pos + 8 > len(data): break
                val = struct.unpack_from("<Q", data, pos)[0]; pos += 8
                fields.append((field_num, "i64", val))
            elif wire_type == 2:
                length, pos = _decode_varint(data, pos)
                if pos + length > len(data): break
                raw = data[pos:pos+length]; pos += length
                try:
                    s = raw.decode("utf-8")
                    if all(c.isprintable() or c in "\n\r\t" for c in s):
                        fields.append((field_num, "string", s))
                    else:
                        fields.append((field_num, "bytes", raw))
                except Exception:
                    fields.append((field_num, "bytes", raw))
            elif wire_type == 5:
                if pos + 4 > len(data): break
                val = struct.unpack_from("<I", data, pos)[0]; pos += 4
                fields.append((field_num, "i32", val))
            else:
                break   # unknown wire type — stop parsing
        except Exception:
            break
    return fields

def is_valid_protobuf(data: bytes) -> bool:
    """Heuristic: first byte looks like a valid protobuf tag."""
    if len(data) < 2:
        return False
    tag = data[0]
    wire = tag & 0x07
    fnum = tag >> 3
    return fnum > 0 and wire in (0, 1, 2, 5)

def protobuf_coverage(data: bytes) -> float:
    """Return fraction of bytes successfully consumed by protobuf decoder (0.0–1.0).
    A value close to 1.0 means the data is likely well-formed protobuf.
    Used to distinguish legitimate protobuf from random bytes that happen to
    start with a valid-looking tag (e.g. the ch2 raw capability token 68a04f3efbff).
    """
    if not data:
        return 0.0
    pos = 0
    while pos < len(data):
        if pos >= len(data):
            break
        try:
            tag, new_pos = _decode_varint(data, pos)
        except Exception:
            break
        if tag == 0:
            break
        wire = tag & 0x07
        fnum = tag >> 3
        if fnum == 0 or wire not in (0, 1, 2, 5):
            break
        pos = new_pos
        try:
            if wire == 0:
                _, pos = _decode_varint(data, pos)
            elif wire == 1:
                pos += 8
            elif wire == 2:
                l, pos = _decode_varint(data, pos)
                pos += l
            elif wire == 5:
                pos += 4
        except Exception:
            break
        if pos > len(data):
            break
    return pos / len(data)

def fmt_protobuf(fields, known: dict = None, indent: int = 1) -> list:
    """Format decoded protobuf fields into human-readable lines."""
    pad = "    " * indent
    lines = []
    for fn, wt, val in fields:
        label = f" [{known[fn]}]" if known and fn in known else ""
        if wt == "bytes":
            nested = decode_protobuf(val) if is_valid_protobuf(val) else []
            if nested:
                lines.append(f"{pad}f{fn}{label} (bytes/{len(val)}) {{")
                lines.extend(fmt_protobuf(nested, indent=indent+1))
                lines.append(f"{pad}}}")
            else:
                lines.append(f"{pad}f{fn}{label} (bytes/{len(val)}): {val.hex()}")
        elif wt == "varint":
            # Also show signed interpretation for large values (likely negative)
            signed = val if val < 0x80000000 else val - 0x100000000
            extra = f"  (signed: {signed})" if signed < 0 else ""
            lines.append(f"{pad}f{fn}{label} = {val}{extra}")
        elif wt == "string":
            lines.append(f"{pad}f{fn}{label} = \"{val}\"")
        else:
            lines.append(f"{pad}f{fn}{label} ({wt}) = {val:#010x}")
    return lines

# ─────────────────────────────────────────────
# GADGETBRIDGE BATTERY PROTOCOL
# ─────────────────────────────────────────────
# This is a SEPARATE RFCOMM service from Maestro.
# Framing: u16(BE) cmd + u16(BE) size + payload[size]
# cmd=0x0303: battery update — payload=[left%, right%, case%]
#   -1 (0xFF) = no bud in case, -28 (0xE4) = bud is in case
# The Maestro Lua dissector (old version) incorrectly ingests these as
# Maestro channel 3 frames because 0x0303 looks like type=0x03 ch=0x03.

GB_CMDS = {
    0x0303: "BATTERY_UPDATE",
    0x0301: "BATTERY_GET",
    0x0101: "VERSION_GET",
    0x0102: "VERSION_RESP",
}

def decode_gb_battery(data: bytes) -> list:
    """Decode GadgetBridge PixelBuds battery/event protocol frame(s).
    Frame: cmd(u16 BE) + size(u16 BE) + payload[size], repeating.
    """
    lines = []
    pos = 0
    while pos + 4 <= len(data):
        cmd  = struct.unpack_from(">H", data, pos)[0]
        size = struct.unpack_from(">H", data, pos+2)[0]
        if pos + 4 + size > len(data):
            lines.append(f"  [truncated at pos={pos}]")
            break
        payload = data[pos+4 : pos+4+size]
        name = GB_CMDS.get(cmd, f"CMD_0x{cmd:04x}")
        pos += 4 + size

        if cmd == 0x0303 and size >= 3:
            # Battery values are signed bytes
            def sb(b): return b if b < 128 else b - 256
            left  = sb(payload[0])
            right = sb(payload[1])
            case  = sb(payload[2])
            def fmt_charge(v):
                if v == -1:  return "NOT_IN_CASE"
                if v == -28: return "IN_CASE(charging?)"
                return f"{v}%"
            lines.append(f"  [BATTERY_UPDATE]")
            lines.append(f"    left  : {fmt_charge(left)}")
            lines.append(f"    right : {fmt_charge(right)}")
            lines.append(f"    case  : {fmt_charge(case)}")
        else:
            lines.append(f"  [{name}] payload={payload.hex()}")
    return lines if lines else [f"  [raw: {data.hex()}]"]

def is_gb_battery_frame(data: bytes) -> bool:
    """Heuristic: check if data looks like a GadgetBridge battery frame.
    Key: cmd bytes 0-1 are 0x03 0x03, size bytes 2-3 are small and plausible.
    """
    if len(data) < 4:
        return False
    cmd  = struct.unpack_from(">H", data, 0)[0]
    size = struct.unpack_from(">H", data, 2)[0]
    return cmd in GB_CMDS and size < 64 and len(data) >= 4 + size

# ─────────────────────────────────────────────
# pw_tokenizer SUPPORT  (inline — no library needed)
# ─────────────────────────────────────────────
# pw_tokenizer encoding (from pigweed spec):
#   Frame = token(4 bytes LE) + args
#   Integer args: zigzag-encoded varint (like protobuf sint32/sint64)
#   String args:  null-terminated UTF-8
#   Float args:   4-byte LE IEEE-754
# Without the .elf token DB we cannot resolve token→format string,
# so we decode args heuristically: try string first, then zigzag ints.

def _pw_zigzag_decode(n: int) -> int:
    """Undo zigzag encoding: (n >> 1) ^ -(n & 1)"""
    return (n >> 1) ^ -(n & 1)

def _decode_pw_varint(data: bytes, pos: int):
    result, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            return result, pos
    return result, pos

def decode_pw_args(args: bytes) -> list:
    """Heuristically decode pw_tokenizer argument bytes.
    Returns list of decoded arg strings.
    """
    decoded = []
    pos = 0
    while pos < len(args):
        # Try null-terminated string first
        null = args.find(b"\x00", pos)
        if null != -1 and null - pos > 0:
            candidate = args[pos:null]
            try:
                s = candidate.decode("utf-8")
                if all(c.isprintable() or c in "\t\n\r" for c in s) and len(s) >= 2:
                    decoded.append(f"str:{s!r}")
                    pos = null + 1
                    continue
            except Exception:
                pass
        # Try 4-byte float — only accept values plausible in audio/RF telemetry.
        # Reject denormals (abs < 1e-6) and huge values: these are almost always
        # varints being misread. Floats appear in e.g. RSSI (-120..0), timestamps.
        if pos + 4 <= len(args):
            import struct as _s
            fval = _s.unpack_from("<f", args, pos)[0]
            if (not (fval != fval)                  # not NaN
                    and not (fval != 0 and abs(fval) < 1e-3)   # not denormal
                    and abs(fval) < 1e6):            # sane range
                decoded.append(f"float:{fval:.4g}")
                pos += 4
                continue
        # Fall back to zigzag varint
        raw, new_pos = _decode_pw_varint(args, pos)
        if new_pos > pos:
            decoded.append(f"int:{_pw_zigzag_decode(raw)}")
            pos = new_pos
        else:
            decoded.append(f"byte:0x{args[pos]:02x}")
            pos += 1
    return decoded

def decode_pw_token_raw(data: bytes) -> str:
    """Decode a raw pw_tokenizer frame: token(4 bytes LE) + args."""
    if len(data) < 3:
        return f"pw_token(too short): {data.hex()}"
    token = int.from_bytes(data[:4] if len(data) >= 4 else data[:3] + b"\x00", "little")
    args  = data[4:] if len(data) >= 4 else b""
    if args:
        decoded_args = decode_pw_args(args)
        arg_str = "  args: " + ", ".join(decoded_args) if decoded_args else f"  args_raw={args.hex()}"
    else:
        arg_str = ""
    return f"pw_token=0x{token:08x}{arg_str}  [needs .elf DB for string]"

def decode_pw_token_b64(raw: bytes) -> list:
    """Decode a $-prefixed pw_tokenizer base64 frame. Returns list of lines."""
    try:
        txt = raw.decode("ascii").strip()
        if not txt.startswith("$"):
            return [f"not a $-prefix token: {txt}"]
        b64 = txt[1:]
        pad = (4 - len(b64) % 4) % 4
        decoded = base64.b64decode(b64 + "=" * pad, validate=False)
        token = int.from_bytes(decoded[:4], "little")
        args  = decoded[4:]
        lines = [f"  pw_token=0x{token:08x}  [needs .elf DB for string]"]
        if args:
            decoded_args = decode_pw_args(args)
            if decoded_args:
                lines.append(f"  args: {', '.join(decoded_args)}")
            else:
                lines.append(f"  args_raw: {args.hex()}")
        return lines
    except Exception as e:
        return [f"  pw_b64_decode_error: {e}  raw={raw.hex()}"]

def looks_pw_b64(data: bytes) -> bool:
    try:
        return data[0:1] == b"$"
    except Exception:
        return False

def looks_pw_token_raw(data: bytes) -> bool:
    """Short frames from LOG STREAM that are not valid protobuf."""
    return len(data) <= 8 and not is_valid_protobuf(data)

# ─────────────────────────────────────────────
# CHANNEL-SPECIFIC DECODERS
# ─────────────────────────────────────────────

# Pixel Buds A has NO ANC, no swipe gestures.
# Taps: single=play/pause, double=next, triple=prev, long=assistant.
CH2_FIELDS  = {1:  "proto_version",  2:  "timestamp_ms",  3:  "timezone",
               4:  "fw_version",     5:  "device_type",
               6:  "build_number",   9:  "device_id",      10: "unknown_10",
               12: "uptime_or_ver",  14: "platform",       15: "feature_flags"}
# f1 with 104-byte 0x6db6db... payload = EQ filter coefficient blob (not protobuf)
CH4_FIELDS  = {1: "msg_type_or_eq",  3: "unknown_3",   4: "unknown_4",
               5: "fw_version",      7: "msg_subtype",  8: "serial_number",
               9: "hw_model",       10: "build_type",  11: "fw_components"}
CH7_FIELDS  = {1: "sample_rate_hz",  2: "bit_depth",   3: "unknown_3",
               4: "codec_id",        5: "unknown_5",    6: "unknown_6"}
CH9_FIELDS  = {1: "msg_type",        2: "wear_state"}
CH10_FIELDS = {1: "device_id",       2: "unknown_2",    3: "unknown_3"}
# Ch11 semantics confirmed by independent Lua dissector:
# f2=seq_num (subsystem cycle counter +12/cycle, NOT time-based, NOT battery)
# f11=conn_mask (3=both buds), f12=tick_us (cross-ref ch1), f13=unknown_13.
# NOTE: do not assume f13 is ADC/battery; if it stays fixed across captures,
# it's likely a static config/limit value rather than a live analog reading.
CH11_FIELDS = {1:  "msg_type",   2:  "seq_num",      3:  "unknown_3",
               4:  "unknown_4",  5:  "audio_mode",    6:  "wear_state",
               7:  "unknown_7",  8:  "unknown_8",     9:  "unknown_9",
               10: "unknown_10", 11: "conn_mask",    12:  "tick_us",
               13: "unknown_13", 17:  "unknown_17",   18:  "unknown_18"}

def decode_ch1(data: bytes) -> list:
    """LOG STREAM: pw_tokenizer raw tokens or protobuf log wrapper."""
    if looks_pw_token_raw(data):
        return ["  " + decode_pw_token_raw(data)]
    if is_valid_protobuf(data):
        f = decode_protobuf(data)
        return ["  [protobuf log wrapper]"] + fmt_protobuf(f)
    return [f"  [raw: {data.hex()}]"]

# CH2 BUDS CAPABILITY fields (buds→phone response, different semantics from phone→buds)
CH2_BUDS_CAPABILITY = {
    1: "buds_proto_ver",  2: "seq",          3: "zero",
    4: "sample_rate_hz",  5: "codec_flags",  6: "unknown_6",
    7: "bit_depth",       8: "unknown_8",    9: "unknown_9",
}

def decode_ch2(data: bytes) -> list:
    """HANDSHAKE channel — carries 4 distinct message subtypes:

    A) Phone→buds session init (protobuf, f1=proto_ver int):
       f1=proto_ver, f2=timestamp_ms, f3=timezone, f4=fw_version(str),
       f5=device_type(str), f6=build_number, f9=device_id, f14=platform.
    B) Buds→phone model ID (protobuf, f1=model string):
       f1="google-pixel-buds-a-series-v1"
    C) Buds→phone capability response (protobuf, f1=0 int, f4=16000):
       f4=sample_rate_hz, f6=?, f7=bit_depth — mirrors ch7 audio config.
    D) Raw 6-byte binary token (buds→phone immediately after OPEN):
       Likely a Maestro-level version/capability bitmap. Not protobuf.
    """
    # Subtype D: raw binary token (6 bytes).
    # 68a04f3efbff starts with 0x68 which looks like a valid tag (f13 varint),
    # but only ~50% of bytes parse cleanly — protobuf_coverage catches this.
    if not is_valid_protobuf(data) or protobuf_coverage(data) < 0.85:
        return [f"  [RAW CAPABILITY TOKEN] {data.hex()}  [binary bitmap, structure TBD]"]

    fields = decode_protobuf(data)
    if not fields:
        return [f"  [empty protobuf]"]

    fn0, wt0, val0 = fields[0]

    # Subtype B: buds model identifier — f1 is a string
    if fn0 == 1 and wt0 == "string":
        return [
            f"  [BUDS MODEL ID]",
            f"  >> model : {val0}",
        ]

    # Subtype C: buds capability response — f1=0 (int), f4=16000 (sample rate)
    # Distinguish from phone init (which has f1=proto_ver > 0 typically, plus string fields)
    has_sample_rate = any(fn == 4 and wt == "varint" and val == 16000 for fn, wt, val in fields)
    if fn0 == 1 and wt0 == "varint" and val0 == 0 and has_sample_rate:
        lines = ["  [BUDS CAPABILITY RESPONSE]"] + fmt_protobuf(fields, CH2_BUDS_CAPABILITY)
        for fn, wt, val in fields:
            if fn == 4 and wt == "varint": lines.append(f"  >> sample_rate_hz : {val}")
            if fn == 7 and wt == "varint": lines.append(f"  >> bit_depth      : {val}")
            if fn == 5 and wt == "varint": lines.append(f"  >> codec_flags    : 0x{val:02x}")
        return lines

    # Subtype A: phone→buds session init
    lines = ["  [PHONE SESSION INIT]"] + fmt_protobuf(fields, CH2_FIELDS)
    for fn, wt, val in fields:
        if fn == 1  and wt == "varint": lines.append(f"  >> proto_ver    : {val}")
        if fn == 2  and wt == "varint": lines.append(f"  >> timestamp    : {val}ms")
        if fn == 4  and wt == "string": lines.append(f"  >> fw_version   : {val}")
        if fn == 6  and wt == "varint": lines.append(f"  >> build_number : {val}")
        if fn == 9  and wt == "string": lines.append(f"  >> device_id    : {val}")
        if fn == 14 and wt == "varint":
            plat = {1: "iOS", 2: "Android"}.get(val, f"unknown({val})")
            lines.append(f"  >> platform     : {plat}")
    return lines

def _ch3_is_protobuf(data: bytes) -> bool:
    """True only if ALL bytes parse as valid protobuf with zero remainder.
    This is the correct discriminator for ch3 because:
      - 0x57 has wire=7 (invalid) → raw immediately
      - 0x58 has wire=0 (looks valid) but 0xffff is a truncated varint → fails
      - 0x10 05 18 56 fully consumes as f2=5 f3=86 → protobuf
    """
    pos = 0
    try:
        while pos < len(data):
            tag, pos = _decode_varint(data, pos)
            if tag == 0: return False
            wire = tag & 7; fnum = tag >> 3
            if fnum == 0 or fnum > 64 or wire not in (0, 1, 2, 5): return False
            if wire == 0:
                _, pos = _decode_varint(data, pos)
            elif wire == 2:
                length, pos = _decode_varint(data, pos)
                if pos + length > len(data): return False
                pos += length
            elif wire == 5:
                if pos + 4 > len(data): return False
                pos += 4
            elif wire == 1:
                if pos + 8 > len(data): return False
                pos += 8
        return pos == len(data)
    except Exception:
        return False

def decode_ch3(data: bytes) -> list:
    """REALTIME CONTROL — three distinct message types on this channel:

    1. BATTERY UPDATE (raw, 3 bytes): b0=0xe4, [bud_byte], [case_byte]
       b0=0xe4 has invalid protobuf wire type (4) → always hits raw path.
       bud_byte:  bit7=BUD_IN_CASE, bits[6:0]=bud battery %
       case_byte: case battery %, 0xFF=case absent
       Which bud: infer from concurrent CH9 EAR_STATE transition.

    2. PROTOBUF CONTROL:
       f1=1 → LONG_PRESS gesture event
       f1=2 → TAP gesture event (single/double/triple not yet distinguished)
       f2=2 → CTRL_INIT (connect) or CASE_EVENT (bud enters/exits case)
       f2=5 → CTRL_TEARDOWN

    3. RAW CLASS|CMD nibbles (touch config, media commands):
       byte[0] = [class:4 | cmd:4], bytes[1:3] = LE param16
       class 0x5=MEDIA, 0xD=ANC_MIC
       cmd   0x4=PLAY_PAUSE, 0x6=NEXT_TRACK, 0x7=PREV_TRACK,
             0x8=VOL_UP,     0xe=VOL_DOWN
       param 0xffff = trigger / use device default
    """
    if not data:
        return ["  [empty]"]

    # Battery update: b0=0xe4 (wire type 4 — always raw path)
    if data[0] == CH3_BATTERY_CMD and len(data) >= 3:
        bud_byte  = data[1]
        case_byte = data[2]
        bud_pct   = bud_byte & 0x7F
        in_case   = bool(bud_byte & 0x80)
        case_pct  = case_byte if case_byte != 0xFF else None
        in_case_str  = "IN_CASE" if in_case else "OUT_OF_CASE"
        case_str     = f"{case_pct}%" if case_pct is not None else "ABSENT"
        lines = [f"  [BATTERY UPDATE]  bud={bud_pct}% {in_case_str}  case={case_str}"]
        lines.append(f"  >> raw: {data.hex()}")
        return lines

    # Protobuf path
    if _ch3_is_protobuf(data):
        fields = decode_protobuf(data)
        lines = ["  [REALTIME CTRL protobuf]"] + fmt_protobuf(fields)
        for fn, wt, val in fields:
            if fn == 1 and wt == "varint":
                gname = CH3_GESTURE_TYPES.get(val, f"GESTURE_0x{val:02x}")
                lines.append(f"  >> gesture_type : {gname}")
            if fn == 2 and wt == "varint":
                cname = CH3_CTRL_SUBTYPES.get(val, f"CTRL_0x{val:02x}")
                lines.append(f"  >> ctrl_subtype : {cname}")
        lines.append(f"  >> raw: {data.hex()}")
        return lines

    # Raw class|cmd nibble path (media commands, touch config)
    b0    = data[0]
    cls   = (b0 >> 4) & 0xF
    cmd   = b0 & 0xF
    cname = CH3_CLASSES.get(cls, f"CLASS_0x{cls:x}")
    cstr  = CH3_CMDS.get(cmd,   f"CMD_0x{cmd:x}")
    lines = [f"  [REALTIME CTRL raw] {cname}|{cstr}  (byte=0x{b0:02x})"]
    if len(data) >= 3:
        param = struct.unpack_from("<H", data, 1)[0]
        note  = "  (trigger / device default)" if param == 0xffff else ""
        lines.append(f"  >> param = 0x{param:04x}{note}")
    elif len(data) == 2:
        lines.append(f"  >> byte1 = 0x{data[1]:02x}")
    lines.append(f"  >> raw: {data.hex()}")
    return lines

def decode_ch4(data: bytes, is_audio_stream: bool = False) -> list:
    """VERSION/AUDIO channel — carries two entirely different data types:

    1. VERSION / EQ CONFIG (at connection, static):
       - Short protobuf: fw_version, serial, hw_model, fw_components
       - EQ blob: f1 bytes[104], repeating 0x6db6db pattern = DSP biquad coefficients

    2. AUDIO STREAM (during long-press, continuous):
       - f1 bytes[104] at ~25 packets/sec = 33 kbps encoded audio
       - Same 104-byte size as EQ blob — distinguished by RATE not by content
       - Audio config: 16kHz, codec_id=2, 24-bit (see CH7)
       - The 0x6db6db pattern also appears in audio data (coincidence of encoding)

    is_audio_stream is set by the caller when packet rate >10/sec on this channel.
    """
    if is_audio_stream:
        # Don't try to decode — it's encoded audio, not structured data
        n_samples = len(data)  # raw payload bytes
        return [f"  [AUDIO STREAM] {n_samples}B encoded frame  (16kHz codec_id=2 ~33kbps)"]

    if not is_valid_protobuf(data):
        return [f"  [raw: {data.hex()}]"]
    f = decode_protobuf(data)
    if not f:
        return [f"  [raw: {data.hex()}]"]

    # Detect EQ coefficient blob: field 1, bytes[104], 0x6db6db repeating pattern
    for fn, wt, val in f:
        if fn == 1 and wt == "bytes" and len(val) >= 16:
            window = val[:32]
            if window.count(0x6d) + window.count(0xb6) + window.count(0xdb) >= 6:
                n_coeff = len(val) // 3
                return [
                    f"  [EQ COEFFICIENT BLOB] {len(val)} bytes, ~{n_coeff} coefficients",
                    f"  >> pattern: 0x6db6db... (24-bit words, Q0.23 DSP biquad coefficients)",
                    f"  >> raw: {val[:16].hex()}...({len(val)-16} more bytes)",
                ]

    lines = ["  [VERSION protobuf]"] + fmt_protobuf(f, CH4_FIELDS)
    for fn, wt, val in f:
        if fn == 5  and wt == "string": lines.append(f"  >> fw_version    : {val}")
        if fn == 8  and wt == "string": lines.append(f"  >> serial        : {val}")
        if fn == 9  and wt == "string": lines.append(f"  >> hw_model      : {val}")
        if fn == 11 and wt == "string":
            components = [c.strip() for c in val.split("\n") if c.strip()]
            lines.append(f"  >> fw_components : {components}")
            lines.append(f"  >> raw: {data.hex()}")
    return lines

def decode_ch5(data: bytes) -> list:
    """CONN STATE: field 1 = state enum."""
    f = decode_protobuf(data)
    for fn, wt, val in f:
        if fn == 1 and wt == "varint":
            state = CONN_STATES.get(val, f"UNKNOWN({val})")
            return [f"  [CONN STATE] {state}"]
    return [f"  [raw: {data.hex()}]"]

def decode_ch7(data: bytes) -> list:
    """AUDIO CONFIG: sample rate, codec, bit depth."""
    if not is_valid_protobuf(data):
        return [f"  [raw: {data.hex()}]"]
    f = decode_protobuf(data)
    lines = ["  [AUDIO CONFIG protobuf]"] + fmt_protobuf(f, CH7_FIELDS)
    return lines

def decode_ch8(data: bytes) -> list:
    """KEEPALIVE: ping or pong."""
    if len(data) == 2:
        if data[0] == 0x38:
            return [f"  [KEEPALIVE PING seq={data[1]}]"]
        if data[0] == 0x01:
            return [f"  [KEEPALIVE PONG val=0x{data[1]:02x}]"]
    f = decode_protobuf(data) if is_valid_protobuf(data) else []
    if f:
        return ["  [keepalive protobuf]"] + fmt_protobuf(f)
    return [f"  [raw: {data.hex()}]"]

# CH9 WEAR+TOUCH TLV type bytes (within f1 wire-type-2 envelope).
# Confirmed types from timeline correlation with real events.
# TOUCH_EVENT_L/R fire with NO value byte (single-byte inner) on every gesture.
# GESTURE_COMPLETE fires ~500ms after touch, value=6 = classifier returned to IDLE.
CH9_TLV = {
    0x01: "LID_STATE",       # case lid: 0=closed 1=open
    0x02: "CHARGE_STATE",    # charging: 0=no 1=yes
    0x03: "EAR_STATE",       # 0=BOTH_OUT 1=RIGHT_IN 2=LEFT_IN 3=BOTH_IN
    0x04: "PRIMARY_BUD",     # which bud is primary (0=right 1=left)
    0x05: "TOUCH_EVENT_L",   # left bud touch — fires with NO value byte on gesture
                             # (previously mislabelled BATTERY_L; real battery is on GadgetBridge RFCOMM)
    0x06: "BATTERY_R",       # right bud 0–125 → ×100/125 = %  (still needs confirmation)
    0x07: "BATTERY_CASE",    # case battery same scale
    0x0b: "GESTURE_COMPLETE",# fires ~500ms after touch; value=6 = classifier IDLE
                             # constant across all gesture types — state signal, not gesture code
}

def decode_ch9(data: bytes) -> list:
    """WEAR+TOUCH channel — protobuf outer, fixed [type:1][value:1] TLV inner.

    Fires on:
      1. Physical wear events (ear in/out, case lid, charging)
      2. Touch gestures — sequence per gesture:
           a. EAR_STATE=LEFT_IN/RIGHT_IN  (in-ear precondition gate)
           b. TOUCH_EVENT_L (no value)    (capacitive touch detected)
           c. GESTURE_COMPLETE val=6      (~500ms later, classifier idle)
         Actual gesture type (TAP vs LONG_PRESS) is in CH3 f1, not here.

    Inner TLV is NOT nested protobuf — 0x03=EAR_STATE is a raw type byte.
    Single-byte inner (length=1): type-only event with no value.
    """
    if len(data) < 2:
        return [f"  [raw: {data.hex()}]"]

    if data[0] == 0x0a:  # f1 wire=2 (outer protobuf field 1, length-delimited)
        inner_len = data[1]
        if 2 + inner_len > len(data):
            return [f"  [truncated: {data.hex()}]"]
        inner = data[2:2 + inner_len]
        rest  = data[2 + inner_len:]
        lines = [f"  [WEAR+TOUCH TLV]  inner raw={inner.hex()}"]
        lines.append(f"  >> raw: {data.hex()}")

        if len(inner) == 1:
            tname = CH9_TLV.get(inner[0], f"TYPE_0x{inner[0]:02x}")
            lines.append(f"  >> {tname}  (event — no value byte)")
            lines.append(f"  >> raw: {data.hex()}")
        else:
            j = 0
            while j + 1 < len(inner):
                t, v = inner[j], inner[j + 1]
                tname = CH9_TLV.get(t, f"TYPE_0x{t:02x}")
                note  = ""
                if t == 0x03:
                    ear = {0:"BOTH_OUT", 1:"RIGHT_IN", 2:"LEFT_IN", 3:"BOTH_IN"}
                    note = f"  ({ear.get(v, v)})"
                elif t in (0x06, 0x07):
                    note = f"  ({v * 100 // 125}%)"
                elif t == 0x01:
                    note = f"  ({'open' if v else 'closed'})"
                elif t == 0x02:
                    note = f"  ({'charging' if v else 'not charging'})"
                elif t == 0x04:
                    note = f"  ({'left' if v else 'right'} is primary)"
                elif t == 0x0b:
                    state = {6: "IDLE"}.get(v, f"val={v}")
                    note  = f"  ({state})"
                lines.append(f"  >> {tname} = {v}{note}")
                j += 2
            # Handle odd trailing byte (type-only event appended after TLV pairs)
            if j < len(inner):
                tname = CH9_TLV.get(inner[j], f"TYPE_0x{inner[j]:02x}")
                lines.append(f"  >> {tname}  (trailing event — no value byte)")
                lines.append(f"  >> raw: {data.hex()}")

        if rest:
            if is_valid_protobuf(rest):
                lines.append("  [additional protobuf]")
                lines.extend(fmt_protobuf(decode_protobuf(rest)))
            else:
                lines.append(f"  [trailing: {rest.hex()}]")
                lines.append(f"  >> raw: {data.hex()}")
        return lines

    if is_valid_protobuf(data):
        return ["  [WEAR+TOUCH protobuf]"] + fmt_protobuf(decode_protobuf(data), CH9_FIELDS)
    return [f"  [raw: {data.hex()}]"]

def decode_ch10(data: bytes) -> list:
    """DEVICE REG: AT IND strings or device registration protobuf."""
    import re as _re
    try:
        txt = data.decode("ascii")
        if txt.startswith("IND:"):
            lines = [f"  [AT IND] {txt.strip()}"]
            for m in _re.finditer(r'"(\w+)",\(([^)]+)\)', txt):
                lines.append(f"    {m.group(1)}: range={m.group(2)}")
            return lines
        if all(c.isprintable() or c in "\r\n\t" for c in txt):
            return [f"  [ASCII] {txt.strip()}"]
    except Exception:
        pass
    if is_valid_protobuf(data):
        f = decode_protobuf(data)
        lines = ["  [DEVICE REG protobuf]"] + fmt_protobuf(f, CH10_FIELDS)
        for fn, wt, val in f:
            if fn == 1 and wt == "string":
                lines.append(f"  >> device_id: {val}")
        return lines
    return [f"  [raw: {data.hex()}]"]

def decode_ch11(data: bytes) -> list:
    """STATUS STREAM: battery, wear, ANC mode, timestamps."""
    if not is_valid_protobuf(data):
        return [f"  [raw: {data.hex()}]"]
    fields = decode_protobuf(data)

    # Short variant (8 bytes): msg_type=1 + fw_component_name
    # e.g. 0801 1204 "200Q" — a firmware component version notification
    # NOT a status update; f2 here is a string component name, not a counter.
    if len(data) <= 10:
        lines = ["  [VERSION NOTIFICATION]"]
        for fn, wt, val in fields:
            if fn == 1 and wt == "varint":
                lines.append(f"  >> msg_type      : {val}")
            elif fn == 2 and wt == "string":
                lines.append(f"  >> fw_component  : {val!r}")
            else:
                lines.append(f"    f{fn}({wt}) = {repr(val) if isinstance(val, str) else val}")
        return lines

    # Long variant (36 bytes): full device status
    lines = ["  [DEVICE STATUS]"] + fmt_protobuf(fields, CH11_FIELDS)
    for fn, wt, val in fields:
        if fn == 5  and wt == "varint":
            lines.append(f"  >> audio_mode    : {val}  [purpose TBD; not ANC]")
        if fn == 6  and wt == "varint":
            wear = {0: "BOTH_OUT", 1: "RIGHT_IN", 2: "LEFT_IN", 3: "BOTH_IN"}
            lines.append(f"  >> wear_state    : {wear.get(val, val)}")
            lines.append(f"  >> raw: {data.hex()}")
        if fn == 13 and wt == "varint":
            # Constant 125 across all samples — NOT percentage.
            # 125 × 32mV = 4000mV nominal Li-ion — likely raw ADC latch B.
            pct = val * 100 // 125
            lines.append(f"  >> batt_adc   : {val}/125  →  {pct}% battery")
            lines.append(f"  >> raw: {data.hex()}")
        if fn == 12 and wt == "varint":
            lines.append(f"  >> tick_us    : {val}µs  (cross-ref ch1 LOG_STREAM tick)")
            lines.append(f"  >> raw: {data.hex()}")
        if fn == 2  and wt == "varint":
            # Increments ~12 per 425µs interval → likely a raw ADC current reading.
            # Range 1088-1384 over ~6ms. Cross-ref with actual charge to calibrate.
            lines.append(f"  >> seq_num    : {val}  (subsystem cycle counter, +12/cycle)")
            lines.append(f"  >> raw: {data.hex()}")
    return lines

def decode_ch32_33(data: bytes) -> list:
    """LOG TOKENIZED: pw_tokenizer base64 chunk + optional protobuf metadata.
    Also handles the short log frame header seen on ch32:
      01 00 1c 0a 11 = type(0x01) flags(0x00) len_hi(0x1c=28) ...
      This is a Pigweed RPC / pw_log frame header, payload truncated in capture.
    """
    # Detect short non-ASCII binary log header (ch32 style: 5 bytes, starts 0x01)
    if len(data) <= 8 and not any(0x20 <= b <= 0x7E for b in data[:3]):
        frame_type = data[0]
        flags      = data[1] if len(data) > 1 else 0
        length     = data[2] if len(data) > 2 else 0
        suffix     = data[3:].hex() if len(data) > 3 else ""
        type_name  = {0x01: "LOG_ENTRY", 0x02: "LOG_ACK", 0x03: "LOG_REQ"}.get(frame_type, f"0x{frame_type:02x}")
        return [
            f"  [PW LOG FRAME HEADER] type={type_name} flags=0x{flags:02x} len={length}",
            f"  >> suffix: {suffix}  [payload truncated in capture]",
        ]
    lines = []
    ascii_end = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            ascii_end = i + 1
        else:
            break
    if ascii_end > 0:
        txt = data[:ascii_end].decode("ascii")
        lines.append(f"  [base64 token chunk] {txt}")
        try:
            pad = (4 - len(txt) % 4) % 4
            raw = base64.b64decode(txt + "=" * pad, validate=False)
            tok = int.from_bytes(raw[:4], "little")
            lines.append(f"  >> pw_token=0x{tok:08x}  [needs .elf token DB]")
        except Exception:
            pass
    suffix = data[ascii_end:]
    if suffix and is_valid_protobuf(suffix):
        f = decode_protobuf(suffix)
        lines.append("  [metadata protobuf]")
        PB_META = {1: "severity", 2: "module_token", 3: "timestamp_i32",
                   4: "severity2",  5: "flags"}
        lines.extend(fmt_protobuf(f, PB_META))
        for fn, wt, val in f:
            if fn == 1 and wt == "varint":
                sev = {0: "DEBUG", 1: "INFO", 2: "WARN", 3: "ERROR", 4: "CRITICAL"}
                lines.append(f"  >> severity: {sev.get(val, val)}")
    elif suffix:
        lines.append(f"  [suffix binary: {suffix.hex()}]")
    return lines if lines else [f"  [raw: {data.hex()}]"]

def decode_ch64(data: bytes) -> list:
    """LOG TOKENIZED B: $<base64> pw_tokenizer with optional args."""
    if looks_pw_b64(data):
        return decode_pw_token_b64(data)
    try:
        txt = data.decode("ascii")
        return [f"  [ASCII] {txt}"]
    except Exception:
        pass
    return [f"  [raw: {data.hex()}]"]

def decode_audio_diag(data: bytes, ch: int) -> list:
    """ASCII audio diagnostic channels (114, 116)."""
    try:
        txt = data.decode("ascii", errors="replace").strip()
        return [f"  [AUDIO DIAG ch{ch}] {txt}"]
    except Exception:
        return [f"  [raw: {data.hex()}]"]

# ─────────────────────────────────────────────
# DISPATCH
# ─────────────────────────────────────────────

def decode_ch6(data: bytes) -> list:
    """CAPABILITY FLAGS: sent once on connect, always 080b1001.
    f1=11 = number of active Maestro logical channels (ch1..ch11).
    f2=1  = protocol revision / feature set version.
    Invariant — if these change, the protocol version changed.
    """
    if is_valid_protobuf(data):
        fields = decode_protobuf(data)
        lines = ["  [CAPABILITY FLAGS]"]
        for fn, wt, val in fields:
            if fn == 1 and wt == "varint":
                lines.append(f"  >> num_channels      : {val}")
            elif fn == 2 and wt == "varint":
                lines.append(f"  >> protocol_revision : {val}")
            else:
                lines.append(f"    f{fn} = {val}")
        return lines
    return [f"  [raw: {data.hex()}]"]

_DECODERS = {
    1:   decode_ch1,
    2:   decode_ch2,
    3:   decode_ch3,
    4:   decode_ch4,
    5:   decode_ch5,
    6:   decode_ch6,
    7:   decode_ch7,
    8:   decode_ch8,
    9:   decode_ch9,
    10:  decode_ch10,
    11:  decode_ch11,
    32:  decode_ch32_33,
    33:  decode_ch32_33,
    64:  decode_ch64,
    99:  decode_ch32_33,
}

# ─────────────────────────────────────────────
# 0x87 STATE_SNAPSHOT DECODER
# ─────────────────────────────────────────────
# STATE_SNAPSHOT frames carry a nested protobuf whose outer structure is:
#   f3 (wire=2) → 2-byte payload = mini-protobuf: [setting_tag][value]
# setting_tag is itself a valid protobuf tag byte encoding field+wire:
#   0x08 = f1  varint → IN_EAR_DETECT   (0=off  1=on)
#   0x18 = f3  varint → unknown_3       (fast_pair only)
#   0x28 = f5  varint → ADAPTIVE_SOUND  (0=off  1=on)
#   0x40 = f8  varint → unknown_8       (fast_pair only)
#   0x58 = f11 varint → TOUCH_CONTROLS  (0=off  1=on)
#   0x68 = f13 varint → VOLUME_EQ       (0=off  1=on)
#   0x70 = f14 varint → BASS_EQ_LEVEL   (0=eq1..5=eq6, i.e. value+1)
# CH8 KEEPALIVE snapshot: 0x18 XX = f3 varint = seq/mode byte
# CH9 WEAR+TOUCH snapshot: same 1a02XXYY pattern = current setting state

SNAPSHOT_SETTINGS = {
    0x08: ("IN_EAR_DETECT",  {0: "off",  1: "on"}),
    0x18: ("unknown_3",      {}),
    0x28: ("ADAPTIVE_SOUND", {0: "off",  1: "on"}),
    0x40: ("unknown_8",      {}),
    0x58: ("TOUCH_CONTROLS", {0: "off",  1: "on"}),
    0x68: ("VOLUME_EQ",      {0: "off",  1: "on"}),
    0x70: ("BASS_EQ_LEVEL",  {0: "1", 1: "2", 2: "3", 3: "4", 4: "5", 5: "6"}),
}

def decode_snapshot(data: bytes) -> list:
    """Decode a 0x87 STATE_SNAPSHOT payload.

    Outer: protobuf field 3 length-delimited (tag=0x1a, len=0x02)
    Inner: 2-byte mini-protobuf [setting_tag][value_varint]
    Also handles CH8 keepalive snapshot (0x18 XX) and bare 0x00.
    """
    if not data:
        return ["  [STATE_SNAPSHOT] (empty)"]

    # CH8-style: single varint field (0x18 XX = f3 varint value)
    if len(data) == 2 and data[0] in (0x18, 0x08, 0x10, 0x1d):
        tag, val = data[0], data[1]
        fname = f"f{tag >> 3}"
        return [f"  [STATE_SNAPSHOT] keepalive/mode {fname}={val}"]

    # Bare single byte
    if len(data) == 1:
        return [f"  [STATE_SNAPSHOT] raw: {data.hex()}"]

    # Standard: 1a 02 XX YY  (f3, len=2, [setting_tag, value])
    if len(data) == 4 and data[0] == 0x1a and data[1] == 0x02:
        setting_tag, value = data[2], data[3]
        name, val_map = SNAPSHOT_SETTINGS.get(setting_tag, (f"setting_0x{setting_tag:02x}", {}))
        val_str = val_map.get(value, str(value))
        return [f"  [STATE_SNAPSHOT] {name} = {val_str}"]

    # Fallback: try to decode as protobuf
    if is_valid_protobuf(data):
        fields = decode_protobuf(data)
        lines = ["  [STATE_SNAPSHOT protobuf]"]
        for fn, wt, val in fields:
            if wt == "bytes" and len(val) == 2:
                stag, sval = val[0], val[1]
                sname, smap = SNAPSHOT_SETTINGS.get(stag, (f"setting_0x{stag:02x}", {}))
                sval_str = smap.get(sval, str(sval))
                lines.append(f"    f{fn} → {sname} = {sval_str}")
            else:
                lines.append(f"    f{fn}({wt}) = {repr(val) if isinstance(val, (str, bytes)) else val}")
        return lines

    return [f"  [STATE_SNAPSHOT] raw: {data.hex()}"]


def decode_payload(ch: int, data: bytes, ftype: int = 0, is_audio_stream: bool = False) -> list:
    # 0x87 STATE_SNAPSHOT: buds→phone bulk settings sync at connect/app-foreground.
    # The payload encodes the current state of a single setting as a 2-byte mini-protobuf.
    # Structure: 1a 02 [setting_tag] [value]  where setting_tag encodes field+type.
    if ftype == 0x87:
        try:
            return decode_snapshot(data)
        except Exception as e:
            return [f"  [STATE_SNAPSHOT] raw: {data.hex()}  ({e})"]

    if ch == 4:
        try:
            return decode_ch4(data, is_audio_stream=is_audio_stream)
        except Exception as e:
            return [f"  [decoder error: {e}] raw: {data.hex()}"]

    if ch in _DECODERS:
        try:
            return _DECODERS[ch](data)
        except Exception as e:
            return [f"  [decoder error: {e}] raw: {data.hex()}"]
    # Generic fallback
    if ch in (114, 116) or ch > 100:
        return decode_audio_diag(data, ch)
    if looks_pw_b64(data):
        return decode_pw_token_b64(data)
    if is_valid_protobuf(data):
        f = decode_protobuf(data)
        return ["  [protobuf]"] + fmt_protobuf(f)
    try:
        txt = data.decode("ascii")
        if all(c.isprintable() or c in "\r\n\t" for c in txt):
            return [f"  [ASCII] {txt.strip()}"]
    except Exception:
        pass
    return [f"  [raw: {data.hex()}]"]

# ─────────────────────────────────────────────
# TSHARK CAPTURE
# ─────────────────────────────────────────────

def run_tshark_maestro(capture_file: str, max_samples: int = 5) -> dict:
    """Extract Maestro payloads from `maestro.full` frames exported by maestro.lua.

    Frame variants supported:
      - Standard: [type][channel][flags][len][payload...]
      - Compact:  [type][channel][payload_byte]
    """
    channels = defaultdict(lambda: {
        "count":   0,
        "sizes":   set(),
        "samples": [],
        "decoded": [],
        "events":  [],          # list of {unix_us, ftype, payload} — ALL packets in order
        "_seen_payloads": set(),
        "_uniq_by_size": defaultdict(list),
    })
    try:
        out = subprocess.check_output([
            "tshark",
            "-r", capture_file,
            "-Y", "maestro",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "maestro.full",
            "-E", "separator=|",
        ], stderr=subprocess.DEVNULL).decode(errors="ignore").splitlines()
    except FileNotFoundError:
        print("ERROR: tshark not found.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: tshark failed: {e}")
        sys.exit(1)

    for line in out:
        if not line.strip():
            continue
        line = line.strip()

        # Split on | separator: "timestamp|frame_hex_field"
        parts = line.split("|", 1)
        ts_str    = parts[0].strip()
        frame_raw = parts[1].strip() if len(parts) > 1 else ts_str

        if frame_raw in ("<MISSING>", ""):
            continue

        # Parse timestamp — tshark gives Unix seconds with fractional part
        try:
            unix_us = int(float(ts_str) * 1e6)
        except (ValueError, IndexError):
            unix_us = 0

        for p in frame_raw.split(","):
            p = p.strip().replace(":", "")
            if not p:
                continue
            try:
                frame = bytes.fromhex(p)
            except ValueError:
                continue

            if len(frame) < 3:
                continue

            ftype, ch = frame[0], frame[1]
            # Accept all frame types — unknown types are labelled UNKNOWN(0xXX)
            # rather than silently dropped (we used to whitelist VALID_FTYPES).

            # Compact 3-byte variant: [type][channel][payload_byte]
            if len(frame) == 3:
                payload = frame[2:3]
            elif len(frame) >= 4:
                plen = frame[3]
                needed = 4 + plen
                if len(frame) < needed:
                    continue
                payload = frame[4:needed]
            else:
                continue

            entry = channels[ch]
            entry["count"] += 1
            size = len(payload)
            entry["sizes"].add(size)

            # Always record the event with its timestamp for timeline mode
            entry["events"].append({
                "unix_us": unix_us,
                "ftype":   ftype,
                "payload": payload,
            })

            # Track unique payloads grouped by payload size.
            # We select representative samples after parsing all frames so we
            # don't accidentally fill the sample budget with one repeated size.
            if payload in entry["_seen_payloads"]:
                continue
            entry["_seen_payloads"].add(payload)
            entry["_uniq_by_size"][size].append(payload)

    # Choose samples with size diversity first, capped by max_samples:
    #   1) first unique payload from each seen size
    #   2) additional unique payloads in encounter order until cap is reached
    for ch, entry in channels.items():
        uniq_by_size = entry["_uniq_by_size"]
        selected = []

        # First pass: one per size.
        for size in uniq_by_size:
            if len(selected) >= max_samples:
                break
            selected.append(uniq_by_size[size][0])

        # Second pass: remaining unique payloads for each size bucket.
        if len(selected) < max_samples:
            for size in uniq_by_size:
                for payload in uniq_by_size[size][1:]:
                    if len(selected) >= max_samples:
                        break
                    selected.append(payload)
                if len(selected) >= max_samples:
                    break

        entry["samples"] = selected
        entry["decoded"] = [decode_payload(ch, payload) for payload in selected]
        del entry["_seen_payloads"]
        del entry["_uniq_by_size"]
    return channels


def run_tshark_battery(capture_file: str, max_samples: int = 5) -> list:
    """Extract GadgetBridge battery/event protocol frames from the raw RFCOMM stream.
    These live on a SEPARATE RFCOMM DLCI from Maestro — NOT inside the Maestro mux.
    GadgetBridge framing: cmd(u16 BE) + size(u16 BE) + payload[size].

    RFCOMM is a stream protocol — a single GadgetBridge frame can be split across
    multiple RFCOMM UIH packets (e.g. if an HCI MTU boundary falls mid-frame).
    We therefore concatenate all payloads per DLCI into a stream and then scan,
    rather than parsing each packet in isolation (which would silently drop splits).

    NOTE: ch11 STATUS STREAM f2/f13 are NOT battery percentage.
    Real battery % comes from this separate RFCOMM channel (cmd=0x0303).
    """
    try:
        out = subprocess.check_output([
            "tshark",
            "-r", capture_file,
            "-Y", "btrfcomm",
            "-T", "fields",
            "-e", "btrfcomm.dlci",
            "-e", "btrfcomm.payload",
        ], stderr=subprocess.DEVNULL).decode(errors="ignore").splitlines()
    except Exception:
        return []

    # Accumulate raw bytes per DLCI — preserves stream continuity across packets
    streams: dict = {}
    for line in out:
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        dlci_str, payload_raw = parts
        if payload_raw in ("<MISSING>", ""):
            continue
        try:
            dlci = int(dlci_str.split(",")[0])
            chunk = bytes.fromhex(payload_raw.split(",")[0].strip())
        except Exception:
            continue
        streams.setdefault(dlci, b"")
        streams[dlci] += chunk

    # Scan each per-DLCI stream for GadgetBridge frames
    events = []
    for dlci, data in streams.items():
        pos = 0
        while pos + 4 <= len(data) and len(events) < max_samples:
            cmd  = struct.unpack_from(">H", data, pos)[0]
            size = struct.unpack_from(">H", data, pos + 2)[0]
            if cmd not in GB_CMDS or size >= 64:
                # Not a GB frame at this offset — advance one byte and resync
                # (handles junk data or a non-GB DLCI being included)
                pos += 1
                continue
            if pos + 4 + size > len(data):
                # Genuine truncation at end of capture — stop rather than spin
                break
            frame = data[pos + 4 : pos + 4 + size]
            decoded = decode_gb_battery(data[pos : pos + 4 + size])
            events.append({"dlci": dlci, "raw": data[pos:pos+4+size].hex(), "decoded": decoded})
            pos += 4 + size
    return events


def run_tshark(capture_file: str, max_samples: int = 5):
    """Wrapper: run both Maestro and battery extractors."""
    return run_tshark_maestro(capture_file, max_samples)

# ─────────────────────────────────────────────
# PRETTY PRINT
# ─────────────────────────────────────────────

def print_analysis(channels: dict, verbose: bool = False):
    sep = "─" * 60
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║          MAESTRO CHANNEL ANALYSIS  (Pixel Buds A)       ║")
    print("╚══════════════════════════════════════════════════════════╝")

    for ch, data in sorted(channels.items(), key=lambda x: x[0]):
        name  = CHANNEL_NAMES.get(ch, f"UNKNOWN_{ch}")
        print(f"\n┌─ CHANNEL {ch:3d}  [{name}]  {sep[:max(0,50-len(name)-len(str(ch)))]}")
        print(f"│  packets : {data['count']}")
        print(f"│  sizes   : {sorted(data['sizes'])}")
        print("│  samples :")
        for i, (raw, decoded) in enumerate(zip(data["samples"], data["decoded"])):
            print(f"│   [{i}] hex: {raw.hex()}")
            for line in decoded:
                print(f"│       {line}")
        print("└" + "─" * 60)

# ─────────────────────────────────────────────
# TIMELINE MODE
# ─────────────────────────────────────────────

# ANSI colours for terminal output
_C = {
    "reset":  "\033[0m",   "bold":   "\033[1m",   "dim":    "\033[2m",
    "cyan":   "\033[96m",  "yellow": "\033[93m",  "green":  "\033[92m",
    "red":    "\033[91m",  "blue":   "\033[94m",  "white":  "\033[97m",
    "magenta":"\033[95m",
}

# Colour per channel group for quick visual scanning
CH_COLOUR = {
    1: "dim",     # LOG STREAM — noisy, dimmed
    2: "cyan",    # HANDSHAKE
    3: "yellow",  # REALTIME CONTROL — gestures
    4: "blue",    # VERSION / EQ
    5: "green",   # CONN STATE
    8: "dim",     # KEEPALIVE
    9: "magenta", # WEAR DETECT
    11:"green",   # STATUS STREAM
}

def _ch_colour(ch: int) -> str:
    key = CH_COLOUR.get(ch, "white")
    return _C[key]

def print_timeline(channels: dict, windows: list = None,
                   filter_channels: set = None, no_colour: bool = False,
                   show_log: bool = False):
    """Print every Maestro packet in chronological order with timestamps.

    Each line:
        HH:MM:SS.mmm  [ACTION_LABEL]  DIR  CH_NAME  decoded_summary

    Args:
        windows      : list of session window dicts (from load_session)
        filter_channels: if set, only show these channel numbers
        no_colour    : disable ANSI colour
        show_log     : include CH1 LOG_STREAM (very noisy, off by default)
    """
    FRAME_DIR = {
        0x01: "→open",  0x02: "←ack ",  0x03: "→cmd ",
        0x04: "→cls ",  0x05: "←data",  0x09: "→ping",
        0x0e: "←rsp ",
    }

    # Gather all events across all channels into one flat list
    all_events = []
    for ch, entry in channels.items():
        if filter_channels and ch not in filter_channels:
            continue
        if not show_log and ch == 1:
            continue
        for ev in entry["events"]:
            all_events.append((ev["unix_us"], ch, ev["ftype"], ev["payload"]))

    all_events.sort(key=lambda x: x[0])

    if not all_events:
        print("  (no events to display — run with --timeline)")
        return

    # Compute action label lookup from windows
    def get_action(unix_us):
        if not windows:
            return None
        for w in windows:
            if w["start_unix_us"] <= unix_us <= w["end_unix_us"]:
                return w["action_id"]
        return None

    def c(text, key):
        if no_colour: return text
        return _C.get(key, "") + text + _C["reset"]

    print()
    print(c("═" * 100, "cyan"))
    print(c("  MAESTRO TIMELINE", "bold") +
          (f"  [{len(all_events)} events]" if all_events else ""))
    if windows:
        print(c("  ▸ Action windows loaded — packets inside windows are annotated", "dim"))
    print(c("═" * 100, "cyan"))
    print()
    print(c(f"  {'TIME':>12}  {'ACTION':<22}  {'DIR':>6}  {'CH':>3}  {'CHANNEL':<18}  DECODED", "dim"))
    print(c("  " + "─" * 96, "dim"))

    prev_action = None
    # Pre-compute per-event is_audio_stream flag for CH4.
    # A CH4 packet is audio stream if its inter-packet gap to either neighbour
    # on CH4 is <100ms (i.e. >10 packets/sec = active audio streaming).
    ch4_times = sorted(
        ev_ts for ev_ts, ev_ch, _ft, _pl in all_events if ev_ch == 4
    )
    ch4_audio_set = set()
    AUDIO_GAP_US = 100_000  # 100ms — audio stream runs at ~25 pkt/sec (40ms gap)
    for i, t in enumerate(ch4_times):
        prev_gap = (t - ch4_times[i-1]) if i > 0 else 999_999_999
        next_gap = (ch4_times[i+1] - t) if i < len(ch4_times)-1 else 999_999_999
        if min(prev_gap, next_gap) < AUDIO_GAP_US:
            ch4_audio_set.add(t)

    for unix_us, ch, ftype, payload in all_events:
        ts       = fmt_ts(unix_us)
        ch_name  = CHANNEL_NAMES.get(ch, f"UNKNOWN_{ch}")
        dir_str  = FRAME_DIR.get(ftype, f"0x{ftype:02x} ")
        action   = get_action(unix_us)
        ch_col   = _ch_colour(ch)

        # Print action boundary marker
        if action != prev_action:
            if action:
                print()
                print(c(f"  ┌─ {action} ", "bold") + c("─" * (80 - len(action)), "dim"))
            elif prev_action:
                print(c("  └─" + "─" * 80, "dim"))
            prev_action = action

        action_str = (action or "")[:22]

        # Decode payload to single summary line
        try:
            is_audio = (ch == 4 and unix_us in ch4_audio_set)
            decoded_lines = decode_payload(ch, payload, ftype=ftype, is_audio_stream=is_audio)
            # Take first meaningful line, strip leading spaces
            summary = next(
                (l.strip() for l in decoded_lines if l.strip() and not l.strip().startswith("[")),
                decoded_lines[0].strip() if decoded_lines else ""
            )
            # If only label lines, use the first one
            if not summary and decoded_lines:
                summary = decoded_lines[0].strip()
            # Trim to fit terminal
            if len(summary) > 55:
                summary = summary[:52] + "..."
        except Exception as e:
            summary = f"[error: {e}]"

        tag = c(f"[{action_str}]", "yellow") if action else " " * (len(action_str) + 2)
        line = (
            f"  {c(ts, 'dim')}  "
            f"{tag:<24}  "
            f"{c(dir_str, 'dim')}  "
            f"{c(str(ch), 'bold'):>5}  "
            f"{c(ch_name, ch_col):<18}  "
            f"{summary}"
        )
        print(line)

    print()
    print(c("  " + "─" * 96, "dim"))
    print(c(f"  {len(all_events)} packets  |  {len(channels)} channels", "dim"))
    print()


def print_analysis_with_timestamps(channels: dict, verbose: bool = False,
                                   windows: list = None):
    """Extended analysis: per-channel samples now include timestamp annotation."""
    sep = "─" * 60
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║          MAESTRO CHANNEL ANALYSIS  (Pixel Buds A)       ║")
    print("╚══════════════════════════════════════════════════════════╝")

    for ch, data in sorted(channels.items(), key=lambda x: x[0]):
        name  = CHANNEL_NAMES.get(ch, f"UNKNOWN_{ch}")
        print(f"\n┌─ CHANNEL {ch:3d}  [{name}]  {sep[:max(0,50-len(name)-len(str(ch)))]}")
        print(f"│  packets : {data['count']}")
        print(f"│  sizes   : {sorted(data['sizes'])}")

        # Timestamp range for this channel
        if data["events"]:
            ts_first = data["events"][0]["unix_us"]
            ts_last  = data["events"][-1]["unix_us"]
            print(f"│  time    : {fmt_ts(ts_first)} → {fmt_ts(ts_last)}")

        print("│  samples :")
        for i, (raw, decoded) in enumerate(zip(data["samples"], data["decoded"])):
            # Find timestamp of this exact payload in events list
            ts_str = ""
            for ev in data["events"]:
                if ev["payload"] == raw:
                    action = classify_timestamp(ev["unix_us"], windows) if windows else None
                    action_str = f"  [{action}]" if action else ""
                    ts_str = f" @ {fmt_ts(ev['unix_us'])}{action_str}"
                    break
            print(f"│   [{i}] hex: {raw.hex()}{ts_str}")
            for line in decoded:
                print(f"│       {line}")
        print("└" + "─" * 60)


# ─────────────────────────────────────────────
# SINGLE HEX DECODE MODE
# ─────────────────────────────────────────────

def decode_single(hex_str: str, ch: int):
    """Decode a single hex payload for a given channel."""
    try:
        data = bytes.fromhex(hex_str.replace(" ", ""))
    except ValueError:
        print(f"ERROR: invalid hex string: {hex_str}")
        sys.exit(1)
    ch_name = CHANNEL_NAMES.get(ch, f"UNKNOWN_{ch}")
    print(f"\n=== Decoding channel {ch} [{ch_name}] payload: {data.hex()} ===")
    for line in decode_payload(ch, data):
        print(line)
    print()

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Maestro protocol decoder for Pixel Buds A",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-r", "--read",      default="btsnoop_hci.log",
                        help="btsnoop capture file (default: btsnoop_hci.log)")
    parser.add_argument("--hex",             help="Decode a single hex payload (use with --ch)")
    parser.add_argument("--ch",              type=int, default=0,
                        help="Channel number for --hex mode")
    parser.add_argument("--full",            action="store_true",
                        help="Show all samples (default: 5 per channel)")
    parser.add_argument("--channels",        help="Comma-separated channel list to display (default: all)")
    parser.add_argument("--timeline",        action="store_true",
                        help="Print all packets in chronological order with timestamps")
    parser.add_argument("--session",         metavar="FILE",
                        help="Session JSON from maestro-guide.py — annotates packets with action names")
    parser.add_argument("--no-colour",       action="store_true",
                        help="Disable ANSI colour in timeline output")
    parser.add_argument("--show-log",        action="store_true",
                        help="Include CH1 LOG_STREAM in timeline (noisy, off by default)")
    args = parser.parse_args()

    if args.hex:
        decode_single(args.hex, args.ch)
        return

    # Load session windows if provided
    windows = []
    if args.session:
        try:
            windows = load_session(args.session)
            print(f"  Session loaded: {len(windows)} action windows from {args.session}")
        except Exception as e:
            print(f"  [WARN] Could not load session: {e}")

    max_samples = 9999 if args.full else 5

    # Maestro channels (via maestro.lua dissector in tshark)
    channels = run_tshark(args.read, max_samples)
    if args.channels:
        wanted = set(int(c) for c in args.channels.split(","))
        channels = {k: v for k, v in channels.items() if k in wanted}

    if args.timeline:
        # Timeline mode: chronological view of all packets
        filter_chs = None
        if args.channels:
            filter_chs = set(int(c) for c in args.channels.split(","))
        print_timeline(channels, windows=windows,
                       filter_channels=filter_chs,
                       no_colour=args.no_colour,
                       show_log=args.show_log)
    else:
        # Default analysis mode — now includes timestamps on samples
        print_analysis_with_timestamps(channels, verbose=args.full, windows=windows)

    # GadgetBridge battery protocol (separate RFCOMM service, NOT in Maestro mux)
    battery_events = run_tshark_battery(args.read, max_samples)
    if battery_events:
        print("\n\n╔══ GADGETBRIDGE BATTERY PROTOCOL (separate RFCOMM) ════════╗")
        print("║  cmd=0x0303: left%, right%, case%  (-1=not in case)       ║")
        print("║  NOTE: ch11 f2/f13 are NOT battery — they are internal    ║")
        print("║  status counters unrelated to charge percentage.          ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        for ev in battery_events:
            print(f"  DLCI={ev['dlci']} raw={ev['raw']}")
            for line in ev["decoded"]:
                print(f"  {line}")
    else:
        print("\n  [No GadgetBridge battery frames found — battery service may")
        print("   be on a different RFCOMM DLCI not captured, or tshark missing")
        print("   btrfcomm field. Try: tshark -r capture.log -Y btrfcomm]")

    # Summary table
    print("\n\n╔══ CHANNEL SUMMARY TABLE ══════════════════════════════════╗")
    print(f"{'CH':>4}  {'NAME':<22}  {'PKTS':>6}  {'TIME RANGE'}")
    print("─" * 70)
    for ch, data in sorted(channels.items()):
        name   = CHANNEL_NAMES.get(ch, f"UNKNOWN_{ch}")
        if data["events"]:
            t0 = fmt_ts(data["events"][0]["unix_us"])
            t1 = fmt_ts(data["events"][-1]["unix_us"])
            trange = f"{t0} → {t1}"
        else:
            trange = ""
        status = "✓" if ch in _DECODERS or ch in (114, 116) else "?"
        print(f"{ch:>4}  {name:<22}  {data['count']:>6}  {status}  {trange}")
    print("╚" + "═" * 69 + "╝")

if __name__ == "__main__":
    main()
