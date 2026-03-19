-- maestro.lua — Wireshark Lua dissector for Pixel Buds A / Maestro protocol
-- Handles L2CAP/RFCOMM reassembly, batched frames, CH03 proto/raw switching,
-- CH09 TLV inner encoding, CH11 correct field semantics.
--
-- Install: copy to ~/.config/wireshark/plugins/maestro.lua
-- Register: Analyze → Decode As → btrfcomm.channel → maestro
--           (set for whichever RFCOMM channel your device uses)

local proto = Proto("maestro", "Pixel Buds A — Maestro")

-- ── proto fields ──────────────────────────────────────────────────────────────
local pf = {
    ftype   = ProtoField.uint8 ("maestro.type",    "Frame Type",  base.HEX),
    channel = ProtoField.uint8 ("maestro.channel", "Channel",     base.DEC),
    flags   = ProtoField.uint8 ("maestro.flags",   "Flags",       base.HEX),
    length  = ProtoField.uint8 ("maestro.length",  "Length",      base.DEC),
    full    = ProtoField.bytes ("maestro.full",    "Full Frame"),
    payload = ProtoField.bytes ("maestro.payload", "Payload"),
}
proto.fields = pf

-- ── name tables ───────────────────────────────────────────────────────────────
local FTYPES = {
    [0x01]="OPEN",      [0x02]="OPEN_ACK",  [0x03]="DATA→buds",
    [0x04]="CLOSE",     [0x05]="DATA←buds", [0x09]="PING",
    [0x0e]="RSP←buds",
}
local CHNAMES = {
    [0x01]="LOG_STREAM", [0x02]="HANDSHAKE",  [0x03]="REALTIME_CTRL",
    [0x04]="VERSION",    [0x08]="KEEPALIVE",  [0x09]="WEAR_DETECT",
    [0x0a]="DEVICE_REG", [0x0b]="STATUS",     [0x0c]="UNKNOWN_C",
}

-- ── varint helper (operates on TvbRange, offset is absolute into original tvb)
-- Returns decoded_value, new_offset.  On error returns nil.
local function rd_varint(tvb, off, max_off)
    local val, shift = 0, 0
    while off <= max_off do
        local b = tvb(off, 1):uint()
        val = val + bit.lshift(bit.band(b, 0x7f), shift)
        off = off + 1
        if bit.band(b, 0x80) == 0 then return val, off end
        shift = shift + 7
        if shift > 28 then return nil, off end  -- overflow guard
    end
    return nil, off  -- truncated varint — caller must treat as fragment
end

-- ── generic protobuf printer (does NOT recurse to avoid infinite loops) ───────
local function print_proto(tvb, off, end_off, tree)
    while off < end_off do
        local tag, noff = rd_varint(tvb, off, end_off - 1)
        if not tag or tag == 0 then break end
        off = noff
        local fnum = bit.rshift(tag, 3)
        local wire = bit.band(tag, 7)
        if fnum == 0 or fnum > 128 then break end

        if wire == 0 then          -- varint
            local v, no = rd_varint(tvb, off, end_off - 1)
            if not v then break end
            tree:add(proto, tvb(off, no - off),
                string.format("f%d varint = %d  (0x%x)", fnum, v, v))
            off = no
        elseif wire == 2 then      -- length-delimited
            local len, no = rd_varint(tvb, off, end_off - 1)
            if not len then break end
            off = no
            if off + len > end_off then break end  -- truncated payload
            local chunk = tvb(off, len)
            -- try to show as string
            local ok, s = pcall(function() return chunk:string() end)
            if ok and s:match("^[%g%s]+$") and #s > 0 then
                tree:add(proto, chunk,
                    string.format("f%d string = %q", fnum, s))
            else
                tree:add(proto, chunk,
                    string.format("f%d bytes[%d] = %s", fnum, len,
                        tostring(chunk)))
            end
            off = off + len
        elseif wire == 5 then      -- 32-bit
            if off + 4 > end_off then break end
            local v = tvb(off, 4):le_uint()
            tree:add(proto, tvb(off, 4),
                string.format("f%d fixed32 = %u  (0x%08x)", fnum, v, v))
            off = off + 4
        elseif wire == 1 then      -- 64-bit
            if off + 8 > end_off then break end
            tree:add(proto, tvb(off, 8),
                string.format("f%d fixed64", fnum))
            off = off + 8
        else
            break  -- unknown wire type — stop rather than corrupt offset
        end
    end
end

-- ── CH01 log stream ───────────────────────────────────────────────────────────
local function dissect_ch01(tvb, off, end_off, tree)
    local sub = tree:add(proto, tvb(off, end_off - off), "Log Envelope")
    -- f1 = payload (bytes, starts with '$' if tokenized)
    -- f2 = level (0=varint)
    -- f3 = tick (fixed32)
    -- f4 = device_id (varint)
    local pos = off
    while pos < end_off do
        local tag, npos = rd_varint(tvb, pos, end_off - 1)
        if not tag or tag == 0 then break end
        pos = npos
        local fnum = bit.rshift(tag, 3)
        local wire = bit.band(tag, 7)
        if wire == 2 then
            local len, no = rd_varint(tvb, pos, end_off - 1)
            if not len or pos + (no - pos) + len > end_off then break end
            pos = no
            local chunk = tvb(pos, len)
            if fnum == 1 then
                local s = chunk:string()
                if s:sub(1,1) == "$" then
                    sub:add(proto, chunk, "payload (pw_tokenized) = " .. s:sub(1,40))
                else
                    sub:add(proto, chunk, "payload (plain) = " .. s:sub(1,80))
                end
            end
            pos = pos + len
        elseif wire == 0 then
            local v, no = rd_varint(tvb, pos, end_off - 1)
            if not v then break end
            if     fnum == 2 then sub:add(proto, tvb(pos, no-pos), "level    = " .. v)
            elseif fnum == 4 then sub:add(proto, tvb(pos, no-pos), "device   = " .. v)
            end
            pos = no
        elseif wire == 5 then
            if pos + 4 > end_off then break end
            local v = tvb(pos, 4):le_uint()
            if fnum == 3 then sub:add(proto, tvb(pos, 4), "tick     = " .. v) end
            pos = pos + 4
        else break end
    end
end

-- ── CH03 realtime control — proto OR raw depending on first byte ──────────────
-- Rule: if byte[0] encodes a valid protobuf tag (field 1-30, wire 0/1/2/5)
--       AND the remaining length is consistent → parse as protobuf.
--       Otherwise parse as raw [class(4b)|cmd(4b)] [param_le16].
local function dissect_ch03(tvb, off, end_off, tree)
    local sz = end_off - off
    if sz == 0 then return end

    -- Correct discriminator: attempt full proto parse; proto only if ALL bytes
    -- consumed without error.  A valid-tag-byte check alone fails — 0x58 is
    -- syntactically a valid proto tag (fnum=11, wire=0) but 0xffff is not a
    -- valid varint continuation, so the attempt catches it correctly.
    local proto_ok = pcall(function()
        local pos = off
        while pos < end_off do
            local tag, npos = rd_varint(tvb, pos, end_off - 1)
            if not tag or tag == 0 then error("bad tag") end
            local fnum = bit.rshift(tag, 3)
            local wire = bit.band(tag, 7)
            if fnum == 0 or fnum > 64 then error("bad fnum") end
            pos = npos
            if     wire == 0 then
                local _, np = rd_varint(tvb, pos, end_off - 1)
                if not np then error("trunc varint") end; pos = np
            elseif wire == 2 then
                local l, np = rd_varint(tvb, pos, end_off - 1)
                if not l then error("trunc len") end; pos = np
                if pos + l > end_off then error("trunc payload") end; pos = pos + l
            elseif wire == 5 then
                if pos + 4 > end_off then error("trunc f32") end; pos = pos + 4
            elseif wire == 1 then
                if pos + 8 > end_off then error("trunc f64") end; pos = pos + 8
            else error("unknown wire") end
        end
        -- All bytes consumed — it's valid protobuf
    end)

    local sub = tree:add(proto, tvb(off, sz), "Realtime Control")

    if proto_ok then
        sub:append_text(" (protobuf)")
        print_proto(tvb, off, end_off, sub)
    else
        -- Raw: [class:4|cmd:4] [param_lo] [param_hi]
        local b0    = tvb(off, 1):uint()
        local class = bit.rshift(b0, 4)
        local cmd   = bit.band(b0, 0x0f)
        local cname = (class == 0x5) and "MEDIA" or
                      (class == 0xD) and "ANC_MIC" or
                      string.format("0x%x", class)
        local cmds = {
            [0x04]="PLAY_PAUSE", [0x06]="NEXT_TRACK",
            [0x07]="PREV_TRACK", [0x08]="VOL_UP",
            [0x0e]="VOL_DOWN",
        }
        local cstr = cmds[cmd] or string.format("0x%x", cmd)
        sub:append_text(string.format(" (raw) class=%s cmd=%s", cname, cstr))
        sub:add(proto, tvb(off, 1),
            string.format("class=0x%x (%s)  cmd=0x%x (%s)", class, cname, cmd, cstr))
        if sz >= 3 then
            local param = tvb(off+1, 2):le_uint()
            if param == 0xffff then
                sub:add(proto, tvb(off+1, 2), "param = MAX / trigger")
            else
                sub:add(proto, tvb(off+1, 2), "param = " .. param)
            end
        end
    end
end

-- ── CH09 wear detect — protobuf outer, TLV inner ─────────────────────────────
-- Inner bytes field content: [type:1][value:1] pairs (TLV, no length byte)
local TLV09 = {
    [0x01]="LID_STATE",  [0x02]="CHARGE_STATE",
    [0x03]="EAR_STATE",  [0x04]="PRIMARY_BUD",
    [0x05]="BATTERY_L",  [0x06]="BATTERY_R",
    [0x07]="BATTERY_CASE",
}
local function dissect_ch09(tvb, off, end_off, tree)
    local sub = tree:add(proto, tvb(off, end_off - off), "Wear Detect")
    local pos = off
    while pos < end_off do
        local tag, npos = rd_varint(tvb, pos, end_off - 1)
        if not tag or tag == 0 then break end
        pos = npos
        local fnum = bit.rshift(tag, 3)
        local wire = bit.band(tag, 7)
        if wire == 2 then
            local len, no = rd_varint(tvb, pos, end_off - 1)
            if not len or no + len > end_off then break end
            pos = no
            local tlv_sub = sub:add(proto, tvb(pos, len),
                string.format("f%d TLV stream [%d bytes]", fnum, len))
            -- TLV: each pair is [type:1][value:1]
            local j = pos
            while j + 1 <= pos + len - 1 do
                local tlv_t = tvb(j, 1):uint()
                local tlv_v = tvb(j+1, 1):uint()
                local tname = TLV09[tlv_t] or string.format("type=0x%02x", tlv_t)
                tlv_sub:add(proto, tvb(j, 2),
                    string.format("%s = 0x%02x (%d)", tname, tlv_v, tlv_v))
                j = j + 2
            end
            pos = pos + len
        elseif wire == 0 then
            local v, no = rd_varint(tvb, pos, end_off - 1)
            if not v then break end
            sub:add(proto, tvb(pos, no-pos), string.format("f%d = %d", fnum, v))
            pos = no
        else break end
    end
end

-- ── CH0B status stream ────────────────────────────────────────────────────────
-- f2  = sequence number (NOT time-based — increments by 12 per subsystem cycle
--        regardless of wall-clock delta, until it jumps on a new session/event)
-- f3-f10 = binary state flags (ANC, EQ, ear-detect, etc.)
-- f11 = connection state bitmask (3 = both buds present)
-- f12 = device tick (µs, matches CH01 log tick)
-- f13 = unknown field (often static value; do not assume battery ADC)
local function dissect_ch0b(tvb, off, end_off, tree)
    local sub   = tree:add(proto, tvb(off, end_off - off), "Status Stream")
    local pos   = off
    local seq, tick, batt, conn = nil, nil, nil, nil
    while pos < end_off do
        local tag, npos = rd_varint(tvb, pos, end_off - 1)
        if not tag or tag == 0 then break end
        pos = npos
        local fnum = bit.rshift(tag, 3)
        local wire = bit.band(tag, 7)
        if wire == 0 then
            local v, no = rd_varint(tvb, pos, end_off - 1)
            if not v then break end
            local label = ""
            if     fnum ==  2 then seq  = v; label = "seq_num   (subsystem cycle counter)"
            elseif fnum == 11 then conn = v; label = "conn_mask (3=both buds present)"
            elseif fnum == 12 then tick = v; label = "tick_us   (matches LOG_STREAM tick)"
            elseif fnum == 13 then batt = v
                label = "unknown_13 (often static; semantics TBD)"
            else label = string.format("state_f%d", fnum) end
            sub:add(proto, tvb(pos, no - pos),
                string.format("f%02d = %d   -- %s", fnum, v, label))
            pos = no
        elseif wire == 2 then
            local len, no = rd_varint(tvb, pos, end_off - 1)
            if not len or no + len > end_off then break end
            sub:add(proto, tvb(no, len),
                string.format("f%d bytes[%d]", fnum, len))
            pos = no + len
        elseif wire == 5 then
            if pos + 4 > end_off then break end
            local v = tvb(pos, 4):le_uint()
            sub:add(proto, tvb(pos, 4),
                string.format("f%02d fixed32 = %u", fnum, v))
            pos = pos + 4
        else break end
    end
    if batt then
        sub:add(proto, string.format(
            "▶ SUMMARY  seq=%s  tick=%s  f13=%s  conn=%s",
            tostring(seq), tostring(tick), tostring(batt), tostring(conn)))
    end
end

-- ── main dissector ────────────────────────────────────────────────────────────
function proto.dissector(tvb, pinfo, tree)
    local tot = tvb:reported_length_remaining()
    if tot < 3 then
        -- Need at least 3 bytes for a compact Maestro frame.
        pinfo.desegment_offset = 0
        pinfo.desegment_len    = DESEGMENT_ONE_MORE_SEGMENT
        return 0
    end

    pinfo.cols.protocol:set("Maestro")
    local maestro_tree = tree:add(proto, tvb(), "Maestro Protocol")
    local offset = 0

    while offset < tot do
        local remain = tot - offset

        -- Compact frame variant: [type][channel][payload_byte]
        -- Seen on some streams where there is payload but no len/flags byte.
        if remain == 3 then
            local ftype = tvb(offset, 1):uint()
            local ch    = tvb(offset + 1, 1):uint()
            local ftype_name = FTYPES[ftype] or string.format("UNKNOWN(0x%02x)", ftype)
            local ch_name    = CHNAMES[ch]   or string.format("CH%02x", ch)
            local frame_tree = maestro_tree:add(proto, tvb(offset, 3),
                string.format("[compact] [%s] %s  len=1", ftype_name, ch_name))

            frame_tree:add(pf.full, tvb(offset, 3))
            frame_tree:add(pf.ftype,   tvb(offset, 1)):append_text("  (" .. ftype_name .. ")")
            frame_tree:add(pf.channel, tvb(offset + 1, 1)):append_text("  (" .. ch_name .. ")")
            frame_tree:add(pf.payload, tvb(offset + 2, 1))

            offset = offset + 3
            break
        end

        -- ── Header check ─────────────────────────────────────────────────────
        if remain < 4 then
            -- Partial header: request more data.
            -- NOTE: pinfo.desegment_offset / desegment_len work here only if
            -- the underlying RFCOMM layer streams data to us. Wireshark's
            -- RFCOMM dissector currently does NOT reassemble across HCI packets,
            -- so in practice a truncated HEADER means a capture artifact.
            -- We mark it and bail rather than silently corrupting the parse tree.
            maestro_tree:add_expert_info(PI_REASSEMBLE, PI_WARN,
                string.format("Truncated Maestro header at offset %d (%d bytes remain)",
                    offset, tot - offset))
            break
        end

        local ftype  = tvb(offset,     1):uint()
        local ch     = tvb(offset + 1, 1):uint()
        local flags  = tvb(offset + 2, 1):uint()
        local plen   = tvb(offset + 3, 1):uint()
        local needed = 4 + plen

        -- ── Payload fragment check ────────────────────────────────────────────
        if tot - offset < needed then
            -- We have the header but not the full payload.
            -- Signal Wireshark to wait for more RFCOMM data.
            pinfo.desegment_offset = offset
            pinfo.desegment_len    = needed - (tot - offset)
            return
        end

        -- ── Validate frame type (basic sanity — unknown types are displayed) ─
        local ftype_name = FTYPES[ftype]   or string.format("UNKNOWN(0x%02x)", ftype)
        local ch_name    = CHNAMES[ch]     or string.format("CH%02x", ch)
        local frame_label = string.format("[%s] %s  len=%d", ftype_name, ch_name, plen)

        local frame_tree = maestro_tree:add(proto, tvb(offset, needed), frame_label)
        frame_tree:add(pf.full,    tvb(offset, needed))
        frame_tree:add(pf.ftype,   tvb(offset,     1)):append_text("  (" .. ftype_name .. ")")
        frame_tree:add(pf.channel, tvb(offset + 1, 1)):append_text("  (" .. ch_name .. ")")
        frame_tree:add(pf.flags,   tvb(offset + 2, 1))
        frame_tree:add(pf.length,  tvb(offset + 3, 1))

        local pay_off = offset + 4
        local pay_end = pay_off + plen

        if plen > 0 then
            frame_tree:add(pf.payload, tvb(pay_off, plen))

            -- Channel-specific dissection
            if     ch == 0x01 then dissect_ch01(tvb, pay_off, pay_end, frame_tree)
            elseif ch == 0x03 then dissect_ch03(tvb, pay_off, pay_end, frame_tree)
            elseif ch == 0x09 then dissect_ch09(tvb, pay_off, pay_end, frame_tree)
            elseif ch == 0x0b then dissect_ch0b(tvb, pay_off, pay_end, frame_tree)
            else
                -- Generic protobuf decode for all other channels
                print_proto(tvb, pay_off, pay_end, frame_tree)
            end
        end

        offset = offset + needed
    end

    return offset
end

-- ── register ──────────────────────────────────────────────────────────────────────────────
-- IMPORTANT: the "Channel 0/1/2..." in the Maestro analysis are LOGICAL
-- channels of the Maestro multiplexer -- NOT RFCOMM DLCIs.  The entire
-- multiplexed stream rides on a SINGLE RFCOMM DLCI whose number varies
-- by device pairing.  We cannot hard-code it.
--
-- Primary strategy: heuristic dissector that auto-detects Maestro frames
-- on ANY RFCOMM DLCI by inspecting the 4-byte frame header.
-- Fallback: static DLCI registration on confirmed DLCIs 20,22,26,34 (0x14,0x16,0x1a,0x22).
-- Last resort: Analyze -> Decode As -> select maestro for your RFCOMM stream.

local VALID_FTYPES = { [0x01]=true, [0x02]=true, [0x03]=true,
                       [0x04]=true, [0x05]=true, [0x09]=true, [0x0e]=true }

local function maestro_heuristic(tvb, pinfo, tree)
    local len = tvb:reported_length_remaining()
    if len < 3 then return false end

    local ch   = tvb(1,1):uint()
    local plen = tvb(3,1):uint()

    -- Channel must be plausible (0–127)
    if ch > 0x7f then return false end
    -- Declared payload length must fit in the packet
    if plen + 3 > len then return false end
    -- Must have at least some known channels to avoid false positives on HFP etc.
    if ch == 0 and plen == 0 then return false end

    proto.dissector(tvb, pinfo, tree)
    return true
end

local heur_ok, heur_err = pcall(function()
    proto:register_heuristic("btrfcomm", maestro_heuristic)
end)

if heur_ok then
else
    local found = false
    for _, tname in ipairs({ "btrfcomm.channel", "btrfcomm.dlci" }) do
        local t = DissectorTable.get(tname)
        if t then
            -- DLCIs are server_channel * 2 (direction bit = 0, acceptor role).
            -- 0x14=20 (server ch 10): commands, timezone, firmware info
            -- 0x16=22 (server ch 11): status stream
            -- 0x22=34 (server ch 17): 030* control/state frames
            -- 0x1a=26 (server ch 13): raw ASCII / audio log stream
            for _, dlci in ipairs({ 20, 21, 22, 23, 26, 27, 34, 35, 36, 37, 38 }) do t:add(dlci, proto) end
            found = true; break
        end
    end
    if not found then
        print("[maestro] WARNING: all registration attempts failed.")
        print("[maestro] Open your capture, right-click an RFCOMM packet,")
        print("[maestro]   Decode As -> Current -> maestro")
    end
end
