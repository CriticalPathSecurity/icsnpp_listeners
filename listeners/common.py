
import asyncio, struct, socket

# ---------- Utilities ----------
def tpkt(data: bytes) -> bytes:
    # TPKT: version=3, reserved=0, length=4+len(data)
    return bytes([0x03,0x00]) + struct.pack(">H", 4+len(data)) + data

def cotp_cc() -> bytes:
    # Minimal COTP CC (Connection Confirm) in response to CR
    # Variable part may vary; this CC is commonly accepted by analyzers.
    # PDU type 0xD0, length 11, dst-ref=0x0000, src-ref=0x0000, class=0x00
    # + TPDU size parameter (0xC0 0x01 0x0A)
    return tpkt(bytes([
        0xD0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x01, 0x0A
    ]))

def s7_ack():
    # Minimal S7comm "Setup Communication" ack (not complete emu, enough for Zeek)
    # S7 header starts with 0x32
    s7 = bytes([
        0x03,0x00,0x00,0x1B,     # (will be overwritten by tpkt) placeholder
    ])
    # We'll craft a simple PDU: COTP DT (0xF0 ...), then S7 header 0x32 (ack)
    cotp = bytes([0xF0, 0x00])  # Data TPDU
    s7h = bytes([
        0x32, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,  # header-ish
    ])
    return tpkt(cotp + s7h)

def enip_build_register_session_reply(session_handle=0x12345678, status=0, options=0):
    # EtherNet/IP Encapsulation Header: 24 bytes
    # Command=0x0065 (RegisterSession), Length=4, SessionHandle, Status, SenderContext(8), Options
    cmd = 0x0065
    length = 4
    sender_context = b'\x00'*8
    header = struct.pack("<HHI I 8s I", cmd, length, session_handle, status, sender_context, options)
    # Protocol version=1, options flags=0
    body = struct.pack("<HH", 1, 0)
    return header + body

def c37_frame():  # very small valid-ish TCP header+frame
    # IEEE C37.118 TCP frames often begin with 0xAA 0x41 (SYNC), then frame type, size
    # Build a minimal command frame (type 0x01) with length 0x0014
    sync = b'\xAA\x41'
    frame_type = b'\x01'    # command
    ver = b'\x02'           # version
    length = struct.pack(">H", 0x0014)
    soc = b'\x00\x00\x00\x00'  # SOC placeholder
    fracsec = b'\x00\x00\x00\x00'
    idcode = struct.pack(">H", 1)
    # no payload
    return sync + frame_type + ver + length + soc + fracsec + idcode

def c1222_minimal():
    # ANSI C12.22 uses ACSE-like envelope; we'll emit a minimal "hello" (not a full association)
    # Enough for Zeek to classify based on header/port.
    return b"\x60\x1A\xA1\x09\x06\x07\x60\x85\x74\x05\x08\x01\x01\xA2\x0D\x04\x0B\x43\x31\x32\x2E\x32\x32\x20\x48\x45\x4C\x4C\x4F"
