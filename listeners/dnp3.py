
import asyncio, struct
import logging

logger = logging.getLogger('DNP3')

class DNP3Server:
    def __init__(self):
        # Configuration
        self.max_requests_per_connection = 500
        self.connection_timeout = 300  # 5 minutes
        self.read_timeout = 10  # 10 seconds per request
        
        # Statistics
        self.total_connections = 0
        self.active_connections = 0

DNP3_CRC_TABLE = [
    0x0000,0x365E,0x6CBC,0x5AE2,0xD978,0xEF26,0xB5C4,0x839A,0xFF89,0xC9D7,0x9335,0xA56B,0x26F1,0x10AF,0x4A4D,0x7C13,
    0xB26B,0x8435,0xDED7,0xE889,0x6B13,0x5D4D,0x07AF,0x31F1,0x4DE2,0x7BBC,0x215E,0x1700,0x949A,0xA2C4,0xF826,0xCE78,
    0x29AF,0x1FF1,0x4513,0x734D,0xF0D7,0xC689,0x9C6B,0xAA35,0xD626,0xE078,0xBA9A,0x8CC4,0x0F5E,0x3900,0x63E2,0x55BC,
    0x9BC4,0xAD9A,0xF778,0xC126,0x42BC,0x74E2,0x2E00,0x185E,0x644D,0x5213,0x08F1,0x3EAF,0xBD35,0x8B6B,0xD189,0xE7D7,
    0x535E,0x6500,0x3FE2,0x09BC,0x8A26,0xBC78,0xE69A,0xD0C4,0xACD7,0x9A89,0xC06B,0xF635,0x75AF,0x43F1,0x1913,0x2F4D,
    0xE135,0xD76B,0x8D89,0xBBD7,0x384D,0x0E13,0x54F1,0x62AF,0x1EBC,0x28E2,0x7200,0x445E,0xC7C4,0xF19A,0xAB78,0x9D26,
    0x7AF1,0x4CAF,0x164D,0x2013,0xA389,0x95D7,0xCF35,0xF96B,0x8578,0xB326,0xE9C4,0xDF9A,0x5C00,0x6A5E,0x30BC,0x06E2,
    0xC89A,0xFEC4,0xA426,0x9278,0x11E2,0x27BC,0x7D5E,0x4B00,0x3713,0x014D,0x5BAF,0x6DF1,0xEE6B,0xD835,0x82D7,0xB489,
    0xA6BC,0x90E2,0xCA00,0xFC5E,0x7FC4,0x499A,0x1378,0x2526,0x5935,0x6F6B,0x3589,0x03D7,0x804D,0xB613,0xECF1,0xDAAF,
    0x14D7,0x2289,0x786B,0x4E35,0xCDAF,0xFBF1,0xA113,0x974D,0xEB5E,0xDD00,0x87E2,0xB1BC,0x3226,0x0478,0x5E9A,0x68C4,
    0x8F13,0xB94D,0xE3AF,0xD5F1,0x566B,0x6035,0x3AD7,0x0C89,0x709A,0x46C4,0x1C26,0x2A78,0xA9E2,0x9FBC,0xC55E,0xF300,
    0x3D78,0x0B26,0x51C4,0x679A,0xE400,0xD25E,0x88BC,0xBEE2,0xC2F1,0xF4AF,0xAE4D,0x9813,0x1B89,0x2DD7,0x7735,0x416B,
    0xF5E2,0xC3BC,0x995E,0xAF00,0x2C9A,0x1AC4,0x4026,0x7678,0x0A6B,0x3C35,0x66D7,0x5089,0xD313,0xE54D,0xBFAF,0x89F1,
    0x4789,0x71D7,0x2B35,0x1D6B,0x9EF1,0xA8AF,0xF24D,0xC413,0xB800,0x8E5E,0xD4BC,0xE2E2,0x6178,0x5726,0x0DC4,0x3B9A,
    0xDC4D,0xEA13,0xB0F1,0x86AF,0x0535,0x336B,0x6989,0x5FD7,0x23C4,0x159A,0x4F78,0x7926,0xFABC,0xCCE2,0x9600,0xA05E,
    0x6E26,0x5878,0x029A,0x34C4,0xB75E,0x8100,0xDBE2,0xEDBC,0x91AF,0xA7F1,0xFD13,0xCB4D,0x48D7,0x7E89,0x246B,0x1235,
]
def dnp3_crc(b: bytes) -> int:
    crc = 0xFFFF
    for x in b:
        idx = (crc ^ x) & 0xFF
        crc = (crc >> 8) ^ DNP3_CRC_TABLE[idx]
    return crc & 0xFFFF

def add_crc_blocks(payload: bytes, first=8, subsequent=16) -> bytes:
    out = bytearray(); i=0; blk=first; firstflag=True
    while i<len(payload):
        chunk = payload[i:i+blk]; out += chunk
        crc = dnp3_crc(chunk); out += struct.pack("<H", crc)
        i += len(chunk)
        if firstflag: firstflag=False; blk=subsequent
    return bytes(out)

# ICSNPP-compliant DNP3 response builders
def build_ack():
    """Build basic DNP3 acknowledgment"""
    header = struct.pack("<BBBBHH", 0x05, 0x64, 5, 0x00, 1, 1024)
    app_layer = struct.pack("<BB", 0xC0, 0x81)  # Application response
    return add_crc_blocks(header + app_layer)

def build_response(dest, src, app_control):
    """Build generic DNP3 response"""
    header = struct.pack("<BBBBHH", 0x05, 0x64, 5, 0x00, dest, src)
    app_layer = struct.pack("<BB", app_control & 0x0F | 0x80, 0x81)  # Response
    return add_crc_blocks(header + app_layer)

def build_read_response(dest, src, app_control):
    """Build DNP3 read response with objects (ICSNPP compliant)"""
    header = struct.pack("<BBBBHH", 0x05, 0x64, 5, 0x00, dest, src)
    app_layer = struct.pack("<BB", app_control & 0x0F | 0x80, 0x81)  # Response
    
    # Add Binary Input objects (Group 1, Variation 2) - ICSNPP standard
    objects = struct.pack("<BBBBB", 0x01, 0x02, 0x00, 0x00, 0x07)  # Group 1, Var 2, range 0-7
    objects += b"\x81"  # Binary input states (flags + bit pattern)
    
    # Add Analog Input objects (Group 30, Variation 1) - ICSNPP standard  
    objects += struct.pack("<BBBBB", 0x1E, 0x01, 0x00, 0x00, 0x03)  # Group 30, Var 1, range 0-3
    objects += struct.pack("<IIII", 0x8100, 0x8200, 0x8300, 0x8400)  # Analog values with flags
    
    return add_crc_blocks(header + app_layer + objects)

def build_control_response(dest, src, app_control, operation):
    """Build DNP3 control response (ICSNPP compliant)"""
    header = struct.pack("<BBBBHH", 0x05, 0x64, 5, 0x00, dest, src)
    app_layer = struct.pack("<BB", app_control & 0x0F | 0x80, 0x81)  # Response
    
    # Add Control Relay Output Block response (Group 12, Variation 1) - ICSNPP standard
    objects = struct.pack("<BBBBB", 0x0C, 0x01, 0x00, 0x00, 0x00)  # Group 12, Var 1, index 0
    
    # CROB response with status
    if operation == "SELECT":
        status = 0x00  # Success
    elif operation in ["OPERATE", "DIRECT_OPERATE"]:
        status = 0x00  # Success
    else:
        status = 0x04  # Not supported
        
    crob_response = struct.pack("<BBHHLB", 0x41, 0x01, 100, 100, 0, status)  # Control code, count, on/off time, status
    
    return add_crc_blocks(header + app_layer + objects + crob_response)

def build_legacy_ack(dest=1,src=100):
    """Legacy ACK builder for backward compatibility"""
    hdr = bytes([0x05,0x64,0x05,0x80]) + struct.pack("<H", dest) + struct.pack("<H", src)
    framed = hdr[:2] + add_crc_blocks(hdr[2:], first=8, subsequent=16)
    return framed

class DNP3Server:
    def __init__(self):
        # Configuration
        self.max_requests_per_connection = 500
        self.connection_timeout = 300  # 5 minutes
        self.read_timeout = 10  # 10 seconds per request
        
        # Statistics
        self.total_connections = 0
        self.active_connections = 0

    async def handle(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr}")
        
        self.total_connections += 1
        self.active_connections += 1
        request_count = 0
        start_time = asyncio.get_event_loop().time()
        
        try:
            while True:
                # Check connection timeout
                if asyncio.get_event_loop().time() - start_time > self.connection_timeout:
                    logger.info(f"Connection timeout for {client_addr}")
                    break
                
                # Check request limit
                if request_count >= self.max_requests_per_connection:
                    logger.warning(f"Request limit exceeded for {client_addr}")
                    break
                
                try:
                    data = await asyncio.wait_for(
                        reader.read(1024), 
                        timeout=self.read_timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug(f"Read timeout from {client_addr}")
                    break
                
                if not data:
                    logger.debug(f"Client {client_addr} disconnected")
                    break
                
                request_count += 1
                logger.debug(f"Request {request_count} from {client_addr}: {len(data)} bytes")
                
                # Enhanced DNP3 frame validation and object handling (ICSNPP compliant)
                if len(data) >= 10:  # Minimum DNP3 frame with application layer
                    if data[0] == 0x05 and data[1] == 0x64:  # DNP3 sync bytes
                        logger.debug(f"Valid DNP3 frame from {client_addr}")
                        
                        # Parse DNP3 header for ICSNPP compliance
                        length = data[2]
                        control = data[3]
                        dest = struct.unpack("<H", data[4:6])[0]
                        src = struct.unpack("<H", data[6:8])[0]
                        
                        # Parse application layer if present
                        if len(data) > 10:
                            app_control = data[10] if len(data) > 10 else 0
                            func_code = data[11] if len(data) > 11 else 0
                            
                            logger.debug(f"DNP3 App Layer: Control=0x{app_control:02x}, Function=0x{func_code:02x}")
                            
                            # Handle specific function codes for ICSNPP compliance
                            if func_code == 0x01:  # READ
                                response = build_read_response(dest, src, app_control)
                            elif func_code == 0x03:  # SELECT
                                response = build_control_response(dest, src, app_control, "SELECT")
                            elif func_code == 0x04:  # OPERATE
                                response = build_control_response(dest, src, app_control, "OPERATE")
                            elif func_code == 0x05:  # DIRECT_OPERATE
                                response = build_control_response(dest, src, app_control, "DIRECT_OPERATE")
                            else:
                                response = build_response(dest, src, app_control)
                        else:
                            response = build_ack()
                    else:
                        logger.debug(f"Invalid DNP3 sync bytes from {client_addr}: {data[:2].hex()}")
                        response = build_ack()
                else:
                    logger.debug(f"DNP3 frame too short from {client_addr}: {len(data)} bytes")
                    response = build_ack()
                writer.write(response)
                await writer.drain()
                
        except asyncio.IncompleteReadError:
            logger.info(f"Connection from {client_addr} closed (incomplete read)")
        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            self.active_connections -= 1
            logger.info(f"Closing connection from {client_addr}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
