
import asyncio, struct
import logging

logger = logging.getLogger('BACNET')

# Minimal BACnet/IP BVLC Result Success reply to any incoming BVLC frame.
# BVLC: 0x81, Function=0x00 (BVLC-Result), Length=0x000A, Result Code=0x0000
BVLC_RESULT_OK = b"\x81\x00\x00\x0A\x00\x00"

class BACnetServer:
    def __init__(self):
        # Statistics
        self.total_packets = 0
        self.valid_bvlc_packets = 0
        
    async def handle(self, transport, data, addr):
        self.total_packets += 1
        logger.debug(f"UDP packet from {addr}, {len(data)} bytes")
        
        # Enhanced BVLC validation
        if len(data) >= 4 and data[0] == 0x81:
            self.valid_bvlc_packets += 1
            bvlc_func = data[1]
            bvlc_length = struct.unpack(">H", data[2:4])[0]
            
            logger.debug(f"BVLC packet: func=0x{bvlc_func:02x}, length={bvlc_length}")
            
            # Send appropriate response based on function
            if bvlc_func in [0x04, 0x09, 0x0A]:  # Unicast/Broadcast/Original-Unicast NPDU
                transport.sendto(BVLC_RESULT_OK, addr)
                logger.debug(f"Sent BVLC Result OK to {addr}")
            else:
                logger.debug(f"Unhandled BVLC function 0x{bvlc_func:02x} from {addr}")
        else:
            logger.debug(f"Non-BVLC packet from {addr}: {data[:4].hex() if len(data) >= 4 else data.hex()}")

async def run_bacnet(port=47808):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _BACHandler(), local_addr=("0.0.0.0", port))
    logger.info(f"BACnet UDP server listening on port {port}")
    return transport

class _BACHandler(asyncio.DatagramProtocol):
    def __init__(self): 
        self.server = BACnetServer()
        
    def datagram_received(self, data, addr):
        try:
            asyncio.create_task(self.server.handle(self.transport, data, addr))
        except Exception as e:
            logger.error(f"Error handling UDP packet from {addr}: {e}")
            
    def connection_made(self, transport): 
        self.transport = transport
        logger.debug("BACnet UDP handler started")
        
    def error_received(self, exc):
        logger.error(f"BACnet UDP error: {exc}")
