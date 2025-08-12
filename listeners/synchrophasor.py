
import asyncio
import logging
from .common import c37_frame

logger = logging.getLogger('SYNCHRO')

class SynchrophasorTCP:
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
                        reader.read(256), 
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
                
                # Enhanced C37.118 frame validation
                if len(data) >= 4:
                    if data[0:2] == b'\xAA\x41':  # C37.118 sync bytes
                        frame_type = data[2] if len(data) > 2 else 0
                        logger.debug(f"C37.118 frame from {client_addr}, type=0x{frame_type:02x}")
                    else:
                        logger.debug(f"Non-C37.118 frame from {client_addr}: {data[:4].hex()}")
                
                response = c37_frame()
                writer.write(response)
                await writer.drain()
                logger.debug(f"Sent C37.118 frame to {client_addr}")
                
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

class SynchrophasorUDP(asyncio.DatagramProtocol):
    def __init__(self):
        # Statistics
        self.total_packets = 0
        self.valid_c37_packets = 0
        
    def datagram_received(self, data, addr):
        self.total_packets += 1
        logger.debug(f"UDP packet from {addr}, {len(data)} bytes")
        
        # Enhanced C37.118 UDP validation
        if len(data) >= 4 and data[0:2] == b'\xAA\x41':
            self.valid_c37_packets += 1
            frame_type = data[2]
            logger.debug(f"C37.118 UDP frame: type=0x{frame_type:02x}")
        else:
            logger.debug(f"Non-C37.118 UDP packet from {addr}: {data[:4].hex() if len(data) >= 4 else data.hex()}")
        
        # Echo a small frame back over UDP
        try:
            response = c37_frame()
            self.transport.sendto(response, addr)
            logger.debug(f"Sent C37.118 UDP response to {addr}")
        except Exception as e:
            logger.error(f"Error sending UDP response to {addr}: {e}")
            
    def connection_made(self, transport): 
        self.transport = transport
        logger.debug("Synchrophasor UDP handler started")
        
    def error_received(self, exc):
        logger.error(f"Synchrophasor UDP error: {exc}")
