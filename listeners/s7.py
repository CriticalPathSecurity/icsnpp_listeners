
import asyncio
import logging
from .common import cotp_cc, s7_ack

logger = logging.getLogger('S7')

class S7Server:
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
        connection_established = False
        
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
                        reader.read(512), 
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
                
                # Handle initial COTP connection request
                if not connection_established and len(data) >= 4:
                    # Check for TPKT header (0x03 0x00)
                    if data[0:2] == b'\x03\x00':
                        logger.debug(f"Received TPKT frame from {client_addr}")
                        # Check for COTP Connection Request (0xe0)
                        if len(data) > 7 and data[5] == 0xe0:
                            logger.debug(f"COTP Connection Request from {client_addr}")
                            writer.write(cotp_cc())
                            await writer.drain()
                            connection_established = True
                            logger.info(f"S7 connection established with {client_addr}")
                            continue
                    
                # Handle subsequent S7 communication
                if connection_established:
                    # Basic S7 frame validation
                    if len(data) >= 10 and data[0:2] == b'\x03\x00':
                        # Look for S7 protocol identifier (0x32)
                        if len(data) > 7 and data[7] == 0x32:
                            logger.debug(f"S7 communication frame from {client_addr}")
                        else:
                            logger.debug(f"Non-S7 TPKT frame from {client_addr}")
                    
                    writer.write(s7_ack())
                    await writer.drain()
                    logger.debug(f"Sent S7 ACK to {client_addr}")
                else:
                    # Send CC for any unrecognized initial frame
                    writer.write(cotp_cc())
                    await writer.drain()
                    connection_established = True
                    logger.debug(f"Sent COTP CC for unrecognized frame from {client_addr}")
                    
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
