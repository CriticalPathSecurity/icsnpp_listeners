
import asyncio
import logging

logger = logging.getLogger('C1222')

class C1222TCP:
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
                
                # Enhanced C12.22 frame validation
                if len(data) >= 2:
                    if data[0] == 0x60:  # ACSE APPLICATION tag
                        logger.debug(f"C12.22 ACSE frame from {client_addr}")
                    elif data[0:2] == b'\xEE\x00':  # Alternative C12.22 header
                        logger.debug(f"C12.22 alternate frame from {client_addr}")
                    else:
                        logger.debug(f"Unknown C12.22 frame from {client_addr}: {data[:4].hex()}")
                
                response = b"\x60\x1A"  # Standard C12.22 response
                writer.write(response)
                await writer.drain()
                logger.debug(f"Sent C12.22 response to {client_addr}")
                
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

class C1222UDP(asyncio.DatagramProtocol):
    def __init__(self):
        # Statistics
        self.total_packets = 0
        self.valid_c1222_packets = 0
        
    def datagram_received(self, data, addr):
        self.total_packets += 1
        logger.debug(f"UDP packet from {addr}, {len(data)} bytes")
        
        # Enhanced C12.22 UDP validation
        if len(data) >= 2:
            if data[0] == 0x60:  # ACSE APPLICATION tag
                self.valid_c1222_packets += 1
                logger.debug(f"C12.22 ACSE UDP frame from {addr}")
            elif data[0:2] == b'\xEE\x00':
                self.valid_c1222_packets += 1
                logger.debug(f"C12.22 alternate UDP frame from {addr}")
            else:
                logger.debug(f"Unknown C12.22 UDP frame from {addr}: {data[:4].hex()}")
        
        try:
            response = b"\x60\x1A"
            self.transport.sendto(response, addr)
            logger.debug(f"Sent C12.22 UDP response to {addr}")
        except Exception as e:
            logger.error(f"Error sending UDP response to {addr}: {e}")
            
    def connection_made(self, transport): 
        self.transport = transport
        logger.debug("C12.22 UDP handler started")
        
    def error_received(self, exc):
        logger.error(f"C12.22 UDP error: {exc}")
