
import asyncio
import logging

logger = logging.getLogger('GENISYS')

# Genisys over TCP/10001 – respond with a fixed, well-formed header-ish payload.
def genisys_minimal():
    # Minimal signature bytes seen by analyzers
    return b"\x00\x01GENISYS\x00\x00"

class GenisysServer:
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
                
                # Enhanced Genisys frame validation
                if len(data) >= 4:
                    if b'GENISYS' in data or data[0:2] in [b'\x00\x01', b'\x01\x00']:
                        logger.debug(f"Potential Genisys frame from {client_addr}")
                    else:
                        logger.debug(f"Unknown frame format from {client_addr}: {data[:8].hex()}")
                
                response = genisys_minimal()
                writer.write(response)
                await writer.drain()
                logger.debug(f"Sent Genisys reply to {client_addr}")
                
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
