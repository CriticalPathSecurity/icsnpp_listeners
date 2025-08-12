
import asyncio, struct
import logging

logger = logging.getLogger('GESRTP')

# Minimal GE SRTP greeting/ack. Not a full SRTP stack; just enough for Zeek to identify traffic.
def make_reply(req: bytes) -> bytes:
    if len(req) < 4:
        return b"SRTP" + b"\x00\x00"
    # very naive echo + OK status
    return req[:4] + b"\x00\x00"

class GESRTPServer:
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
                
                # Enhanced GE SRTP frame validation
                if len(data) >= 4:
                    # Look for potential SRTP signature or protocol identifier
                    if b'SRTP' in data or data[0] in [0x01, 0x02, 0x03]:  # Common SRTP frame types
                        logger.debug(f"Potential GE SRTP frame from {client_addr}")
                    else:
                        logger.debug(f"Unknown frame format from {client_addr}: {data[:8].hex()}")
                
                response = make_reply(data)
                writer.write(response)
                await writer.drain()
                logger.debug(f"Sent GE SRTP reply to {client_addr}")
                
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
