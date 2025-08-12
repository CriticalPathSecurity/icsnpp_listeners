
import asyncio, struct
import logging
from .common import enip_build_register_session_reply

logger = logging.getLogger('ENIP')

class ENIPServer:
    def __init__(self):
        # Configuration
        self.max_requests_per_connection = 500
        self.connection_timeout = 300  # 5 minutes
        self.read_timeout = 10  # 10 seconds per request
        
        # Session management
        self.sessions = {}
        self.next_session_handle = 0x12345678
        
        # Statistics
        self.total_connections = 0
        self.active_connections = 0

    def _get_next_session_handle(self):
        """Generate a unique session handle."""
        handle = self.next_session_handle
        self.next_session_handle += 1
        return handle

    async def handle(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr}")
        
        self.total_connections += 1
        self.active_connections += 1
        request_count = 0
        start_time = asyncio.get_event_loop().time()
        session_handle = None
        
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
                
                # Validate minimum EtherNet/IP encapsulation header size (24 bytes)
                if len(data) >= 24:
                    cmd = int.from_bytes(data[0:2], "little")
                    length = int.from_bytes(data[2:4], "little")
                    recv_session = int.from_bytes(data[4:8], "little")
                    status = int.from_bytes(data[8:12], "little")
                    
                    logger.debug(f"EtherNet/IP: cmd=0x{cmd:04x}, len={length}, session=0x{recv_session:08x}, status={status}")
                    
                    # Enhanced command handling for ICSNPP compliance
                    if cmd == 0x0065:  # RegisterSession
                        if session_handle is None:
                            session_handle = self._get_next_session_handle()
                            self.sessions[session_handle] = {
                                'client_addr': client_addr,
                                'created_at': asyncio.get_event_loop().time(),
                                'commands_processed': 0
                            }
                            logger.info(f"Registered session 0x{session_handle:08x} for {client_addr}")
                        response = self._build_register_session_response(session_handle)
                    elif cmd == 0x0066:  # UnRegisterSession
                        if session_handle and session_handle in self.sessions:
                            del self.sessions[session_handle]
                            logger.info(f"Unregistered session 0x{session_handle:08x} for {client_addr}")
                        response = self._build_unregister_session_response()
                    elif cmd == 0x006F:  # SendRRData (ICSNPP compliant)
                        if session_handle and session_handle in self.sessions:
                            self.sessions[session_handle]['commands_processed'] += 1
                            response = self._build_rrdata_response(data, session_handle)
                        else:
                            response = self._build_error_response(cmd, 0x0001)  # Invalid session
                    elif cmd == 0x0070:  # SendUnitData (ICSNPP compliant)
                        if session_handle and session_handle in self.sessions:
                            response = self._build_unitdata_response(data, session_handle)
                        else:
                            response = self._build_error_response(cmd, 0x0001)  # Invalid session
                    elif cmd == 0x0063:  # ListServices (ICSNPP compliant)
                        response = self._build_list_services_response()
                    elif cmd == 0x0064:  # ListIdentity (ICSNPP compliant)
                        response = self._build_list_identity_response()
                    else:
                        logger.debug(f"Unsupported EtherNet/IP command: 0x{cmd:04x}")
                        response = self._build_error_response(cmd, 0x0001)  # Unsupported command
                                'created': asyncio.get_event_loop().time()
                            }
                            logger.info(f"Created session 0x{session_handle:08x} for {client_addr}")
                        
                        response = enip_build_register_session_reply(session_handle)
                        writer.write(response)
                        await writer.drain()
                        logger.debug(f"Sent RegisterSession reply (session=0x{session_handle:08x}) to {client_addr}")
                        
                    elif cmd == 0x0066:  # UnRegisterSession
                        if session_handle and session_handle in self.sessions:
                            del self.sessions[session_handle]
                            logger.info(f"Closed session 0x{session_handle:08x} for {client_addr}")
                        
                        # Send simple ACK for UnRegisterSession
                        response = struct.pack("<HHI I 8s I", 0x0066, 0, recv_session, 0, b'\x00'*8, 0)
                        writer.write(response)
                        await writer.drain()
                        break
                        
                    else:
                        logger.debug(f"Unhandled EtherNet/IP command 0x{cmd:04x} from {client_addr}")
                        
                else:
                    logger.warning(f"Received packet too small for EtherNet/IP header: {len(data)} bytes from {client_addr}")
                    
        except asyncio.IncompleteReadError:
            logger.info(f"Connection from {client_addr} closed (incomplete read)")
        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            # Clean up session
            if session_handle and session_handle in self.sessions:
                del self.sessions[session_handle]
                logger.debug(f"Cleaned up session 0x{session_handle:08x}")
            
            self.active_connections -= 1
            logger.info(f"Closing connection from {client_addr}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
