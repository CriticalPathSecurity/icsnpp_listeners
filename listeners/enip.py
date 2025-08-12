import asyncio, struct
import logging

logger = logging.getLogger('ENIP')

class ENIPServer:
    def __init__(self):
        self.sessions = {}
        self.session_counter = 1
        
        # Configuration
        self.max_requests_per_connection = 1000
        self.connection_timeout = 300  # 5 minutes
        self.read_timeout = 10  # 10 seconds per request
        
        # Statistics
        self.total_connections = 0
        self.active_connections = 0

    def _get_next_session_handle(self):
        handle = self.session_counter
        self.session_counter += 1
        return handle

    def _build_register_session_response(self, session_handle):
        """Build ICSNPP-compliant RegisterSession response"""
        header = struct.pack("<HHIIII", 
            0x0065,  # RegisterSession command
            4,       # Length
            session_handle,  # Session handle
            0,       # Status (success)
            0, 0     # Context
        )
        # Protocol version and options
        payload = struct.pack("<HH", 1, 0)  # Version 1, no options
        return header + payload

    def _build_unregister_session_response(self):
        """Build ICSNPP-compliant UnRegisterSession response"""
        return struct.pack("<HHIIII", 
            0x0066,  # UnRegisterSession command
            0,       # Length
            0,       # Session handle
            0,       # Status (success)
            0, 0     # Context
        )

    def _build_list_services_response(self):
        """Build ICSNPP-compliant ListServices response"""
        header = struct.pack("<HHIIII", 
            0x0063,  # ListServices command
            20,      # Length
            0,       # Session handle
            0,       # Status (success)
            0, 0     # Context
        )
        # Service list - Communications service
        service = struct.pack("<HHBBBBBBBBBBBBBB",
            0x0100,  # Type code (Communications)
            16,      # Length
            1,       # Version
            0x20,    # Capability flags
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  # Service name "Communications"
        )
        return header + struct.pack("<H", 1) + service  # Item count + service

    def _build_list_identity_response(self):
        """Build ICSNPP-compliant ListIdentity response"""
        header = struct.pack("<HHIIII", 
            0x0064,  # ListIdentity command
            63,      # Length
            0,       # Session handle
            0,       # Status (success)
            0, 0     # Context
        )
        # Identity object
        identity = struct.pack("<HHHHBBBBHHHH",
            0x000C,  # Type code (ListIdentity)
            55,      # Length
            1,       # Encapsulation version
            0,       # Socket address (sin_family)
            0,       # Socket address (sin_port)
            0,       # Socket address (sin_addr)
            0,       # Socket address (padding)
            0,       # Socket address (padding)
            1,       # Vendor ID
            1,       # Device type
            1,       # Product code
            1,       # Revision
            0,       # Status
            0x1234,  # Serial number
            14       # Product name length
        )
        product_name = b"ICSNPP Trainer"
        state = 0x03  # Configured state
        
        return header + struct.pack("<H", 1) + identity + product_name + struct.pack("<B", state)

    def _build_rrdata_response(self, request_data, session_handle):
        """Build ICSNPP-compliant SendRRData response with CIP objects"""
        header = struct.pack("<HHIIII", 
            0x006F,  # SendRRData command
            16,      # Length (will be updated)
            session_handle,
            0,       # Status (success)
            0, 0     # Context
        )
        
        # Parse CIP request if present in data
        if len(request_data) > 40:  # Has CIP data
            # CIP response for common objects
            cip_response = self._build_cip_response(request_data[40:])
        else:
            cip_response = b"\x00\x00\x00\x00"  # Simple success
            
        # Interface handle and timeout
        interface_data = struct.pack("<II", 0, 0)
        
        # Update length
        total_length = len(interface_data) + len(cip_response)
        header = struct.pack("<HHIIII", 
            0x006F, total_length, session_handle, 0, 0, 0
        )
        
        return header + interface_data + cip_response

    def _build_cip_response(self, cip_data):
        """Build CIP response for ICSNPP compliance"""
        if len(cip_data) < 4:
            return b"\x00\x00\x00\x00"
            
        # Parse CIP service and class
        service = cip_data[0] if len(cip_data) > 0 else 0
        path_size = cip_data[1] if len(cip_data) > 1 else 0
        
        # Common CIP objects for ICSNPP training
        if service == 0x01:  # Get_Attribute_Single
            return self._build_get_attribute_response(cip_data)
        elif service == 0x10:  # Set_Attribute_Single
            return self._build_set_attribute_response()
        elif service == 0x4C:  # Get_Attribute_List
            return self._build_get_attribute_list_response()
        else:
            # Generic success response
            return struct.pack("<BBH", service | 0x80, 0x00, 0x00)

    def _build_get_attribute_response(self, cip_data):
        """Build Get_Attribute_Single response"""
        # Identity Object (Class 0x01) - ICSNPP standard
        response = struct.pack("<BBH", 0x81, 0x00, 0x00)  # Service response + success
        # Common attributes
        response += struct.pack("<HHHHHH", 1, 1, 1, 1, 0x1234, 14)  # Vendor, device type, etc.
        response += b"ICSNPP Trainer"
        return response

    def _build_set_attribute_response(self):
        """Build Set_Attribute_Single response"""
        return struct.pack("<BBH", 0x90, 0x00, 0x00)  # Service response + success

    def _build_get_attribute_list_response(self):
        """Build Get_Attribute_List response"""
        response = struct.pack("<BBH", 0xCC, 0x00, 0x00)  # Service response + success
        # Attribute list for Identity Object
        response += struct.pack("<H", 7)  # Number of attributes
        response += struct.pack("<HHHHHHH", 1, 1, 1, 1, 0x1234, 14, 3)  # Common attributes
        return response

    def _build_unitdata_response(self, request_data, session_handle):
        """Build ICSNPP-compliant SendUnitData response"""
        header = struct.pack("<HHIIII", 
            0x0070,  # SendUnitData command
            8,       # Length
            session_handle,
            0,       # Status (success)
            0, 0     # Context
        )
        # Interface handle and timeout
        interface_data = struct.pack("<II", 0, 0)
        return header + interface_data

    def _build_error_response(self, command, error_code):
        """Build ICSNPP-compliant error response"""
        return struct.pack("<HHIIII", 
            command,    # Echo command
            0,          # Length
            0,          # Session handle
            error_code, # Error status
            0, 0        # Context
        )

    async def handle(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New EtherNet/IP connection from {client_addr}")
        
        self.total_connections += 1
        self.active_connections += 1
        
        session_handle = None
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
                else:
                    logger.debug(f"Invalid EtherNet/IP frame from {client_addr}: {len(data)} bytes")
                    continue
                
                writer.write(response)
                await writer.drain()
                
        except asyncio.IncompleteReadError:
            logger.info(f"Connection from {client_addr} closed (incomplete read)")
        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            self.active_connections -= 1
            if session_handle and session_handle in self.sessions:
                del self.sessions[session_handle]
            logger.info(f"Closing connection from {client_addr}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
