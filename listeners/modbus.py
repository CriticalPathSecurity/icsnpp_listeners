
import asyncio, struct
import logging

# Get logger (don't configure here - let main script handle configuration)
logger = logging.getLogger('MODBUS')

class ModbusServer:
    def __init__(self):
        self.coils = [False]*20000
        self.discrete_inputs = [i%7==0 for i in range(20000)]
        self.holding_registers = [i%65536 for i in range(20000)]
        self.input_registers = [((i*3)+1)%65536 for i in range(20000)]
        
        # Configuration
        self.max_requests_per_connection = 1000
        self.connection_timeout = 300  # 5 minutes
        self.read_timeout = 10  # 10 seconds per request

    def _read_bits(self, arr, addr, qty):
        result = arr[addr:addr+qty]
        out = bytearray((qty+7)//8)
        for idx, bit in enumerate(result):
            if bit: out[idx//8] |= 1<<(idx%8)
        return bytes(out)

    def _read_regs(self, arr, addr, qty):
        return b"".join(struct.pack(">H", v) for v in arr[addr:addr+qty])

    async def handle(self, reader, writer):
        client_addr = writer.get_extra_info('peername')
        logger.info(f"New connection from {client_addr}")
        
        # Set connection timeout
        writer.transport.set_write_buffer_limits(high=65536, low=16384)
        
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
                    # Add read timeout
                    hdr = await asyncio.wait_for(
                        reader.readexactly(7), 
                        timeout=self.read_timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug(f"Read timeout from {client_addr}")
                    break
                except asyncio.IncompleteReadError as e:
                    if e.partial:
                        logger.debug(f"Received partial header from {client_addr}: {e.partial.hex()}")
                    break
                
                request_count += 1
                
                tx, proto, length, uid = struct.unpack(">HHHB", hdr)
                
                # Enhanced validation
                if proto != 0:
                    logger.debug(f"Invalid protocol {proto} from {client_addr}")
                    continue
                    
                if length < 2 or length > 253:  # Modbus ADU max size is 260, MBAP is 7
                    logger.debug(f"Invalid length {length} from {client_addr}")
                    continue
                
                try:
                    pdu = await asyncio.wait_for(
                        reader.readexactly(length-1), 
                        timeout=self.read_timeout
                    )
                except asyncio.TimeoutError:
                    logger.debug(f"PDU read timeout from {client_addr}")
                    break
                except asyncio.IncompleteReadError:
                    logger.debug(f"Incomplete PDU from {client_addr}")
                    break
                    
                if not pdu:
                    logger.debug(f"Empty PDU from {client_addr}")
                    continue
                    
                func = pdu[0]
                logger.debug(f"Request {request_count} from {client_addr}: TX={tx}, Function={func}, UID={uid}")
                
                # Helper functions for responses
                def exc(code): return bytes([func|0x80, code])
                def ok(data):  return bytes([func]) + data
                
                # Basic function code validation
                if func not in [1, 2, 3, 4, 5, 6, 15, 16, 23]:  # Include read/write file record
                    resp = exc(1)  # Illegal function
                    logger.debug(f"Unsupported function code {func} from {client_addr}")
                elif func in (1,2):
                    if len(pdu)<5: resp=exc(3)
                    else:
                        addr,qty = struct.unpack(">HH", pdu[1:5])
                        if qty<1 or addr+qty>20000: resp=exc(3)
                        else:
                            src = self.coils if func==1 else self.discrete_inputs
                            data = self._read_bits(src, addr, qty)
                            resp = ok(bytes([len(data)])+data)
                elif func in (3,4):
                    if len(pdu)<5: resp=exc(3)
                    else:
                        addr,qty = struct.unpack(">HH", pdu[1:5])
                        if qty<1 or qty>125 or addr+qty>20000: resp=exc(3)
                        else:
                            src = self.holding_registers if func==3 else self.input_registers
                            data = self._read_regs(src, addr, qty)
                            resp = ok(bytes([len(data)])+data)
                elif func==5:
                    if len(pdu)<5: resp=exc(3)
                    else:
                        addr,val = struct.unpack(">HH", pdu[1:5])
                        if val not in (0x0000,0xFF00) or addr>=20000: resp=exc(3)
                        else: 
                            # Actually update the coil
                            self.coils[addr] = (val == 0xFF00)
                            resp = ok(struct.pack(">HH", addr, val))
                elif func==6:
                    if len(pdu)<5: resp=exc(3)
                    else:
                        addr,val = struct.unpack(">HH", pdu[1:5])
                        if addr>=20000: resp=exc(3)
                        else: 
                            # Actually update the register
                            self.holding_registers[addr] = val & 0xFFFF
                            resp = ok(struct.pack(">HH", addr, val&0xFFFF))
                elif func==15:
                    if len(pdu)<6: resp=exc(3)
                    else:
                        addr,qty,bc = struct.unpack(">HHB", pdu[1:6])
                        if qty<1 or addr+qty>20000 or len(pdu)!=6+bc: resp=exc(3)
                        else: 
                            # Actually update the coils
                            coil_data = pdu[6:6+bc]
                            for i in range(qty):
                                byte_idx = i // 8
                                bit_idx = i % 8
                                if byte_idx < len(coil_data):
                                    self.coils[addr + i] = bool(coil_data[byte_idx] & (1 << bit_idx))
                            resp = ok(struct.pack(">HH", addr, qty))
                elif func==16:
                    if len(pdu)<6: resp=exc(3)
                    else:
                        addr,qty,bc = struct.unpack(">HHB", pdu[1:6])
                        if qty<1 or qty>123 or addr+qty>20000 or len(pdu)!=6+bc: resp=exc(3)
                        else: 
                            # Actually update the registers
                            reg_data = pdu[6:6+bc]
                            for i in range(qty):
                                if i*2+1 < len(reg_data):
                                    val = struct.unpack(">H", reg_data[i*2:i*2+2])[0]
                                    self.holding_registers[addr + i] = val
                            resp = ok(struct.pack(">HH", addr, qty))
                else:
                    resp=exc(1)
                out = struct.pack(">HHHB", tx, 0, len(resp)+1, uid)+resp
                writer.write(out); await writer.drain()
        except asyncio.IncompleteReadError:
            logger.info(f"Connection from {client_addr} closed (incomplete read)")
        except Exception as e:
            logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            logger.info(f"Closing connection from {client_addr}")
            writer.close(); await writer.wait_closed()
