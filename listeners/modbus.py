
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
                
                # Enhanced function code validation - Full ICSNPP compliance
                if func not in [1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 20, 21, 22, 23, 24, 43]:
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
                # Function 7 - Read Exception Status (ICSNPP compliant)
                elif func == 7:
                    # Returns device exception status (8 bits)
                    exception_status = 0x00  # No exceptions
                    resp = ok(bytes([exception_status]))
                # Function 8 - Diagnostics (ICSNPP compliant)
                elif func == 8:
                    if len(pdu) < 5:
                        resp = exc(3)
                    else:
                        subfunc, data = struct.unpack(">HH", pdu[1:5])
                        # Echo diagnostics data back
                        resp = ok(struct.pack(">HH", subfunc, data))
                # Function 17 - Report Slave ID (ICSNPP compliant)
                elif func == 17:
                    # Device identification response
                    device_id = b"PyModbus Simulator v1.0"
                    run_indicator = 0xFF  # Running
                    resp = ok(bytes([len(device_id), run_indicator]) + device_id)
                # Function 20 - Read File Record (ICSNPP compliant)
                elif func == 20:
                    if len(pdu) < 2:
                        resp = exc(3)
                    else:
                        # Simple file record response
                        resp = ok(b"\x05\x06\x0D\xFE\x00\x20")  # Dummy file data
                # Function 21 - Write File Record (ICSNPP compliant)
                elif func == 21:
                    if len(pdu) < 10:
                        resp = exc(3)
                    else:
                        # Echo back the request data
                        resp = ok(pdu[1:])
                # Function 22 - Mask Write Register (ICSNPP compliant)
                elif func == 22:
                    if len(pdu) < 7:
                        resp = exc(3)
                    else:
                        addr, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
                        if addr >= 20000:
                            resp = exc(2)
                        else:
                            # Apply mask operation
                            current_val = self.holding_registers[addr]
                            new_val = (current_val & and_mask) | (or_mask & ~and_mask)
                            self.holding_registers[addr] = new_val & 0xFFFF
                            resp = ok(struct.pack(">HHH", addr, and_mask, or_mask))
                # Function 23 - Read/Write Multiple Registers (ICSNPP compliant)
                elif func == 23:
                    if len(pdu) < 10:
                        resp = exc(3)
                    else:
                        read_addr, read_qty, write_addr, write_qty, write_bc = struct.unpack(">HHHHB", pdu[1:10])
                        if (read_addr + read_qty > 20000 or write_addr + write_qty > 20000 or 
                            write_qty < 1 or read_qty < 1 or len(pdu) != 10 + write_bc):
                            resp = exc(3)
                        else:
                            # Write registers first
                            write_data = pdu[10:10+write_bc]
                            for i in range(write_qty):
                                if i*2+1 < len(write_data):
                                    val = struct.unpack(">H", write_data[i*2:i*2+2])[0]
                                    self.holding_registers[write_addr + i] = val
                            # Then read registers
                            read_data = self._read_regs(self.holding_registers, read_addr, read_qty)
                            resp = ok(bytes([len(read_data)]) + read_data)
                # Function 24 - Read FIFO Queue (ICSNPP compliant)
                elif func == 24:
                    if len(pdu) < 3:
                        resp = exc(3)
                    else:
                        fifo_addr = struct.unpack(">H", pdu[1:3])[0]
                        if fifo_addr >= 20000:
                            resp = exc(2)
                        else:
                            # Simulate FIFO queue with dummy data
                            fifo_data = struct.pack(">HHHH", 4, 0x1234, 0x5678, 0x9ABC)  # Count + data
                            resp = ok(struct.pack(">H", len(fifo_data)//2) + fifo_data)
                # Function 43 - Encapsulated Interface Transport (ICSNPP compliant)
                elif func == 43:
                    if len(pdu) < 4:
                        resp = exc(3)
                    else:
                        mei_type = pdu[1]
                        if mei_type == 0x0E:  # Read Device Identification
                            device_id_code = pdu[2] if len(pdu) > 2 else 0x01
                            object_id = pdu[3] if len(pdu) > 3 else 0x00
                            # Basic device identification response
                            resp_data = bytes([0x0E, 0x01, 0x00, 0x00, 0x01, 0x00])  # MEI type + conformity + more follows + next object + num objects + object id
                            resp_data += bytes([0x07]) + b"PyModbus"  # Vendor name
                            resp = ok(resp_data)
                        else:
                            resp = exc(1)  # Function not supported
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
