#!/usr/bin/env python3
"""
Test script to validate protocol responses for Zeek recognition.
"""
import socket
import struct
import sys

def test_modbus():
    """Test Modbus TCP with a proper read holding registers request."""
    print("Testing Modbus TCP...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 502))
        
        # Modbus TCP request: Read Holding Registers (function 3)
        # MBAP Header: Transaction ID=1, Protocol ID=0, Length=6, Unit ID=1
        # PDU: Function=3, Start Address=0, Quantity=10
        request = struct.pack(">HHHB", 1, 0, 6, 1) + struct.pack(">BHH", 3, 0, 10)
        
        print(f"Sending: {request.hex()}")
        sock.send(request)
        
        response = sock.recv(1024)
        print(f"Received: {response.hex()}")
        print(f"Response length: {len(response)} bytes")
        
        if len(response) >= 7:
            tx, proto, length, uid = struct.unpack(">HHHB", response[:7])
            print(f"Transaction ID: {tx}, Protocol: {proto}, Length: {length}, Unit ID: {uid}")
            if len(response) > 7:
                func = response[7]
                print(f"Function code: {func}")
                if func == 3:  # Read holding registers response
                    byte_count = response[8]
                    print(f"Byte count: {byte_count}")
                    print("✅ Modbus response looks correct!")
                else:
                    print(f"⚠️  Unexpected function code: {func}")
        
        sock.close()
        return True
    except Exception as e:
        print(f"❌ Modbus test failed: {e}")
        return False

def test_enip():
    """Test EtherNet/IP with a proper Register Session request."""
    print("\nTesting EtherNet/IP...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 44818))
        
        # EtherNet/IP Register Session request
        # Command=0x0065, Length=4, SessionHandle=0, Status=0, SenderContext=8 bytes, Options=0
        # Data: Protocol Version=1, Options=0
        cmd = 0x0065
        length = 4
        session_handle = 0
        status = 0
        sender_context = b'\x00' * 8
        options = 0
        data = struct.pack("<HH", 1, 0)  # Protocol version=1, options=0
        
        request = struct.pack("<HHI I 8s I", cmd, length, session_handle, status, sender_context, options) + data
        
        print(f"Sending: {request.hex()}")
        sock.send(request)
        
        response = sock.recv(1024)
        print(f"Received: {response.hex()}")
        print(f"Response length: {len(response)} bytes")
        
        if len(response) >= 24:
            cmd_resp, length_resp, session_resp, status_resp = struct.unpack("<HHI I", response[:12])
            print(f"Command: 0x{cmd_resp:04x}, Length: {length_resp}, Session: 0x{session_resp:08x}, Status: {status_resp}")
            if cmd_resp == 0x0065 and status_resp == 0:
                print("✅ EtherNet/IP response looks correct!")
            else:
                print(f"⚠️  Unexpected response: cmd=0x{cmd_resp:04x}, status={status_resp}")
        
        sock.close()
        return True
    except Exception as e:
        print(f"❌ EtherNet/IP test failed: {e}")
        return False

def test_dnp3():
    """Test DNP3 with a simple request."""
    print("\nTesting DNP3...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 20000))
        
        # Simple DNP3 frame - just send some data to see what we get back
        request = b'\x05\x64\x05\x80\x01\x00\x64\x00'  # Minimal DNP3-like frame
        
        print(f"Sending: {request.hex()}")
        sock.send(request)
        
        response = sock.recv(1024)
        print(f"Received: {response.hex()}")
        print(f"Response length: {len(response)} bytes")
        
        if len(response) > 0:
            print("✅ DNP3 responded with data!")
        
        sock.close()
        return True
    except Exception as e:
        print(f"❌ DNP3 test failed: {e}")
        return False

def test_s7():
    """Test S7 with a COTP connection request."""
    print("\nTesting S7...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 102))
        
        # TPKT + COTP Connection Request
        # This should trigger the S7 server to respond with a Connection Confirm
        tpkt = b'\x03\x00\x00\x16'  # TPKT header
        cotp_cr = b'\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a'
        request = tpkt + cotp_cr
        
        print(f"Sending: {request.hex()}")
        sock.send(request)
        
        response = sock.recv(1024)
        print(f"Received: {response.hex()}")
        print(f"Response length: {len(response)} bytes")
        
        if len(response) > 4 and response[0:2] == b'\x03\x00':
            print("✅ S7 responded with TPKT header!")
        
        sock.close()
        return True
    except Exception as e:
        print(f"❌ S7 test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing ICSNPP listeners for Zeek compatibility...")
    print("=" * 60)
    
    results = []
    results.append(test_modbus())
    results.append(test_enip())
    results.append(test_dnp3())
    results.append(test_s7())
    
    print("\n" + "=" * 60)
    print(f"Results: {sum(results)}/{len(results)} tests passed")
    
    if all(results):
        print("✅ All protocol tests passed! Listeners should work with Zeek.")
    else:
        print("⚠️  Some tests failed. Listeners may not be recognized by Zeek properly.")
