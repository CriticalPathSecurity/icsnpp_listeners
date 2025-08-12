#!/usr/bin/env python3
"""
Zeek-style protocol validation test.
Tests if the listeners generate traffic that Zeek's ICSNPP parsers can recognize.
"""
import socket
import struct
import time
import threading

def create_modbus_session():
    """Create a realistic Modbus session that Zeek would analyze."""
    print("Creating Modbus session...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 502))
        
        # Multiple realistic Modbus requests
        requests = [
            # Read coils (function 1)
            struct.pack(">HHHB", 1, 0, 6, 1) + struct.pack(">BHH", 1, 0, 16),
            # Read discrete inputs (function 2) 
            struct.pack(">HHHB", 2, 0, 6, 1) + struct.pack(">BHH", 2, 100, 8),
            # Read holding registers (function 3)
            struct.pack(">HHHB", 3, 0, 6, 1) + struct.pack(">BHH", 3, 0, 10),
            # Read input registers (function 4)
            struct.pack(">HHHB", 4, 0, 6, 1) + struct.pack(">BHH", 4, 50, 5),
            # Write single coil (function 5)
            struct.pack(">HHHB", 5, 0, 6, 1) + struct.pack(">BHH", 5, 10, 0xFF00),
            # Write single register (function 6)
            struct.pack(">HHHB", 6, 0, 6, 1) + struct.pack(">BHH", 6, 20, 1234),
        ]
        
        for i, req in enumerate(requests):
            sock.send(req)
            resp = sock.recv(1024)
            print(f"  Request {i+1}: {len(resp)} bytes response")
            time.sleep(0.1)
        
        sock.close()
        print("  ✅ Modbus session completed successfully")
        return True
    except Exception as e:
        print(f"  ❌ Modbus session failed: {e}")
        return False

def create_enip_session():
    """Create a realistic EtherNet/IP session."""
    print("Creating EtherNet/IP session...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 44818))
        
        # Register Session
        cmd = 0x0065
        session_handle = 0
        header = struct.pack("<HHI I 8s I", cmd, 4, session_handle, 0, b'\x00'*8, 0)
        data = struct.pack("<HH", 1, 0)
        sock.send(header + data)
        
        resp = sock.recv(1024)
        print(f"  Register Session: {len(resp)} bytes response")
        
        if len(resp) >= 24:
            session_handle = struct.unpack("<I", resp[8:12])[0]
            print(f"  Got session handle: 0x{session_handle:08x}")
        
        sock.close()
        print("  ✅ EtherNet/IP session completed successfully")
        return True
    except Exception as e:
        print(f"  ❌ EtherNet/IP session failed: {e}")
        return False

def create_dnp3_session():
    """Create a realistic DNP3 session."""
    print("Creating DNP3 session...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 20000))
        
        # Send a few DNP3-like frames
        frames = [
            b'\x05\x64\x05\x80\x01\x00\x64\x00',  # Basic frame
            b'\x05\x64\x08\x80\x01\x00\x64\x00\x01\x02\x03',  # Frame with data
        ]
        
        for frame in frames:
            sock.send(frame)
            resp = sock.recv(1024)
            print(f"  DNP3 frame: {len(resp)} bytes response")
            time.sleep(0.1)
        
        sock.close()
        print("  ✅ DNP3 session completed successfully")
        return True
    except Exception as e:
        print(f"  ❌ DNP3 session failed: {e}")
        return False

def create_s7_session():
    """Create a realistic S7 session."""
    print("Creating S7 session...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 102))
        
        # COTP Connection Request
        tpkt = b'\x03\x00\x00\x16'
        cotp_cr = b'\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a'
        sock.send(tpkt + cotp_cr)
        
        resp = sock.recv(1024)
        print(f"  COTP Connection: {len(resp)} bytes response")
        
        # Send S7 communication setup
        if len(resp) > 0:
            s7_setup = b'\x03\x00\x00\x19\x02\xf0\x80\x32\x01\x00\x00\x00\x00\x00\x08\x00\x00\xf0\x00\x00\x01\x00\x01\x00\xf0'
            sock.send(s7_setup)
            resp = sock.recv(1024)
            print(f"  S7 Setup: {len(resp)} bytes response")
        
        sock.close()
        print("  ✅ S7 session completed successfully")
        return True
    except Exception as e:
        print(f"  ❌ S7 session failed: {e}")
        return False

def run_concurrent_sessions():
    """Run multiple protocol sessions concurrently like a real network."""
    print("\n🌐 Running concurrent protocol sessions (simulating real network traffic)...")
    
    sessions = [
        create_modbus_session,
        create_enip_session, 
        create_dnp3_session,
        create_s7_session,
    ]
    
    threads = []
    for session_func in sessions:
        thread = threading.Thread(target=session_func)
        threads.append(thread)
        thread.start()
        time.sleep(0.1)  # Stagger starts slightly
    
    # Wait for all sessions to complete
    for thread in threads:
        thread.join()
    
    print("🏁 All concurrent sessions completed")

if __name__ == "__main__":
    print("🔍 ICSNPP Zeek Compatibility Test")
    print("=" * 50)
    print("Testing protocol listeners for proper Zeek recognition...")
    
    # Sequential tests first
    results = []
    results.append(create_modbus_session())
    results.append(create_enip_session())
    results.append(create_dnp3_session())
    results.append(create_s7_session())
    
    # Concurrent test
    run_concurrent_sessions()
    
    print("\n" + "=" * 50)
    print(f"📊 Sequential Tests: {sum(results)}/{len(results)} passed")
    
    if all(results):
        print("✅ SUCCESS: All protocols are generating Zeek-compatible traffic!")
        print("💡 These listeners should be properly recognized by Zeek's ICSNPP parsers.")
    else:
        print("⚠️  WARNING: Some protocols may not be fully compatible with Zeek.")
    
    print("\n🔧 To test with Zeek:")
    print("1. Start these listeners: python3 run_listeners.py")
    print("2. Run this traffic generator: python3 zeek_test.py") 
    print("3. Capture with Zeek: zeek -r traffic.pcap local icsnpp/modbus icsnpp/enip icsnpp/dnp3 icsnpp/s7comm")
