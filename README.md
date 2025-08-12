# ICSNPP Listeners

A collection of lightweight protocol listeners designed for Zeek ICS network security package (ICSNPP) training and testing.

## Overview

This tool provides minimal protocol implementations for various Industrial Control System (ICS) protocols to generate realistic network traffic that can be analyzed by Zeek's ICSNPP parsers.

## Supported Protocols

| Protocol | Default Port | Type | Description |
|----------|--------------|------|-------------|
| Modbus | 502 | TCP | Modbus TCP protocol with basic function code support |
| DNP3 | 20000 | TCP | Distributed Network Protocol 3 |
| EtherNet/IP | 44818 | TCP | EtherNet/IP (ENIP) protocol |
| S7comm | 102 | TCP | Siemens S7 communication protocol |
| BACnet/IP | 47808 | UDP | Building Automation and Control Networks |
| GE SRTP | 18245 | TCP | General Electric Service Request Transport Protocol |
| Genisys | 10001 | TCP | Genisys protocol |
| IEEE C37.118 | 4712/4713 | TCP/UDP | Synchrophasor protocol |
| ANSI C12.22 | 1153 | TCP/UDP | Smart meter communication protocol |

## Installation

```bash
git clone <repository-url>
cd icsnpp_listeners
pip install -r requirements.txt  # If requirements.txt exists
```

## Usage

### Basic Usage

Start all listeners with default ports:
```bash
python3 run_listeners.py
```

### Custom Configuration

```bash
# Start with custom ports
python3 run_listeners.py --modbus-port 5020 --dnp3-port 20001

# Disable specific protocols
python3 run_listeners.py --disable modbus s7 bacnet

# Enable connection logging
python3 run_listeners.py --log-connections --log-level DEBUG
```

### Command Line Options

```
--modbus-port INT       Modbus TCP port (default: 502)
--dnp3-port INT         DNP3 TCP port (default: 20000)
--enip-port INT         EtherNet/IP TCP port (default: 44818)
--s7-port INT           S7comm TCP port (default: 102)
--bacnet-port INT       BACnet UDP port (default: 47808)
--gesrtp-port INT       GE SRTP TCP port (default: 18245)
--genisys-port INT      Genisys TCP port (default: 10001)
--synchro-tcp-port INT  Synchrophasor TCP port (default: 4712)
--synchro-udp-port INT  Synchrophasor UDP port (default: 4713)
--c1222-port INT        C12.22 TCP/UDP port (default: 1153)

--disable PROTOCOLS     Disable protocols: modbus dnp3 enip s7 bacnet gesrtp genisys synchrotcp synchroudp c1222tcp c1222udp
--log-level LEVEL       Set logging level: DEBUG, INFO, WARNING, ERROR
--log-connections       Log all connection attempts and closures
```

## Protocol Implementation Details

### Modbus TCP
- Supports function codes: 1, 2, 3, 4, 5, 6, 15, 16
- Simulates 20,000 coils, discrete inputs, holding registers, and input registers
- Proper MBAP header validation and CRC handling
- Exception responses for invalid requests

### DNP3
- Minimal DNP3 frame structure with CRC calculation
- Responds with ACK frames to any incoming data
- Proper DNP3 header format with source/destination addressing

### EtherNet/IP
- Handles RegisterSession commands (0x0065)
- Returns proper encapsulation header responses
- Session management for EtherNet/IP communication

### Other Protocols
- Minimal implementations designed to trigger Zeek protocol detection
- Return protocol-specific headers and acknowledgments
- Sufficient for training Zeek parsers and analyzing network traffic

## Security Considerations

⚠️ **Warning**: These listeners are designed for training and testing purposes only. They should not be used in production environments or exposed to untrusted networks.

- No authentication or authorization mechanisms
- Minimal input validation
- Designed for controlled lab environments only
- May be vulnerable to denial-of-service attacks

## Testing with Zeek

1. Start the listeners:
   ```bash
   python3 run_listeners.py --log-connections
   ```

2. Generate traffic using ICS client tools or scripts

3. Monitor with Zeek:
   ```bash
   zeek -i interface local "icsnpp/*"
   ```

## Development

### Adding New Protocols

1. Create a new handler in `listeners/` directory
2. Inherit from `BaseProtocolHandler` or `BaseUDPHandler`
3. Implement the required abstract methods
4. Add protocol configuration to `Config.DEFAULT_PROTOCOLS`
5. Update the main script to include the new protocol

### Contributing

1. Follow existing code patterns and error handling
2. Add appropriate logging
3. Include protocol documentation
4. Test with actual Zeek parsers

## License

[Add license information]

## Acknowledgments

Designed for use with the Zeek ICS Network Security Package (ICSNPP) project.
