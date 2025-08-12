
#!/usr/bin/env python3
import asyncio, argparse, logging

from listeners.modbus import ModbusServer
from listeners.dnp3 import DNP3Server
from listeners.enip import ENIPServer
from listeners.s7 import S7Server
from listeners.bacnet import run_bacnet
from listeners.gesrtp import GESRTPServer
from listeners.genisys import GenisysServer
from listeners.synchrophasor import SynchrophasorTCP, SynchrophasorUDP
from listeners.c1222 import C1222TCP, C1222UDP

def parse_args():
    p = argparse.ArgumentParser(description="ICSNPP multi-protocol listeners for Zeek training labs")
    p.add_argument("--modbus-port", type=int, default=502)
    p.add_argument("--dnp3-port", type=int, default=20000)
    p.add_argument("--enip-port", type=int, default=44818)
    p.add_argument("--s7-port", type=int, default=102)
    p.add_argument("--bacnet-port", type=int, default=47808)
    p.add_argument("--gesrtp-port", type=int, default=18245)
    p.add_argument("--genisys-port", type=int, default=10001)
    p.add_argument("--synchro-tcp-port", type=int, default=4712)
    p.add_argument("--synchro-udp-port", type=int, default=4713)
    p.add_argument("--c1222-port", type=int, default=1153)
    p.add_argument("--disable", nargs="*", default=[], help="Any of: modbus dnp3 enip s7 bacnet gesrtp genisys synchrotcp synchroudp c1222tcp c1222udp")
    p.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help="Set logging level")
    p.add_argument("--log-connections", action='store_true', help="Log all connection attempts and closures")
    p.add_argument("--daemon", action='store_true', help="Run as daemon (headless mode)")
    p.add_argument("--pid-file", type=str, help="Write PID to file for daemon management")
    p.add_argument("--bind", type=str, default="0.0.0.0", help="IP address to bind to (default: 0.0.0.0)")
    p.add_argument("--quiet", action='store_true', help="Suppress startup output (useful for daemon mode)")
    return p.parse_args()

async def main():
    args = parse_args()
    
    # Handle PID file creation for daemon mode
    if args.pid_file:
        import os
        with open(args.pid_file, 'w') as f:
            f.write(str(os.getpid()))
    
    # Configure logging
    log_level = getattr(logging, args.log_level)
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if args.daemon:
        # For daemon mode, log to syslog if available, otherwise to file
        try:
            import logging.handlers as log_handlers
            handler = log_handlers.SysLogHandler(address='/dev/log')
            handler.setFormatter(logging.Formatter('icsnpp_listeners: %(name)s - %(levelname)s - %(message)s'))
            logging.basicConfig(level=log_level, handlers=[handler])
        except:
            # Fall back to file logging
            logging.basicConfig(
                level=log_level,
                format=log_format,
                filename='/tmp/icsnpp_listeners.log',
                filemode='a'
            )
    else:
        logging.basicConfig(
            level=log_level,
            format=log_format,
            force=True
        )
    
    # Log PID after logging is configured
    if args.pid_file:
        import os
        logging.info(f"PID {os.getpid()} written to {args.pid_file}")
    
    if args.log_connections:
        # Set individual protocol loggers to INFO to see connections
        for protocol in ['MODBUS', 'DNP3', 'ENIP', 'S7', 'BACNET', 'GESRTP', 'GENISYS', 'SYNCHRO', 'C1222']:
            logging.getLogger(protocol).setLevel(logging.INFO)
    
    # Add graceful shutdown handling
    def signal_handler():
        logging.info("Received shutdown signal, stopping listeners...")
        for task in tasks:
            task.cancel()
    
    import signal
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, f: signal_handler())
    
    tasks = []
    
    if not args.quiet:
        print("Starting ICSNPP listeners...")
    logging.info("Starting ICSNPP listeners...")

    loop = asyncio.get_running_loop()

    if "modbus" not in args.disable:
        mod = ModbusServer()
        s = await asyncio.start_server(mod.handle, args.bind, args.modbus_port)
        if not args.quiet:
            print(f"[MODBUS]   TCP {args.bind}:{args.modbus_port}")
        logging.info(f"MODBUS TCP server listening on {args.bind}:{args.modbus_port}")
        tasks.append(s.serve_forever())

    if "dnp3" not in args.disable:
        d = DNP3Server()
        s = await asyncio.start_server(d.handle, args.bind, args.dnp3_port)
        if not args.quiet:
            print(f"[DNP3]     TCP {args.bind}:{args.dnp3_port}")
        logging.info(f"DNP3 TCP server listening on {args.bind}:{args.dnp3_port}")
        tasks.append(s.serve_forever())

    if "enip" not in args.disable:
        e = ENIPServer()
        s = await asyncio.start_server(e.handle, args.bind, args.enip_port)
        if not args.quiet:
            print(f"[ENIP]     TCP {args.bind}:{args.enip_port}")
        logging.info(f"EtherNet/IP TCP server listening on {args.bind}:{args.enip_port}")
        tasks.append(s.serve_forever())

    if "s7" not in args.disable:
        s7 = S7Server()
        s = await asyncio.start_server(s7.handle, args.bind, args.s7_port)
        if not args.quiet:
            print(f"[S7COMM]   TCP {args.bind}:{args.s7_port}")
        logging.info(f"S7comm TCP server listening on {args.bind}:{args.s7_port}")
        tasks.append(s.serve_forever())

    if "bacnet" not in args.disable:
        await run_bacnet(args.bacnet_port)
        if not args.quiet:
            print(f"[BACnet]   UDP {args.bind}:{args.bacnet_port}")
        logging.info(f"BACnet UDP server listening on {args.bind}:{args.bacnet_port}")

    if "gesrtp" not in args.disable:
        ge = GESRTPServer()
        s = await asyncio.start_server(ge.handle, args.bind, args.gesrtp_port)
        if not args.quiet:
            print(f"[GE-SRTP]  TCP {args.bind}:{args.gesrtp_port}")
        logging.info(f"GE SRTP TCP server listening on {args.bind}:{args.gesrtp_port}")
        tasks.append(s.serve_forever())

    if "genisys" not in args.disable:
        g = GenisysServer()
        s = await asyncio.start_server(g.handle, args.bind, args.genisys_port)
        if not args.quiet:
            print(f"[Genisys]  TCP {args.bind}:{args.genisys_port}")
        logging.info(f"Genisys TCP server listening on {args.bind}:{args.genisys_port}")
        tasks.append(s.serve_forever())

    if "synchrotcp" not in args.disable:
        st = SynchrophasorTCP()
        s = await asyncio.start_server(st.handle, args.bind, args.synchro_tcp_port)
        if not args.quiet:
            print(f"[C37.118]  TCP {args.bind}:{args.synchro_tcp_port}")
        logging.info(f"C37.118 TCP server listening on {args.bind}:{args.synchro_tcp_port}")
        tasks.append(s.serve_forever())

    if "synchroudp" not in args.disable:
        su = SynchrophasorUDP()
        await loop.create_datagram_endpoint(lambda: su, local_addr=(args.bind, args.synchro_udp_port))
        if not args.quiet:
            print(f"[C37.118]  UDP {args.bind}:{args.synchro_udp_port}")
        logging.info(f"C37.118 UDP server listening on {args.bind}:{args.synchro_udp_port}")

    if "c1222tcp" not in args.disable:
        ctt = C1222TCP()
        s = await asyncio.start_server(ctt.handle, args.bind, args.c1222_port)
        if not args.quiet:
            print(f"[C12.22]   TCP {args.bind}:{args.c1222_port}")
        logging.info(f"C12.22 TCP server listening on {args.bind}:{args.c1222_port}")
        tasks.append(s.serve_forever())

    if "c1222udp" not in args.disable:
        ctu = C1222UDP()
        await loop.create_datagram_endpoint(lambda: ctu, local_addr=(args.bind, args.c1222_port))
        if not args.quiet:
            print(f"[C12.22]   UDP {args.bind}:{args.c1222_port}")
        logging.info(f"C12.22 UDP server listening on {args.bind}:{args.c1222_port}")

    if not tasks:
        if not args.quiet:
            print("No TCP listeners enabled.")
        logging.warning("No TCP listeners enabled")
    else:
        if not args.quiet:
            print(f"All listeners started. Running{'as daemon' if args.daemon else ''}...")
        logging.info(f"All listeners started successfully")
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
