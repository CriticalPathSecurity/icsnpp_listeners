"""
Configuration management for ICSNPP listeners.
"""
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class ProtocolConfig:
    """Configuration for a single protocol."""
    name: str
    port: int
    enabled: bool = True
    tcp: bool = True
    udp: bool = False
    
@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_connections: bool = False
    log_requests: bool = False

class Config:
    """Main configuration class."""
    
    DEFAULT_PROTOCOLS = {
        'modbus': ProtocolConfig('MODBUS', 502),
        'dnp3': ProtocolConfig('DNP3', 20000),
        'enip': ProtocolConfig('ENIP', 44818),
        's7': ProtocolConfig('S7', 102),
        'bacnet': ProtocolConfig('BACNET', 47808, tcp=False, udp=True),
        'gesrtp': ProtocolConfig('GESRTP', 18245),
        'genisys': ProtocolConfig('GENISYS', 10001),
        'synchrotcp': ProtocolConfig('SYNCHRO_TCP', 4712),
        'synchroudp': ProtocolConfig('SYNCHRO_UDP', 4713, tcp=False, udp=True),
        'c1222tcp': ProtocolConfig('C1222_TCP', 1153),
        'c1222udp': ProtocolConfig('C1222_UDP', 1153, tcp=False, udp=True),
    }
    
    def __init__(self):
        self.protocols: Dict[str, ProtocolConfig] = self.DEFAULT_PROTOCOLS.copy()
        self.logging = LoggingConfig()
        self.bind_address = "0.0.0.0"
    
    def disable_protocols(self, disabled: List[str]) -> None:
        """Disable specified protocols."""
        for proto in disabled:
            if proto in self.protocols:
                self.protocols[proto].enabled = False
    
    def get_enabled_protocols(self) -> Dict[str, ProtocolConfig]:
        """Get all enabled protocols."""
        return {k: v for k, v in self.protocols.items() if v.enabled}
    
    def setup_logging(self) -> None:
        """Configure logging based on current settings."""
        log_level = getattr(logging, self.logging.level.upper())
        logging.basicConfig(
            level=log_level,
            format=self.logging.format,
            force=True  # Override any existing configuration
        )
        
        if self.logging.log_connections:
            # Set individual protocol loggers to INFO to see connections
            for config in self.protocols.values():
                logging.getLogger(config.name).setLevel(logging.INFO)
        
        if self.logging.log_requests:
            # Set to DEBUG to see individual requests
            for config in self.protocols.values():
                logging.getLogger(config.name).setLevel(logging.DEBUG)
