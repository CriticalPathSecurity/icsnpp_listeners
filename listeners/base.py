"""
Base classes and common functionality for protocol handlers.
"""
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional, Tuple

class BaseProtocolHandler(ABC):
    """Base class for all protocol handlers."""
    
    def __init__(self, protocol_name: str):
        self.protocol_name = protocol_name
        self.logger = logging.getLogger(protocol_name)
    
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Main connection handler with common error handling and logging."""
        client_addr = writer.get_extra_info('peername')
        self.logger.info(f"New connection from {client_addr}")
        
        try:
            await self._handle_connection(reader, writer, client_addr)
        except asyncio.IncompleteReadError:
            self.logger.info(f"Connection from {client_addr} closed (incomplete read)")
        except ConnectionResetError:
            self.logger.info(f"Connection from {client_addr} reset by peer")
        except Exception as e:
            self.logger.error(f"Error handling connection from {client_addr}: {e}")
        finally:
            self.logger.debug(f"Closing connection from {client_addr}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                self.logger.warning(f"Error closing connection: {e}")
    
    @abstractmethod
    async def _handle_connection(self, reader: asyncio.StreamReader, 
                               writer: asyncio.StreamWriter, client_addr: Tuple) -> None:
        """Protocol-specific connection handling logic."""
        pass

class BaseUDPHandler(asyncio.DatagramProtocol):
    """Base class for UDP protocol handlers."""
    
    def __init__(self, protocol_name: str):
        self.protocol_name = protocol_name
        self.logger = logging.getLogger(protocol_name)
        self.transport = None
    
    def connection_made(self, transport):
        self.transport = transport
        self.logger.debug(f"UDP handler for {self.protocol_name} started")
    
    def datagram_received(self, data: bytes, addr: Tuple) -> None:
        """Handle incoming UDP datagram with error handling."""
        try:
            self.logger.debug(f"UDP packet from {addr}, {len(data)} bytes")
            self._handle_datagram(data, addr)
        except Exception as e:
            self.logger.error(f"Error handling UDP packet from {addr}: {e}")
    
    @abstractmethod
    def _handle_datagram(self, data: bytes, addr: Tuple) -> None:
        """Protocol-specific datagram handling logic."""
        pass

class ProtocolConstants:
    """Common protocol constants and limits."""
    
    # Common buffer sizes
    DEFAULT_READ_SIZE = 1024
    MAX_READ_SIZE = 65536
    
    # Common timeouts
    CONNECTION_TIMEOUT = 30.0
    READ_TIMEOUT = 10.0
