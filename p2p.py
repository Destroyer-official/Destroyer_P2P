"""
Simple P2P Chat Application

A lightweight peer-to-peer chat application using TCP for direct communication 
over IPv4/IPv6 networks with NAT traversal capabilities.
"""

import asyncio
import logging
import os
import random
import re
import signal
import socket
import ssl
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger(__name__)

# Terminal colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RED = '\033[91m'
RESET = '\033[0m'

# Default STUN server configuration
DEFAULT_STUN_SERVER = "stun.l.google.com"
DEFAULT_STUN_PORT = 19302

async def get_public_ip_port(stun_host: str = DEFAULT_STUN_SERVER, stun_port: int = DEFAULT_STUN_PORT) -> Tuple[Optional[str], Optional[int]]:
    """
    Discovers the public IP address and port using STUN protocol.
    
    Implements a basic STUN client following RFC 5389 to determine the public
    endpoint (IP address and port) for NAT traversal.
    
    Args:
        stun_host: STUN server hostname
        stun_port: STUN server port
        
    Returns:
        Tuple containing (public_ip, public_port) or (None, None) if discovery fails
    """
    sock = None
    try:
        # Try multiple STUN servers if the default fails
        stun_servers = [
            (stun_host, stun_port),
            ("stun.stunprotocol.org", 3478),
            ("stun.sipgate.net", 3478)
        ]
        
        # Try each STUN server until successful
        for curr_stun_host, curr_stun_port in stun_servers:
            log.info(f"Trying STUN server: {curr_stun_host}:{curr_stun_port}")
            
            addrinfo = await asyncio.get_event_loop().getaddrinfo(
                curr_stun_host, curr_stun_port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_DGRAM
            )

            target_addr = None
            target_family = None
            # Try IPv6 first
            for family, type, proto, canonname, sockaddr in addrinfo:
                if family == socket.AF_INET6:
                    target_addr = sockaddr
                    target_family = socket.AF_INET6
                    log.info(f"Using STUN server IPv6 address: {target_addr}")
                    break
            # Fall back to IPv4
            if not target_addr:
                for family, type, proto, canonname, sockaddr in addrinfo:
                    if family == socket.AF_INET:
                        target_addr = sockaddr
                        target_family = socket.AF_INET
                        log.info(f"Using STUN server IPv4 address: {target_addr}")
                        break

            if not target_addr or not target_family:
                log.warning(f"Could not resolve STUN server address: {curr_stun_host}")
                continue  # Try next server

            # Create new socket for each attempt
            if sock:
                sock.close()
                
            sock = socket.socket(target_family, socket.SOCK_DGRAM)
            sock.setblocking(False)

            try:
                if target_family == socket.AF_INET6:
                    sock.bind(("::", 0))
                else:
                    sock.bind(("0.0.0.0", 0))
            except OSError as e:
                log.warning(f"Failed to bind socket: {e}")
                continue  # Try next server

            local_ip, local_port = sock.getsockname()[:2]
            log.info(f"UDP Socket bound to: {local_ip}:{local_port}")

            # Build the STUN request (RFC 5389)
            transaction_id = os.urandom(12)
            magic_cookie = bytes([0x21, 0x12, 0xA4, 0x42])
            message_type = bytes([0x00, 0x01])  # Binding Request
            message_length = bytes([0x00, 0x00])
            message = message_type + message_length + magic_cookie + transaction_id

            loop = asyncio.get_event_loop()
            
            # Send the request with retries
            max_retries = 3
            for retry in range(max_retries):
                try:
                    # Cross-platform way to send UDP packet asynchronously
                    sock.setblocking(True)
                    try:
                        await loop.run_in_executor(None, lambda: sock.sendto(message, target_addr))
                    finally:
                        sock.setblocking(False)
                        
                    log.debug(f"Sent STUN request to {target_addr} (attempt {retry+1}/{max_retries})")
                    
                    # Wait for response with timeout
                    try:
                        # Cross-platform way to receive UDP packet asynchronously
                        response_future = loop.create_future()
                        
                        def receive_callback():
                            try:
                                sock.setblocking(True)
                                try:
                                    data, addr = sock.recvfrom(1024)
                                    return (data, addr)
                                finally:
                                    sock.setblocking(False)
                            except Exception as e:
                                raise e
                                
                        data, addr = await asyncio.wait_for(
                            loop.run_in_executor(None, receive_callback),
                            timeout=2.0
                        )
                        
                        log.debug(f"Received STUN response from {addr}")

                        if len(data) < 20 or data[4:8] != magic_cookie or data[8:20] != transaction_id:
                            log.warning("Received invalid STUN response (header mismatch).")
                            continue  # Try again with the same server

                        # Parse the STUN response
                        pos = 20
                        while pos + 4 <= len(data):
                            attr_type = int.from_bytes(data[pos:pos+2], 'big')
                            attr_len = int.from_bytes(data[pos+2:pos+4], 'big')

                            # XOR-MAPPED-ADDRESS attribute
                            if attr_type == 0x0020:
                                addr_pos = pos + 4
                                family_byte = data[addr_pos + 1]
                                port = int.from_bytes(data[addr_pos+2:addr_pos+4], 'big') ^ 0x2112

                                if family_byte == 0x01:  # IPv4
                                    ip_bytes = bytes(x ^ y for x, y in zip(data[addr_pos+4:addr_pos+8], magic_cookie))
                                    ip = socket.inet_ntop(socket.AF_INET, ip_bytes)
                                    log.info(f"STUN discovered Public IPv4: {ip}:{port}")
                                    return ip, port
                                elif family_byte == 0x02:  # IPv6
                                    xor_mask = magic_cookie + transaction_id
                                    ip_bytes = bytearray(data[addr_pos+4:addr_pos+20])
                                    for i in range(16):
                                        ip_bytes[i] ^= xor_mask[i]
                                    ip = socket.inet_ntop(socket.AF_INET6, bytes(ip_bytes))
                                    log.info(f"STUN discovered Public IPv6: {ip}:{port}")
                                    return ip, port
                                else:
                                    log.warning(f"Unknown address family in STUN response: {family_byte}")
                                    break  # Try next server
                            
                            # Move to next attribute
                            pos += 4 + attr_len
                            if attr_len % 4 != 0:
                                pos += 4 - (attr_len % 4)

                        log.warning("XOR-MAPPED-ADDRESS attribute not found in STUN response.")
                        break  # Try next server

                    except asyncio.TimeoutError:
                        log.warning(f"STUN request timed out (attempt {retry+1}/{max_retries}).")
                        if retry == max_retries - 1:
                            break  # Try next server
                        await asyncio.sleep(0.5 * (retry + 1))  # Exponential backoff

                except OSError as e:
                    log.warning(f"Socket error during STUN request: {e}")
                    break  # Try next server
                except Exception as e:
                    log.warning(f"Error during STUN request: {e}")
                    if retry == max_retries - 1:
                        break
                    await asyncio.sleep(0.5 * (retry + 1))  # Exponential backoff
        
        # All STUN servers failed
        log.error("All STUN servers failed. Could not determine public IP.")
        return None, None

    except socket.gaierror as e:
        log.error(f"DNS resolution failed for STUN servers: {e}")
        return None, None
    except Exception as e:
        log.error(f"Error during STUN operation: {e}", exc_info=True)
        return None, None
    finally:
        if sock:
            sock.close()
            log.debug("Closed STUN UDP socket.")

async def recv_all(sock: socket.socket, n: int) -> Union[bytes, None]:
    """
    Reliably receive exactly n bytes from a socket with timeout handling.
    
    Args:
        sock: The socket to receive from
        n: Number of bytes to receive
        
    Returns:
        Received data as bytes or None if error/timeout/connection closed
    """
    data = bytearray()
    start_time = asyncio.get_event_loop().time()
    timeout = 60.0  # 60 second timeout for complete reception
    
    # Check if this is an SSL socket
    is_ssl_socket = hasattr(sock, '_sslobj') and sock._sslobj is not None
    
    while len(data) < n:
        if asyncio.get_event_loop().time() - start_time > timeout:
            log.warning(f"Timeout receiving {n} bytes (got {len(data)} bytes so far)")
            return None
            
        try:
            loop = asyncio.get_event_loop()
            remaining = n - len(data)
            packet = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: sock.recv(min(remaining, 8192))), 
                timeout=5.0
            )
            
            if not packet:  # Connection closed
                log.debug(f"Connection closed while receiving data (got {len(data)}/{n} bytes)")
                return None
                
            data.extend(packet)
            
        except asyncio.CancelledError:
            log.debug("recv_all operation cancelled")
            raise  # Re-raise to propagate the cancellation
        except asyncio.TimeoutError:
            # Short timeout for this attempt, but continue trying
            continue
        except BlockingIOError:
            await asyncio.sleep(0.01)
            continue
        except ConnectionResetError:
            log.warning("Connection reset while receiving data")
            return None
        except OSError as e:
            error_code = getattr(e, 'errno', None)
            log.error(f"Socket error during recv_all: {e} (errno: {error_code})", exc_info=True)
            return None
        except Exception as e:
            log.error(f"Unexpected error in recv_all: {e}", exc_info=True)
            return None
    
    return bytes(data)

async def send_framed(sock: socket.socket, data: bytes) -> bool:
    """
    Sends length-prefixed data over a socket.
    
    Prefixes the data with a 4-byte length header (big-endian) for framing.
    
    Args:
        sock: The socket to send over
        data: The data to send
        
    Returns:
        True if sending was successful, False otherwise
    """
    try:
        frame = struct.pack(">I", len(data)) + data
        
        # Check if this is an SSL socket
        is_ssl_socket = hasattr(sock, '_sslobj') and sock._sslobj is not None
        
        if is_ssl_socket:
            # Special handling for SSL sockets
            loop = asyncio.get_event_loop()
            remaining = len(frame)
            view = memoryview(frame)
            sent = 0
            
            # Temporarily set socket to blocking mode for SSL send
            was_non_blocking = sock.getblocking() == False
            if was_non_blocking:
                sock.setblocking(True)
                
            try:
                while sent < remaining:
                    try:
                        chunk_sent = await loop.run_in_executor(
                            None, 
                            lambda: sock.send(view[sent:])
                        )
                        if chunk_sent == 0:
                            return False
                        sent += chunk_sent
                    except ssl.SSLWantWriteError:
                        await asyncio.sleep(0.01)  # Brief pause and retry
                    except ssl.SSLWantReadError:
                        await asyncio.sleep(0.01)  # Brief pause and retry
            finally:
                # Restore non-blocking state if needed
                if was_non_blocking:
                    sock.setblocking(False)
                    
            return sent == remaining
        else:
            # Regular socket
            await asyncio.wait_for(
                asyncio.get_event_loop().sock_sendall(sock, frame),
                timeout=30.0
            )
            return True
    except asyncio.TimeoutError:
        log.error(f"Timeout sending {len(data)} bytes")
        return False
    except ConnectionResetError:
        log.warning("Connection reset while sending data")
        return False
    except BrokenPipeError:
        log.warning("Broken pipe while sending data")
        return False
    except OSError as e:
        log.error(f"Failed to send framed data: {e}")
        return False
    except Exception as e:
        log.error(f"Unexpected error sending framed data: {e}", exc_info=True)
        return False

async def receive_framed(sock: socket.socket, timeout: float = 60.0) -> Union[bytes, None]:
    """
    Receives length-prefixed data from a socket.
    
    First reads a 4-byte big-endian length header, then reads that many bytes
    of payload data.
    
    Args:
        sock: The socket to receive from
        timeout: Maximum time to wait for complete message, in seconds
        
    Returns:
        The received data payload or None if error/timeout/connection closed
    """
    try:
        # Check if this is an SSL socket
        is_ssl_socket = hasattr(sock, '_sslobj') and sock._sslobj is not None
        
        if is_ssl_socket:
            # Special handling for SSL sockets
            was_non_blocking = sock.getblocking() == False
            if was_non_blocking:
                sock.setblocking(True)
                
            try:
                # Read the 4-byte length prefix
                loop = asyncio.get_event_loop()
                len_bytes = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: sock.recv(4)),
                    timeout=timeout
                )
                
                if len_bytes is None or len(len_bytes) < 4:
                    log.warning("Connection closed or timeout while receiving frame length")
                    return None
                    
                msg_len = struct.unpack(">I", len_bytes)[0]
                
                # Sanity check: 50MB maximum message size
                if msg_len > 50 * 1024 * 1024:
                    log.error(f"Frame length too large: {msg_len}. Possible corruption.")
                    return None
                    
                if msg_len > 100:
                    log.debug(f"Receiving framed message of length: {msg_len}")
                
                # Read the message data
                msg_data = bytearray()
                remaining = msg_len
                
                while remaining > 0:
                    chunk = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recv(min(remaining, 8192))),
                        timeout=timeout
                    )
                    
                    if not chunk:
                        log.warning("Connection closed while receiving frame data")
                        return None
                        
                    msg_data.extend(chunk)
                    remaining -= len(chunk)
                    
                return bytes(msg_data)
            finally:
                # Restore non-blocking state if needed
                if was_non_blocking:
                    sock.setblocking(False)
        else:
            # Regular socket
            len_bytes = await asyncio.wait_for(recv_all(sock, 4), timeout=timeout)
            if len_bytes is None:
                log.warning("Connection closed or timeout while receiving frame length")
                return None

            msg_len = struct.unpack(">I", len_bytes)[0]
            
            # Sanity check: 50MB maximum message size
            if msg_len > 50 * 1024 * 1024:
                log.error(f"Frame length too large: {msg_len}. Possible corruption.")
                return None
                
            if msg_len > 100:
                log.debug(f"Receiving framed message of length: {msg_len}")

            # Read the message data
            msg_data = await asyncio.wait_for(recv_all(sock, msg_len), timeout=timeout)
            if msg_data is None:
                log.warning("Connection closed or timeout while receiving frame data")
                return None

            return msg_data

    except asyncio.TimeoutError:
        log.debug("Timeout while receiving framed message")
        return None
    except ConnectionResetError:
        log.warning("Connection reset while receiving framed message")
        return None
    except ssl.SSLWantReadError:
        log.debug("SSL needs more data to read, but none available now")
        await asyncio.sleep(0.1)  # Give time for data to arrive
        return None
    except ssl.SSLWantWriteError:
        log.debug("SSL needs to write before reading")
        await asyncio.sleep(0.1)
        return None
    except OSError as e:
        log.error(f"Socket error receiving framed data: {e}")
        return None
    except struct.error as e:
        log.error(f"Struct unpacking error: {e} - possibly corrupted data")
        return None
    except Exception as e:
        log.error(f"Unexpected error receiving framed data: {e}", exc_info=True)
        return None

class SimpleP2PChat:
    """
    A peer-to-peer chat application using TCP for direct communication.
    
    Features:
    - IPv4 and IPv6 support with dual-stack capability
    - NAT traversal using STUN for public IP/port discovery
    - Connection recovery with automatic reconnection
    - Reliable framed message protocol
    - Heartbeat-based connection monitoring
    """
    def __init__(self):
        # Network state
        self.public_ip = None
        self.public_port = None
        self.tcp_socket = None
        self.peer_ip = None
        self.peer_port = None
        self.is_connected = False
        self.last_known_peer = None
        
        # Tasks and async control
        self.receive_task = None
        self.heartbeat_task = None
        self.stop_event = asyncio.Event()
        self.connection_lock = asyncio.Lock()
        self.message_queue = asyncio.Queue()
        
        # User state
        self.local_username = f"User_{random.randint(100,999)}"
        self.peer_username = "Peer"
        self.reconnect_attempts = 0
        
        # Configuration Constants
        self.MAX_RECONNECT_ATTEMPTS = 3
        self.STUN_TIMEOUT = 2.0
        self.STUN_RETRIES = 3
        self.CONNECTION_TIMEOUT = 10.0
        self.RECEIVE_TIMEOUT = 90.0
        self.SEND_TIMEOUT = 30.0
        self.RECV_BUFFER_SIZE = 8192
        self.MAX_FRAME_SIZE = 50 * 1024 * 1024  # 50MB
        self.HEARTBEAT_INTERVAL = 20
        self.MISSED_HEARTBEATS_THRESHOLD = 3
        self.MAX_USERNAME_LENGTH = 32
        self.USERNAME_REGEX = r"^.*$"  # Allow all characters

    async def _close_connection(self, attempt_reconnect=False):
        """
        Closes the current TCP connection and resets connection state.
        
        Args:
            attempt_reconnect: If True, try to reconnect to the last peer
        """
        async with self.connection_lock:
            log.info("Closing TCP connection.")
            was_connected = self.is_connected
            self.is_connected = False
            self.stop_event.set()
            
            # Cancel tasks
            if self.receive_task and not self.receive_task.done():
                try:
                    self.receive_task.cancel()
                    await asyncio.sleep(0.1)
                except Exception as e:
                    log.error(f"Error cancelling receive task: {e}", exc_info=True)
                self.receive_task = None
                
            if self.heartbeat_task and not self.heartbeat_task.done():
                try:
                    self.heartbeat_task.cancel()
                    await asyncio.sleep(0.1)
                except Exception as e:
                    log.error(f"Error cancelling heartbeat task: {e}", exc_info=True)
                self.heartbeat_task = None
                
            # Close socket
            if self.tcp_socket:
                try:
                    self.tcp_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # Socket may already be closed
                try:
                    self.tcp_socket.close()
                except Exception as e:
                    log.error(f"Error closing socket: {e}", exc_info=True)
                self.tcp_socket = None
                
            # Store peer info for potential reconnect
            if self.peer_ip and self.peer_port:
                self.last_known_peer = (self.peer_ip, self.peer_port)
            
            # Try to reconnect if requested
            if was_connected and attempt_reconnect and self.last_known_peer and self.reconnect_attempts < self.MAX_RECONNECT_ATTEMPTS:
                self.reconnect_attempts += 1
                peer_ip, peer_port = self.last_known_peer
                
                print(f"\n{YELLOW}Connection lost. Attempting to reconnect ({self.reconnect_attempts}/{self.MAX_RECONNECT_ATTEMPTS})...{RESET}")
                try:
                    await self._connect_to_peer(peer_ip, peer_port)
                    if self.is_connected:
                        print(f"\n{GREEN}Reconnected successfully!{RESET}")
                        log.info(f"Reconnected to {peer_ip}:{peer_port}")
                        self.reconnect_attempts = 0
                        self.stop_event.clear()
                        
                        # Start chat session again
                        asyncio.create_task(self._chat_session(is_reconnect=True))
                        return
                except Exception as e:
                    log.error(f"Reconnection attempt failed: {e}", exc_info=True)
            
            if attempt_reconnect and self.reconnect_attempts >= self.MAX_RECONNECT_ATTEMPTS:
                print(f"\n{RED}Failed to reconnect after {self.MAX_RECONNECT_ATTEMPTS} attempts.{RESET}")
                self.reconnect_attempts = 0
            
            # Reset peer info after failed reconnects
            self.peer_ip = None
            self.peer_port = None
            self.peer_username = "Peer" # Reset peer username
            
            print(f"\n{BLUE}Disconnected. Returning to main menu.{RESET}")

    async def _async_input(self, prompt: str) -> str:
        """
        Gets user input asynchronously without blocking the event loop.
        
        Args:
            prompt: Text prompt to display to the user
            
        Returns:
            User input string
        """
        print(prompt, end='', flush=True)
        
        loop = asyncio.get_event_loop()
        try:
            return await loop.run_in_executor(None, input)
        except EOFError:
            # Handle Ctrl+D
            print("\nEOF detected")
            return "exit"
        except KeyboardInterrupt:
            # Handle Ctrl+C
            print("\nInput interrupted")
            return "exit"
        except Exception as e:
            log.error(f"Error getting input: {e}")
            return ""

    async def _receive_messages(self):
        """
        Handles receiving and processing messages from the connected peer.
        
        Runs as a background task that continuously monitors the socket for
        incoming framed messages and processes them based on message type.
        """
        consecutive_errors = 0
        MAX_CONSECUTIVE_ERRORS = 5
        BACKOFF_DELAY = 0.5  # seconds
        
        log.info("Starting message receive loop")
        
        try:
            while not self.stop_event.is_set() and self.tcp_socket:
                try:
                    data = await receive_framed(self.tcp_socket, timeout=self.RECEIVE_TIMEOUT)
                    consecutive_errors = 0
                    BACKOFF_DELAY = 0.5  # Reset backoff on success

                    if data is None:
                        # Check if connection is still active
                        if self.tcp_socket and not self.stop_event.is_set():
                            log.info("Receive loop detected closed connection unexpectedly.")
                            print(f"\n{YELLOW}Peer has disconnected or connection lost.{RESET}")
                            await self._close_connection(attempt_reconnect=True)
                        else:
                            log.info("Receive loop exiting (socket closed or stop event set).")
                        break

                    try:
                        message = data.decode('utf-8').strip()

                        try:
                            if message.startswith('USERNAME:'):
                                peer_name_candidate = message[len('USERNAME:'):].strip()
                                if 1 <= len(peer_name_candidate) <= self.MAX_USERNAME_LENGTH and re.match(self.USERNAME_REGEX, peer_name_candidate):
                                    self.peer_username = peer_name_candidate
                                    print(f"\n{GREEN}Connected with {self.peer_username}{RESET}")
                                    print("\n")
                                else:
                                    log.warning(f"Received invalid username: '{peer_name_candidate}'")
                            elif message == 'EXIT':
                                print(f"\n{YELLOW}{self.peer_username} has left the chat.{RESET}")
                                log.info(f"Peer {self.peer_username} initiated disconnect.")
                                await self._close_connection(attempt_reconnect=False)
                                break
                            elif message.startswith('MSG:'):
                                parts = message.split(':', 2)
                                if len(parts) == 3:
                                    sender, content = parts[1], parts[2]
                                    # Clear line before printing message
                                    print("\r" + " " * 100 + "\r", end='')
                                    print(f"{MAGENTA}{sender}: {RESET}{content}")
                                    print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
                                else:
                                    log.warning(f"Received malformed message: {message}")
                            elif message == 'HEARTBEAT':
                                log.debug("Received heartbeat message")
                                try:
                                    await send_framed(self.tcp_socket, "HEARTBEAT_ACK".encode('utf-8'))
                                except Exception as e:
                                    log.debug(f"Failed to send heartbeat ACK: {e}")
                            elif message == 'HEARTBEAT_ACK':
                                log.debug("Received heartbeat acknowledgment")
                            elif message == 'RECONNECTED':
                                print(f"\n{GREEN}{self.peer_username} has reconnected.{RESET}")
                                print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
                            else:
                                log.warning(f"Received unknown message type: {message[:50]}...")
                        except Exception as e:
                            log.error(f"Error processing message '{message[:50]}...': {e}", exc_info=True)

                    except UnicodeDecodeError:
                        log.warning("Received non-UTF8 data, ignoring.")

                except asyncio.CancelledError:
                    log.info("Receive task cancelled.")
                    raise
                except ConnectionResetError:
                    log.info("Connection reset by peer.")
                    print(f"\n{YELLOW}Connection reset by peer.{RESET}")
                    if not self.stop_event.is_set():
                        await self._close_connection(attempt_reconnect=True)
                    break

                except OSError as e:
                    consecutive_errors += 1
                    # Check for closed socket errors
                    if e.errno in (9, 10038, 10054, 10053):  # Various socket closed errors
                        log.warning(f"Receive loop detected socket closed/error: {e}")
                        if not self.stop_event.is_set():
                            await self._close_connection(attempt_reconnect=True)
                        break
                    else:
                        log.error(f"Socket error during receive: {e}", exc_info=True)
                        if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                            log.warning("Max consecutive receive errors reached.")
                            if not self.stop_event.is_set():
                                await self._close_connection(attempt_reconnect=True)
                            break
                        # Exponential backoff
                        await asyncio.sleep(min(BACKOFF_DELAY * consecutive_errors, 5.0))

                except Exception as e:
                    consecutive_errors += 1
                    log.error(f"Unexpected error during receive: {e}", exc_info=True)
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                        log.warning("Max consecutive unexpected errors reached.")
                        if not self.stop_event.is_set():
                            await self._close_connection(attempt_reconnect=True)
                        break
                    # Exponential backoff
                    await asyncio.sleep(min(BACKOFF_DELAY * consecutive_errors, 5.0))

            log.info("Receive loop finished normally.")
        except asyncio.CancelledError:
            log.info("Receive loop cancelled.")
            raise
        except Exception as e:
            log.error(f"Receive loop exited with unhandled exception: {e}", exc_info=True)
        finally:
            # Update connection state if loop exits unexpectedly
            if self.is_connected and not self.stop_event.is_set():
                 log.warning("Receive loop ended unexpectedly without explicit close. Closing connection.")
                 try:
                     await self._close_connection(attempt_reconnect=True)
                 except Exception as e:
                     log.error(f"Error during final cleanup in receive loop: {e}", exc_info=True)
            log.info("Receive loop cleanup complete")

    async def _send_heartbeats(self):
        """
        Sends periodic heartbeat messages to keep the connection alive.
        
        Monitors connection health and initiates reconnection if too many
        heartbeats are missed.
        """
        missed_heartbeats = 0
        
        while not self.stop_event.is_set() and self.is_connected:
            try:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                
                if not self.is_connected or self.stop_event.is_set():
                    break
                
                if self.tcp_socket:
                    success = await send_framed(self.tcp_socket, "HEARTBEAT".encode('utf-8'))
                    if not success:
                        missed_heartbeats += 1
                        log.warning(f"Failed to send heartbeat. Missed: {missed_heartbeats}/{self.MISSED_HEARTBEATS_THRESHOLD}")
                        
                        if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                            log.warning("Too many missed heartbeats. Connection may be dead.")
                            print(f"\n{YELLOW}Connection appears to be dead. Attempting to reconnect...{RESET}")
                            if not self.stop_event.is_set():
                                await self._close_connection(attempt_reconnect=True)
                            break
                    else:
                        missed_heartbeats = 0  # Reset counter on success
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Error sending heartbeat: {e}")
                missed_heartbeats += 1
                
                if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                    if not self.stop_event.is_set():
                        await self._close_connection(attempt_reconnect=True)
                    break

    async def _connect_to_peer(self, peer_ip, peer_port):
        """
        Establishes a TCP connection to a peer.
        
        Handles both IPv4 and IPv6 addressing and sets up socket options
        for reliable communications.
        
        Args:
            peer_ip: Peer's IP address (IPv4 or IPv6)
            peer_port: Peer's port number
            
        Returns:
            True if connection successful, raises exception otherwise
        """
        client_socket = None
        
        try:
            print(f"\n{YELLOW}Connecting to [{peer_ip}]:{peer_port}...{RESET}")

            loop = asyncio.get_event_loop()
            log.info(f"Resolving address for {peer_ip}:{peer_port}")
            
            try:
                addrinfo = await loop.getaddrinfo(
                    peer_ip, peer_port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM
                )
            except socket.gaierror as e:
                log.error(f"Failed to resolve {peer_ip}:{peer_port} - {e}", exc_info=True)
                raise

            if not addrinfo:
                log.error(f"No addresses found for {peer_ip}:{peer_port}")
                raise socket.gaierror("Could not resolve host or address.")

            # Try multiple address families (IPv6, IPv4)
            last_error = None
            log.info(f"Found {len(addrinfo)} address candidates for {peer_ip}:{peer_port}")
            
            for i, (family, type_, proto, _, sockaddr) in enumerate(addrinfo):
                try:
                    log.info(f"Trying connection candidate {i+1}/{len(addrinfo)}: {family=}, {sockaddr=}")
                    client_socket = socket.socket(family, type_, proto)
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    
                    # Set TCP keepalive parameters if supported
                    try:
                        if hasattr(socket, 'TCP_KEEPIDLE'):
                            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                        if hasattr(socket, 'TCP_KEEPINTVL'):
                            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
                        if hasattr(socket, 'TCP_KEEPCNT'):
                            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                    except Exception as e:
                        log.debug(f"Could not set some TCP keepalive options: {e}")
                        # Non-critical, continue anyway

                    log.info(f"Attempting connection to {sockaddr} (timeout: {self.CONNECTION_TIMEOUT}s)")
                    try:
                        # Cross-platform TCP connection method
                        client_socket.setblocking(True)

                        async def connect_with_timeout():
                            try:
                                await asyncio.wait_for(
                                    loop.run_in_executor(None, lambda: client_socket.connect(sockaddr)),
                                    timeout=self.CONNECTION_TIMEOUT
                                )
                                return True
                            except socket.error as e:
                                # Already connected is fine
                                if e.errno == getattr(socket.errno, 'EISCONN', 56):
                                    return True
                                raise
                                
                        await connect_with_timeout()
                        
                        # Set back to non-blocking mode after connection
                        client_socket.setblocking(False)
                        log.info(f"Connection to {sockaddr} succeeded")
                    except asyncio.TimeoutError:
                        log.warning(f"Connection to {sockaddr} timed out after {self.CONNECTION_TIMEOUT}s")
                        raise
                    except OSError as e:
                        log.warning(f"Connection to {sockaddr} failed: {e}")
                        raise
                    
                    # Connection succeeded
                    self.tcp_socket = client_socket
                    self.peer_ip = peer_ip
                    self.peer_port = peer_port
                    self.is_connected = True
                    
                    # Save successful connection
                    self.last_known_peer = (peer_ip, peer_port)
                    log.info(f"Successfully connected to {peer_ip}:{peer_port}")
                    return True
                    
                except asyncio.CancelledError:
                    log.info("Connection attempt was cancelled")
                    if client_socket:
                        client_socket.close()
                    raise
                except (OSError, asyncio.TimeoutError) as e:
                    log.warning(f"Connection attempt failed: {e}")
                    last_error = e
                    if client_socket:
                        client_socket.close()
                        client_socket = None
                    continue  # Try next address
            
            # All connection attempts failed
            if last_error:
                log.error(f"All connection attempts failed. Last error: {last_error}")
                raise last_error
            else:
                log.error("Failed to connect to any available address")
                raise ConnectionError("Failed to connect to any available address")
                
        except asyncio.CancelledError:
            log.info("Connection process cancelled")
            if client_socket:
                client_socket.close()
            raise
        except Exception as e:
            log.error(f"Connection to {peer_ip}:{peer_port} failed: {e}", exc_info=True)
            if client_socket:
                client_socket.close()
            raise e

    async def _chat_session(self, is_reconnect=False):
        """
        Manages an active chat session after connection is established.
        
        Handles username exchange, message sending/receiving, and connection
        monitoring during an active chat session.
        
        Args:
            is_reconnect: True if this is a reconnected session
        """
        if not self.tcp_socket:
            log.warning("Attempted to start chat session without a socket.")
            return

        self.stop_event.clear()
        self.is_connected = True

        # Username Exchange (skip if reconnecting)
        if not is_reconnect:
            if not self.local_username or self.local_username.startswith("User_"):
                while True:
                    candidate_name = (await self._async_input(f"{YELLOW}Enter your username (max {self.MAX_USERNAME_LENGTH} chars): {RESET}")).strip()
                    if not candidate_name:
                        self.local_username = f"User_{random.randint(100,999)}"
                        print(f"Using default username: {self.local_username}")
                        break
                    elif len(candidate_name) > self.MAX_USERNAME_LENGTH:
                        print(f"{RED}Username too long. Max length is {self.MAX_USERNAME_LENGTH}.{RESET}")
                    elif not re.match(self.USERNAME_REGEX, candidate_name):
                        print(f"{RED}Invalid username format.{RESET}")
                    else:
                        self.local_username = candidate_name
                        break

        try:
            # Send username or reconnection notice
            if is_reconnect:
                await send_framed(self.tcp_socket, f"RECONNECTED".encode('utf-8'))
                print(f"{GREEN}Reconnected to chat session.{RESET}")
            else:
                username_msg = f"USERNAME:{self.local_username}"
                await send_framed(self.tcp_socket, username_msg.encode('utf-8'))
        except Exception as e:
            log.error(f"Failed to send initial message: {e}")
            print(f"{RED}Error establishing chat session. Disconnecting.{RESET}")
            await self._close_connection()
            return

        # Start receiving and heartbeat tasks
        self.receive_task = asyncio.create_task(self._receive_messages())
        self.heartbeat_task = asyncio.create_task(self._send_heartbeats())

        if not is_reconnect:
            print(f"\n{GREEN}Chat session started.{RESET}")
            print(f"{YELLOW}Type 'exit' to quit.{RESET}\n")

        # Process queued messages (for reconnect)
        if is_reconnect and not self.message_queue.empty():
            print(f"{YELLOW}Sending queued messages...{RESET}")
            while not self.message_queue.empty():
                try:
                    queued_msg = await self.message_queue.get()
                    if self.is_connected:
                        await send_framed(self.tcp_socket, queued_msg.encode('utf-8'))
                except Exception as e:
                    log.error(f"Failed to send queued message: {e}")
                    await self.message_queue.put(queued_msg)
                    await self._close_connection(attempt_reconnect=True)
                    break

        # Message sending loop
        while not self.stop_event.is_set() and self.is_connected:
            try:
                message = await self._async_input(f"{CYAN}{self.local_username}: {RESET}")
                message = message.strip()

                if not self.is_connected or self.stop_event.is_set():
                    break

                if message.lower() == 'exit':
                    try:
                        await send_framed(self.tcp_socket, b"EXIT")
                    except:
                        pass  # Ignore errors when exiting
                    break

                if message:
                    try:
                        msg_data = f"MSG:{self.local_username}:{message}"
                        success = await send_framed(self.tcp_socket, msg_data.encode('utf-8'))
                        
                        if not success:
                            log.warning("Failed to send message, connection may be lost")
                            # Queue message for potential reconnect
                            if self.message_queue.qsize() < 100: # Limit queue size
                                await self.message_queue.put(msg_data)
                            else:
                                log.warning("Message queue full, discarding oldest message.")
                                try: 
                                    await self.message_queue.get_nowait() # Discard oldest
                                except asyncio.QueueEmpty:
                                    pass
                                await self.message_queue.put(msg_data)
                            
                            if self.is_connected:
                                log.info("Attempting reconnect after failed send.")
                                if not self.stop_event.is_set():
                                    await self._close_connection(attempt_reconnect=True)
                                break
                    except Exception as e:
                        log.error(f"Failed to send message: {e}")
                        if self.message_queue.qsize() < 100:
                            await self.message_queue.put(msg_data)
                        else:
                            log.warning("Message queue full, discarding oldest message.")
                            try: 
                                await self.message_queue.get_nowait()
                            except asyncio.QueueEmpty:
                                pass
                            await self.message_queue.put(msg_data)
                        if not self.stop_event.is_set():
                            await self._close_connection(attempt_reconnect=True)
                        break

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Error in sending loop: {e}")
                break

        # Cleanup
        await self._close_connection()

    async def handle_connections(self):
        """
        Main menu and connection handling loop.
        
        Provides the user interface for starting a server (listener),
        connecting to peers, or managing network settings.
        """
        server_socket = None
        
        while True:
            try:
                if self.is_connected:
                    log.info("Waiting for stop event before showing main menu")
                    await self.stop_event.wait()
                    self.is_connected = False

                print("\nOptions:")
                print(f" {GREEN}1. Wait for incoming connection (Server){RESET}")
                print(f" {YELLOW}2. Connect to a peer (Client){RESET}")
                print(f" {BLUE}3. Retry STUN discovery{RESET}")
                print(f" {RED}4. Exit{RESET}")

                try:
                    choice = (await self._async_input(f"{BLUE}Choose an option (1-4): {RESET}")).strip()
                except Exception as e:
                    log.error(f"Error getting user choice: {e}", exc_info=True)
                    print(f"{RED}Error reading input. Please try again.{RESET}")
                    continue

                # Server Mode
                if choice == '1':
                    # Try to set up dual-stack socket first (IPv6 that can accept IPv4)
                    server_socket = None
                    listen_port = self.public_port or random.randint(10000, 60000)
                    
                    # Try multiple socket configurations in order of preference
                    socket_configs = [
                        # IPv6 dual-stack (accepts both IPv6 and IPv4)
                        {"family": socket.AF_INET6, "addr": "::", "ipv6_only": False},
                        # IPv6 only
                        {"family": socket.AF_INET6, "addr": "::", "ipv6_only": True},
                        # IPv4 only
                        {"family": socket.AF_INET, "addr": "0.0.0.0"}
                    ]
                    
                    for config in socket_configs:
                        try:
                            if server_socket:
                                server_socket.close()
                                
                            if config["family"] == socket.AF_INET6:
                                server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                
                                # Try to set IPV6_V6ONLY
                                try:
                                    server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 
                                                           1 if config["ipv6_only"] else 0)
                                except Exception as e:
                                    log.debug(f"Could not set IPV6_V6ONLY to {config['ipv6_only']}: {e}")
                            else:
                                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                
                            # Try multiple ports if binding fails
                            max_port_attempts = 5
                            for port_attempt in range(max_port_attempts):
                                try:
                                    current_port = listen_port + port_attempt
                                    if current_port > 65535:
                                        current_port = random.randint(10000, 60000)
                                        
                                    log.info(f"Attempting to bind server socket to {config['addr']}:{current_port}")
                                    server_socket.bind((config["addr"], current_port))
                                    listen_port = current_port
                                    server_socket.listen(1)
                                    
                                    log.info(f"Server socket bound to {config['addr']}:{listen_port}")
                                    if config["family"] == socket.AF_INET6:
                                        v6_only = "IPv6-only" if config.get("ipv6_only", False) else "dual-stack"
                                        print(f"\n{GREEN}Server listening on [{config['addr']}]:{listen_port} ({v6_only}){RESET}")
                                    else:
                                        print(f"\n{GREEN}Server listening on {config['addr']}:{listen_port} (IPv4){RESET}")
                                        
                                    if self.public_ip:
                                        ip_display = f"[{self.public_ip}]" if ':' in self.public_ip else self.public_ip
                                        print(f"{MAGENTA}Your public endpoint: {ip_display}:{self.public_port}{RESET}")
                                    print(f"{CYAN}Waiting for a connection...{RESET}")
                                    
                                    break
                                    
                                except OSError as e:
                                    # If port is in use, try another
                                    if e.errno in (98, 10048):  # Address already in use
                                        log.warning(f"Port {current_port} is already in use, trying another port.")
                                        if port_attempt == max_port_attempts - 1:
                                            log.error(f"All port attempts failed for {config['addr']}")
                                            raise
                                    else:
                                        log.error(f"Failed to bind to {config['addr']}:{current_port}: {e}", exc_info=True)
                                        raise
                        
                            # Socket is ready
                            break
                            
                        except OSError as e:
                            log.warning(f"Failed to create server socket with config {config}: {e}")
                            if server_socket:
                                server_socket.close()
                                server_socket = None
                    
                    # Check if socket creation failed
                    if not server_socket:
                        print(f"{RED}Failed to create server socket with any configuration.{RESET}")
                        continue

                    try:
                        # Set non-blocking mode
                        server_socket.setblocking(False)
                        
                        loop = asyncio.get_event_loop()
                        try:
                            print(f"{YELLOW}Press Ctrl+C to cancel waiting for connection{RESET}")
                            
                            # Cross-platform async accept implementation
                            async def accept_connection_with_timeout():
                                server_socket.setblocking(True)
                                try:
                                    return await loop.run_in_executor(None, server_socket.accept)
                                finally:
                                    server_socket.setblocking(False)
                            
                            # Wait for connection with timeout
                            client_socket, client_address = await asyncio.wait_for(
                                accept_connection_with_timeout(),
                                timeout=120.0  # 2 minute timeout
                            )
                            
                            # Configure the client socket
                            client_socket.setblocking(False)
                            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                            
                            # Set TCP keepalive parameters if supported
                            try:
                                if hasattr(socket, 'TCP_KEEPIDLE'):
                                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                                if hasattr(socket, 'TCP_KEEPINTVL'):
                                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
                                if hasattr(socket, 'TCP_KEEPCNT'):
                                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                            except Exception as e:
                                log.debug(f"Could not set TCP keepalive options on client socket: {e}")

                            log.info(f"Accepted connection from {client_address}")
                            self.tcp_socket = client_socket
                            self.peer_ip = client_address[0]
                            self.peer_port = client_address[1]
                            
                            print(f"\n{GREEN}Client connected from {client_address}{RESET}")
                            
                            if server_socket:
                                server_socket.close()
                                server_socket = None

                            await self._chat_session()
                            
                        except asyncio.TimeoutError:
                            print(f"{YELLOW}No connection received within timeout period.{RESET}")
                        except asyncio.CancelledError:
                            print(f"{YELLOW}Waiting for connection was cancelled.{RESET}")
                            
                    except KeyboardInterrupt:
                        print(f"{YELLOW}Cancelled waiting for connection.{RESET}")
                    except OSError as e:
                        if e.errno in (98, 10048):  # Address already in use
                            print(f"{RED}Error: Port {listen_port} is already in use.{RESET}")
                        else:
                            print(f"{RED}Server error: {e}{RESET}")
                            log.error(f"Server socket error: {e}", exc_info=True)
                    except Exception as e:
                        print(f"{RED}Server error: {e}{RESET}")
                        log.error(f"Unexpected server error: {e}", exc_info=True)
                    finally:
                        if server_socket:
                            try:
                                server_socket.close()
                            except Exception as e:
                                log.error(f"Error closing server socket: {e}", exc_info=True)
                            server_socket = None

                # Client Mode
                elif choice == '2':
                    try:
                        peer_ip = (await self._async_input(f"\nEnter peer's IP address (IPv6 or IPv4): {RESET}")).strip()
                        if not peer_ip:
                            print(f"{RED}IP address cannot be empty.{RESET}")
                            continue
                            
                        peer_port_str = (await self._async_input(f"Enter peer's port number: {RESET}")).strip()
                        
                        try:
                            peer_port = int(peer_port_str)
                            if not (1 <= peer_port <= 65535):
                                raise ValueError("Port must be between 1 and 65535.")

                            try:
                                # Connect with retry logic
                                await self._connect_to_peer(peer_ip, peer_port)
                                print(f"{GREEN}Connected successfully!{RESET}")
                                await self._chat_session()
                                
                            except ValueError as e:
                                print(f"{RED}Invalid port number: {e}{RESET}")
                            except socket.gaierror:
                                print(f"{RED}Error: Could not resolve hostname or invalid IP address.{RESET}")
                            except ConnectionRefusedError:
                                print(f"{RED}Connection refused. Is the peer server running?{RESET}")
                            except asyncio.TimeoutError:
                                print(f"{RED}Connection timed out. Peer may be offline or behind restrictive firewall.{RESET}")
                            except OSError as e:
                                print(f"{RED}Network error: {e}{RESET}")
                                log.error(f"Network error connecting to peer: {e}", exc_info=True)
                            except Exception as e:
                                print(f"{RED}Connection error: {e}{RESET}")
                                log.error(f"Unexpected error connecting to peer: {e}", exc_info=True)
                                
                        except ValueError:
                            print(f"{RED}Invalid port number. Please enter a number between 1-65535.{RESET}")
                    except asyncio.CancelledError:
                        log.info("Client connection process cancelled")
                        print(f"{YELLOW}Connection attempt cancelled.{RESET}")
                    except Exception as e:
                        log.error(f"Error in client mode: {e}", exc_info=True)
                        print(f"{RED}Unexpected error: {e}{RESET}")

                # Retry STUN
                elif choice == '3':
                    print("Rediscovering public IP via STUN...")
                    try:
                        self.public_ip, self.public_port = await get_public_ip_port()

                        if self.public_ip:
                            if ':' in self.public_ip:
                                print(f"{GREEN}Public IPv6: [{self.public_ip}]:{self.public_port}{RESET}")
                            else:
                                print(f"{GREEN}Public IPv4: {self.public_ip}:{self.public_port}{RESET}")
                        else:
                            print(f"{RED}Could not determine public IP using STUN.{RESET}")
                            print(f"{YELLOW}You may still be able to accept incoming connections on a local network.{RESET}")
                    except Exception as e:
                        log.error(f"STUN discovery error: {e}", exc_info=True)
                        print(f"{RED}Error during STUN discovery: {e}{RESET}")

                # Exit
                elif choice == '4':
                    print(f"{YELLOW}Exiting...{RESET}")
                    break
                  
                else:
                    print(f"{RED}Invalid choice. Please enter 1, 2, 3, or 4.{RESET}")

            except KeyboardInterrupt:
                print(f"\n{YELLOW}Operation interrupted. Returning to main menu.{RESET}")
                if server_socket:
                    try:
                        server_socket.close()
                    except:
                        pass
                    server_socket = None
            except asyncio.CancelledError:
                log.info("Main connection handling loop cancelled")
                break
            except Exception as e:
                log.error(f"Unexpected error in handle_connections: {e}", exc_info=True)
                print(f"\n{RED}Unexpected error: {e}. Continuing...{RESET}")

        # Cleanup on exit
        if server_socket:
            try:
                server_socket.close()
            except Exception as e:
                log.error(f"Error closing server socket during exit: {e}", exc_info=True)
          
        self.stop_event.set()
        
        # Cleanup tasks
        for task_name, task in [("receive_task", self.receive_task), ("heartbeat_task", self.heartbeat_task)]:
            if task and not task.done():
                try:
                    task.cancel()
                    await asyncio.sleep(0.1)
                except Exception as e:
                    log.error(f"Error cancelling {task_name}: {e}", exc_info=True)

    async def start(self):
        """
        Start the P2P chat application.
        
        Initializes the application, discovers the public IP endpoint using STUN,
        and presents the main menu to the user.
        """
        print(f"{CYAN}--- Simple P2P Chat ---{RESET}")
        print("Discovering public IP via STUN...")
        
        try:
            self.public_ip, self.public_port = await get_public_ip_port()

            if self.public_ip:
                if ':' in self.public_ip:
                    print(f"{GREEN}Public IPv6: [{self.public_ip}]:{self.public_port}{RESET}")
                else:
                    print(f"{GREEN}Public IPv4: {self.public_ip}:{self.public_port}{RESET}")
            else:
                print(f"{YELLOW}Could not determine public IP using STUN.{RESET}")
                print(f"{YELLOW}You may still be able to accept incoming connections on a local network.{RESET}")
                
            await self.handle_connections()
            
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Program interrupted by user.{RESET}")
        except Exception as e:
            print(f"\n{RED}Unhandled error: {e}{RESET}")
            log.error(f"Unhandled error in main loop: {e}", exc_info=True)
        finally:
            # Final cleanup
            if self.tcp_socket:
                try:
                    self.tcp_socket.close()
                except:
                    pass


if __name__ == "__main__":
    # Set signal handlers for graceful exit
    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda signum, frame: sys.exit(0))
    except (AttributeError, ValueError):
        pass
        
    chat_app = SimpleP2PChat()
    try:
        asyncio.run(chat_app.start())
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        log.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n{RED}Fatal error: {e}{RESET}")
    finally:
        if chat_app.tcp_socket:
            try:
                chat_app.tcp_socket.close()
            except:
                pass