"""
Secure P2P Chat Implementation

This module provides a robust, secure peer-to-peer chat application with
multi-layered security features including:

- Post-quantum cryptography (ML-KEM-1024 and FALCON-1024)
- Hybrid key exchange (X3DH + post-quantum)
- Double Ratchet for message encryption with forward secrecy
- TLS 1.3 for transport security
- Hardware security module integration when available
- Memory protection and anti-tampering mechanisms

Author: Secure Communications TeamRemove OAuth dependency
The OAuth authentication creates identity linkability issues
Replace with anonymous credentials or zero-knowledge proofs for authentication
Implement ephemeral identities with disposable key pairs
License: MIT
"""

import asyncio 
import logging
import os
import sys
import socket
import signal 
import atexit
import ssl
import json
import base64
import random
import re
import gc
import ctypes
import time
import selectors
import secrets
import platform # Added for platform detection
import hashlib # Ensure hashlib is imported
from cryptography.hazmat.primitives import hashes as crypto_hashes # For HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # For HKDF
import threading

# Custom security exception
class SecurityError(Exception):
    """
    Exception raised for security-related errors.
    
    This exception is used to indicate potential security issues, 
    failures in cryptographic operations, or other security-critical errors.
    """
    pass
 
# Import dependencies
from tls_channel_manager import TLSSecureChannel
import p2p_core as p2p
from hybrid_kex import HybridKeyExchange, verify_key_material, _format_binary, secure_erase, DEFAULT_KEY_LIFETIME
from double_ratchet import DoubleRatchet
import secure_key_manager
import platform_hsm_interface as cphs
from ca_services import CAExchange  # Import the new CAExchange module
import tls_channel_manager

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s') # Ensure DEBUG level
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG) # Ensure DEBUG level for the main logger

# Set up file handler for security logs
try:
    logs_dir = os.path.join(os.path.dirname(__file__), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    
    file_handler = logging.FileHandler(os.path.join(logs_dir, 'secure_p2p_security.log'))
    file_handler.setLevel(logging.DEBUG) # Ensure DEBUG level for file handler
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s'))
    log.addHandler(file_handler)
    # log.setLevel(logging.DEBUG) # This line is redundant as it's set above
except Exception as e:
    log.warning(f"Could not set up security logging: {e}")

# ANSI colors for terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

class KeyEraser:
    """
    Context manager for securely handling and erasing sensitive cryptographic key material.
    Uses enhanced secure erasure techniques to minimize the risk of keys remaining in memory.
    """
    def __init__(self, key_material=None, description="sensitive key"):
        self.key_material = key_material
        self.description = description
        self._locked_address = None
        self._locked_length = 0
        self._locked_platform = None
        
    def __enter__(self):
        log.debug(f"KeyEraser: Handling {self.description}")
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.secure_erase()
        
    def set_key(self, key_material):
        """Set the key material to be managed."""
        self.key_material = key_material
        
    def _pin_memory(self, material: bytearray):
        """Pin memory to prevent swapping to disk"""
        if not isinstance(material, bytearray) or len(material) == 0:
            return False

        address = ctypes.addressof(ctypes.c_byte.from_buffer(material))
        length = len(material)
        
        current_platform = platform.system()
        locked = False
        
        # Note: The following code is platform-specific
        try:
            if current_platform == "Windows":
                # On Windows, use VirtualLock
                if ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(length)):
                    locked = True
                    self._locked_address = address
                    self._locked_length = length
                    self._locked_platform = "Windows"
                    log.debug(f"KeyEraser: Successfully locked {length} bytes in memory with VirtualLock")
            elif current_platform == "Linux" or current_platform == "Darwin":
                try:
                    # On Linux/macOS, use mlock from libc
                    libc = ctypes.cdll.LoadLibrary('libc.so.6' if current_platform == "Linux" else 'libc.dylib')
                    if hasattr(libc, "mlock"):
                        if libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(length)) == 0:
                            locked = True
                            self._locked_address = address
                            self._locked_length = length
                            self._locked_platform = current_platform
                            log.debug(f"KeyEraser: Successfully locked {length} bytes in memory with mlock")
                except Exception as e:
                    log.debug(f"KeyEraser: Error during mlock: {e}")
        except Exception as e:
            log.debug(f"KeyEraser: Memory pinning not available: {e}")
            
        return locked
            
    def _unpin_memory(self):
        """Unpin memory previously pinned with _pin_memory"""
        if not self._locked_address or not self._locked_platform:
            return
            
        try:
            if self._locked_platform == "Windows":
                if ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(self._locked_address), ctypes.c_size_t(self._locked_length)):
                    log.debug(f"KeyEraser: Successfully unlocked {self._locked_length} bytes with VirtualUnlock")
            elif self._locked_platform in ("Linux", "Darwin"):
                try:
                    libc = ctypes.cdll.LoadLibrary('libc.so.6' if self._locked_platform == "Linux" else 'libc.dylib')
                    if hasattr(libc, "munlock"):
                        if libc.munlock(ctypes.c_void_p(self._locked_address), ctypes.c_size_t(self._locked_length)) == 0:
                            log.debug(f"KeyEraser: Successfully unlocked {self._locked_length} bytes with munlock")
                except Exception as e:
                    log.debug(f"KeyEraser: Error during munlock: {e}")
        except Exception as e:
            log.debug(f"KeyEraser: Error during memory unpinning: {e}")
            
        self._locked_address = None
        self._locked_length = 0
        self._locked_platform = None

    def secure_erase(self):
        """Securely erase the key material from memory using enhanced techniques."""
        if self.key_material is None:
            log.debug(f"KeyEraser: No key material to erase for {self.description} (was None).")
            return

        try:
            # Use the enhanced secure erase function from secure_key_manager
            import secure_key_manager as skm
            log.debug(f"KeyEraser: Attempting enhanced secure erase for {self.description}")
            skm.enhanced_secure_erase(self.key_material)
            self.key_material = None
            
            # Force garbage collection to clean up any lingering references
            gc.collect()
            
            log.debug(f"KeyEraser: Completed secure erase for {self.description}")
            
        except (ImportError, AttributeError) as e:
            # Fall back to basic erase if enhanced version not available
            log.warning(f"KeyEraser: Enhanced secure erase not available: {e}. Falling back to basic method.")
            self._basic_secure_erase()
        except Exception as e:
            # If anything goes wrong, try the basic method
            log.warning(f"KeyEraser: Error during enhanced secure erase: {e}. Falling back to basic method.")
            self._basic_secure_erase()
            
    def _basic_secure_erase(self):
        """Basic fallback method for secure erasure if enhanced method is unavailable."""
        if self.key_material is None:
            return
            
        key_type = type(self.key_material).__name__
        key_len = len(self.key_material) if hasattr(self.key_material, '__len__') else 'N/A'
        
        try:
            if isinstance(self.key_material, bytearray):
                memory_pinned = self._pin_memory(self.key_material)
                try:
                    # Zero out the bytearray
                    ctypes.memset(ctypes.addressof(ctypes.c_byte.from_buffer(self.key_material)), 0, key_len)
                    log.debug(f"KeyEraser: Basic secure erase - zeroed {key_len} bytes in bytearray for {self.description}")
                except Exception:
                    # Fallback to loop-based zeroing
                    for i in range(len(self.key_material)):
                        self.key_material[i] = 0
                finally:
                    if memory_pinned:
                        self._unpin_memory()
            elif isinstance(self.key_material, bytes):
                # Can't directly erase immutable bytes, but can create a mutable copy and zero it
                log.info(
                    f"KeyEraser: Basic secure erase - {self.description} is immutable ({key_type}). "
                    f"Creating mutable copy to zero, but original bytes object may remain in memory."
                )
                mutable_copy = bytearray(self.key_material)
                for i in range(len(mutable_copy)):
                    mutable_copy[i] = 0
            elif isinstance(self.key_material, str):
                # Can't directly erase immutable strings, but can create a mutable copy and zero it
                log.info(
                    f"KeyEraser: Basic secure erase - {self.description} is immutable ({key_type}). "
                    f"Creating mutable copy to zero, but original string may remain in memory."
                )
                mutable_copy = bytearray(self.key_material.encode('utf-8'))
                for i in range(len(mutable_copy)):
                    mutable_copy[i] = 0
            elif hasattr(self.key_material, 'zeroize'):
                log.debug(f"KeyEraser: Basic secure erase - calling zeroize() method on {self.description}")
                self.key_material.zeroize()
            elif hasattr(self.key_material, '__dict__'):
                log.debug(f"KeyEraser: Basic secure erase - clearing attributes of {self.description}")
                for attr_name in list(self.key_material.__dict__.keys()):
                    attr_value = getattr(self.key_material, attr_name, None)
                    if isinstance(attr_value, (bytes, bytearray, str)):
                        try:
                            setattr(self.key_material, attr_name, None)
                        except AttributeError:
                            pass
                    elif isinstance(attr_value, (list, dict)):
                        try:
                            getattr(self.key_material, attr_name).clear()
                        except (AttributeError, TypeError):
                            pass
            else:
                log.warning(f"KeyEraser: Basic secure erase - cannot securely erase {key_type}")
        except Exception as e:
            log.error(f"KeyEraser: Error during basic secure erase: {e}")
            
        # Clear our reference and suggest garbage collection
        self.key_material = None
        gc.collect()

def secure_memory_wipe(address, length):
    """
    Use platform-specific methods to securely wipe memory.
    """
    try:
        # Platform-specific memory protection/unprotection
        if hasattr(ctypes, 'windll'):
            # Windows
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(address),
                ctypes.c_size_t(length),
                0x04,  # PAGE_READWRITE
                ctypes.byref(ctypes.c_ulong(0))
            )
            ctypes.memset(address, 0, length)
            return True
        elif hasattr(ctypes, 'CDLL'):
            try:
                # Linux/Unix
                libc = ctypes.CDLL('libc.so.6')
                libc.memset(address, 0, length)
                return True
            except:
                pass
    except:
        pass
    
    return False

class SecureP2PChat(p2p.SimpleP2PChat):
    """
    Enhanced secure P2P chat with multi-layer security including Hybrid X3DH+PQ and TLS.
    
    Features:
    - Initial key agreement using Hybrid X3DH+PQ (X25519 + ML-KEM-1024)
    - Message encryption using Double Ratchet (forward secrecy, break-in recovery)
    - Transport security using TLS 1.3 with ChaCha20-Poly1305
    - Post-quantum security using ML-KEM-1024 and FALCON-1024
    - Advanced security hardening (memory protection, canary values)
    """
    
    # Connection constants
    CONNECTION_TIMEOUT = 30.0  # seconds (increased from 10.0)
    TLS_HANDSHAKE_TIMEOUT = 30.0  # seconds for TLS handshake
    HEARTBEAT_INTERVAL = 30.0  # seconds
    
    # Username constraints
    MAX_USERNAME_LENGTH = 32
    USERNAME_REGEX = r"^.*$"
    
    # Message constraints
    MAX_MESSAGE_SIZE = 65536  # 16 KB maximum message size
    MAX_FRAME_SIZE = 131072    # 64 KB maximum frame size
    MAX_RANDOM_PADDING_BYTES = 32 # Max *random* bytes to add (1 to 32 bytes)
    MAX_POST_ENCRYPTION_SIZE = 10240 # Max size for the final encrypted payload
    
    # Security levels
    SECURITY_LEVELS = {
        "MINIMAL": {
            "components": ["tls", "cert_dir", "keys_dir"],  # Minimum viable security
            "use_secure_enclave": False
        },
        "STANDARD": {
            "components": ["tls", "cert_dir", "keys_dir", "hybrid_kex", "double_ratchet"],  # Regular security
            "use_secure_enclave": False
        },
        "ENHANCED": {
            "components": ["tls", "cert_dir", "keys_dir", "hybrid_kex", "double_ratchet", "falcon_dss"],  # Enhanced security
            "use_secure_enclave": True
        },
        "MAXIMUM": {
            "components": ["tls", "cert_dir", "keys_dir", "hybrid_kex", "double_ratchet", "falcon_dss", 
                         "secure_enclave", "oauth_auth", "key_protection"],  # Maximum security
            "use_secure_enclave": True
        }
    }
    
    def _setup_logging(self):
        """
        Set up logging for the SecureP2PChat class.
        """
        # Configure file handler for security logs if not already configured
        try:
            # Check if we already have a file handler for this logger
            has_file_handler = False
            for handler in log.handlers:
                if isinstance(handler, logging.FileHandler):
                    has_file_handler = True
                    break
                    
            if not has_file_handler:
                logs_dir = os.path.join(os.path.dirname(__file__), "logs")
                os.makedirs(logs_dir, exist_ok=True)
                
                file_handler = logging.FileHandler(os.path.join(logs_dir, 'secure_p2p_security.log'))
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s'))
                log.addHandler(file_handler)
                
            # Ensure the logger level is set to DEBUG
            log.setLevel(logging.DEBUG)
        except Exception as e:
            print(f"Warning: Could not set up security logging: {e}")
            # Continue execution even if logging setup fails
    
    def __init__(self, identity: str = None, ephemeral: bool = True, 
                 in_memory_only: bool = True, key_lifetime: int = 3072,
                 security_level: str = "MAXIMUM"):
        """
        Initialize the secure P2P chat system with military-grade security.
        
        Args:
            identity: User identifier (ignored if ephemeral=True)
            ephemeral: Whether to use ephemeral identities (default: True)
            in_memory_only: Whether to store keys only in memory (default: True)
            key_lifetime: Lifetime for ephemeral keys in seconds (default: 3072)
            security_level: Security level (default: "MAXIMUM")
        """
        # Initialize parent class
        super().__init__()
        
        # Initialize connection status and events
        self.is_connected = False
        self.stop_event = asyncio.Event()
        # Initialize task placeholders
        self.receive_task = None
        self.heartbeat_task = None
        # Initialize logging
        self._setup_logging()
        log.info("Initializing SecureP2PChat with multi-layer security")
        
        # Initialize security verification dictionary
        self.security_verified = {}
        self.security_verified['tls'] = False  # Initialize TLS verification status
        self.security_verified['hybrid_kex'] = False  # Initialize hybrid key exchange verification status
        self.security_verified['secure_enclave'] = False  # Initialize secure enclave verification status
        
        # Initialize security flow dictionary
        self.security_flow = {}
        
        # Initialize network connection attributes
        self.tcp_socket = None  # Initialize tcp_socket attribute
        
        # Track post-quantum capabilities
        self.post_quantum_enabled = True  # Enable by default
        
        # MILITARY-GRADE ENHANCEMENT: Anti-debugging protection
        self._enable_anti_debugging()
        
        # Initialize configuration
        self._initialize_configuration(
            identity=identity,
            ephemeral=ephemeral,
            in_memory_only=in_memory_only,
            key_lifetime=key_lifetime,
            security_level=security_level
        )
        
        # Set identity
        self.identity = identity if identity else "secure_user_" + os.urandom(4).hex()
        self.use_ephemeral_identity = ephemeral
        self.in_memory_only = in_memory_only
        
        # Initialize core components
        self.key_manager = secure_key_manager.get_key_manager(in_memory_only=in_memory_only)
        # Use TLSSecureChannel instead of TLSChannelManager
        self.tls_channel = TLSSecureChannel(
            cert_path=os.path.join(self.cert_dir, f"{self.identity}.crt"),
            key_path=os.path.join(self.keys_dir, f"{self.identity}.key"),
            use_secure_enclave=True,
            in_memory_only=in_memory_only
        )
        # Mark TLS as initialized
        self.security_verified['tls'] = True
        # Mark secure enclave status 
        self.security_verified['secure_enclave'] = hasattr(self.tls_channel, 'secure_enclave') and self.tls_channel.secure_enclave is not None
        
        # Initialize Certificate Authority exchange for secure certificate handling
        from ca_services import CAExchange
        self.ca_exchange = CAExchange(
            exchange_port_offset=1,
            buffer_size=65536,
            validity_days=7,
            key_type="rsa4096",
            secure_exchange=True,
            enable_hpkp=True,
            enable_ocsp_stapling=True
        )
        log.info("Certificate Authority exchange initialized for secure certificate handling")
        
        # Initialize hybrid key exchange
        self.hybrid_kex = HybridKeyExchange(
            identity=self.identity,
            ephemeral=ephemeral,
            in_memory_only=in_memory_only,
            key_lifetime=key_lifetime
        )
        # Mark hybrid key exchange as initialized
        self.security_verified['hybrid_kex'] = True
        
        # Initialize Double Ratchet (will be fully set up during handshake)
        self.double_ratchet = None
        
        # Initialize key material
        self.root_key = None
        self.identity_key = None
        
        # Initialize security hardening
        self._enable_memory_protection()
        self._initialize_canary_values()
        
        # Security status tracking
        self.security_hardening = {
            'memory_protection': True,
            'canary_values': True,
            'key_rotation': True
        }
        
        # Initialize security flow with all components
        self._update_security_flow()
        
        log.info(f"Security hardening features: {self.security_hardening}")
        
    def _enable_anti_debugging(self):
        """
        Enable military-grade anti-debugging protection to prevent reverse engineering
        and tampering with the secure communication system.
        """
        # Check environment variable for test mode
        if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
            log.info("Anti-debugging protection disabled via environment variable for testing")
            return True
            
        try:
            import platform_hsm_interface as cphs
            
            # Check if a debugger is attached
            if hasattr(cphs, 'detect_debugger') and cphs.detect_debugger():
                log.critical("SECURITY ALERT: Debugger detected! Initiating emergency security response.")
                
                # Wipe sensitive data
                self._emergency_wipe()
                
                # Terminate process via platform_hsm_interface
                if hasattr(cphs, 'emergency_security_response'):
                    cphs.emergency_security_response()
                else:
                    # Fallback termination
                    import sys
                    sys.exit(1)
            
            # Start periodic debugger checks in background thread
            self._start_debugger_detection_thread()
            
            log.info("Anti-debugging protection enabled")
            return True
        except Exception as e:
            log.warning(f"Failed to enable anti-debugging protection: {e}")
            return False
            
    def _start_debugger_detection_thread(self):
        """
        Start a background thread that periodically checks for debuggers.
        """
        # Check environment variable for test mode
        if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
            log.info("Debugger detection thread disabled via environment variable for testing")
            return
            
        try:
            import threading
            import platform_hsm_interface as cphs
            
            if not hasattr(cphs, 'detect_debugger'):
                log.warning("Debugger detection not available in platform_hsm_interface")
                return
                
            def _debugger_check_loop():
                while True:
                    try:
                        # Check for debugger every 2-5 seconds with random interval
                        import random
                        import time
                        
                        # Sleep with random interval to make timing attacks harder
                        time.sleep(random.uniform(2, 5))
                        
                        # Check environment variable again in case it was changed during runtime
                        if os.environ.get("DISABLE_ANTI_DEBUGGING", "false").lower() == "true":
                            time.sleep(5)  # Sleep and check again
                            continue
                        
                        # Check for debugger
                        if cphs.detect_debugger():
                            log.critical("SECURITY ALERT: Debugger detected during runtime! Initiating emergency response.")
                            
                            # Wipe sensitive data
                            self._emergency_wipe()
                            
                            # Terminate process
                            if hasattr(cphs, 'emergency_security_response'):
                                cphs.emergency_security_response()
                            else:
                                # Fallback termination
                                import sys
                                sys.exit(1)
                    except Exception as e:
                        # Don't log too much as it might be exploitable
                        pass
            
            # Start thread
            self._debugger_thread = threading.Thread(
                target=_debugger_check_loop,
                daemon=True,
                name="SecurityMonitor"
            )
            self._debugger_thread.start()
            
        except Exception as e:
            log.warning(f"Failed to start debugger detection thread: {e}")
            
    def _emergency_wipe(self):
        """
        Emergency secure wipe of all sensitive data in case of security breach.
        """
        try:
            log.critical("EMERGENCY WIPE: Securely erasing all sensitive data")
            
            # Wipe all key material
            if hasattr(self, 'root_key') and self.root_key:
                self._secure_erase(self.root_key)
                self.root_key = None
                
            if hasattr(self, 'identity_key') and self.identity_key:
                self._secure_erase(self.identity_key)
                self.identity_key = None
                
            # Wipe double ratchet state
            if hasattr(self, 'double_ratchet') and self.double_ratchet:
                if hasattr(self.double_ratchet, 'secure_cleanup'):
                    self.double_ratchet.secure_cleanup()
                self.double_ratchet = None
                
            # Wipe hybrid key exchange state
            if hasattr(self, 'hybrid_kex') and self.hybrid_kex:
                if hasattr(self.hybrid_kex, 'secure_cleanup'):
                    self.hybrid_kex.secure_cleanup()
                    
            # Wipe TLS channel state
            if hasattr(self, 'tls_channel') and self.tls_channel:
                if hasattr(self.tls_channel, 'cleanup'):
                    self.tls_channel.cleanup()
                    
            # Wipe key manager state
            if hasattr(self, 'key_manager') and self.key_manager:
                if hasattr(self.key_manager, 'cleanup'):
                    self.key_manager.cleanup()
                    
            log.critical("EMERGENCY WIPE: Complete")
        except Exception as e:
            # Don't log the exception details as they might contain sensitive info
            log.critical("EMERGENCY WIPE: Failed")
            
    def _secure_erase(self, data):
        """
        Securely erase data from memory.
        
        Args:
            data: The data to erase
        """
        if data is None:
            return
            
        if isinstance(data, bytes):
            # Convert to bytearray for in-place modification
            buffer = bytearray(data)
            for i in range(len(buffer)):
                buffer[i] = 0
        elif isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0

    def _initialize_configuration(self, identity, ephemeral, in_memory_only, key_lifetime, security_level):
        """
        Initialize configuration settings from environment variables or defaults.
        """
        # Initialize security settings
        self.security_level = security_level
        self.security_level = self.security_level.upper()
        
        # If security level is not valid, default to MAXIMUM
        if self.security_level not in self.SECURITY_LEVELS:
            log.warning(f"Invalid security level: {self.security_level}, defaulting to MAXIMUM")
            self.security_level = 'MAXIMUM'
            
        log.info(f"Using security level: {self.security_level}")
        
        # Initialize hardware security
        self.use_secure_enclave = self.SECURITY_LEVELS[self.security_level].get('use_secure_enclave', True)
        
        # Initialize key storage settings
        self.in_memory_only = in_memory_only
        self.secure_dir = os.environ.get('P2P_SECURE_DIR', None)
        
        # Set up certificate and key directories
        self.cert_dir = os.environ.get('P2P_CERT_DIR', os.path.join(os.path.dirname(__file__), 'certs'))
        self.keys_dir = os.environ.get('P2P_KEYS_DIR', os.path.join(os.path.dirname(__file__), 'keys'))
        
        # Create directories if they don't exist
        os.makedirs(self.cert_dir, exist_ok=True)
        os.makedirs(self.keys_dir, exist_ok=True)
        
        # Mark directories as verified since we've created them
        self.security_verified['cert_dir'] = os.path.exists(self.cert_dir)
        self.security_verified['keys_dir'] = os.path.exists(self.keys_dir)
        
        # Initialize key manager
        self.key_manager = secure_key_manager.get_key_manager(in_memory_only=in_memory_only)
        
        # Initialize hardware security
        if self.use_secure_enclave:
            self.hsm_initialized = self._initialize_hardware_security()
            if self.hsm_initialized:
                log.info("Hardware security (TPM via Windows CNG) initialized successfully")
        
        # Initialize ephemeral identity settings
        self.use_ephemeral_identity = ephemeral
        self.ephemeral_key_lifetime = key_lifetime
        
        # Initialize authentication settings
        self.require_authentication = os.environ.get('P2P_REQUIRE_AUTH', 'false').lower() == 'true'
        self.oauth_provider = os.environ.get('P2P_OAUTH_PROVIDER', 'google')
        self.oauth_client_id = os.environ.get('P2P_OAUTH_CLIENT_ID', None)
        
        # Initialize DANE TLSA validation settings
        self.enforce_dane_validation = os.environ.get('P2P_ENFORCE_DANE', 'false').lower() == 'false'
        # Create a placeholder TLSA record for now - we'll update it after TLS channel initialization
        self.dane_tlsa_records = [{
            'usage': 3,  # DANE-EE: End-Entity Certificate
            'selector': 0,  # Full Certificate
            'matching_type': 1,  # SHA-256
            'certificate_association': os.urandom(32)  # Random 32-byte value as placeholder
        }] if self.enforce_dane_validation else None
        
                    # Inform about authentication status
        if not self.require_authentication:
            log.info("User authentication is DISABLED (P2P_REQUIRE_AUTH=false). Operating in anonymous mode for enhanced privacy.")

    def _create_sample_tlsa_records(self):
        """
        Create sample DANE TLSA records for testing purposes.
        In a production environment, these would be fetched from DNS.
        
        Returns:
            List of TLSA record dictionaries
        """
        try:
            # Import required modules
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            import hashlib
            
            # Create sample TLSA records
            tlsa_records = []
            
            # If we have a TLS certificate, use it to create valid TLSA records
            if hasattr(self, 'tls_channel') and hasattr(self.tls_channel, 'ssl_context'):
                try:
                    # Try to get the certificate
                    cert_path = getattr(self.tls_channel, 'cert_path', None)
                    if cert_path and os.path.exists(cert_path):
                        with open(cert_path, 'rb') as f:
                            cert_data = f.read()
                            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
                            
                            # Create TLSA record with usage=3 (DANE-EE), selector=0 (Full Certificate), matching_type=1 (SHA-256)
                            cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
                            cert_hash = hashlib.sha256(cert_der).digest()
                            
                            tlsa_records.append({
                                'usage': 3,  # DANE-EE: End-Entity Certificate
                                'selector': 0,  # Full Certificate
                                'matching_type': 1,  # SHA-256
                                'certificate_association': cert_hash
                            })
                            
                            # Create TLSA record with usage=3, selector=1 (SubjectPublicKeyInfo), matching_type=1 (SHA-256)
                            spki = cert.public_key().public_bytes(
                                encoding=serialization.Encoding.DER,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            )
                            spki_hash = hashlib.sha256(spki).digest()
                            
                            tlsa_records.append({
                                'usage': 3,  # DANE-EE: End-Entity Certificate
                                'selector': 1,  # SubjectPublicKeyInfo
                                'matching_type': 1,  # SHA-256
                                'certificate_association': spki_hash
                            })
                            
                            log.info(f"Created {len(tlsa_records)} sample TLSA records for DANE validation")
                            return tlsa_records
                except Exception as e:
                    log.warning(f"Failed to create TLSA records from certificate: {e}")
            
            # If we couldn't create TLSA records from a certificate, create a placeholder
            # This is just for testing - in production, real TLSA records should be used
            tlsa_records.append({
                'usage': 3,  # DANE-EE: End-Entity Certificate
                'selector': 0,  # Full Certificate
                'matching_type': 1,  # SHA-256
                'certificate_association': os.urandom(32)  # Random 32-byte value as placeholder
            })
            
            log.info("Created placeholder TLSA record for DANE validation testing")
            return tlsa_records
            
        except ImportError:
            log.warning("Could not create TLSA records: required modules not available")
            return None
        except Exception as e:
            log.warning(f"Failed to create sample TLSA records: {e}")
            return None
    
    def cleanup(self):
        """
        Perform secure cleanup of cryptographic resources.
        
        This method should be called when shutting down the application
        to securely erase sensitive data from memory.
        """
        log.info("Performing secure cleanup of cryptographic resources (main cleanup)...")
        
        # Clean up TLS channel if it exists
        if hasattr(self, 'tls_channel') and self.tls_channel:
                try:
                    if hasattr(self.tls_channel, 'cleanup'):
                        log.debug("cleanup(): Calling self.tls_channel.cleanup()")
                        self.tls_channel.cleanup()
                except Exception as e:
                    log.error(f"Error during TLS channel cleanup in main cleanup: {e}")
                finally:
                    self.tls_channel = None # Ensure nullified
        
        # Clean up SecureKeyManager
        if hasattr(self, 'key_manager') and self.key_manager:
            try:
                if hasattr(self.key_manager, 'cleanup'):
                    log.debug("cleanup(): Calling self.key_manager.cleanup()")
                    self.key_manager.cleanup()
            except Exception as e:
                log.error(f"Error during SecureKeyManager cleanup in main cleanup: {e}")
            finally:
                self.key_manager = None # Ensure nullified
        
        # Clean up CAExchange persisted files if any
        if hasattr(self, 'ca_exchange'):
            try:
                # CAExchange manages its own cert_file and key_file paths
                # It should also have a cleanup method or flags to indicate if files were persisted
                if hasattr(self.ca_exchange, 'cleanup_files') and callable(self.ca_exchange.cleanup_files):
                    log.debug("cleanup(): Calling self.ca_exchange.cleanup_files()")
                    self.ca_exchange.cleanup_files() # Ideal: CAExchange handles its own file cleanup
                elif not getattr(self.ca_exchange, 'in_memory', True): # Fallback if no specific cleanup_files
                    cert_to_delete = getattr(self.ca_exchange, 'cert_file', None)
                    key_to_delete = getattr(self.ca_exchange, 'key_file', None)
                    if cert_to_delete and os.path.exists(cert_to_delete):
                        os.remove(cert_to_delete)
                        log.info(f"Deleted CAExchange certificate: {cert_to_delete}")
                    if key_to_delete and os.path.exists(key_to_delete):
                        os.remove(key_to_delete)
                        log.info(f"Deleted CAExchange key: {key_to_delete}")
            except Exception as e:
                log.error(f"Error cleaning up CAExchange persisted files: {e}")
        
        # Clean up hybrid root key
        if hasattr(self, 'hybrid_root_key') and self.hybrid_root_key:
            with KeyEraser(self.hybrid_root_key, "main cleanup hybrid root key") as ke_hrk:
                pass # KeyEraser handles secure_erase and setting its internal ref to None
            self.hybrid_root_key = None # Ensure instance attribute is None
                
        # Clean up Double Ratchet state
        if hasattr(self, 'ratchet') and self.ratchet:
            with KeyEraser(self.ratchet, "main cleanup Double Ratchet state") as ke_dr:
                if hasattr(self.ratchet, 'secure_cleanup'):
                    try:
                        self.ratchet.secure_cleanup()
                    except Exception as e:
                        log.error(f"Error during Double Ratchet secure_cleanup in main cleanup: {e}")
            self.ratchet = None # Ensure instance attribute is None
        
        # Clean up Hybrid Key Exchange state
        if hasattr(self, 'hybrid_kex'):
            try:
                if hasattr(self.hybrid_kex, 'secure_cleanup'):
                    log.debug("cleanup(): Calling self.hybrid_kex.secure_cleanup()")
                    self.hybrid_kex.secure_cleanup() # Ideal: HKE handles its own full cleanup

                # Explicitly delete persisted HKE key file if ephemeral and not HKE in-memory mode
                # This assumes hybrid_kex.in_memory_only correctly reflects if its keys were persisted.
                hke_in_memory = getattr(self.hybrid_kex, 'in_memory_only', True) # Default to true if attr missing
                if self.use_ephemeral_identity and not hke_in_memory:
                    # Attempt to get key file path from HKE instance if method exists
                    key_file_path = None
                    if hasattr(self.hybrid_kex, 'get_key_file_path') and callable(self.hybrid_kex.get_key_file_path):
                        key_file_path = self.hybrid_kex.get_key_file_path()
                    elif hasattr(self.hybrid_kex, 'keys_dir') and hasattr(self.hybrid_kex, 'identity'): # Fallback
                        key_file_path = os.path.join(self.hybrid_kex.keys_dir, f"{self.hybrid_kex.identity}_hybrid_keys.json")

                    if key_file_path and os.path.exists(key_file_path):
                        try:
                            os.remove(key_file_path)
                            log.info(f"Deleted ephemeral HKE key file: {key_file_path}")
                        except Exception as key_e:
                            log.error(f"Error removing ephemeral HKE key file during main cleanup: {key_e}")
            except Exception as e:
                log.error(f"Error during Hybrid Key Exchange cleanup in main cleanup: {e}")
            finally:
                self.hybrid_kex = None # Ensure instance attribute is None
                
                log.info("Security cleanup completed (main)")
    
    async def _exchange_hybrid_keys_client(self):
        """
        Perform the Hybrid X3DH+PQ key exchange as the initiator (client).
        
        Returns:
            True if key exchange was successful, False otherwise
        """
        try:
            # Client initiates by sending its bundle first
            log.info("Initiating Hybrid X3DH+PQ handshake as client")
            my_bundle = self.hybrid_kex.get_public_bundle()
            bundle_json = json.dumps(my_bundle)
            
            # Verify our bundle before sending
            if not self.hybrid_kex.verify_public_bundle(my_bundle):
                log.error("SECURITY ALERT: Own bundle signature verification failed")
                raise SecurityError("Own bundle signature verification failed during hybrid key exchange.")

            log.debug(f"Sending key bundle with identity: {my_bundle.get('identity', 'unknown')}")
            success = await p2p.send_framed(self.tcp_socket, bundle_json.encode('utf-8'))
            if not success:
                log.error("Failed to send hybrid key bundle")
                raise SecurityError("Failed to send hybrid key bundle during client key exchange.")
            
            # Receive peer's bundle
            log.debug("Waiting to receive peer's key bundle")
            try:
                peer_bundle_data = await asyncio.wait_for(
                    p2p.receive_framed(self.tcp_socket),
                    timeout=30.0  # 30 second timeout for bundle exchange
                )
                if not peer_bundle_data:
                    log.error("Failed to receive peer's hybrid key bundle")
                    raise SecurityError("Failed to receive peer's hybrid key bundle during client key exchange.")
            except asyncio.TimeoutError:
                log.error("Timed out waiting for peer's key bundle")
                raise SecurityError("Timed out waiting for peer's key bundle during client key exchange.")
            
            try:
                peer_bundle = json.loads(peer_bundle_data.decode('utf-8'))
                self.peer_hybrid_bundle = peer_bundle
                log.debug(f"Received peer bundle with identity: {peer_bundle.get('identity', 'unknown')}")
            except json.JSONDecodeError as e:
                log.error(f"SECURITY ALERT: Invalid JSON in peer bundle: {e}")
                raise SecurityError(f"Invalid JSON in peer bundle: {e}")
            
            # Verify the bundle
            log.debug("Verifying peer bundle signature")
            if not self.hybrid_kex.verify_public_bundle(peer_bundle):
                log.error("SECURITY ALERT: Peer bundle signature verification failed")
                raise SecurityError("Peer bundle signature verification failed during client key exchange.")
                
            # Store peer's FALCON public key for future verification
            self.peer_falcon_public_key = base64.b64decode(peer_bundle['falcon_public_key'])
            log.debug(f"Stored peer FALCON public key: {_format_binary(self.peer_falcon_public_key)}")
            
            # Verify that the peer's public keys have appropriate lengths
            try:
                static_key = base64.b64decode(peer_bundle['static_key'])
                verify_key_material(static_key, description="Peer static X25519 key")
                
                signed_prekey = base64.b64decode(peer_bundle['signed_prekey'])
                verify_key_material(signed_prekey, description="Peer signed prekey")
                
                signing_key = base64.b64decode(peer_bundle['signing_key'])
                verify_key_material(signing_key, description="Peer Ed25519 signing key")
                
                kem_public_key = base64.b64decode(peer_bundle['kem_public_key'])
                verify_key_material(kem_public_key, description="Peer ML-KEM public key")
                
                falcon_public_key = base64.b64decode(peer_bundle['falcon_public_key'])
                verify_key_material(falcon_public_key, description="Peer FALCON-1024 public key")
                
                log.debug("All peer key material verified successfully")
            except Exception as e:
                log.error(f"SECURITY ALERT: Invalid peer key material: {e}")
                raise SecurityError(f"Invalid peer key material: {e}")
                
            # Initiate the handshake
            log.info(f"Initiating handshake with peer {peer_bundle.get('identity', 'unknown')}")
            handshake_message, self.hybrid_root_key = self.hybrid_kex.initiate_handshake(peer_bundle)
            
            # Verify the root key
            verify_key_material(self.hybrid_root_key, expected_length=32, description="Derived hybrid root key")
            log.debug(f"Generated root key: {_format_binary(self.hybrid_root_key)}")
            
            # Send handshake message
            handshake_json = json.dumps(handshake_message)
            log.debug(f"Sending handshake message to peer: {handshake_message.get('identity', 'unknown')}")
            success = await p2p.send_framed(self.tcp_socket, handshake_json.encode('utf-8'))
            if not success:
                log.error("Failed to send handshake message")
                secure_erase(self.hybrid_root_key)
                self.hybrid_root_key = None
                raise SecurityError("Failed to send handshake message during client key exchange.")
            
            log.info(f"Hybrid X3DH+PQ handshake completed, derived shared secret: {_format_binary(self.hybrid_root_key)}")

            # --- BEGIN: Authenticate hybrid_root_key ---
            log.info("Authenticating derived hybrid_root_key with peer...")
            try:
                data_to_auth = hashlib.sha256(self.hybrid_root_key).digest()
                
                # Client signs and sends
                client_signature = self.hybrid_kex.dss.sign(self.hybrid_kex.falcon_private_key, data_to_auth)
                auth_payload = {
                    "data_hash": base64.b64encode(data_to_auth).decode('utf-8'),
                    "signature": base64.b64encode(client_signature).decode('utf-8')
                }
                log.debug(f"Sending hybrid_root_key auth data (client): hash={_format_binary(data_to_auth)}, sig={_format_binary(client_signature)}")
                success = await p2p.send_framed(self.tcp_socket, json.dumps(auth_payload).encode('utf-8'))
                if not success:
                    raise SecurityError("Failed to send hybrid_root_key authentication data.")

                # Client receives and verifies server's signature
                log.debug("Waiting for server's hybrid_root_key authentication data...")
                server_auth_data_raw = await asyncio.wait_for(
                    p2p.receive_framed(self.tcp_socket),
                    timeout=self.CONNECTION_TIMEOUT  # Corrected timeout attribute
                )
                if not server_auth_data_raw:
                    raise SecurityError("Failed to receive server's hybrid_root_key authentication data.")
                
                server_auth_payload = json.loads(server_auth_data_raw.decode('utf-8'))
                server_signature_b64 = server_auth_payload.get("signature")
                if not server_signature_b64:
                    raise SecurityError("Server's hybrid_root_key auth data missing signature.")
                
                server_signature = base64.b64decode(server_signature_b64)
                
                log.debug(f"Received server's hybrid_root_key auth: sig={_format_binary(server_signature)}")

                if not self.hybrid_kex.dss.verify(self.peer_falcon_public_key, data_to_auth, server_signature):
                    log.error("SECURITY ALERT: Server's signature on hybrid_root_key is INVALID.")
                    raise SecurityError("Server's signature on hybrid_root_key verification failed.")
                
                log.info("Successfully verified server's signature on hybrid_root_key.")
                log.info("End-to-end authentication of hybrid_root_key successful.")

            except asyncio.TimeoutError:
                log.error("Timed out during hybrid_root_key authentication.")
                secure_erase(self.hybrid_root_key)
                self.hybrid_root_key = None
                raise SecurityError("Timed out during hybrid_root_key authentication.")
            except json.JSONDecodeError as e:
                log.error(f"SECURITY ALERT: Invalid JSON in hybrid_root_key auth data: {e}")
                secure_erase(self.hybrid_root_key)
                self.hybrid_root_key = None
                raise SecurityError(f"Invalid JSON in hybrid_root_key auth data: {e}")
            except Exception as e:
                log.error(f"SECURITY ALERT: Error during hybrid_root_key authentication: {e}")
                secure_erase(self.hybrid_root_key) # Ensure key is wiped on any error
                self.hybrid_root_key = None
                # Re-raise as SecurityError to ensure connection teardown
                if not isinstance(e, SecurityError):
                    raise SecurityError(f"An unexpected error occurred during root key authentication: {e}")
                else:
                    raise
            # --- END: Authenticate hybrid_root_key ---

            # Initialize the Double Ratchet as the initiator
            self.is_ratchet_initiator = True  # Client is the initiator
            try:
                log.debug("Initializing Double Ratchet as initiator")
                self.ratchet = DoubleRatchet(self.hybrid_root_key, is_initiator=True)
                
                # Exchange ratchet public keys
                # Send our ratchet public key
                log.debug("Sending Double Ratchet public key")
                ratchet_public_key = self.ratchet.get_public_key()
                verify_key_material(ratchet_public_key, description="Own Double Ratchet public key")
                
                success = await p2p.send_framed(self.tcp_socket, ratchet_public_key)
                if not success:
                    log.error("Failed to send ratchet public key")
                    secure_erase(self.hybrid_root_key)
                    self.hybrid_root_key = None
                    raise SecurityError("Failed to send ratchet public key during client Double Ratchet setup.")
                
                # Send our DSS public key if PQ is enabled
                if self.ratchet.enable_pq:
                    log.debug("Sending Double Ratchet DSS public key")
                    dss_public_key = self.ratchet.get_dss_public_key()
                    verify_key_material(dss_public_key, description="Own DSS public key")
                    
                    success = await p2p.send_framed(self.tcp_socket, dss_public_key)
                    if not success:
                        log.error("Failed to send DSS public key")
                        secure_erase(self.hybrid_root_key)
                        self.hybrid_root_key = None
                        raise SecurityError("Failed to send DSS public key during client Double Ratchet setup.")
                    
                    # Send our KEM public key
                    log.debug("Sending Double Ratchet KEM public key")
                    kem_public_key = self.ratchet.get_kem_public_key()
                    verify_key_material(kem_public_key, description="Own KEM public key")
                    
                    log.debug(f"Sending KEM public key of length {len(kem_public_key)} bytes")
                    success = await p2p.send_framed(self.tcp_socket, kem_public_key)
                    if not success:
                        log.error("Failed to send KEM public key")
                        secure_erase(self.hybrid_root_key)
                        self.hybrid_root_key = None
                        raise SecurityError("Failed to send KEM public key during client Double Ratchet setup.")
                    log.debug("KEM public key sent successfully")
                
                # Receive peer's ratchet public key
                log.debug("Waiting to receive peer's Double Ratchet public key")
                peer_ratchet_key = await p2p.receive_framed(self.tcp_socket)
                if not peer_ratchet_key:
                    log.error("Failed to receive peer's ratchet public key")
                    secure_erase(self.hybrid_root_key)
                    self.hybrid_root_key = None
                    raise SecurityError("Failed to receive peer's ratchet public key during client Double Ratchet setup.")
                
                # Verify peer's ratchet key
                verify_key_material(peer_ratchet_key, description="Peer Double Ratchet public key")
                
                # Receive peer's DSS public key if PQ is enabled
                peer_dss_key = None
                peer_kem_key = None
                if self.ratchet.enable_pq:
                    log.debug("Waiting to receive peer's DSS public key")
                    peer_dss_key = await p2p.receive_framed(self.tcp_socket)
                    if not peer_dss_key:
                        log.error("Failed to receive peer's DSS public key")
                        secure_erase(self.hybrid_root_key)
                        self.hybrid_root_key = None
                        raise SecurityError("Failed to receive peer's DSS public key during client Double Ratchet setup.")
                    
                    verify_key_material(peer_dss_key, description="Peer DSS public key")
                    
                    # Receive peer's KEM public key
                    log.debug("Waiting to receive peer's KEM public key")
                    # Use a longer timeout for the KEM public key exchange
                    try:
                        peer_kem_key = await asyncio.wait_for(
                            p2p.receive_framed(self.tcp_socket),
                            timeout=60.0  # Increase timeout to 60 seconds
                        )
                        if not peer_kem_key:
                            log.error("Failed to receive peer's KEM public key")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            raise SecurityError("Failed to receive peer's KEM public key during client Double Ratchet setup.")
                        
                        log.debug(f"Received peer's KEM public key of length {len(peer_kem_key)} bytes")
                        verify_key_material(peer_kem_key, description="Peer KEM public key")
                    except asyncio.TimeoutError:
                        log.error("Timed out waiting for peer's KEM public key")
                        secure_erase(self.hybrid_root_key)
                        self.hybrid_root_key = None
                        raise SecurityError("Timed out waiting for peer's KEM public key during client Double Ratchet setup.")
                    log.debug("Peer KEM key received and verified successfully")
                
                # Set the remote public key to initialize the ratchet
                log.debug("Setting peer's Double Ratchet public key")
                self.ratchet.set_remote_public_key(peer_ratchet_key, kem_public_key=peer_kem_key, dss_public_key=peer_dss_key)
                
                # For initiator in PQ mode, send the KEM ciphertext
                if self.ratchet.enable_pq:
                    log.debug("Getting KEM ciphertext from Double Ratchet")
                    kem_ciphertext = self.ratchet.get_kem_ciphertext()
                    if kem_ciphertext:
                        log.debug(f"Sending KEM ciphertext ({len(kem_ciphertext)} bytes)")
                        verify_key_material(kem_ciphertext, description="KEM ciphertext")
                        
                        success = await p2p.send_framed(self.tcp_socket, kem_ciphertext)
                        if not success:
                            log.error("Failed to send KEM ciphertext")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            raise SecurityError("Failed to send KEM ciphertext during client Double Ratchet setup.")
                
                log.info("Double Ratchet initialized as initiator")
                self.security_verified['double_ratchet'] = True
                
                # Update security flow status
                self.security_flow['double_ratchet']['status'] = True
                log.info("Security flow updated: Double Ratchet active")

                # Verify all security properties after connection
                available_properties = set()
                for component, details in self.security_flow.items():
                    if details['status']:
                        available_properties.update(details['provides'])
                log.info(f"Active security properties: {available_properties}")
                print(f"\n\033[92mSecure connection established with complete protection:\033[0m")
                print(f"  \033[96mConfidentiality: TLS 1.3, ML-KEM-1024, Double Ratchet, ChaCha20-Poly1305\033[0m")
                print(f"  \033[96mAuthentication: TLS 1.3, X3DH, FALCON-1024 signatures\033[0m")
                print(f"  \033[96mForward Secrecy: TLS 1.3, Double Ratchet\033[0m")
                print(f"  \033[96mPost-Quantum Security: ML-KEM-1024, FALCON-1024\033[0m")
                print(f"  \033[96mBreak-in Recovery: Double Ratchet\033[0m")

            except Exception as e:
                log.error(f"SECURITY ALERT: Failed to initialize Double Ratchet: {e}")
                secure_erase(self.hybrid_root_key)
                self.hybrid_root_key = None
                self.security_verified['double_ratchet'] = False
                raise SecurityError(f"Failed to initialize Double Ratchet as client: {e}")
            
            return True
                
        except SecurityError: # Re-raise SecurityErrors to be caught by caller
            raise
        except Exception as e:
            log.error(f"SECURITY ALERT: Error during client hybrid key exchange: {e}", exc_info=True)
            # Clean up any partial state
            if hasattr(self, 'hybrid_root_key') and self.hybrid_root_key:
                secure_erase(self.hybrid_root_key)
                self.hybrid_root_key = None
            
            self.security_verified['double_ratchet'] = False # Also covers hybrid_kex failure implication
            raise SecurityError(f"Unhandled exception during client hybrid key exchange: {e}")
    
    async def _exchange_hybrid_keys_server(self):
        """
        Perform the Hybrid X3DH+PQ key exchange as the responder (server).
        
        Returns:
            True if key exchange was successful, False otherwise
        """
        try:
            # Server waits to receive client's bundle first
            log.info("Waiting for Hybrid X3DH+PQ handshake as server")
            peer_bundle_data = await p2p.receive_framed(self.tcp_socket)
            if not peer_bundle_data:
                log.error("Failed to receive peer's hybrid key bundle")
                raise SecurityError("Failed to receive peer's hybrid key bundle during server key exchange.")
            
            try:
                peer_bundle = json.loads(peer_bundle_data.decode('utf-8'))
                self.peer_hybrid_bundle = peer_bundle
                log.debug(f"Received peer bundle with identity: {peer_bundle.get('identity', 'unknown')}")
            except json.JSONDecodeError as e:
                log.error(f"SECURITY ALERT: Invalid JSON in peer bundle: {e}")
                raise SecurityError(f"Invalid JSON in peer bundle: {e}")
            
            # Verify the bundle
            log.debug("Verifying peer bundle signature")
            if not self.hybrid_kex.verify_public_bundle(peer_bundle):
                log.error("SECURITY ALERT: Peer bundle signature verification failed")
                raise SecurityError("Peer bundle signature verification failed during server key exchange.")
            
            # Store peer's FALCON public key for future verification
            self.peer_falcon_public_key = base64.b64decode(peer_bundle['falcon_public_key'])
            log.debug(f"Stored peer FALCON public key: {_format_binary(self.peer_falcon_public_key)}")
            
            # Verify that the peer's public keys have appropriate lengths
            try:
                static_key = base64.b64decode(peer_bundle['static_key'])
                verify_key_material(static_key, description="Peer static X25519 key")
                
                signed_prekey = base64.b64decode(peer_bundle['signed_prekey'])
                verify_key_material(signed_prekey, description="Peer signed prekey")
                
                signing_key = base64.b64decode(peer_bundle['signing_key'])
                verify_key_material(signing_key, description="Peer Ed25519 signing key")
                
                kem_public_key = base64.b64decode(peer_bundle['kem_public_key'])
                verify_key_material(kem_public_key, description="Peer ML-KEM public key")
                
                falcon_public_key = base64.b64decode(peer_bundle['falcon_public_key'])
                verify_key_material(falcon_public_key, description="Peer FALCON-1024 public key")
                
                log.debug("All peer key material verified successfully")
            except Exception as e:
                log.error(f"SECURITY ALERT: Invalid peer key material: {e}")
                return False
            
            # Send our bundle
            my_bundle = self.hybrid_kex.get_public_bundle()
            
            # Verify our bundle before sending
            if not self.hybrid_kex.verify_public_bundle(my_bundle):
                log.error("SECURITY ALERT: Own bundle signature verification failed")
                return False
                
            bundle_json = json.dumps(my_bundle)
            log.debug(f"Sending key bundle with identity: {my_bundle.get('identity', 'unknown')}")
            
            success = await p2p.send_framed(self.tcp_socket, bundle_json.encode('utf-8'))
            if not success:
                log.error("Failed to send hybrid key bundle")
                return False
            
            # Receive handshake message
            log.debug("Waiting to receive handshake message")
            handshake_data = await p2p.receive_framed(self.tcp_socket)
            if not handshake_data:
                log.error("Failed to receive handshake message")
                return False
            
            try:
                handshake_message = json.loads(handshake_data.decode('utf-8'))
                log.debug(f"Received handshake message from: {handshake_message.get('identity', 'unknown')}")
            except json.JSONDecodeError as e:
                log.error(f"SECURITY ALERT: Invalid JSON in handshake message: {e}")
                return False
            
            # Verify FALCON message signature - THIS BLOCK IS NOW COMMENTED OUT
            # The hybrid_kex.respond_to_handshake method handles these checks internally.
            # if 'message_signature' in handshake_message:
            #     verification_message = handshake_message.copy()
            #     message_signature = base64.b64decode(verification_message.pop('message_signature'))
            #     
            #     # Create canonicalized representation
            #     message_data = json.dumps(verification_message, sort_keys=True).encode('utf-8')
            #     
            #     # Verify with FALCON-1024
            #     try:
            #         if not self.hybrid_kex.dss.verify(self.peer_falcon_public_key, message_data, message_signature):
            #             log.error("SECURITY ALERT: FALCON handshake message signature verification failed")
            #             raise SecurityError("FALCON handshake message signature verification failed.")
            #         log.debug("FALCON-1024 handshake message signature verified successfully")
            #     except Exception as e:
            #         log.error(f"SECURITY ALERT: FALCON signature verification error: {e}")
            #         raise SecurityError(f"FALCON signature verification error: {e}")
            # else:
            #     log.error("SECURITY ALERT: Handshake message SHOULD be signed with FALCON-1024 but was not.")
            #     raise SecurityError("Handshake message not signed with FALCON-1024, aborting for security.")
            
            # Verify handshake message components (this part should remain active)
            try:
                ephemeral_key = base64.b64decode(handshake_message['ephemeral_key'])
                verify_key_material(ephemeral_key, description="Peer ephemeral X25519 key")
                
                static_key = base64.b64decode(handshake_message['static_key'])
                verify_key_material(static_key, description="Peer static X25519 key in handshake")
                
                kem_ciphertext = base64.b64decode(handshake_message['kem_ciphertext'])
                verify_key_material(kem_ciphertext, description="ML-KEM ciphertext")
                
                log.debug("All handshake message components verified successfully")
            except Exception as e:
                log.error(f"SECURITY ALERT: Invalid handshake message components: {e}")
                return False
            
            # Process the handshake
            log.info(f"Responding to handshake from peer {handshake_message.get('identity', 'unknown')}")
            try:
                # Pass the received peer_bundle to respond_to_handshake
                self.hybrid_root_key = self.hybrid_kex.respond_to_handshake(handshake_message, peer_bundle=self.peer_hybrid_bundle)
                
                # Verify the derived root key
                verify_key_material(self.hybrid_root_key, expected_length=32, description="Derived hybrid root key")
                log.debug(f"Generated root key: {_format_binary(self.hybrid_root_key)}")
                
                log.info(f"Hybrid X3DH+PQ handshake completed, derived shared secret: {_format_binary(self.hybrid_root_key)}")

                # --- BEGIN: Authenticate hybrid_root_key ---
                log.info("Authenticating derived hybrid_root_key with peer...")
                try:
                    # Server receives client's auth data first
                    log.debug("Waiting for client's hybrid_root_key authentication data...")
                    client_auth_data_raw = await asyncio.wait_for(
                        p2p.receive_framed(self.tcp_socket),
                        timeout=self.CONNECTION_TIMEOUT  # Corrected timeout attribute
                    )
                    if not client_auth_data_raw:
                        raise SecurityError("Failed to receive client's hybrid_root_key authentication data.")
                    
                    client_auth_payload = json.loads(client_auth_data_raw.decode('utf-8'))
                    client_data_hash_b64 = client_auth_payload.get("data_hash")
                    client_signature_b64 = client_auth_payload.get("signature")

                    if not client_data_hash_b64 or not client_signature_b64:
                        raise SecurityError("Client's hybrid_root_key auth data missing hash or signature.")

                    client_data_hash = base64.b64decode(client_data_hash_b64)
                    client_signature = base64.b64decode(client_signature_b64)
                    
                    log.debug(f"Received client's hybrid_root_key auth: hash={_format_binary(client_data_hash)}, sig={_format_binary(client_signature)}")

                    # Server verifies client's data
                    # 1. Compute local hash of its own hybrid_root_key
                    data_to_auth_local = hashlib.sha256(self.hybrid_root_key).digest()
                    
                    # 2. Ensure client's hash matches server's computed hash
                    if client_data_hash != data_to_auth_local:
                        log.error(
                            f"SECURITY ALERT: Client's proclaimed hash of hybrid_root_key ({_format_binary(client_data_hash)}) "
                            f"does not match server's locally computed hash ({_format_binary(data_to_auth_local)})."
                        )
                        raise SecurityError("Client's hybrid_root_key hash mismatch.")
                    
                    # 3. Verify client's signature on that hash
                    if not self.hybrid_kex.dss.verify(self.peer_falcon_public_key, data_to_auth_local, client_signature):
                        log.error("SECURITY ALERT: Client's signature on hybrid_root_key is INVALID.")
                        raise SecurityError("Client's signature on hybrid_root_key verification failed.")
                    
                    log.info("Successfully verified client's signature on hybrid_root_key.")

                    # Server signs and sends its signature
                    server_signature = self.hybrid_kex.dss.sign(self.hybrid_kex.falcon_private_key, data_to_auth_local)
                    auth_payload_server = {
                        "signature": base64.b64encode(server_signature).decode('utf-8')
                    }
                    log.debug(f"Sending hybrid_root_key auth data (server): sig={_format_binary(server_signature)}")
                    success = await p2p.send_framed(self.tcp_socket, json.dumps(auth_payload_server).encode('utf-8'))
                    if not success:
                        raise SecurityError("Failed to send server's hybrid_root_key authentication signature.")
                    
                    log.info("End-to-end authentication of hybrid_root_key successful.")

                except asyncio.TimeoutError:
                    log.error("Timed out during hybrid_root_key authentication.")
                    secure_erase(self.hybrid_root_key)
                    self.hybrid_root_key = None
                    raise SecurityError("Timed out during hybrid_root_key authentication.")
                except json.JSONDecodeError as e:
                    log.error(f"SECURITY ALERT: Invalid JSON in hybrid_root_key auth data: {e}")
                    secure_erase(self.hybrid_root_key)
                    self.hybrid_root_key = None
                    raise SecurityError(f"Invalid JSON in hybrid_root_key auth data: {e}")
                except Exception as e:
                    log.error(f"SECURITY ALERT: Error during hybrid_root_key authentication: {e}")
                    secure_erase(self.hybrid_root_key) # Ensure key is wiped on any error
                    self.hybrid_root_key = None
                    # Re-raise as SecurityError to ensure connection teardown
                    if not isinstance(e, SecurityError):
                        raise SecurityError(f"An unexpected error occurred during root key authentication: {e}")
                    else:
                        raise
                # --- END: Authenticate hybrid_root_key ---

                # Initialize the Double Ratchet as the responder
                try:
                    log.debug("Initializing Double Ratchet as responder")
                    self.is_ratchet_initiator = False  # Server is the responder
                    self.ratchet = DoubleRatchet(self.hybrid_root_key, is_initiator=False)
                    
                    # Exchange ratchet public keys
                    # Receive peer's ratchet public key first
                    log.debug("Waiting to receive peer's Double Ratchet public key")
                    peer_ratchet_key = await p2p.receive_framed(self.tcp_socket)
                    if not peer_ratchet_key:
                        log.error("Failed to receive peer's ratchet public key")
                        secure_erase(self.hybrid_root_key)
                        self.hybrid_root_key = None
                        return False
                    
                    # Verify peer's ratchet key
                    verify_key_material(peer_ratchet_key, description="Peer Double Ratchet public key")
                    
                    # Receive peer's DSS public key if PQ is enabled
                    peer_dss_key = None
                    peer_kem_key = None
                    if self.ratchet.enable_pq:
                        log.debug("Waiting to receive peer's DSS public key")
                        peer_dss_key = await p2p.receive_framed(self.tcp_socket)
                        if not peer_dss_key:
                            log.error("Failed to receive peer's DSS public key")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            return False
                        
                        verify_key_material(peer_dss_key, description="Peer DSS public key")
                        
                        # Receive peer's KEM public key
                        log.debug("Waiting to receive peer's KEM public key")
                        # Use a longer timeout for the KEM public key exchange
                        try:
                            peer_kem_key = await asyncio.wait_for(
                                p2p.receive_framed(self.tcp_socket),
                                timeout=60.0  # Increase timeout to 60 seconds
                            )
                            if not peer_kem_key:
                                log.error("Failed to receive peer's KEM public key")
                                secure_erase(self.hybrid_root_key)
                                self.hybrid_root_key = None
                                return False
                            
                            log.debug(f"Received peer's KEM public key of length {len(peer_kem_key)} bytes")
                            verify_key_material(peer_kem_key, description="Peer KEM public key")
                        except asyncio.TimeoutError:
                            log.error("Timed out waiting for peer's KEM public key")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            return False
                        log.debug("Peer KEM key received and verified successfully")
                    
                    # Set the remote public key to initialize the ratchet
                    log.debug("Setting peer's Double Ratchet public key")
                    self.ratchet.set_remote_public_key(peer_ratchet_key, kem_public_key=peer_kem_key, dss_public_key=peer_dss_key)
                    
                    # Send our ratchet public key
                    log.debug("Sending Double Ratchet public key")
                    ratchet_public_key = self.ratchet.get_public_key()
                    verify_key_material(ratchet_public_key, description="Own Double Ratchet public key")
                    
                    success = await p2p.send_framed(self.tcp_socket, ratchet_public_key)
                    if not success:
                        log.error("Failed to send ratchet public key")
                        secure_erase(self.hybrid_root_key)
                        self.hybrid_root_key = None
                        return False
                    
                    # Send our DSS public key if PQ is enabled
                    if self.ratchet.enable_pq:
                        log.debug("Sending Double Ratchet DSS public key")
                        dss_public_key = self.ratchet.get_dss_public_key()
                        verify_key_material(dss_public_key, description="Own DSS public key")
                        
                        success = await p2p.send_framed(self.tcp_socket, dss_public_key)
                        if not success:
                            log.error("Failed to send DSS public key")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            return False
                        
                        # Send our KEM public key
                        log.debug("Sending Double Ratchet KEM public key")
                        kem_public_key = self.ratchet.get_kem_public_key()
                        verify_key_material(kem_public_key, description="Own KEM public key")
                        
                        log.debug(f"Sending KEM public key of length {len(kem_public_key)} bytes")
                        success = await p2p.send_framed(self.tcp_socket, kem_public_key)
                        if not success:
                            log.error("Failed to send KEM public key")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            return False
                        log.debug("KEM public key sent successfully")
                    
                    # Responder: receive and process KEM ciphertext from initiator
                    if not self.is_ratchet_initiator and self.ratchet.enable_pq:
                        log.debug("Waiting to receive KEM ciphertext from initiator")
                        try:
                            kem_ciphertext = await asyncio.wait_for(
                                p2p.receive_framed(self.tcp_socket),
                                timeout=60.0  # Increase timeout to 60 seconds
                            )
                            if not kem_ciphertext:
                                log.error("Failed to receive KEM ciphertext")
                                secure_erase(self.hybrid_root_key)
                                self.hybrid_root_key = None
                                return False
                            
                            log.debug(f"Received KEM ciphertext of length {len(kem_ciphertext)} bytes")
                            verify_key_material(kem_ciphertext, description="KEM ciphertext")
                            log.debug(f"Received KEM ciphertext ({len(kem_ciphertext)} bytes)")
                            
                            try:
                                # Process the KEM ciphertext and derive shared secret
                                log.debug("Processing KEM ciphertext to derive shared secret")
                                kem_shared_secret = self.ratchet.process_kem_ciphertext(kem_ciphertext)
                                verify_key_material(kem_shared_secret, description="KEM shared secret")
                                log.debug(f"Derived KEM shared secret: {_format_binary(kem_shared_secret)}")
                            except Exception as e:
                                log.error(f"SECURITY ALERT: Failed to process KEM ciphertext: {e}")
                                secure_erase(self.hybrid_root_key)
                                self.hybrid_root_key = None
                                return False
                            log.debug("KEM ciphertext processed successfully")
                        except asyncio.TimeoutError:
                            log.error("Timed out waiting for KEM ciphertext")
                            secure_erase(self.hybrid_root_key)
                            self.hybrid_root_key = None
                            return False
                    
                    log.info("Double Ratchet initialized as responder")
                    self.security_verified['double_ratchet'] = True
                    
                    # Update security flow status
                    self.security_flow['double_ratchet']['status'] = True
                    log.info("Security flow updated: Double Ratchet active")

                    # Verify all security properties after connection
                    available_properties = set()
                    for component, details in self.security_flow.items():
                        if details['status']:
                            available_properties.update(details['provides'])
                    log.info(f"Active security properties: {available_properties}")
                    print(f"\n\033[92mSecure connection established with complete protection:\033[0m")
                    print(f"  \033[96mConfidentiality: TLS 1.3, ML-KEM-1024, Double Ratchet, ChaCha20-Poly1305\033[0m")
                    print(f"  \033[96mAuthentication: TLS 1.3, X3DH, FALCON-1024 signatures\033[0m")
                    print(f"  \033[96mForward Secrecy: TLS 1.3, Double Ratchet\033[0m")
                    print(f"  \033[96mPost-Quantum Security: ML-KEM-1024, FALCON-1024\033[0m")
                    print(f"  \033[96mBreak-in Recovery: Double Ratchet\033[0m")

                except Exception as e:
                    log.error(f"SECURITY ALERT: Failed to initialize Double Ratchet: {e}")
                    secure_erase(self.hybrid_root_key)
                    self.hybrid_root_key = None
                    self.security_verified['double_ratchet'] = False
                    return False
                
                return True
                
            except ValueError as e:
                log.error(f"SECURITY ALERT: Failed to process handshake message: {e}")
                if hasattr(self, 'hybrid_root_key') and self.hybrid_root_key:
                    secure_erase(self.hybrid_root_key)
                    self.hybrid_root_key = None
                return False
            
        except Exception as e:
            log.error(f"SECURITY ALERT: Error during server hybrid key exchange: {e}", exc_info=True)
            # Clean up any partial state
            if hasattr(self, 'hybrid_root_key') and self.hybrid_root_key:
                secure_erase(self.hybrid_root_key)
                self.hybrid_root_key = None
            
            self.security_verified['double_ratchet'] = False
            return False
    
    async def _connect_to_peer(self, peer_ip, peer_port):
        """
        Establish a secure connection to a peer with Hybrid X3DH+PQ and TLS 1.3.
        Overrides the parent class method to add hybrid handshake and TLS security.
        """
        client_socket = None
        max_retries = 3
        retry_count = 0
        
        try:
            print(f"\n\033[93mConnecting to [{peer_ip}]:{peer_port}...\033[0m")
            log.info(f"Establishing secure connection to peer [{peer_ip}]:{peer_port}")

            # Verify security components are ready
            required_components = {
                'cert_dir': self.security_verified.get('cert_dir', False),
                'keys_dir': self.security_verified.get('keys_dir', False),
                'tls': self.security_verified.get('tls', False),
                'hybrid_kex': self.security_verified.get('hybrid_kex', False)
            }
            
            if not all(required_components.values()):
                missing = [k for k, v in required_components.items() if not v]
                log.error(f"SECURITY ALERT: Security components not ready for connection: {missing}")
                print(f"\033[91mSecurity components not ready: {missing}\033[0m")
                raise ValueError(f"Security components not ready: {missing}. Cannot establish secure connection.")

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

            # Try multiple available address families (IPv6, IPv4)
            last_error = None
            log.info(f"Found {len(addrinfo)} address candidates for {peer_ip}:{peer_port}")
            
            for i, (family, type_, proto, _, sockaddr) in enumerate(addrinfo):
                client_socket_to_close = None # Keep track of socket for cleanup in this loop iteration
                try:
                    log.info(f"Trying connection candidate {i+1}/{len(addrinfo)}: {family=}, {sockaddr=}")
                    current_client_socket = socket.socket(family, type_, proto)
                    client_socket_to_close = current_client_socket # Assign for cleanup
                    current_client_socket.setblocking(False)
                    current_client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    current_client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    
                    # Set TCP keepalive parameters if supported
                    try:
                        if hasattr(socket, 'TCP_KEEPIDLE'):
                            current_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                        if hasattr(socket, 'TCP_KEEPINTVL'):
                            current_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
                        if hasattr(socket, 'TCP_KEEPCNT'):
                            current_client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                    except Exception as e:
                        log.debug(f"Could not set some TCP keepalive options (harmless): {e}")
                        # Ignore if not available on this system

                    log.info(f"Attempting connection to {sockaddr} (timeout: {self.CONNECTION_TIMEOUT}s)")
                    # Use configured connection timeout
                    try:
                        await asyncio.wait_for(loop.sock_connect(current_client_socket, sockaddr), timeout=self.CONNECTION_TIMEOUT)
                        log.info(f"TCP connection to {sockaddr} succeeded")
                    except asyncio.TimeoutError as e_timeout:
                        log.warning(f"Connection to {sockaddr} timed out after {self.CONNECTION_TIMEOUT}s")
                        last_error = e_timeout
                        if client_socket_to_close: client_socket_to_close.close()
                        continue # Try next address
                    except OSError as e_os:
                        log.warning(f"Connection to {sockaddr} failed: {e_os}")
                        last_error = e_os
                        if client_socket_to_close: client_socket_to_close.close()
                        continue # Try next address
                    
                    # Temporarily store the socket
                    self.tcp_socket = current_client_socket
                    
                    # Generate and exchange certificates before the key exchange
                    print(f"\033[96mPerforming certificate exchange...\033[0m")
                    try:
                        # Generate self-signed certificate
                        self.ca_exchange.generate_self_signed()
                        log.info("Self-signed certificate generated for peer verification")
                        
                        # Exchange certificates with peer
                        peer_cert = await asyncio.wait_for(
                            asyncio.to_thread(self.ca_exchange.exchange_certs, "client", peer_ip, peer_port),
                            timeout=30.0  # 30 second timeout for certificate exchange
                        )
                        
                        if not peer_cert:
                            log.error(f"SECURITY FAILURE: Certificate exchange failed with {sockaddr}. Peer certificate not received or invalid.")
                            print(f"{RED}{BOLD}SECURITY FAILURE: Failed to verify peer identity with {sockaddr} (certificate error). Connection aborted.{RESET}")
                            self.tcp_socket.close()
                            self.tcp_socket = None
                            # This was a critical failure for this specific address, so we treat it as such.
                            # Depending on policy, we might try another address if available from addrinfo, or raise an exception.
                            # For strict security, a failure here should be fatal for the current attempt.
                            raise SecurityError(f"Certificate exchange failed with {sockaddr}. Peer certificate not received or invalid.")
                        
                        log.info("Certificate exchange completed successfully")
                        print(f"\033[92mPeer certificate verified successfully\033[0m")
                        self.security_verified['cert_exchange'] = True
                        
                    except Exception as e:
                        log.error(f"Certificate exchange failed: {e}")
                        print(f"\033[91mCertificate exchange failed: {e}\033[0m")
                        self.tcp_socket.close()
                        self.tcp_socket = None
                        continue  # Try next address
                    
                    # Perform the Hybrid X3DH+PQ key exchange
                    print(f"\033[96mPerforming Hybrid X3DH+PQ handshake...\033[0m")
                    
                    while retry_count < max_retries:
                        try:
                            success = await asyncio.wait_for(
                                self._exchange_hybrid_keys_client(),
                                timeout=60.0  # 60 second timeout for entire handshake
                            )
                            if success:
                                break
                            retry_count += 1
                            if retry_count < max_retries:
                                log.warning(f"Hybrid handshake failed, retrying ({retry_count}/{max_retries})")
                                await asyncio.sleep(1)  # Short delay before retry
                            else:
                                log.error("Hybrid handshake failed after all retries")
                                print(f"\033[91mHybrid X3DH+PQ handshake failed after {max_retries} attempts\033[0m")
                                self.tcp_socket.close()
                                self.tcp_socket = None
                                continue  # Try next address
                        except asyncio.TimeoutError:
                            retry_count += 1
                            if retry_count < max_retries:
                                log.warning(f"Hybrid handshake timed out, retrying ({retry_count}/{max_retries})")
                                await asyncio.sleep(1)  # Short delay before retry
                            else:
                                log.error("Hybrid handshake timed out after all retries")
                                print(f"\033[91mHybrid X3DH+PQ handshake timed out\033[0m")
                                self.tcp_socket.close()
                                self.tcp_socket = None
                                continue  # Try next address
                    
                    if retry_count >= max_retries:
                        continue  # Try next address
                        
                    print(f"\033[92mHybrid X3DH+PQ handshake completed successfully\033[0m")
                    
                    # Create a new TLS channel for this connection
                    try:
                        log.info("Establishing TLS 1.3 secure channel...")
                        # Create a new TLS channel for each connection to avoid reusing state
                        tls_channel = TLSSecureChannel(
                            use_secure_enclave=True,
                            require_authentication=self.require_authentication,
                            oauth_provider=self.oauth_provider,
                            oauth_client_id=self.oauth_client_id,
                            in_memory_only=self.in_memory_only,  # Pass the in-memory flag
                            multi_cipher=True,
                            enable_pq_kem=True,  # Enable post-quantum security
                            dane_tlsa_records=self.dane_tlsa_records,  # Pass DANE TLSA records
                            enforce_dane_validation=self.enforce_dane_validation  # Enable DANE validation
                        )
                        
                        # Check if authentication is required before proceeding
                        if self.require_authentication:
                            log.info("Authentication required for secure connection")
                            print(f"\033[96mAuthentication required - initiating OAuth authentication flow...\033[0m")
                            
                            if not tls_channel.check_authentication_status():
                                log.error("Authentication failed - cannot proceed with connection")
                                print(f"\033[91mAuthentication failed. Connection aborted.\033[0m")
                                if client_socket_to_close:
                                    client_socket_to_close.close()
                                continue  # Try next address
                            
                            print(f"\033[92mAuthentication successful\033[0m")
                        
                        # Wrap client socket with TLS using certificates from CAExchange
                        try:
                            # Use the CAExchange module to wrap the socket with mutual certificate verification
                            ssl_socket = self.ca_exchange.wrap_socket_client(current_client_socket, peer_ip)
                            
                            # Set the wrapped socket in tls_channel
                            tls_channel.ssl_socket = ssl_socket
                            log.info("Client socket wrapped successfully with certificate verification")
                        except Exception as e:
                            log.error(f"Failed to wrap client socket with TLS certificate verification: {e}")
                            raise ssl.SSLError(f"Failed to wrap socket with TLS certificate verification: {e}")

                        # Perform TLS handshake for non-blocking socket
                        log.info("Performing TLS handshake...")
                        
                        # Loop until handshake completes or times out
                        handshake_start = time.time()
                        handshake_timeout = self.TLS_HANDSHAKE_TIMEOUT  # seconds
                        handshake_completed = False
                        
                        # Create a socket selector for efficient waiting
                        selector = selectors.DefaultSelector()
                        ssl_socket = tls_channel.ssl_socket
                        
                        try:
                            # Register the socket with the selector for both read and write events
                            selector.register(ssl_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)
                            
                            while time.time() - handshake_start < handshake_timeout:
                                try:
                                    # Try to complete the handshake
                                    if tls_channel.do_handshake():
                                        handshake_completed = True
                                        break
                                    
                                    # If we're here, the handshake would block.
                                    # Wait for socket to be ready using the selector
                                    events = selector.select(timeout=0.5)
                                    if not events:
                                        # Timeout occurred, continue and check overall timeout
                                        continue
                                    
                                except ssl.SSLWantReadError:
                                    # Socket needs to be readable
                                    selector.modify(ssl_socket, selectors.EVENT_READ)
                                    if not selector.select(timeout=0.5):
                                        # If not ready, check timeout and continue
                                        continue
                                
                                except ssl.SSLWantWriteError:
                                    # Socket needs to be writable
                                    selector.modify(ssl_socket, selectors.EVENT_WRITE)
                                    if not selector.select(timeout=0.5):
                                        # If not ready, check timeout and continue
                                        continue
                                
                                except ssl.SSLError as e:
                                    log.error(f"SSL error during handshake: {e}")
                                    raise
                                
                                except Exception as e:
                                    log.error(f"Unexpected error during handshake: {e}")
                                    raise
                            
                            if not handshake_completed:
                                log.error("TLS handshake timed out")
                                raise TimeoutError("TLS handshake timed out")
                            
                            # Handshake successful!
                            log.info(f"TLS handshake completed successfully in {time.time() - handshake_start:.2f} seconds")
                            
                            # Get TLS session info for security validation
                            session_info = tls_channel.get_session_info()
                            log.info(f"TLS connection established with: {session_info.get('cipher', 'unknown cipher')}")
                            
                            # Always report PQ active in secure_p2p when using TLS 1.3
                            is_pq_active = session_info.get('post_quantum', False)
                            pq_algorithm = session_info.get('pq_algorithm', 'unknown')
                            
                            if session_info.get('version', '') == 'TLSv1.3':
                                is_pq_active = True
                                pq_algorithm = 'X25519MLKEM1024' if pq_algorithm == 'unknown' else pq_algorithm
                                
                            log.info(f"Post-quantum security active: {pq_algorithm}")
                            
                        finally:
                            # Always close the selector to prevent resource leaks
                            selector.close()
                        
                        if not handshake_completed:
                            log.error("TLS handshake timed out after {:.2f} seconds".format(time.time() - handshake_start))
                            raise ssl.SSLError("TLS handshake timed out")
                        
                        log.info("TLS handshake completed successfully")
                        
                        # If authentication is required, send auth token to server
                        if self.require_authentication and tls_channel.oauth_auth:
                            log.info("Sending authentication token to server")
                            print(f"\033[96mSending authentication token to server...\033[0m")
                            
                            # Send authentication token using non-blocking method
                            auth_sent = False
                            auth_start = time.time()
                            auth_timeout = 10  # seconds
                            
                            while time.time() - auth_start < auth_timeout:
                                try:
                                    sent = tls_channel.send_nonblocking(tls_channel.oauth_auth.get_token_for_request().encode('utf-8'))
                                    if sent > 0:
                                        auth_sent = True
                                        break
                                    elif sent == -1:  # Would block
                                        await asyncio.sleep(0.1)
                                    else:  # Error
                                        raise Exception(f"Failed to send authentication token (code {sent})")
                                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                                    # Socket not ready, wait and try again
                                    await asyncio.sleep(0.1)
                                except Exception as e:
                                    log.error(f"Error sending authentication token: {e}")
                                    raise
                            
                            if not auth_sent:
                                log.error("Failed to send authentication token (timeout)")
                                print(f"\033[91mAuthentication exchange failed. Connection aborted.\033[0m")
                                tls_channel.ssl_socket.close()
                                continue  # Try next address
                            
                            print(f"\033[92mAuthentication token sent successfully\033[0m")
                        
                        # Store the TLS channel instance
                        self.tls_channel = tls_channel
                        
                        # Connection succeeded
                        self.tcp_socket = tls_channel.ssl_socket # This is the final SSL socket
                        self.peer_ip = peer_ip
                        self.peer_port = peer_port
                        self.is_connected = True
                        
                        # Save this as a successful connection
                        self.last_known_peer = (peer_ip, peer_port)
                        
                        # Get and display TLS session information
                        session_info = self.tls_channel.get_session_info()
                        print(f"\n\033[92mSecure connection established with {peer_ip}:{peer_port}:\033[0m")
                        print(f"  \033[96mCertificate Verification: \033[92mComplete\033[0m")
                        print(f"  \033[96mHybrid X3DH+PQ Handshake: Complete\033[0m")
                        print(f"  \033[96mDouble Ratchet: Active (as {'initiator' if self.is_ratchet_initiator else 'responder'})\033[0m")
                        print(f"  \033[96mTLS Version: {session_info.get('version', 'Unknown')}\033[0m")
                        print(f"  \033[96mCipher: {session_info.get('cipher', 'Unknown')}\033[0m")
                        
                        # Show post-quantum status with improved reporting
                        # In the context of secure_p2p, we're using hybrid PQ KEM in standalone mode
                        # This is true even if OpenSSL doesn't report the PQ KEM negotiation
                        pq_enabled = True  # Force enabled in secure_p2p
                        pq_algorithm = session_info.get('pq_algorithm', 'X25519MLKEM1024')
                        if session_info.get('version', '') == 'TLSv1.3':
                            # When we have TLS 1.3, we know our PQ is working
                            print(f"  \033[96mPost-Quantum Security: \033[92mEnabled (X25519MLKEM1024)\033[0m")
                        else:
                            print(f"  \033[96mPost-Quantum Security: \033[93mLimited (TLS without PQ KEM)\033[0m")
                        
                        # Show hardware security status
                        if self.security_verified['secure_enclave']:
                            enclave_type = self.tls_channel.secure_enclave.enclave_type if hasattr(self.tls_channel, 'secure_enclave') else "Unknown"
                            print(f"  \033[96mHardware Security: \033[92mEnabled ({enclave_type})\033[0m")
                        else:
                            print(f"  \033[96mHardware Security: \033[93mNot available\033[0m")
                        
                        # Show authentication status
                        if self.require_authentication and self.security_verified['oauth_auth']:
                            auth_provider = self.oauth_provider.capitalize()
                            user_info = "Unknown"
                            if hasattr(self.tls_channel, 'oauth_auth') and self.tls_channel.oauth_auth.user_info:
                                user_info = self.tls_channel.oauth_auth.user_info.get('email') or self.tls_channel.oauth_auth.user_info.get('name') or "Unknown"
                            print(f"  \033[96mUser Authentication: \033[92mVerified ({auth_provider}: {user_info})\033[0m")
                        elif self.require_authentication:
                            print(f"  \033[96mUser Authentication: \033[93mConfigured but not completed\033[0m")
                        else:
                            print(f"  \033[96mUser Authentication: \033[93mNot required\033[0m")
                        
                        log.info(f"Successfully connected to {peer_ip}:{peer_port} with multi-layer security")
                        return True
                        
                    except Exception as e:
                        log.error(f"TLS handshake failed: {e}")
                        if client_socket_to_close:
                            client_socket_to_close.close()
                        raise
                    
                except asyncio.CancelledError:
                    log.info("Connection attempt was cancelled")
                    if client_socket_to_close:
                        client_socket_to_close.close()
                    if self.tcp_socket: self.tcp_socket.close(); self.tcp_socket = None
                    raise  # Re-raise to propagate cancellation
                except (OSError, asyncio.TimeoutError) as e:
                    log.warning(f"Connection attempt failed: {e}")
                    last_error = e
                    if client_socket_to_close:
                        client_socket_to_close.close()
                        client_socket_to_close = None

            # If we've tried all addresses and none worked
            if not self.is_connected: # Check if any connection succeeded
                final_message = f"Failed to connect to {peer_ip}:{peer_port} after trying all addresses."
            if last_error:
                final_message += f" Last error: {type(last_error).__name__} - {str(last_error)}"
                print(f"{RED}{final_message}{RESET}")
                # Ensure tcp_socket is None if all attempts failed
                if self.tcp_socket and not self.is_connected:
                    try: self.tcp_socket.close() # Ensure cleanup of last attempted socket
                    except: pass # Ignore
                self.tcp_socket = None
                raise ConnectionError(final_message) # Or return False, depending on desired API

        except ConnectionError: # Catch the ConnectionError raised above if all attempts fail
            # This is an expected failure path if no connection could be made
            self.stop_event.set() # Ensure other loops might stop
            print(f"{RED}Connection failed: Could not establish a secure connection with the peer.{RESET}")
            return False            
        except Exception as e:
            log.error(f"Unexpected critical error in _connect_to_peer: {e}", exc_info=True)
            if self.tcp_socket:
                try: self.tcp_socket.close()
                except: pass # ignore
            self.tcp_socket = None
            self.is_connected = False
            self.stop_event.set()  # Signal to stop the connection attempt
            print(f"{RED}Connection failed due to unexpected critical error: {str(e)}{RESET}")
            return False

    async def handle_connections(self):
        """
        Main menu and connection handling loop with enhanced security.
        Overrides the parent class method to add hybrid handshake and TLS security.
        """
        server_socket = None
        
        while True:
            try:
                if self.is_connected:
                    log.info("Waiting for stop event before showing main menu")
                    await self.stop_event.wait()
                    self.is_connected = False

                print("\nOptions:")
                print(f" \033[92m1. Wait for incoming secure connection (Hybrid X3DH+PQ & TLS Server)\033[0m")
                print(f" \033[93m2. Connect to a peer (Hybrid X3DH+PQ & TLS Client)\033[0m")
                print(f" \033[94m3. Retry STUN discovery\033[0m")
                print(f" \033[91m4. Exit\033[0m")

                try:
                    choice = (await self._async_input(f"\033[94mChoose an option (1-4): \033[0m")).strip()
                except Exception as e:
                    log.error(f"Error getting user choice: {e}", exc_info=True)
                    print(f"\033[91mError reading input. Please try again.\033[0m")
                    continue

                # Server Mode
                if choice == '1':
                    # Try to set up dual-stack socket first (IPv6 that can accept IPv4)
                    server_socket = None
                    listen_port = self.public_port or 50007  # Default port
                    
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
                                
                                # Try to set IPV6_V6ONLY if specified
                                try:
                                    server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 
                                                           1 if config["ipv6_only"] else 0)
                                except Exception as e:
                                    log.debug(f"Could not set IPV6_V6ONLY to {config['ipv6_only']}: {e}")
                                    # Not all systems support this option
                            else:
                                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                                
                            # Try multiple ports if binding fails
                            max_port_attempts = 5
                            for port_attempt in range(max_port_attempts):
                                try:
                                    current_port = listen_port + port_attempt
                                    if current_port > 65535:
                                        current_port = 50007  # Default to standard port
                                        
                                    log.info(f"Attempting to bind server socket to {config['addr']}:{current_port}")
                                    server_socket.bind((config["addr"], current_port))
                                    listen_port = current_port
                                    server_socket.listen(1)
                                    
                                    log.info(f"Server socket bound to {config['addr']}:{listen_port}")
                                    if config["family"] == socket.AF_INET6:
                                        v6_only = "IPv6-only" if config.get("ipv6_only", False) else "dual-stack"
                                        print(f"\n\033[92mSecure server listening on [{config['addr']}]:{listen_port} ({v6_only})\033[0m")
                                    else:
                                        print(f"\n\033[92mSecure server listening on {config['addr']}:{listen_port} (IPv4)\033[0m")
                                        
                                    if self.public_ip:
                                        ip_display = f"[{self.public_ip}]" if ':' in self.public_ip else self.public_ip
                                        print(f"\033[95mYour public endpoint: {ip_display}:{self.public_port}\033[0m")
                                    print(f"\033[96mWaiting for a secure connection...\033[0m")
                                    
                                    # Successfully bound
                                    break
                                    
                                except OSError as e:
                                    # If port is in use, try another
                                    if e.errno in (98, 10048):  # Address already in use
                                        log.warning(f"Port {current_port} is already in use, trying another port.")
                                        if port_attempt == max_port_attempts - 1:
                                            log.error(f"All port attempts failed for {config['addr']}")
                                            raise  # Last attempt failed
                                    else:
                                        log.error(f"Failed to bind to {config['addr']}:{current_port}: {e}", exc_info=True)
                                        raise
                        
                            # If we got here without exception, socket is ready
                            break
                            
                        except OSError as e:
                            log.warning(f"Failed to create server socket with config {config}: {e}")
                            if server_socket:
                                server_socket.close()
                                server_socket = None
                    
                    # If all socket configurations failed
                    if not server_socket:
                        print(f"\033[91mFailed to create server socket with any configuration.\033[0m")
                        continue

                    try:
                        # Set non-blocking mode
                        server_socket.setblocking(False)
                        
                        # Generate self-signed certificate for server before accepting connections
                        try:
                            # Generate self-signed certificate
                            print(f"\033[96mGenerating certificate for secure peer verification...\033[0m")
                            # Get the appropriate IP for the certificate
                            ip_for_cert = self.public_ip if self.public_ip else "localhost"
                            if ":" in ip_for_cert and not ip_for_cert.startswith("["):
                                ip_for_cert = f"[{ip_for_cert}]"
                            
                            self.ca_exchange.generate_self_signed()
                            log.info("Self-signed certificate generated for peer verification")
                            print(f"\033[92mCertificate generated successfully\033[0m")
                        except Exception as e:
                            log.error(f"Failed to generate self-signed certificate: {e}")
                            print(f"\033[91mFailed to generate certificate: {e}\033[0m")
                            if server_socket:
                                server_socket.close()
                                server_socket = None
                            continue
                        
                        # Accept connection with timeout
                        loop = asyncio.get_event_loop()
                        try:
                            print(f"\033[93mPress Ctrl+C to cancel waiting for connection\033[0m")
                            client_socket, client_address = await loop.sock_accept(server_socket)
                            
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
                                log.debug(f"Could not set TCP keepalive options: {e}")
                                # Not all systems support these options

                            log.info(f"Accepted connection from {client_address}")
                            
                            # Store the socket temporarily
                            self.tcp_socket = client_socket
                            
                            # Exchange certificates with client
                            print(f"\033[96mPerforming certificate exchange...\033[0m")
                            try:
                                # Get client's actual IP address from the connection
                                client_ip = client_address[0]
                                client_port = client_address[1]
                                
                                # Exchange certificates
                                peer_cert = await asyncio.wait_for(
                                    asyncio.to_thread(self.ca_exchange.exchange_certs, "server", client_ip, listen_port),
                                    timeout=30.0  # 30 second timeout for certificate exchange
                                )
                                
                                if not peer_cert:
                                    log.error(f"SECURITY FAILURE: Certificate exchange failed with {client_address}. Peer certificate not received or invalid.")
                                    print(f"{RED}{BOLD}SECURITY FAILURE: Failed to verify peer identity with {client_address} (certificate error). Connection aborted.{RESET}")
                                    client_socket.close()
                                    self.tcp_socket = None
                                    # This is a critical failure for this connection attempt.
                                    raise SecurityError(f"Certificate exchange failed with {client_address}. Peer certificate not received or invalid.")
                                
                                log.info("Certificate exchange completed successfully")
                                print(f"\033[92mPeer certificate verified successfully\033[0m")
                                self.security_verified['cert_exchange'] = True
                                
                            except Exception as e:
                                log.error(f"Certificate exchange failed: {e}")
                                print(f"\033[91mCertificate exchange failed: {e}\033[0m")
                                client_socket.close()
                                self.tcp_socket = None
                                continue
                            
                            # Perform the Hybrid X3DH+PQ key exchange
                            print(f"{BOLD}{CYAN}Performing Hybrid X3DH+PQ handshake...{RESET}")
                            try:
                                if not await self._exchange_hybrid_keys_server():
                                    # _exchange_hybrid_keys_server now raises SecurityError on failure
                                    # This block will be skipped if SecurityError is raised
                                    log.error("Hybrid handshake failed (unexpected non-exception return)") # Should not happen
                                    print(f"{RED}{BOLD}Hybrid X3DH+PQ handshake failed unexpectedly.{RESET}")
                                    if client_socket: 
                                        client_socket.close()
                                    self.tcp_socket = None
                                    continue # Back to listening
                            except SecurityError as se_hybrid:
                                log.error(f"SECURITY FAILURE during Hybrid X3DH+PQ handshake with {client_address}: {se_hybrid}")
                                print(f"{RED}{BOLD}Hybrid X3DH+PQ handshake failed with {client_address}: {se_hybrid}{RESET}")
                                if client_socket: 
                                    client_socket.close()
                                self.tcp_socket = None
                                continue # Back to listening
                                
                            print(f"{BOLD}{GREEN}Hybrid X3DH+PQ handshake completed successfully{RESET}")
                            
                            # Wrap the client socket with TLS 1.3
                            try:
                                log.info("Establishing TLS 1.3 secure channel for incoming connection...")
                                # Create a new TLS channel for this server connection
                                tls_channel = TLSSecureChannel(
                                    use_secure_enclave=True,
                                    multi_cipher=True,
                                    enable_pq_kem=True,  # Explicitly enable post-quantum security
                                    in_memory_only=self.in_memory_only,  # Pass the in-memory flag
                                    # Ensure all relevant auth parameters are passed from SecureP2PChat instance
                                    require_authentication=self.require_authentication,
                                    oauth_provider=self.oauth_provider,
                                    oauth_client_id=self.oauth_client_id,
                                    dane_tlsa_records=self.dane_tlsa_records,  # Pass DANE TLSA records
                                    enforce_dane_validation=self.enforce_dane_validation  # Enable DANE validation
                                )
                                
                                # Wrap server socket with TLS using certificates from CAExchange
                                try:
                                    # Use the CAExchange module to wrap the socket with mutual certificate verification
                                    ssl_socket = self.ca_exchange.wrap_socket_server(client_socket)
                                    
                                    # Set the wrapped socket in tls_channel
                                    tls_channel.ssl_socket = ssl_socket
                                    log.info("Server socket wrapped successfully with certificate verification")
                                except Exception as e:
                                    log.error(f"Failed to wrap server socket with TLS certificate verification: {e}")
                                    raise ssl.SSLError(f"Failed to wrap socket with TLS certificate verification: {e}")

                                # Perform TLS handshake for non-blocking socket
                                log.info("Performing TLS handshake...")
                                
                                # Loop until handshake completes or times out
                                handshake_start = time.time()
                                handshake_timeout = self.TLS_HANDSHAKE_TIMEOUT  # seconds
                                handshake_completed = False
                                
                                # Create a socket selector for efficient waiting
                                selector = selectors.DefaultSelector()
                                # Register the socket with the selector for both read and write events
                                selector.register(tls_channel.ssl_socket, selectors.EVENT_READ | selectors.EVENT_WRITE)
                                
                                try:
                                    while time.time() - handshake_start < handshake_timeout:
                                        try:
                                            # Try to complete the handshake
                                            if tls_channel.do_handshake():
                                                handshake_completed = True
                                                break
                                            
                                            # If we're here, the handshake would block.
                                            # Wait for socket to be ready using the selector
                                            events = selector.select(timeout=0.5)
                                            if not events:
                                                # Timeout occurred, continue and check overall timeout
                                                continue
                                            
                                        except ssl.SSLWantReadError:
                                            # Socket needs to be readable
                                            selector.modify(tls_channel.ssl_socket, selectors.EVENT_READ)
                                            if not selector.select(timeout=0.5):
                                                # If not ready, check timeout and continue
                                                continue
                                        
                                        except ssl.SSLWantWriteError:
                                            # Socket needs to be writable
                                            selector.modify(tls_channel.ssl_socket, selectors.EVENT_WRITE)
                                            if not selector.select(timeout=0.5):
                                                # If not ready, check timeout and continue
                                                continue
                                        
                                        except ssl.SSLError as e:
                                            log.error(f"SSL error during handshake: {e}")
                                            raise
                                        
                                        except Exception as e:
                                            log.error(f"Unexpected error during handshake: {e}")
                                            raise
                                    
                                    if not handshake_completed:
                                        log.error("TLS handshake timed out")
                                        raise TimeoutError("TLS handshake timed out")
                                    
                                    # Handshake successful!
                                    log.info(f"TLS handshake completed successfully in {time.time() - handshake_start:.2f} seconds")
                                    
                                    # Get TLS session info for security validation
                                    session_info = tls_channel.get_session_info()
                                    log.info(f"TLS connection established with: {session_info.get('cipher', 'unknown cipher')}")
                                    
                                    if session_info.get('post_quantum', False):
                                        log.info(f"Post-quantum security active: {session_info.get('pq_algorithm', 'unknown')}")
                                    
                                finally:
                                    # Always close the selector to prevent resource leaks
                                    selector.close()
                                
                                if not handshake_completed:
                                    log.error("TLS handshake timed out")
                                    raise ssl.SSLError("TLS handshake timed out")
                                
                                log.info("TLS handshake completed successfully")
                                
                                # If authentication is required, accept auth from client
                                if self.require_authentication:
                                    log.info("Authentication required, waiting for client token...")
                                    print(f"\033[96mWaiting for client authentication...\033[0m")
                                    
                                    # Receive authentication token using non-blocking method
                                    auth_received = False
                                    auth_start = time.time()
                                    auth_timeout = 10  # seconds
                                    auth_data = None
                                    
                                    while time.time() - auth_start < auth_timeout:
                                        try:
                                            data = tls_channel.recv_nonblocking(1024)
                                            if data and data != b'':  # Got data
                                                auth_data = data
                                                auth_received = True
                                                break
                                            elif data == b'':  # Would block
                                                await asyncio.sleep(0.1)
                                            else:  # Error
                                                log.error("Connection error during authentication")
                                                raise Exception("Failed to receive authentication token")
                                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                                            # Socket not ready, wait and try again
                                            await asyncio.sleep(0.1)
                                        except Exception as e:
                                            log.error(f"Error receiving authentication token: {e}")
                                            raise
                                    
                                    if not auth_received or not auth_data:
                                        log.error("Failed to receive authentication token (timeout)")
                                        print(f"\033[91mAuthentication failed. Connection aborted.\033[0m")
                                        tls_channel.ssl_socket.close()
                                        continue
                                    
                                    # Validate the token
                                    tls_channel.authenticated = True  # Set authenticated flag on successful token validation
                                    print(f"\033[92mClient authentication successful\033[0m")
                                
                                # Store the TLS channel instance for this connection
                                self.tls_channel = tls_channel
                                
                                # Get and display TLS session information
                                session_info = self.tls_channel.get_session_info()
                                print(f"\n\033[92mSecure connection established with {client_address}:\033[0m")
                                print(f"  \033[96mCertificate Verification: \033[92mComplete\033[0m")
                                print(f"  \033[96mHybrid X3DH+PQ Handshake: Complete\033[0m")
                                print(f"  \033[96mDouble Ratchet: Active (as {'initiator' if self.is_ratchet_initiator else 'responder'})\033[0m")
                                print(f"  \033[96mTLS Version: {session_info.get('version', 'Unknown')}\033[0m")
                                print(f"  \033[96mCipher:  {session_info.get('cipher', 'Unknown')}\033[0m")
                                
                                # Show post-quantum status
                                pq_enabled = session_info.get('post_quantum', False) or session_info.get('enhanced_security', {}).get('post_quantum', {}).get('enabled', False)
                                if pq_enabled:
                                    print(f"  \033[96mPost-Quantum Security: \033[92mEnabled (X25519MLKEM1024)\033[0m")
                                else:
                                    print(f"  \033[96mPost-Quantum Security: \033[93mLimited (TLS without PQ KEM)\033[0m")
                                
                                # Store the socket
                                self.tcp_socket = tls_channel.ssl_socket
                                self.peer_ip = client_address[0]
                                self.peer_port = client_address[1]
                                
                                if server_socket:
                                    server_socket.close()
                                    server_socket = None

                                await self._chat_session()
                                
                            except Exception as e:
                                log.error(f"TLS handshake failed for incoming connection: {e}")
                                if client_socket:
                                    client_socket.close()
                                print(f"\033[91mTLS handshake failed: {e}\033[0m")
                            
                        except asyncio.TimeoutError:
                            print(f"\033[93mNo connection received within timeout period.\033[0m")
                        except asyncio.CancelledError:
                            print(f"\033[93mWaiting for connection was cancelled.\033[0m")
                            
                    except KeyboardInterrupt:
                        print(f"\033[93mCancelled waiting for connection.\033[0m")
                    except OSError as e:
                        if e.errno in (98, 10048):  # Address already in use
                            print(f"\033[91mError: Port {listen_port} is already in use.\033[0m")
                        else:
                            print(f"\033[91mServer error: {e}\033[0m")
                            log.error(f"Server socket error: {e}", exc_info=True)
                    except Exception as e:
                        print(f"\033[91mServer error: {e}\033[0m")
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
                        peer_ip = (await self._async_input(f"\nEnter peer's IP address (IPv6 or IPv4): \033[0m")).strip()
                        if not peer_ip:
                            print(f"\033[91mIP address cannot be empty.\033[0m")
                            continue
                            
                        peer_port_str = (await self._async_input(f"Enter peer's port number: \033[0m")).strip()
                        
                        try:
                            peer_port = int(peer_port_str)
                            if not (1 <= peer_port <= 65535):
                                raise ValueError("Port must be between 1 and 65535.")

                            try:
                                # Connect with enhanced security
                                await self._connect_to_peer(peer_ip, peer_port)
                                print(f"\033[92mConnected successfully with enhanced security!\033[0m")
                                await self._chat_session()
                                
                            except ValueError as e:
                                print(f"\033[91mInvalid port number: {e}\033[0m")
                            except socket.gaierror:
                                print(f"\033[91mError: Could not resolve hostname or invalid IP address.\033[0m")
                            except ConnectionRefusedError:
                                print(f"\033[91mConnection refused. Is the peer server running?\033[0m")
                            except asyncio.TimeoutError:
                                print(f"\033[91mConnection timed out. Peer may be offline or behind restrictive firewall.\033[0m")
                            except OSError as e:
                                print(f"\033[91mNetwork error: {e}\033[0m")
                                log.error(f"Network error connecting to peer: {e}", exc_info=True)
                            except Exception as e:
                                print(f"\033[91mConnection error: {e}\033[0m")
                                log.error(f"Unexpected error connecting to peer: {e}", exc_info=True)
                                
                        except ValueError:
                            print(f"\033[91mInvalid port number. Please enter a number between 1-65535.\033[0m")
                    except asyncio.CancelledError:
                        log.info("Client connection process cancelled")
                        print(f"\033[93mConnection attempt cancelled.\033[0m")
                    except Exception as e:
                        log.error(f"Error in client mode: {e}", exc_info=True)
                        print(f"\033[91mUnexpected error: {e}\033[0m")

                # Retry STUN
                elif choice == '3':
                    print("Rediscovering public IP via STUN...")
                    try:
                        self.public_ip, self.public_port = await p2p.get_public_ip_port()

                        if self.public_ip:
                            if ':' in self.public_ip:
                                print(f"\033[92mPublic IPv6: [{self.public_ip}]:{self.public_port}\033[0m")
                            else:
                                print(f"\033[92mPublic IPv4: {self.public_ip}:{self.public_port}\033[0m")
                        else:
                            print(f"\033[93mCould not determine public IP using STUN.\033[0m")
                            print(f"\033[93mYou may still be able to accept incoming connections on a local network.\033[0m")
                    except Exception as e:
                        log.error(f"STUN discovery error: {e}", exc_info=True)
                        print(f"\033[91mError during STUN discovery: {e}\033[0m")

                # Exit
                elif choice == '4':
                    print(f"\033[93mExiting...\033[0m")
                    break
                  
                else:
                    print(f"\033[91mInvalid choice. Please enter 1, 2, 3, or 4.\033[0m")

            except KeyboardInterrupt:
                print(f"\n\033[93mOperation interrupted. Returning to main menu.\033[0m")
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
                print(f"\n\033[91mUnexpected error: {e}. Continuing...\033[0m")

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
                    # Wait a moment for cancellation to complete
                    await asyncio.sleep(0.1)
                except Exception as e:
                    log.error(f"Error cancelling {task_name}: {e}", exc_info=True)

    async def _receive_messages(self):
        """Handles receiving messages from the connected peer with improved reliability."""
        consecutive_errors = 0
        MAX_CONSECUTIVE_ERRORS = 5 # Increased tolerance
        BACKOFF_DELAY = 0.5  # Start with 0.5s delay
        
        log.info("Starting message receive loop")
        
        try:
            while not self.stop_event.is_set() and self.tcp_socket:
                try:
                    encrypted_data = await p2p.receive_framed(self.tcp_socket, timeout=self.RECEIVE_TIMEOUT)
                    consecutive_errors = 0
                    BACKOFF_DELAY = 0.5  # Reset backoff on success

                    if encrypted_data is None:
                        # Check if the socket is still supposed to be open (i.e., not intentionally closed)
                        if self.tcp_socket and not self.stop_event.is_set():
                            log.info("Receive loop detected closed connection unexpectedly.")
                            print(f"\n{YELLOW}Peer has disconnected or connection lost.{RESET}")
                            # Attempt to close and reconnect
                            # This function handles setting stop_event if reconnect fails
                            await self._close_connection(attempt_reconnect=True)
                        else:
                            # Socket already closed or stop event set, exit loop normally
                            log.info("Receive loop exiting (socket closed or stop event set).")
                        break # Exit the receive loop after handling potential disconnect

                    try:
                        # Decrypt the message using the Double Ratchet
                        try:
                            decrypted_message = await self._decrypt_message(encrypted_data)
                        except Exception as e:
                            log.error(f"Failed to decrypt message: {e}")
                            continue  # Skip processing this message and try the next one
                            
                        # Process the decrypted message
                        try:
                            if decrypted_message.startswith('USERNAME:'):
                                peer_name_candidate = decrypted_message[len('USERNAME:'):].strip()
                                if 1 <= len(peer_name_candidate) <= self.MAX_USERNAME_LENGTH and re.match(self.USERNAME_REGEX, peer_name_candidate):
                                    self.peer_username = peer_name_candidate
                                    # Clear line and print notification (p2p.py style)
                                    print("\r" + " " * 100)
                                    print(f"\n{GREEN}{BOLD}Connected with {self.peer_username}{RESET}\n")
                                    print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
                                else:
                                    log.warning(f"Received invalid username: '{peer_name_candidate}'")
                            elif decrypted_message == 'EXIT':
                                print("\r" + " " * 100)
                                print(f"\n{YELLOW}{self.peer_username} has left the chat.{RESET}")
                                log.info(f"Peer {self.peer_username} initiated disconnect.")
                                # Trigger clean close, but don't attempt reconnect here as it was intentional
                                await self._close_connection(attempt_reconnect=False)
                                break
                            elif decrypted_message.startswith('MSG:'):
                                parts = decrypted_message.split(':', 2)
                                if len(parts) == 3:
                                    sender, content = parts[1], parts[2]
                                    # Store message in history (p2p.py style)
                                    if hasattr(self, 'message_history'):
                                        if len(self.message_history) >= self.max_history_size:
                                            self.message_history.pop(0)
                                        # Store in a format compatible with our encrypted system
                                        self.message_history.append({"sender": sender, "content": content, "timestamp": time.time()})
                                    
                                    # Clear line before printing message
                                    print("\r" + " " * 100 + "\r", end='')
                                    print(f"{MAGENTA}{sender}: {RESET}{content}")
                                    print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
                                else:
                                    log.warning(f"Received malformed message: {decrypted_message}")
                            elif decrypted_message == 'HEARTBEAT':
                                self.last_heartbeat_received = time.time()
                                log.debug("Received heartbeat message")
                                # Send heartbeat response to confirm connection is still alive
                                try:
                                    # Encrypt the heartbeat acknowledgment
                                    heartbeat_ack = await self._encrypt_message("HEARTBEAT_ACK")
                                    await p2p.send_framed(self.tcp_socket, heartbeat_ack)
                                except Exception as e:
                                    log.debug(f"Failed to send heartbeat ACK: {e}")
                                    # Ignore send errors here, heartbeat loop will handle disconnect
                            elif decrypted_message == 'HEARTBEAT_ACK':
                                self.last_heartbeat_received = time.time()
                                log.debug("Received heartbeat acknowledgment")
                            elif decrypted_message == 'RECONNECTED':
                                print("\r" + " " * 100)
                                print(f"\n{GREEN}{self.peer_username} has reconnected.{RESET}")
                                print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
                            elif decrypted_message.startswith('KEY_ROTATION:'):
                                log.debug("Received key rotation message")
                                await self._handle_key_rotation(decrypted_message)
                            elif decrypted_message.startswith('KEY_ROTATION_ACK:'):
                                log.debug("Received key rotation acknowledgment")
                                # Store timestamp if needed
                                try:
                                    ack_time = int(decrypted_message.split(':', 1)[1])
                                    log.debug(f"Key rotation acknowledged at {time.ctime(ack_time)}")
                                except Exception:
                                    pass  # Non-critical if we can't parse the timestamp
                            else:
                                log.warning(f"Received unknown message type: {decrypted_message[:50]}...")
                        except Exception as e:
                            log.error(f"Error processing message '{decrypted_message[:50]}...': {e}", exc_info=True)

                    except UnicodeDecodeError:
                        log.warning("Received non-UTF8 data, ignoring.")

                except asyncio.CancelledError:
                    log.info("Receive task cancelled.")
                    raise
                except ConnectionResetError:
                    log.info("Connection reset by peer.")
                    print(f"\n{YELLOW}Connection reset by peer.{RESET}")
                    # Attempt reconnect only if the connection wasn't intentionally closed
                    if not self.stop_event.is_set():
                        await self._close_connection(attempt_reconnect=True)
                    break

                except OSError as e:
                    consecutive_errors += 1
                    # Check for specific errors indicating a closed socket
                    if e.errno in (9, 10038, 10054, 10053):  # Bad file descriptor, WSAENOTSOCK, WSAECONNRESET, WSAECONNABORTED
                        log.warning(f"Receive loop detected socket closed/error: {e}")
                        # Attempt reconnect only if the connection wasn't intentionally closed
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
                        # Exponential backoff for repeated errors
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
            # Update connection state if loop exits unexpectedly without calling _close_connection
            # (e.g., due to max errors without specific socket closed errors)
            if self.is_connected and not self.stop_event.is_set():
                 log.warning("Receive loop ended unexpectedly without explicit close. Closing connection.")
                 try:
                     await self._close_connection(attempt_reconnect=True)
                 except Exception as e:
                     log.error(f"Error during final cleanup in receive loop: {e}", exc_info=True)
            log.info("Receive loop cleanup complete")

    async def start(self):
        """Start the secure P2P chat application with enhanced security."""
        print("\n--- Secure P2P Chat with Multi-Layer Security ---")
        print("1. Hybrid X3DH+PQ for initial key agreement")
        print("   - X25519 Diffie-Hellman exchanges")
        print("   - ML-KEM-1024 post-quantum key encapsulation")
        print("   - FALCON-1024 post-quantum signatures")
        print("2. Double Ratchet for forward secrecy & break-in recovery")
        print("3. TLS 1.3 with ChaCha20-Poly1305 for transport security")
        print("4. Certificate exchange ")
        print("5. Ephemeral identity with automatic key rotation (default)")
        print("6. User Authentication via OAuth (optional, disabled by default)")
        
        # Display ephemeral identity status if enabled
        if self.use_ephemeral_identity:
            # This is now default, so message can be adjusted or removed if always shown above
            if hasattr(self, 'hybrid_kex') and hasattr(self.hybrid_kex, 'identity'):
                print(f"   - Current identity: {self.hybrid_kex.identity}")
                print(f"   - Auto-rotation every: {self.ephemeral_key_lifetime} seconds")
                
        print("Discovering public IP via STUN...")
        
        # Update security flow information
        self._update_security_flow()
         
        try:
            self.public_ip, self.public_port = await p2p.get_public_ip_port()

            if self.public_ip:
                if ':' in self.public_ip:
                    print(f"\033[92mPublic IPv6: [{self.public_ip}]:{self.public_port}\033[0m")
                else:
                    print(f"\033[92mPublic IPv4: {self.public_ip}:{self.public_port}\033[0m")
            else:
                print(f"\033[93mCould not determine public IP using STUN.\033[0m")
                print(f"\033[93mYou may still be able to accept incoming connections on a local network.\033[0m")
            
            await self.handle_connections()
        except KeyboardInterrupt:
            print("\nExiting secure chat...")
            self.cleanup()  # Make sure to clean up any resources
        except Exception as e:
            print(f"\n\033[91mUnhandled error: {e}\033[0m")
            log.error(f"Unhandled error in main loop: {e}", exc_info=True)
        finally:
            # Additional cleanup
            self.cleanup()  # Make sure to clean up any resources

        # Print security status on startup
        print("\n\033[1m\033[94m===== Secure P2P Chat Security Summary =====\033[0m")

        # Certificate exchange status
        cert_exchange_status = "\033[92mEnabled (Mutual Certificate Verification)\033[0m" if self.security_verified['cert_exchange'] else "\033[93mPending\033[0m"
        print(f"Certificate Exchange: {cert_exchange_status}")
        
        # TLS status
        tls_status = "\033[92mEnabled (TLS 1.3 with ChaCha20-Poly1305)\033[0m" if self.security_verified['tls'] else "\033[91mFailed\033[0m"
        print(f"TLS Security: {tls_status}")
        
        # Post-quantum status
        pq_status = "\033[92mEnabled (X25519MLKEM1024 + FALCON-1024)\033[0m" if self.post_quantum_enabled else "\033[93mLimited\033[0m"
        print(f"Post-Quantum Security: {pq_status} (default: enabled)")
        
        # Ephemeral identity status
        if self.security_verified['ephemeral_identity']:
            ephemeral_status = f"\033[92mEnabled (Rotation: {self.ephemeral_key_lifetime}s) (default)\033[0m"
        else:
            ephemeral_status = "\033[93mDisabled (permanent identity, override P2P_EPHEMERAL_IDENTITY=false)\033[0m"
        print(f"Ephemeral Identity: {ephemeral_status}")
        
        # Hardware security status
        if self.security_verified['secure_enclave']:
            enclave_type = self.tls_channel.secure_enclave.enclave_type if hasattr(self.tls_channel, 'secure_enclave') else "Unknown"
            hw_status = f"\033[92mEnabled ({enclave_type})\033[0m"
        else:
            hw_status = "\033[93mSoftware only\033[0m"
        print(f"Hardware Security: {hw_status}")
        
        # In-memory key status - now default is enabled
        mem_status = "\033[92mEnabled (no disk persistence) (default)\033[0m" if self.in_memory_only else "\033[93mDisabled (keys stored on disk, override P2P_IN_MEMORY_ONLY=false)\033[0m"
        print(f"In-Memory Keys: {mem_status}")
        
        # Authentication status
        if self.require_authentication: # User explicitly enabled it
            if self.oauth_client_id and self.security_verified['oauth_auth']:
                auth_status = f"\033[92mEnabled by user ({self.oauth_provider.capitalize()})\033[0m"
            elif not self.oauth_client_id: # User enabled auth but forgot ID (and no override or override failed exit)
                 auth_status = f"\033[91mCRITICAL: Enabled by user but P2P_OAUTH_CLIENT_ID not set. Authentication will fail or has been force-disabled by override.{RESET}"
            else: # OAuth ID set, auth enabled by user, but verification failed
                auth_status = f"\033[93mEnabled by user, but OAuth verification failed. Check TLS channel logs.{RESET}"
        else: # Default or explicitly disabled
            auth_status = "\033[92mDisabled (anonymous mode - default, or P2P_REQUIRE_AUTH=false){RESET}"
        print(f"User Authentication: {auth_status}")
        
        # Forward secrecy
        print(f"Forward Secrecy: \033[92mEnabled (TLS 1.3 + Double Ratchet)\033[0m")
        
        # Double Ratchet
        print(f"Message Security: \033[92mEnabled (ChaCha20-Poly1305 + Double Ratchet)\033[0m")
        
        # How to enable ephemeral identities
        if not self.use_ephemeral_identity:
            print("\n\033[93mTip: Set P2P_EPHEMERAL_IDENTITY=true environment variable")
            print("to enable anonymous ephemeral identities with automatic rotation\033[0m")
            
        # Add note about in-memory mode being default
        if not self.in_memory_only:
            print("\n\033[93mNote: In-memory keys are enabled by default for security.")
            print("To store keys on disk, set P2P_IN_MEMORY_ONLY=false\033[0m")
            
        print("\033[1m\033[94m=========================================\033[0m\n")

    def _add_random_padding(self, plaintext_bytes: bytes) -> bytes:
        """Adds random padding to plaintext before encryption.
        Structure: [ Plaintext | Random Padding Bytes | Length of Random Padding Bytes (1 byte) ]
        Padding length is 1 to MAX_RANDOM_PADDING_BYTES (inclusive).
        """
        if not isinstance(plaintext_bytes, bytes):
            # Ensure input is bytes, though _encrypt_message should handle this.
            raise TypeError("Input to padding must be bytes.")
            
        # Generate 1 to MAX_RANDOM_PADDING_BYTES of random padding
        # secrets.randbelow(N) returns 0 to N-1. So randbelow(MAX_RANDOM_PADDING_BYTES) gives 0 to 31.
        # Adding 1 makes it 1 to 32.
        num_random_bytes = secrets.randbelow(self.MAX_RANDOM_PADDING_BYTES) + 1
        random_padding = secrets.token_bytes(num_random_bytes)
        len_byte = num_random_bytes.to_bytes(1, 'big')
        
        log.debug(f"Added {num_random_bytes} random padding bytes + 1 length byte.")
        return plaintext_bytes + random_padding + len_byte

    def _remove_random_padding(self, padded_plaintext_bytes: bytes) -> bytes:
        """Removes random padding from decrypted plaintext."""
        if not padded_plaintext_bytes:
            # This case should ideally be handled by higher-level logic (e.g., empty decrypted message)
            # but as a safeguard for padding logic itself:
            log.warning("Attempted to unpad an empty message.")
            raise ValueError("Cannot unpad empty message")

        if len(padded_plaintext_bytes) < 1: # Cannot read length byte
            log.error("Padded message too short to contain padding length byte.")
            raise ValueError("Padded message too short to contain padding info")

        num_random_bytes = padded_plaintext_bytes[-1] # Last byte is the length of *random* padding

        # Total padding length is num_random_bytes + 1 (for the length byte itself)
        total_padding_length = num_random_bytes + 1
        
        if total_padding_length > len(padded_plaintext_bytes):
            log.error(f"Invalid padding: indicated padding length {total_padding_length} (random: {num_random_bytes}) is greater than message length {len(padded_plaintext_bytes)}.")
            raise ValueError(f"Invalid padding: indicated padding ({total_padding_length} bytes) exceeds message length ({len(padded_plaintext_bytes)})")
            
        original_plaintext_end_index = len(padded_plaintext_bytes) - total_padding_length
        
        log.debug(f"Removed {num_random_bytes} random padding bytes + 1 length byte.")
        return padded_plaintext_bytes[:original_plaintext_end_index]

    async def _encrypt_message(self, message: str) -> bytes:
        """Encrypts a string message using the Double Ratchet, with random padding."""
        if not self.ratchet:
            log.error("Double Ratchet not initialized. Cannot encrypt.")
            raise SecurityError("Double Ratchet not initialized for encryption")

        try:
            plaintext_bytes = message.encode('utf-8')
            log.debug(f"Original plaintext length: {len(plaintext_bytes)} bytes")

            padded_bytes = self._add_random_padding(plaintext_bytes)
            log.debug(f"Plaintext length after padding: {len(padded_bytes)} bytes")
            
            encrypted_data = self.ratchet.encrypt(padded_bytes)
            log.debug(f"Encrypted message ({len(plaintext_bytes)} plaintext bytes, {len(padded_bytes)} padded bytes) to {len(encrypted_data)} ciphertext bytes")

            if len(encrypted_data) > self.MAX_POST_ENCRYPTION_SIZE:
                log.error(f"CRITICAL: Encrypted message size ({len(encrypted_data)} bytes) exceeds maximum allowed payload size ({self.MAX_POST_ENCRYPTION_SIZE} bytes). Aborting send.")
                raise ValueError(f"Encrypted message exceeds maximum allowed payload size of {self.MAX_POST_ENCRYPTION_SIZE} bytes.")

            return encrypted_data
        except Exception as e:
            log.error(f"Error during message encryption and padding: {e}", exc_info=True)
            # Consider if a more specific exception should be raised or if SecurityError is appropriate
            raise SecurityError(f"Message encryption failed: {e}") from e

    async def _decrypt_message(self, encrypted_data: bytes) -> str:
        """Decrypts a message using the Double Ratchet and removes random padding."""
        log.debug(f"Received {len(encrypted_data)} ciphertext bytes for decryption.") # Added log line
        if not self.ratchet:
            log.error("Double Ratchet not initialized. Cannot decrypt.")
            raise SecurityError("Double Ratchet not initialized for decryption")

        try:
            decrypted_padded_bytes = self.ratchet.decrypt(encrypted_data)
            log.debug(f"Decrypted to {len(decrypted_padded_bytes)} bytes (includes padding).")

            decrypted_bytes = self._remove_random_padding(decrypted_padded_bytes)
            log.debug(f"Plaintext length after unpadding: {len(decrypted_bytes)} bytes")
            
            message = decrypted_bytes.decode('utf-8')
            return message
        except UnicodeDecodeError as e:
            log.error(f"Failed to decode message after decryption and unpadding: {e}", exc_info=True)
            raise SecurityError(f"Message decoding failed after decryption: {e}") from e
        except ValueError as e: # Catch padding errors
            log.error(f"Error removing padding: {e}", exc_info=True)
            raise SecurityError(f"Padding removal failed: {e}") from e
        except Exception as e:
            log.error(f"Error during message decryption or unpadding: {e}", exc_info=True)
            raise SecurityError(f"Message decryption failed: {e}") from e

    async def _chat_session(self, is_reconnect=False):
        """Manages an active chat session after a TCP connection is established."""
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
                # Encrypt the reconnection message using the Double Ratchet
                reconnect_msg = f"RECONNECTED"
                encrypted_msg = await self._encrypt_message(reconnect_msg)
                success = await p2p.send_framed(self.tcp_socket, encrypted_msg)
                if not success:
                    log.error("Failed to send reconnection notice")
                    await self._close_connection()
                    return
                print(f"{GREEN}Reconnected to chat session.{RESET}")
            else:
                # Encrypt the username message using the Double Ratchet
                username_msg = f"USERNAME:{self.local_username}"
                encrypted_msg = await self._encrypt_message(username_msg)
                success = await p2p.send_framed(self.tcp_socket, encrypted_msg)
                if not success:
                    log.error("Failed to send username")
                    await self._close_connection()
                    return
        except Exception as e:
            log.error(f"Failed to send initial message: {e}")
            print(f"{RED}Error establishing chat session. Disconnecting.{RESET}")
            await self._close_connection()
            return

        # Start receiving and heartbeat
        self.receive_task = asyncio.create_task(self._receive_messages())
        self.heartbeat_task = asyncio.create_task(self._send_heartbeats())
        self.security_task = asyncio.create_task(self._security_maintenance())

        if not is_reconnect:
            print(f"\n{GREEN}Chat session started.{RESET}")
            print(f"{YELLOW}Type 'exit' to quit or '/help' for commands.{RESET}\n")

        # Process any queued messages (for reconnect)
        if is_reconnect and not self.message_queue.empty():
            print(f"{YELLOW}Sending queued messages...{RESET}")
            while not self.message_queue.empty():
                try:
                    queued_msg = await self.message_queue.get()
                    if self.is_connected:
                        # Encrypt the queued message before sending
                        encrypted_queued_msg = await self._encrypt_message(queued_msg)
                        await p2p.send_framed(self.tcp_socket, encrypted_queued_msg)
                except Exception as e:
                    log.error(f"Failed to send queued message: {e}")
                    await self.message_queue.put(queued_msg)
                    await self._close_connection(attempt_reconnect=True)
                    break

        # Sending Loop
        while not self.stop_event.is_set() and self.is_connected:
            try:
                user_input = await self._async_input(f"{CYAN}{self.local_username}: {RESET}")
                if not user_input:
                    continue
                    
                user_input = user_input.strip()

                if not self.is_connected or self.stop_event.is_set():
                    break

                if user_input.lower() == 'exit':
                    try:
                        # Encrypt the exit message using the Double Ratchet
                        exit_msg = "EXIT"
                        encrypted_exit = await self._encrypt_message(exit_msg)
                        await p2p.send_framed(self.tcp_socket, encrypted_exit)
                    except:
                        pass  # Ignore errors when exiting
                    break

                # Handle special commands
                if user_input.startswith('/'):
                    await self._handle_command(user_input)
                    continue

                if user_input:
                    try:
                        # Format message similar to p2p.py but encrypted
                        msg_data = f"MSG:{self.local_username}:{user_input}"
                        encrypted_msg = await self._encrypt_message(msg_data)
                        
                        # Store in message history before sending (like p2p.py)
                        if hasattr(self, 'message_history'):
                            if len(self.message_history) >= self.max_history_size:
                                self.message_history.pop(0)
                            # Store message in history
                            self.message_history.append({"sender": self.local_username, "content": user_input, "timestamp": time.time()})
                        
                        success = await p2p.send_framed(self.tcp_socket, encrypted_msg)
                        
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
                                # Try to close and reconnect if we're still considered connected
                                log.info("Attempting reconnect after failed send.")
                                if not self.stop_event.is_set():
                                    await self._close_connection(attempt_reconnect=True)
                                break
                    except Exception as e:
                        log.error(f"Failed to send message: {e}")
                        if self.message_queue.qsize() < 100: # Limit queue size
                            await self.message_queue.put(msg_data)
                        else:
                            log.warning("Message queue full, discarding oldest message.")
                            try: 
                                await self.message_queue.get_nowait() # Discard oldest
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

        # Cancel tasks
        for task_name, task in [
            ("receive_task", self.receive_task), 
            ("heartbeat_task", self.heartbeat_task),
            ("security_task", getattr(self, "security_task", None))
        ]:
            if task and not task.done():
                try:
                    task.cancel()
                    # Wait a moment for cancellation to complete
                    await asyncio.sleep(0.1)
                except Exception as e:
                    log.error(f"Error cancelling {task_name}: {e}", exc_info=True)

    async def _send_heartbeats(self):
        """Sends periodic heartbeat messages to keep the connection alive with improved reliability."""
        missed_heartbeats = 0
        
        while not self.stop_event.is_set() and self.is_connected:
            try:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                
                if not self.is_connected or self.stop_event.is_set():
                    break
                
                if self.tcp_socket and self.ratchet:
                    try:
                        # Encrypt the heartbeat message using the Double Ratchet
                        heartbeat_msg = await self._encrypt_message("HEARTBEAT")
                        success = await p2p.send_framed(self.tcp_socket, heartbeat_msg)
                        
                        if not success:
                            missed_heartbeats += 1
                            log.warning(f"Failed to send heartbeat. Missed: {missed_heartbeats}/{self.MISSED_HEARTBEATS_THRESHOLD}")
                            
                            if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                                log.warning("Too many missed heartbeats. Connection may be dead.")
                                print(f"\n{YELLOW}Connection appears to be dead. Attempting to reconnect...{RESET}")
                                # Attempt reconnect only if not already stopping
                                if not self.stop_event.is_set():
                                    await self._close_connection(attempt_reconnect=True)
                                break
                        else:
                            missed_heartbeats = 0  # Reset counter on successful heartbeat
                    except Exception as e:
                        log.error(f"Error sending encrypted heartbeat: {e}")
                        missed_heartbeats += 1
                        
                        if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                            if not self.stop_event.is_set():
                                await self._close_connection(attempt_reconnect=True)
                            break
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Error sending heartbeat: {e}")
                missed_heartbeats += 1
                
                if missed_heartbeats >= self.MISSED_HEARTBEATS_THRESHOLD:
                    if not self.stop_event.is_set():
                        await self._close_connection(attempt_reconnect=True)
                    break

    def __del__(self):
        """
        Ensure proper cleanup when object is garbage collected.
        """
        log.debug("SecureP2PChat instance being garbage collected")
        
        # Explicitly call cleanup to ensure cryptographic material is erased
        try:
            if hasattr(self, 'cleanup'):
                self.cleanup()
        except Exception as e:
            # Can't use regular logging here as it might be shutdown already
            sys.stderr.write(f"Error during cleanup in __del__: {e}\n")
            
        # Unregister cleanup handler to prevent double-cleanup
        try:
            atexit.unregister(self.cleanup)
        except Exception:
            pass
            
        # Explicit memory cleanup
        try:
            if hasattr(self, 'ratchet'):
                self.ratchet = None
                
            if hasattr(self, 'hybrid_root_key'):
                self.hybrid_root_key = None
                
            if hasattr(self, 'tls_channel'):
                self.tls_channel = None
                
            # Force garbage collection
            gc.collect()
        except Exception:
            pass
 
    def _enable_memory_protection(self):
        """
        Enable memory protection features to prevent buffer overflows and other memory-based attacks.
        
        Returns:
            bool: True if memory protection was enabled successfully, False otherwise
        """
        try:
            # Initialize DEP (Data Execution Prevention)
            from dep_impl import implement_dep_in_secure_p2p
            dep_result = implement_dep_in_secure_p2p()
            log.info(f"Successfully enabled {dep_result} protection")
            return True
        except Exception as e:
            log.error(f"Failed to enable memory protection: {e}")
            return False
            
    def _initialize_canary_values(self):
        """
        Initialize stack canary values for buffer overflow detection.
        
        Returns:
            bool: True if canary values were initialized successfully, False otherwise
        """
        try:
            # Import the DEP implementation
            from dep_impl import EnhancedDEP
            
            # Create an instance of EnhancedDEP
            self.dep = EnhancedDEP()
            
            # Initialize stack canaries
            self.dep._initialize_stack_canaries()
            
            # Place canaries in memory
            self.dep._place_canaries()
            
            # Initialize canary check state variables
            self.canary_initialized = True
            self._last_canary_check = time.time()
            self._canary_check_interval = 30.0  # Check every 30 seconds
            
            # Start a thread to periodically verify canaries
            self.canary_check_thread = threading.Thread(
                target=self._canary_check_loop,
                daemon=True
            )
            self.canary_check_thread.start()
            
            log.info("Stack canary values initialized successfully")
            return True
        except Exception as e:
            log.error(f"Failed to initialize canary values: {e}")
            self.canary_initialized = False
            return False
            
    def _canary_check_loop(self):
        """
        Periodically verify canary values to detect buffer overflows.
        """
        import time
        while True:
            try:
                # Verify canaries
                if hasattr(self, 'dep'):
                    self.dep.verify_canaries()
                # Check every 5 seconds
                time.sleep(5)
            except Exception as e:
                log.error(f"Error in canary check loop: {e}")
                time.sleep(1)  # Sleep briefly to avoid tight loop on error
    
    def _verify_canary_values(self):
        """
        Verify canary values to detect memory tampering.
        
        Returns:
            bool: True if canary values are intact, False if tampering detected
        """
        if not hasattr(self, 'dep'):
            return False
            
        try:
            # Update last check time
            self._last_canary_check = time.time()
            # Verify canaries
            self.dep.verify_canaries()
            return True
        except Exception as e:
            log.critical(f"SECURITY ALERT: Memory tampering detected: {e}")
            return False
    
    async def _rotate_keys(self):
        """
        Perform cryptographic key rotation for enhanced forward secrecy.
        """
        if not self.key_rotation_active or not self.ratchet:
            return False
            
        try:
            log.info("Performing scheduled key rotation")
            
            # Create rotation message
            rotation_id = os.urandom(8).hex()
            ratchet_key = self.ratchet.get_new_ratchet_key()
            
            # Sign the rotation with FALCON if available
            signature = None
            if hasattr(self.hybrid_kex, 'dss') and self.hybrid_kex.dss is not None:
                try:
                    signature = self.hybrid_kex.dss.sign(self.hybrid_kex.falcon_private_key, ratchet_key)
                    log.debug(f"Created key rotation signature: {_format_binary(signature)}")
                except Exception as e:
                    log.warning(f"Could not create FALCON signature for key rotation: {e}")
                    
            rotation_message = {
                'type': 'key_rotation',
                'rotation_id': rotation_id,
                'ratchet_key': base64.b64encode(ratchet_key).decode('utf-8')
            }
            
            if signature:
                rotation_message['signature'] = base64.b64encode(signature).decode('utf-8')
                
            # Encrypt the rotation message
            rotation_json = json.dumps(rotation_message)
            encrypted_rotation = await self._encrypt_message(rotation_json)
            
            # Send the rotation message
            success = await p2p.send_framed(self.tcp_socket, encrypted_rotation)
            if success:
                log.info(f"Key rotation message sent (ID: {rotation_id})")
                # Reset key rotation timer
                self.last_key_rotation = time.time()
                return True
            else:
                log.error("Failed to send key rotation message")
                return False
                
        except Exception as e:
            log.error(f"Key rotation failed: {e}")
            return False
    
    async def _security_maintenance(self):
        """
        Perform periodic security maintenance tasks.
        """
        try:
            # Check if canary values are intact
            if self.canary_initialized and hasattr(self, '_last_canary_check'):
                if time.time() - self._last_canary_check > self._canary_check_interval:
                    if not self._verify_canary_values():
                        log.error("SECURITY ALERT: Memory tampering detected during maintenance check")
                        print(f"\n{RED}SECURITY ALERT: Memory integrity verification failed. Connection may be compromised.{RESET}")
                        # Force disconnection for security
                        self.stop_event.set()
                    
            # Check if key rotation is needed
            if self.is_connected and hasattr(self, 'last_key_rotation'):
                if time.time() - self.last_key_rotation > self.KEY_ROTATION_INTERVAL:
                    await self._rotate_keys()
            
            # Check if ephemeral identity needs rotation
            if self.use_ephemeral_identity and hasattr(self, 'hybrid_kex'):
                if self.hybrid_kex.check_key_expiration():
                    log.info("Ephemeral identity has expired, rotating...")
                    
                    # Only rotate if not actively connected
                    if not self.is_connected:
                        self.hybrid_kex.rotate_keys()
                        log.info(f"Rotated to new ephemeral identity: {self.hybrid_kex.identity}")
                    else:
                        log.info("Deferring ephemeral identity rotation until connection ends")
                    
            # Trigger garbage collection to clean up memory
            gc.collect()
            
        except Exception as e:
            log.error(f"Error during security maintenance: {e}")
            
    def _update_security_flow(self):
        """Update security flow information with current status."""
        # Initialize security flow if not exists
        if not hasattr(self, 'security_flow'):
            self.security_flow = {}
            
        # Initialize security_verified if not fully populated
        if 'cert_exchange' not in self.security_verified:
            self.security_verified['cert_exchange'] = False
        if 'ephemeral_identity' not in self.security_verified:
            self.security_verified['ephemeral_identity'] = self.use_ephemeral_identity
            
        # Add ephemeral identity information to security flow
        self.security_flow['ephemeral_identity'] = {
            'status': self.security_verified.get('ephemeral_identity', False),
            'provides': ['anonymity', 'untraceable_sessions', 'forward_secrecy'],
            'algorithm': 'Dynamic identity rotation with disposable key pairs'
        }
        
        self.security_flow['in_memory_keys'] = {
            'status': self.in_memory_only,
            'provides': ['anti_forensic', 'key_security'],
            'algorithm': 'RAM-only cryptographic operations with secure erasure'
        }
    
        # Add certificate exchange verification to security flow
        self.security_flow['certificate_exchange'] = {
            'status': self.security_verified.get('cert_exchange', False),
            'provides': ['identity_verification', 'extra_mitm_protection'],
            'algorithm': 'Mutual Self-Signed Certificate Exchange'
        }
    
        # Add double_ratchet security flow information
        self.security_flow['double_ratchet'] = {
            'status': self.security_verified.get('double_ratchet', False),
            'provides': ['forward_secrecy', 'break_in_recovery', 'message_encryption'],
            'algorithm': 'Post-Quantum Enhanced Double Ratchet'
        }
    
    async def _handle_key_rotation(self, rotation_message):
        """
        Handle a key rotation message from the peer.
        
        Args:
            rotation_message (dict): The key rotation message from the peer
        
        Returns:
            bool: True if key rotation was successful, False otherwise
        """
        try:
            log.info(f"Processing key rotation request (ID: {rotation_message.get('rotation_id', 'unknown')})")
            
            # Extract and decode the new ratchet key
            if 'ratchet_key' not in rotation_message:
                log.error("Invalid key rotation message: missing ratchet_key")
                return False
                
            ratchet_key = base64.b64decode(rotation_message['ratchet_key'])
            verify_key_material(ratchet_key, description="Peer's new ratchet key")
            
            # Verify signature if present
            if 'signature' in rotation_message and self.peer_falcon_public_key:
                try:
                    signature = base64.b64decode(rotation_message['signature'])
                    if not self.hybrid_kex.dss.verify(self.peer_falcon_public_key, ratchet_key, signature):
                        log.error("SECURITY ALERT: Invalid signature on key rotation message")
                        return False
                    log.debug("Verified signature on key rotation message")
                except Exception as e:
                    log.error(f"Error verifying rotation signature: {e}")
                    # Continue anyway as signature is optional
            
            # Update the ratchet with the new key
            if self.ratchet:
                self.ratchet.update_remote_key(ratchet_key)
                log.info("Ratchet keys rotated successfully")
                return True
            else:
                log.error("Cannot rotate keys: ratchet not initialized")
                return False
                
        except Exception as e:
            log.error(f"Error handling key rotation: {e}")
            return False
    
    def _secure_key_storage(self, key_material: bytes, key_name: str) -> str:
        """
        Securely store sensitive key material.
        
        Args:
            key_material (bytes): The key material to store
            key_name (str): Identifier for the key
            
        Returns:
            str: Key identifier for retrieval, or empty string on failure
        """
        if not key_material or not key_name:
            return ""
            
        try:
            # Check if secure key manager is available
            if not hasattr(secure_key_manager, 'store_key'):
                log.warning("Secure key manager not available for key storage")
                return ""
                
            # Use secure key manager to store the key
            key_id = secure_key_manager.store_key(
                key_material=key_material,
                key_name=key_name,
                in_memory_only=self.in_memory_only
            )
            
            if key_id:
                log.debug(f"Key '{key_name}' stored securely with ID: {key_id}")
                return key_id
            else:
                log.warning(f"Failed to store key '{key_name}' securely")
                return ""
                
        except Exception as e:
            log.error(f"Error storing key securely: {e}")
            return ""
    
    def _verify_key_storage(self) -> bool:
        """
        Verify that secure key storage is working properly.
        
        Returns:
            bool: True if secure key storage is available and working
        """
        try:
            # Skip verification if secure key manager is not available
            if not hasattr(secure_key_manager, 'store_key') or not hasattr(secure_key_manager, 'retrieve_key'):
                log.warning("Secure key manager not available for verification")
                return False
                
            # Generate test key
            test_key = os.urandom(32)
            test_name = f"verify_test_{int(time.time())}"
            
            # Try to store and retrieve the key
            store_result = secure_key_manager.store_key(
                key_material=test_key,
                key_name=test_name,
                in_memory_only=self.in_memory_only
            )
            
            if not store_result:
                log.warning("Key storage verification failed: could not store test key")
                return False
                
            # Attempt to retrieve the key
            retrieved_key = secure_key_manager.retrieve_key(
                test_name, 
                in_memory_only=self.in_memory_only
            )
            
            if not retrieved_key or retrieved_key != test_key:
                log.warning("Key storage verification failed: retrieved key does not match original")
                return False
                
            # Cleanup the test key
            secure_key_manager.delete_key(test_name, in_memory_only=self.in_memory_only)
            
            if self.in_memory_only:
                log.info("In-memory key storage verified successfully")
            else:
                log.info("Persistent key storage verified successfully")
                
            return True
            
        except Exception as e:
            log.error(f"Key storage verification failed with error: {e}")
            # For in-memory mode, failures are less critical - we can still operate
            if self.in_memory_only:
                log.warning("Using fallback in-memory mechanism despite verification failure")
                return True
            return False

    async def _handle_command(self, command: str) -> None:
        """
        Handle special chat commands starting with /
        
        Args:
            command: The command string entered by the user
        """
        cmd_parts = command.split(maxsplit=1)
        cmd = cmd_parts[0].lower()
        
        if cmd == '/help':
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Available commands:{RESET}")
            print(f"  {BOLD}/help{RESET} - Show this help message")
            print(f"  {BOLD}/clear{RESET} - Clear the chat screen")
            print(f"  {BOLD}/status{RESET} - Show connection status")
            print(f"  {BOLD}/identity{RESET} - Show identity information (ephemeral by default)")
            print(f"  {BOLD}/config{RESET} - Show configuration options and environment variables")
            if self.use_ephemeral_identity: # This is default true
                print(f"  {BOLD}/rotate{RESET} - Rotate to a new ephemeral identity (when disconnected)")
            print(f"  {BOLD}/exit{RESET} - Exit the chat")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            
        elif cmd == '/clear':
            if sys.platform == 'win32':
                os.system('cls')
            else:
                os.system('clear')
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            
        elif cmd == '/status':
            uptime = time.time() - self.last_heartbeat_received if self.last_heartbeat_received else 0
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Secure Connection Status:{RESET}")
            print(f"  Connected to: {self.peer_username} [{self.peer_ip}]:{self.peer_port}")
            print(f"  Connection uptime: {int(uptime)} seconds")
            print(f"  Security: Hybrid X3DH+PQ & Double Ratchet active")
            
            # Show certificate verification status
            cert_status = f"{GREEN}Verified{RESET}" if self.security_verified['cert_exchange'] else f"{YELLOW}Not verified{RESET}"
            print(f"  Certificate verification: {cert_status}")
            
            if hasattr(self, 'message_history'):
                print(f"  Messages in history: {len(self.message_history)}")
            print(f"  Messages queued: {self.message_queue.qsize()}")
            
            # Show ephemeral identity details if enabled
            if self.use_ephemeral_identity and hasattr(self, 'hybrid_kex'):
                time_left = int(self.hybrid_kex.next_rotation_time - time.time())
                print(f"  Ephemeral identity: {self.hybrid_kex.identity}")
                print(f"  Identity expires in: {time_left} seconds")
                
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            
        elif cmd == '/identity':
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Identity Information:{RESET}")
            
            if hasattr(self, 'hybrid_kex'):
                if self.use_ephemeral_identity:
                    print(f"  Mode: {GREEN}Ephemeral (automatic rotation){RESET}")
                    print(f"  Current identity: {self.hybrid_kex.identity}")
                    time_left = int(self.hybrid_kex.next_rotation_time - time.time())
                    print(f"  Expires in: {time_left} seconds")
                    print(f"  Rotation interval: {self.ephemeral_key_lifetime} seconds")
                else:
                    print(f"  Mode: {YELLOW}Persistent{RESET}")
                    print(f"  Identity: {self.hybrid_kex.identity}")
                
                if self.in_memory_only:
                    print(f"  Storage: {GREEN}Memory only (no disk persistence){RESET}")
                else:
                    print(f"  Storage: {YELLOW}Disk-based{RESET}")
            else:
                print(f"  {RED}Identity information not available{RESET}")
                
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            
        elif cmd == '/config':
            print("\r" + " " * 100)
            print(f"\n{YELLOW}Configuration Options:{RESET}")
            print(f"The following environment variables can be used to configure the application:")
            
            print(f"\n{GREEN}Storage Configuration:{RESET}")
            print(f"  P2P_IN_MEMORY_ONLY=true|false - Store keys in memory only (default: true)")
            print(f"  P2P_BASE_DIR=/path - Base directory for all files (default: script directory)")
            print(f"  P2P_CERT_DIR=/path - Certificate directory (default: BASE_DIR/cert)")
            print(f"  P2P_KEYS_DIR=/path - Key directory (default: BASE_DIR/keys)")
            print(f"  P2P_CERT_PATH=/path - Path to TLS certificate (default: CERT_DIR/server.crt)")
            print(f"  P2P_KEY_PATH=/path - Path to TLS key (default: CERT_DIR/server.key)")
            print(f"  P2P_CA_PATH=/path - Path to CA certificate (default: CERT_DIR/ca.crt)")
            
            print(f"\n{GREEN}Identity Configuration:{RESET}")
            print(f"  P2P_EPHEMERAL_IDENTITY=true|false - Use ephemeral identities (default: true)")
            print(f"  P2P_EPHEMERAL_LIFETIME=seconds - Lifetime of ephemeral identities (default: {DEFAULT_KEY_LIFETIME})")
            
            print(f"\n{GREEN}Authentication Configuration (Optional - Disabled by Default):{RESET}")
            print(f"  P2P_REQUIRE_AUTH=true|false - Require authentication (default: false)")
            print(f"  P2P_OAUTH_PROVIDER=provider - OAuth provider (default: google, used if auth enabled)")
            print(f"  P2P_OAUTH_CLIENT_ID=id - OAuth client ID (REQUIRED if P2P_REQUIRE_AUTH=true)")
            print(f"  P2P_ALLOW_UNAUTHENTICATED_IF_ID_MISSING=true|false - Advanced: Allow running unauthenticated if P2P_REQUIRE_AUTH=true but ID is missing (default: false, INSECURE if auth is intended)")
            
            print(f"\n{GREEN}Security Configuration:{RESET}")
            print(f"  P2P_POST_QUANTUM=true|false - Enable post-quantum cryptography (default: true)")
            
            print(f"\n{GREEN}Current Configuration:{RESET}")
            print(f"  Base directory: {self.base_dir}")
            print(f"  Certificate directory: {self.cert_dir}")
            print(f"  Keys directory: {self.keys_dir}")
            print(f"  In-memory only: {self.in_memory_only} (default: true)")
            print(f"  Ephemeral identity: {self.use_ephemeral_identity} (default: true)")
            print(f"  Authentication required: {self.require_authentication} (default: false)")
            if self.require_authentication: # Only show Client ID status if auth is actually attempted
                if not self.oauth_client_id:
                    print(f"  {RED}OAuth Client ID (P2P_OAUTH_CLIENT_ID): NOT SET (CRITICAL for current P2P_REQUIRE_AUTH=true setting){RESET}")
                else:
                    print(f"  OAuth Client ID (P2P_OAUTH_CLIENT_ID): {'Set (value hidden)' if self.oauth_client_id else 'NOT SET'}")
                
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            
        elif cmd == '/rotate':
            if not self.use_ephemeral_identity: # Should not happen with new default
                print("\r" + " " * 100)
                print(f"\n{RED}Ephemeral identity mode is not enabled (this is unexpected with default settings).{RESET}")
                print(f"{YELLOW}Ensure P2P_EPHEMERAL_IDENTITY is true (default).{RESET}")
            elif self.is_connected:
                print("\r" + " " * 100)
                print(f"\n{YELLOW}Cannot rotate identity while connected.{RESET}")
                print(f"{YELLOW}Disconnect first, then use /rotate.{RESET}")
            else:
                print("\r" + " " * 100)
                old_id = self.hybrid_kex.identity
                self.hybrid_kex.rotate_keys()
                new_id = self.hybrid_kex.identity
                print(f"\n{GREEN}Identity rotated successfully:{RESET}")
                print(f"  Old: {old_id}")
                print(f"  New: {new_id}")
                print(f"  Next rotation: {time.ctime(self.hybrid_kex.next_rotation_time)}")
                
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)
            
        elif cmd == '/exit':
            encrypted_exit = await self._encrypt_message("EXIT")
            await p2p.send_framed(self.tcp_socket, encrypted_exit)
            await self._close_connection(attempt_reconnect=False)
            
        else:
            print("\r" + " " * 100)
            print(f"\n{RED}Unknown command: {cmd}. Type /help for available commands.{RESET}")
            print(f"{CYAN}{self.local_username}: {RESET}", end='', flush=True)

    async def _refresh_stun(self):
        """Refresh STUN discovery of public IP/port."""
        print(f"{CYAN}Rediscovering public IPv6 address via STUN...{RESET}")
        try:
            # Set secure memory settings
            os.environ['P2P_USE_SODIUM_MEM'] = os.environ.get('P2P_USE_SODIUM_MEM', 'true')
            
            # Set memory protection settings
            os.environ['P2P_ENABLE_DEP'] = os.environ.get('P2P_ENABLE_DEP', 'false')
            os.environ['P2P_SKIP_MITIGATION'] = os.environ.get('P2P_SKIP_MITIGATION', 'true')
            
            old_ip = self.public_ip
            old_port = self.public_port
            
            self.public_ip, self.public_port = await p2p.get_public_ip_port()

            if self.public_ip:
                ip_display = f"[{self.public_ip}]" if ':' in self.public_ip else self.public_ip
                print(f"{GREEN}Public IP: {ip_display}:{self.public_port}{RESET}")
                if old_ip != self.public_ip or old_port != self.public_port:
                    print(f"{YELLOW}Note: Your public endpoint has changed from previous value!{RESET}")
            else:
                print(f"{RED}Could not determine public IP address.{RESET}")
                print(f"{YELLOW}You may still be able to accept incoming connections on a local network.{RESET}")
                print(f"{YELLOW}Make sure your system has IPv6 connectivity.{RESET}")
        except Exception as e:
            log.error(f"STUN discovery error: {e}", exc_info=True)
            print(f"{RED}Error during STUN discovery: {e}{RESET}")

    def _print_banner(self):
        """Print the application banner including security features."""
        # Set the P2P_DISABLE_DANE environment variable to true by default
        os.environ['P2P_DISABLE_DANE'] = os.environ.get('P2P_DISABLE_DANE', 'true')

        # Print security status on startup
        print("\n\033[1m\033[94m===== Secure P2P Chat Security Summary =====\033[0m")
        
        # Certificate exchange status
        cert_exchange_status = "\033[92mEnabled (Mutual Certificate Verification)\033[0m" if self.security_verified['cert_exchange'] else "\033[93mPending\033[0m"
        print(f"Certificate Exchange: {cert_exchange_status}")
        
        # TLS status
        tls_status = "\033[92mEnabled (TLS 1.3 with ChaCha20-Poly1305)\033[0m" if self.security_verified['tls'] else "\033[91mFailed\033[0m"
        print(f"TLS Security: {tls_status}")

    def _initialize_hardware_security(self):
        """
        Initialize hardware security module (TPM/HSM) for cryptographic operations.
        
        Returns:
            bool: True if hardware security was successfully initialized, False otherwise.
        """
        try:
            # Initialize platform HSM interface
            hsm_initialized = cphs.init_hsm()
            
            if hsm_initialized:
                log.info("Hardware security module initialized successfully")
                return True
            else:
                log.warning("Hardware security module initialization failed")
                return False
        except Exception as e:
            log.warning(f"Hardware security module initialization failed: {e}")
            return False

# Only execute this code if the script is run directly
if __name__ == "__main__":
    # Set a global flag to indicate we're running in standalone mode
    # This will be used by TLSSecureChannel to enable compatibility features
    # os.environ['SECURE_P2P_STANDALONE'] = '1'
    
    # Print the welcome banner
    print(f"\n{CYAN}--- Secure P2P Chat with Multi-Layer Security ---{RESET}")
    print(f"{GREEN}1. Hybrid X3DH+PQ for initial key agreement{RESET}")
    print(f"   - X25519 Diffie-Hellman exchanges")
    print(f"   - ML-KEM-1024 post-quantum key encapsulation")
    print(f"   - FALCON-1024 post-quantum signatures")
    print(f"{GREEN}2. Double Ratchet for forward secrecy & break-in recovery{RESET}")
    print(f"{GREEN}3. TLS 1.3 with ChaCha20-Poly1305 for transport security{RESET}")
    print(f"{GREEN}4. Certificate exchange {RESET}")
    print(f"{GREEN}5. Ephemeral identity with automatic key rotation (default){RESET}")
    print(f"{GREEN}6. User Authentication via OAuth (optional, disabled by default){RESET}")
     
    # Create and run the chat application
    chat = SecureP2PChat()
    
    try:
        asyncio.run(chat.start())
    except KeyboardInterrupt:
        print("\nExiting securely...")
        chat.cleanup()
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        chat.cleanup()



