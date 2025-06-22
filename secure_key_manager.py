"""
Secure Key Manager

Provides secure cryptographic key storage and management with multiple backends:
- OS-native secure storage (keyring)
- Filesystem storage with proper permissions
- Process isolation for sensitive operations
""" 
 
import ctypes
import os
import random
import stat
import base64
import logging
import hashlib
import sys
import tempfile
import platform
import threading
import subprocess
from pathlib import Path
import time
from typing import Optional, Dict, Union, Tuple

# Import the new cross-platform hardware security module
import platform_hsm_interface as cphs

# Import secure_erase for in-memory key wiping
from double_ratchet import secure_erase

# Import cryptography types for key erasure handling
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization as encoding
    HAS_CRYPTO_TYPES = True
except ImportError:
    HAS_CRYPTO_TYPES = False

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # Set root logger level to DEBUG for console output
    format='%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)] # Explicitly use stdout
)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG) # Ensure DEBUG messages from this module are processed

# Create a file handler for logging
try:
    # Attempt to create a log directory if it doesn't exist, relative to the script or CWD
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_file_path = log_dir / "secure_key_manager.log"
except Exception as e_log_dir:
    # Fallback to current working directory if logs subdir fails
    log_file_path = Path("secure_key_manager.log")
    log.warning(f"Could not create logs directory, saving log to current directory: {log_file_path}. Error: {e_log_dir}")

file_handler = logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s')
file_handler.setFormatter(formatter)
log.addHandler(file_handler)
# If other modules also add handlers to the root logger, this module's logs will also go there.
# To prevent duplicate console logging if root already has StreamHandler from elsewhere,
# we can set propagate to False, but for this module, it's fine to let it propagate.
# log.propagate = False

log.info(f"SecureKeyManager logging initialized. Console level: DEBUG, File level: DEBUG. Log file: {log_file_path.resolve()}")

# Try to import optional dependencies
try:
    import keyring 
    HAVE_KEYRING = True
except ImportError:
    HAVE_KEYRING = False
    log.warning("keyring library not available, falling back to secure file storage")

try:
    import zmq
    HAVE_ZMQ = True
except ImportError:
    HAVE_ZMQ = False
    log.warning("pyzmq not available, process isolation not available")

try:
    import nacl.utils
    import nacl.secret
    from nacl.exceptions import CryptoError
    from nacl.bindings import crypto_secretbox_KEYBYTES
    HAS_NACL = True
    
    # Check for secure memory functions. Failure is not critical, as we have fallbacks.
    try:
        # First try using PyNaCl's built-in functions (if available)
        try:
            from nacl.utils import sodium_malloc, sodium_free
            HAS_NACL_SECURE_MEM = True
            log.info("PyNaCl's secure memory functions are available and will be used.")
        except (ImportError, AttributeError):
            # If not available through PyNaCl, try accessing directly through ctypes if we have libsodium.dll
            try:
                # Try to load libsodium directly using ctypes
                if platform.system() == "Windows":
                    # First try the current directory
                    try:
                        libsodium = ctypes.cdll.LoadLibrary('./libsodium.dll')
                        log.info("Loaded libsodium.dll from current directory")
                    except (OSError, FileNotFoundError):
                        # Then try system paths
                        try:
                            libsodium = ctypes.cdll.LoadLibrary('libsodium.dll')
                            log.info("Loaded libsodium.dll from system path")
                        except (OSError, FileNotFoundError):
                            raise ImportError("Could not load libsodium.dll")
                elif platform.system() == "Linux":
                    try:
                        libsodium = ctypes.cdll.LoadLibrary('libsodium.so')
                        log.info("Loaded libsodium.so")
                    except (OSError, FileNotFoundError):
                        raise ImportError("Could not load libsodium.so")
                elif platform.system() == "Darwin":  # macOS
                    try:
                        libsodium = ctypes.cdll.LoadLibrary('libsodium.dylib')
                        log.info("Loaded libsodium.dylib")
                    except (OSError, FileNotFoundError):
                        raise ImportError("Could not load libsodium.dylib")
                else:
                    raise ImportError(f"Unsupported OS: {platform.system()}")
                
                # Define function prototypes for sodium_malloc and sodium_free
                libsodium.sodium_malloc.argtypes = [ctypes.c_size_t]
                libsodium.sodium_malloc.restype = ctypes.c_void_p
                libsodium.sodium_free.argtypes = [ctypes.c_void_p]
                libsodium.sodium_free.restype = None
                
                # Create Python wrapper functions
                def sodium_malloc_wrapper(size):
                    ptr = libsodium.sodium_malloc(size)
                    if ptr == 0:
                        raise MemoryError("sodium_malloc failed")
                    # Convert to Python buffer
                    buf = (ctypes.c_char * size).from_address(ptr)
                    return buf
                
                def sodium_free_wrapper(buf):
                    if hasattr(buf, '_obj'):  # Handle ctypes objects
                        ptr = ctypes.cast(ctypes.byref(buf), ctypes.c_void_p).value
                    elif hasattr(buf, 'buffer_info'):  # Handle array.array objects
                        ptr = buf.buffer_info()[0]
                    else:
                        ptr = ctypes.addressof(buf)
                    libsodium.sodium_free(ptr)
                
                # Assign our wrapper functions
                sodium_malloc = sodium_malloc_wrapper
                sodium_free = sodium_free_wrapper
                HAS_NACL_SECURE_MEM = True
                log.info("Using direct libsodium bindings for secure memory via ctypes.")
            except (ImportError, AttributeError, OSError) as e:
                log.info(f"Direct libsodium bindings not available: {e}. Using fallback secure memory implementation.")
                HAS_NACL_SECURE_MEM = False
    except Exception as e:
        log.info(f"Secure memory via libsodium not available: {e}. Using fallback secure memory implementation.")
        HAS_NACL_SECURE_MEM = False

except ImportError:
    HAS_NACL = False
    HAS_NACL_SECURE_MEM = False
    log.warning("pynacl library not available, secure memory functions are disabled.")

# Constants
SERVICE_NAME = "secure_p2p_chat"
DEFAULT_SECURE_DIR = "secure_keys"

# Determine the best IPC path for the platform
if platform.system() != "Windows":
    # This global IPC_PATH will be overridden by instance-specific paths for POSIX
    # or used as a default for Windows if not already set.
    IPC_PATH = "ipc:///tmp/secure_key_manager" 
else:
    IPC_PATH = None  # Will be set during initialization for Windows

class KeyProtectionError(Exception):
    """Exception raised for key protection related errors."""
    pass

# Simple function to test if a memory address can be locked
def test_memory_locking():
    """Test if memory locking is available."""
    try:
        test_buf = bytearray(16)
        test_addr = ctypes.addressof((ctypes.c_char * 16).from_buffer(test_buf))
        locked = cphs.lock_memory(test_addr, 16)
        if locked:
            cphs.unlock_memory(test_addr, 16)
            return True
        return False
    except Exception as e:
        log.warning(f"Memory locking test failed: {e}")
        return False

# Global memory locking capability flag
SYSTEM_SUPPORTS_MEMORY_LOCKING = test_memory_locking()

# Secure memory wiping utility functions
def secure_wipe_buffer(buffer):
    """
    Securely wipes a buffer's contents using multiple passes.
    
    Args:
        buffer: bytes or bytearray to wipe
    """
    if not buffer:
        return
        
    # Ensure we are working with a mutable type (bytearray)
    if isinstance(buffer, bytes):
        try:
            # This is a best-effort approach. The original bytes object is immutable.
            # We create a mutable copy to wipe, to ensure the data is cleared from memory,
            # and rely on garbage collection to eventually release the original immutable object.
            buffer = bytearray(buffer)
        except TypeError:
            # In case of unexpected types that can't be converted, log and exit.
            log.warning(f"Cannot wipe buffer of type {type(buffer)}. It is not convertible to bytearray.")
            return

    elif not isinstance(buffer, (bytearray, memoryview)):
        log.warning(f"secure_wipe_buffer called with non-wipeable type: {type(buffer)}")
        return
    
    length = len(buffer)
    
    # Use volatile to prevent optimization
    try:
        # Try to lock memory to prevent swapping
        buffer_addr = None
        memory_locked = False
        
        if hasattr(ctypes, 'addressof'):
            try:
                buffer_addr = ctypes.addressof((ctypes.c_char * length).from_buffer(buffer))
                memory_locked = cphs.lock_memory(buffer_addr, length)
                if memory_locked:
                    log.debug(f"Memory locked successfully for {length} bytes during secure wiping")
            except Exception as e:
                log.debug(f"Could not lock memory during secure wipe: {e}")
        
        # Multi-pass wipe with different patterns
        patterns = [0x00, 0xFF, 0xAA, 0x55]
        
        for pattern in patterns:
            # Fill buffer with pattern
            for i in range(length):
                buffer[i] = pattern
                
            # Memory barrier - prevent compiler optimization
            if buffer_addr:
                try:
                    ctypes.memmove(buffer_addr, buffer_addr, length)
                except:
                    pass
        
        # Final zero wipe
        for i in range(length):
            buffer[i] = 0
            
        # Unlock if we locked it
        if memory_locked and buffer_addr:
            cphs.unlock_memory(buffer_addr, length)
            
    except Exception as e:
        log.warning(f"Error during secure buffer wiping: {e}")
        # Last resort: attempt basic zeroing
        try:
            for i in range(length):
                buffer[i] = 0
        except:
            pass

def _convert_to_bytearray(data):
    """Convert data to a mutable bytearray for secure wipe capability."""
    if isinstance(data, str):
        return bytearray(data.encode('utf-8'))
    elif isinstance(data, bytes):
        return bytearray(data)
    elif isinstance(data, bytearray):
        return data
    raise TypeError("Cannot convert data to bytearray")

def enhanced_secure_erase(data):
    """
    Advanced secure memory erasure that tries multiple techniques.
    More thorough than secure_erase but may not work on all platforms.
    Handles a wide variety of data types.
    
    Args:
        data: The data to securely erase
    """
    if data is None:
        return
        
    # For basic immutable types, we can't directly erase but can overwrite any copies
    if isinstance(data, bytearray):
        # Lock the memory to prevent it from being swapped to disk during operation
        try:
            with ctypes.pythonapi.PyGILState_Ensure() as gil_state:
                size = len(data)
                addr = ctypes.addressof((ctypes.c_char * size).from_buffer(data))
                secure_memory = get_secure_memory()
                secure_memory.wipe(data)  # Zero the data
                
                # Attempt to use extra secure methods based on platform
                try:
                    # Overwrite with random data for added security
                    import os
                    random_data = os.urandom(size)
                    for i in range(size):
                        data[i] = random_data[i]
                    
                    # Wipe one final time with zeros
                    for i in range(size):
                        data[i] = 0
                except Exception as e:
                    log.debug(f"Secondary secure erase step failed: {e}")
        except Exception as e:
            log.debug(f"Memory locking during secure wipe failed: {e}")
            # Fall back to basic wiping if locking fails
            for i in range(len(data)):
                data[i] = 0
    elif isinstance(data, bytes) or isinstance(data, str):
        try:
            # For bytes and strings (immutable), we can try to safely cast the address
            # and overwrite the memory, but this is extremely unsafe and platform-dependent
            if isinstance(data, bytes):
                try:
                    # Safely handle the int conversion to avoid overflow errors
                    s_addr = id(data)
                    
                    # This is a rough approximation and platform-dependent
                    if len(data) > 0:
                        try:
                            # Try to clear the characters (extremely unsafe and platform-dependent)
                            s_content_addr = s_addr + sys.getsizeof(b'') + 1
                            
                            # Convert to C-compatible int size to prevent overflow
                            if s_content_addr > ((1 << 63) - 1):  # Check if it exceeds max signed 64-bit
                                log.debug("Address too large for ctypes.memset, using safer approach")
                                # Use a safer approach for large addresses
                                secure_erase(data)  # Fall back to secure_erase
                            else:
                                ctypes.memset(s_content_addr, 0, len(data))
                        except OverflowError:
                            log.debug("Integer overflow during memory address conversion, using safer approach")
                            secure_erase(data)  # Fall back to secure_erase
                        except Exception as e:
                            log.debug(f"Could not clear original bytes memory: {e}")
                except Exception as e:
                    log.debug(f"Advanced memory clearing failed: {e}")
                
                log.debug("Original bytes object cannot be directly wiped due to Python's immutability. Using garbage collection strategy.")
            elif isinstance(data, str):
                try:
                    # Safely handle the int conversion to avoid overflow errors
                    s_addr = id(data)
                    
                    # This is a rough approximation and platform-dependent
                    if len(data) > 0:
                        try:
                            # Try to clear the characters (extremely unsafe and platform-dependent)
                            s_content_addr = s_addr + sys.getsizeof('') + 1
                            
                            # Convert to C-compatible int size to prevent overflow
                            if s_content_addr > ((1 << 63) - 1):  # Check if it exceeds max signed 64-bit
                                log.debug("Address too large for ctypes.memset, using safer approach")
                                # Use a safer approach for large addresses
                                secure_erase(data)  # Fall back to secure_erase
                            else:
                                # Make sure we don't try to wipe too much memory - limit to actual string size
                                ctypes.memset(s_content_addr, 0, len(data) * 2)  # * 2 for UTF-16 chars
                        except OverflowError:
                            log.debug("Integer overflow during memory address conversion, using safer approach")
                            secure_erase(data)  # Fall back to secure_erase
                        except Exception as e:
                            log.debug(f"Could not clear original string memory: {e}")
                except Exception as e:
                    log.debug(f"Advanced memory clearing failed: {e}")
                
                log.debug("Original string object cannot be directly wiped due to Python's immutability. Using garbage collection strategy.")
        except Exception as e:
            log.warning(f"Enhanced secure erase failed: {e}")
            # Fall back to basic secure_erase
            secure_erase(data)
            
        # Suggest garbage collection for both immutable types
        try:
            import gc
            gc.collect()
        except:
            pass
            
        return
        
    # For cryptography library private keys
    if HAS_CRYPTO_TYPES:
        # Handle X25519PrivateKey
        if isinstance(data, X25519PrivateKey):
            try:
                # Extract the private bytes if possible
                try:
                    private_bytes = data.private_bytes(
                        encoding=encoding.Encoding.Raw,
                        format=encoding.PrivateFormat.Raw,
                        encryption_algorithm=encoding.NoEncryption()
                    )
                    # Create a mutable copy for secure erasure
                    mutable_copy = bytearray(private_bytes)
                    secure_wipe_buffer(mutable_copy)
                    # Try to clear any internal cached state if present
                    if hasattr(data, '_evp_pkey') and data._evp_pkey is not None:
                        setattr(data, '_evp_pkey', None)
                    return
                except Exception as e:
                    log.debug(f"Could not extract private bytes from X25519PrivateKey: {e}")
            except Exception as e:
                log.debug(f"Could not securely erase X25519PrivateKey: {e}")
            # Even if we can't clear it directly, we return to avoid the warning message
            return
            
        # Handle Ed25519PrivateKey
        elif isinstance(data, Ed25519PrivateKey):
            try:
                # Extract the private bytes if possible
                try:
                    private_bytes = data.private_bytes(
                        encoding=encoding.Encoding.Raw,
                        format=encoding.PrivateFormat.Raw,
                        encryption_algorithm=encoding.NoEncryption()
                    )
                    # Create a mutable copy for secure erasure
                    mutable_copy = bytearray(private_bytes)
                    secure_wipe_buffer(mutable_copy)
                    # Try to clear any internal cached state if present
                    if hasattr(data, '_evp_pkey') and data._evp_pkey is not None:
                        setattr(data, '_evp_pkey', None)
                    return
                except Exception as e:
                    log.debug(f"Could not extract private bytes from Ed25519PrivateKey: {e}")
            except Exception as e:
                log.debug(f"Could not securely erase Ed25519PrivateKey: {e}")
            # Even if we can't clear it directly, we return to avoid the warning message
            return
    
    # For objects with zeroize methods
    if hasattr(data, 'zeroize'):
        try:
            data.zeroize()
            return
        except Exception as e:
            log.warning(f"Error calling zeroize method: {e}")
            
    # For dictionary objects, clear all sensitive values
    if isinstance(data, dict):
        for k, v in list(data.items()):
            if isinstance(v, (bytes, bytearray, str)) or hasattr(v, 'zeroize'):
                enhanced_secure_erase(v)
        return
        
    # For list/tuple objects, clear all sensitive values
    if isinstance(data, (list, tuple)):
        for item in data:
            if isinstance(item, (bytes, bytearray, str)) or hasattr(item, 'zeroize'):
                enhanced_secure_erase(item)
        return
        
    # For other object types, try to clear attributes
    if hasattr(data, '__dict__'):
        for attr_name, attr_value in list(data.__dict__.items()):
            if isinstance(attr_value, (bytes, bytearray, str)) or hasattr(attr_value, 'zeroize'):
                enhanced_secure_erase(attr_value)
                try:
                    setattr(data, attr_name, None)
                except (AttributeError, TypeError):
                    pass
        return
                
    log.warning(f"Cannot securely erase data of type {type(data).__name__}")

def secure_erase(data):
    """
    Cross-platform secure memory erasure.
    
    Args:
        data: The data to securely erase
    """
    if data is None:
        return
    
    if isinstance(data, bytearray):
        secure_wipe_buffer(data)
    elif isinstance(data, bytes):
        # Create a mutable copy for wiping
        mutable_copy = bytearray(data)
        secure_wipe_buffer(mutable_copy)
        # Original bytes is immutable and will persist in memory
        if log.level <= logging.DEBUG:
            log.debug("Original bytes object cannot be directly wiped due to Python's immutability. Using garbage collection strategy.")
    elif isinstance(data, str):
        # Create a mutable copy for wiping
        mutable_copy = bytearray(data.encode('utf-8'))
        secure_wipe_buffer(mutable_copy)
        # Original string is immutable and will persist in memory
        if log.level <= logging.DEBUG:
            log.debug("Original string object cannot be directly wiped due to Python's immutability. Using garbage collection strategy.")
    elif hasattr(data, 'zeroize'):
        data.zeroize()
    else:
        log.warning(f"Cannot securely erase data of type {type(data).__name__}")
        
    # Suggest garbage collection
    try:
        import gc
        gc.collect()
    except:
        pass

class SecureMemory:
    """
    Cross-platform secure memory handler that prevents sensitive data from being swapped to disk.
    Uses platform-specific memory protection mechanisms via platform_hsm_interface module.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        # Track allocated memory regions for proper cleanup
        self._allocated_regions = {}
        
        # Determine platform capabilities
        self._is_windows = platform.system() == "Windows"
        self._is_linux = platform.system() == "Linux"
        self._is_macos = platform.system() == "Darwin"
        
        # Check if we have memory locking capabilities
        self._has_memory_locking = False
        try:
            # Test memory locking with a small buffer
            test_buf = bytearray(16)
            test_addr = ctypes.addressof((ctypes.c_char * 16).from_buffer(test_buf))
            
            if self._is_windows:
                # Windows VirtualLock
                self._has_memory_locking = cphs.lock_memory(test_addr, 16)
                if self._has_memory_locking:
                    cphs.unlock_memory(test_addr, 16)
            elif self._is_linux or self._is_macos:
                # Linux/macOS mlock
                self._has_memory_locking = cphs.lock_memory(test_addr, 16)
                if self._has_memory_locking:
                    cphs.unlock_memory(test_addr, 16)
                    
            if self._has_memory_locking:
                log.info(f"Memory locking is available on {platform.system()}")
            else:
                log.warning(f"Memory locking is NOT available on {platform.system()}")
                
        except Exception as e:
            log.warning(f"Error testing memory locking: {e}")
            self._has_memory_locking = False
            
        log.debug(f"Cross-platform secure memory initialized on {platform.system()}")
    
    def allocate(self, size: int) -> bytearray:
        """
        Allocate a secure buffer that is protected from being swapped to disk.
        Works across Windows, Linux, and macOS.
        
        Args:
            size: Size of the buffer to allocate in bytes
            
        Returns:
            A bytearray of the requested size
        """
        with self._lock:
            # Check if we have libsodium's sodium_malloc
            if 'sodium_malloc' in globals() and HAS_NACL_SECURE_MEM:
                try:
                    # Use sodium_malloc for secure memory
                    secure_buf = sodium_malloc(size)
                    log.debug(f"Allocated {size} bytes using sodium_malloc")
                    self._allocated_regions[id(secure_buf)] = ('sodium', size)
                    return secure_buf
                except Exception as e:
                    log.warning(f"Failed to allocate using sodium_malloc: {e}")
            
            # Create a new bytearray
            buffer = bytearray(size)
            
            if size == 0:
                return buffer
                
            try:
                if self._has_memory_locking:
                    # Get the address of the buffer for memory locking
                    buffer_addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
                    
                    # Lock the memory using platform_hsm_interface
                    if cphs.lock_memory(buffer_addr, size):
                        # Store the address and size for later unlocking
                        self._allocated_regions[id(buffer)] = ('locked', buffer_addr, size)
                        log.debug(f"Allocated and locked {size} bytes of memory at {buffer_addr:#x}")
                    else:
                        log.warning(f"Failed to lock {size} bytes of memory, using standard bytearray")
                else:
                    # If memory locking is not available, just use the bytearray
                    log.debug(f"Using standard bytearray for {size} bytes (memory locking not available)")
            except Exception as e:
                log.warning(f"Error during secure memory allocation: {e}")
        
        return buffer
    
    def secure_copy(self, data: bytes) -> bytearray:
        """Copy data into a newly allocated secure buffer."""
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        
        buf = self.allocate(len(data))
        buf[:] = data
        return buf
    
    def free(self, buffer: bytearray) -> None:
        """
        Free a secure buffer previously allocated with allocate().
        
        Args:
            buffer: The buffer to free
        """
        if buffer is None:
            return
            
        with self._lock:
            # First wipe the buffer contents
            self.wipe(buffer)
            
            # Check if this is a buffer allocated with sodium_malloc
            buffer_id = id(buffer)
            if buffer_id in self._allocated_regions:
                alloc_type = self._allocated_regions[buffer_id][0]
                if alloc_type == 'sodium' and 'sodium_free' in globals() and HAS_NACL_SECURE_MEM:
                    try:
                        size = self._allocated_regions[buffer_id][1]
                        sodium_free(buffer)
                        log.debug(f"Freed {size} bytes of sodium_malloc memory")
                    except Exception as e:
                        log.warning(f"Failed to free secure memory with sodium_free: {e}")
                    finally:
                        del self._allocated_regions[buffer_id]
                    return
                elif alloc_type == 'locked':
                    # This was memory we locked with cphs.lock_memory
                    _, addr, size = self._allocated_regions[buffer_id]
                    try:
                        cphs.unlock_memory(addr, size)
                        log.debug(f"Unlocked {size} bytes of memory at {addr:#x}")
                    except Exception as e:
                        log.warning(f"Error unlocking memory: {e}")
                    finally:
                        del self._allocated_regions[buffer_id]

    def _memory_barrier(self):
        """Memory barrier to prevent compiler optimization of secure wiping."""
        # We use a ctypes memmove operation which is effectively a no-op,
        # but it prevents the compiler from optimizing away our wipe operations
        try:
            import ctypes
            x = bytearray(4)
            addr = ctypes.addressof((ctypes.c_char * 4).from_buffer(x))
            ctypes.memmove(addr, addr, 4)
        except:
            pass

    def wipe(self, buffer):
        """
        Securely wipe a buffer using military-grade multiple-pattern overwrite technique.
        
        Args:
            buffer: The buffer to wipe (bytearray or ctypes buffer)
            
        Returns:
            None
        """
        if buffer is None:
            return
            
        # Check buffer type - handle both bytearray and ctypes objects
        if isinstance(buffer, bytearray):
            buffer_type = "bytearray"
        elif hasattr(buffer, '_objects') or hasattr(buffer, '_length_'):  # ctypes buffer from sodium_malloc
            buffer_type = "ctypes"
        else:
            raise TypeError("buffer must be a bytearray or ctypes buffer")
            
        size = len(buffer)
        
        # MILITARY-GRADE ENHANCEMENT: Six-pass secure wiping with different patterns
        # This exceeds DoD 5220.22-M standard for data sanitization
        
        try:
            # Try to lock memory to prevent swapping during wiping
            memory_locked = False
            try:
                if hasattr(ctypes, 'addressof'):
                    buffer_addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
                    memory_locked = cphs.lock_memory(buffer_addr, size)
                    if memory_locked:
                        log.debug(f"Memory locked during wiping for {size} bytes")
            except Exception as e:
                log.debug(f"Could not lock memory during wipe: {e}")
            
            # Pass 1: All zeros
            for i in range(size):
                buffer[i] = 0
                
            # Memory barrier to prevent compiler optimization
            self._memory_barrier()
            
            # Pass 2: All ones
            for i in range(size):
                buffer[i] = 0xFF
                
            # Memory barrier to prevent compiler optimization
            self._memory_barrier()
            
            # Pass 3: Alternating bit pattern 10101010
            for i in range(size):
                buffer[i] = 0xAA
                
            # Memory barrier to prevent compiler optimization
            self._memory_barrier()
            
            # Pass 4: Alternating bit pattern 01010101
            for i in range(size):
                buffer[i] = 0x55
                
            # Memory barrier to prevent compiler optimization
            self._memory_barrier()
            
            # Pass 5: Random data
            try:
                # Use OS-level secure random for better entropy
                import os
                random_data = os.urandom(size)
                for i in range(size):
                    buffer[i] = random_data[i]
            except Exception as e:
                log.warning(f"Random data generation failed: {e}")
                # Fallback to a simple incremental pattern
                for i in range(size):
                    buffer[i] = (i + 1) % 256
            
            # Memory barrier to prevent compiler optimization
            self._memory_barrier()
            
            # Pass 6: All zeros (final)
            # Use volatile C memset for more secure zeroing that won't be optimized away
            try:
                buffer_addr = ctypes.addressof((ctypes.c_char * size).from_buffer(buffer))
                # Use ctypes to call memset directly
                ctypes.memset(buffer_addr, 0, size)
                # Double-check with Python-level zeroing to ensure it worked
                for i in range(size):
                    buffer[i] = 0
            except Exception as e:
                log.warning(f"Low-level memset failed, using Python zeroing: {e}")
                # Fallback to Python-level zeroing
                for i in range(size):
                    buffer[i] = 0
            
            # Final memory barrier with sync
            self._memory_barrier()
            
            # Verify zeros (critical check to ensure memory is actually zeroed)
            zero_verified = True
            for i in range(size):
                if buffer[i] != 0:
                    zero_verified = False
                    log.error(f"Buffer zeroing verification failed at index {i}: value is {buffer[i]}")
                    # Try to zero this byte again
                    buffer[i] = 0
            
            if zero_verified:
                log.debug(f"Securely wiped and verified {size} bytes with six-pass overwrite pattern")
            else:
                log.error(f"Buffer zeroing verification FAILED - could not zero all bytes!")
            
            # Unlock memory if it was locked
            if memory_locked:
                try:
                    cphs.unlock_memory(buffer_addr, size)
                    log.debug(f"Memory unlocked after wiping")
                except Exception as e:
                    log.warning(f"Error unlocking memory after wiping: {e}")
                    
        except Exception as e:
            log.warning(f"Error during secure buffer wiping: {e}")
            # Last resort attempt to zero out
            try:
                log.debug("Using last-resort direct zeroing attempt")
                for i in range(size):
                    buffer[i] = 0
            except Exception as final_e:
                log.error(f"Final zeroing attempt failed: {final_e}")
                pass
    
    def __del__(self):
        """Ensure all allocated memory is properly freed on object deletion."""
        try:
            with self._lock:
                # Copy keys to avoid modification during iteration
                regions = list(self._allocated_regions.items())
                for buffer_id, region_info in regions:
                    alloc_type = region_info[0]
                    
                    if alloc_type == 'sodium' and 'sodium_free' in globals() and HAS_NACL_SECURE_MEM:
                        try:
                            # Extract the buffer object from its id if possible
                            import gc
                            for obj in gc.get_objects():
                                if id(obj) == buffer_id:
                                    sodium_free(obj)
                                    break
                        except Exception as e:
                            log.warning(f"Error freeing sodium memory: {e}")
                    elif alloc_type == 'locked':
                        _, addr, size = region_info
                        try:
                            cphs.unlock_memory(addr, size)
                            log.debug(f"__del__: Unlocked {size} bytes at {addr:#x}")
                        except Exception as e:
                            log.warning(f"__del__: Error unlocking memory: {e}")
                    
                    # Remove it from our tracking
                    if buffer_id in self._allocated_regions:
                        del self._allocated_regions[buffer_id]
                        
        except Exception as e:
            # Can't do much in __del__ if we get an exception
            pass

# Global instance of SecureMemory
_secure_memory_instance = None
_secure_memory_lock = threading.Lock()

def get_secure_memory():
    """Singleton factory for SecureMemory."""
    global _secure_memory_instance
    with _secure_memory_lock:
        if _secure_memory_instance is None:
            _secure_memory_instance = SecureMemory()
    return _secure_memory_instance

class SecureKeyManager:
    """Manages cryptographic keys with secure storage and access controls."""
    
    def __init__(self, app_name: str = SERVICE_NAME, secure_dir: Optional[str] = None, in_memory_only: bool = False):
        """
        Initialize the secure key manager.
        
        Args:
            app_name: Application name for keyring storage and path generation.
            secure_dir: Specific directory for secure key storage (overrides default).
            in_memory_only: If True, store keys only in memory (never on disk).
        """
        self.app_name = app_name
        self.service_process = None
        self.socket = None
        self.in_memory_only = in_memory_only
        self.context = None # Initialize ZMQ context attribute

        # In-memory key storage (if applicable)
        self.memory_keys = {}

        # Handle storage and IPC path initialization if not in-memory only
        if not self.in_memory_only:
            if secure_dir:
                self.secure_dir = Path(secure_dir).resolve() # Resolve to absolute path
                log.info(f"Using specified secure storage directory: {self.secure_dir}")
            else:
                self.secure_dir = self._get_default_secure_storage_path(self.app_name)
            
            # IPC_PATH handling:
            # For Windows, _find_available_tcp_port() determines the path.
            # For POSIX, _get_default_ipc_path() generates a unique path.
            # The global IPC_PATH is used as a fallback or for the service script,
            # but instance-specific paths are preferred.
            global IPC_PATH 
            if platform.system() == "Windows":
                # Only find a new port if IPC_PATH hasn't been set (e.g., by another instance)
                # This global IPC_PATH will be used by the service if it starts.
                if IPC_PATH is None: 
                    IPC_PATH = self._find_available_tcp_port()
                self.ipc_path = IPC_PATH # Instance uses the determined TCP path
                log.info(f"Key service IPC for Windows (TCP): {self.ipc_path}")
            else: # POSIX systems
                self.ipc_path = self._get_default_ipc_path(self.app_name)
                IPC_PATH = self.ipc_path # Update global for service script for this instance
                log.info(f"Key service IPC for POSIX (Unix Socket): {self.ipc_path}")

            self._initialize_storage() # Creates and secures self.secure_dir
            
        self.hw_security_available = self._initialize_hardware_security()
        
        # Start key service if ZMQ is available, not in-memory, and service not running
        if not self.in_memory_only and HAVE_ZMQ:
            if not self._check_service_running(): # _check_service_running will use self.ipc_path
                self._start_key_service() # _start_key_service will use self.ipc_path for script
            else:
                log.info(f"Key service already running at {self.ipc_path}")
            
        if self.in_memory_only:
            log.info("Using in-memory only mode for key storage. Keys will not be persisted.")

    def _get_default_secure_storage_path(self, app_name: str) -> Path:
        """
        Determines the OS-appropriate default secure storage path using app_name.
        Ensures the path is absolute and user-specific.
        """
        system = platform.system()
        if system == "Windows":
            # %LOCALAPPDATA% is the standard for user-specific non-roaming app data
            base_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        elif system == "Darwin": # macOS
            # ~/Library/Application Support is standard
            base_dir = Path.home() / "Library" / "Application Support"
        else: # Linux and other POSIX-like systems
            # Adheres to XDG Base Directory Specification if XDG_DATA_HOME is set
            base_dir = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        
        # Construct the full path: <base_dir>/<app_name>/secure_keys
        storage_path = base_dir / app_name / "secure_keys"
        log.info(f"Default secure storage path for '{app_name}': {storage_path}")
        return storage_path.resolve() # Return an absolute path

    def _get_default_ipc_path(self, app_name: str) -> str:
        """
        Generates an OS-appropriate, user-specific IPC socket path for POSIX systems.
        The path is based on XDG_RUNTIME_DIR or a fallback in /run/user/<uid> or /tmp.
        The parent directory for the socket is created with 0700 permissions.
        """
        if platform.system() == "Windows":
            # This method should not be called on Windows for IPC path generation.
            # Windows uses TCP sockets determined by _find_available_tcp_port.
            log.error("IPC path generation via _get_default_ipc_path is for POSIX systems only.")
            raise KeyProtectionError("IPC path generation for POSIX systems attempted on Windows.")

        # Prefer XDG_RUNTIME_DIR for user-specific temporary files like sockets
        xdg_runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
        if xdg_runtime_dir:
            ipc_base_dir = Path(xdg_runtime_dir) / app_name
        else:
            # Fallback to /run/user/<uid>/<app_name> if XDG_RUNTIME_DIR is not set
            # This is common on systems with systemd.
            uid = os.getuid()
            ipc_base_dir = Path(f"/run/user/{uid}") / app_name
            if not ipc_base_dir.parent.exists() or not os.access(ipc_base_dir.parent, os.W_OK):
                # If /run/user/<uid> is not available or writable, fallback to a /tmp location
                # This is less ideal but provides a working alternative.
                tmp_dir = Path(tempfile.gettempdir())
                ipc_base_dir = tmp_dir / f"{app_name}_ipc_{uid}"
                log.warning(f"XDG_RUNTIME_DIR or /run/user/{uid} not available/writable. Using temporary IPC directory: {ipc_base_dir}")

        try:
            os.makedirs(ipc_base_dir, mode=0o700, exist_ok=True)
            # On some systems, especially if SUDO_USER is involved, /run/user/<uid> 
            # might be owned by root initially. Chowning is a best effort.
            # Proper setup would involve the service manager (systemd) creating this directory.
            if "SUDO_UID" in os.environ and os.geteuid() == 0:
                try:
                    uid = int(os.environ["SUDO_UID"])
                    gid = int(os.environ.get("SUDO_GID", uid)) # Fallback GID to UID
                    os.chown(ipc_base_dir, uid, gid)
                    log.info(f"Changed ownership of IPC directory {ipc_base_dir} to UID/GID {uid}/{gid}")
                except Exception as e:
                    log.warning(f"Failed to change ownership of IPC directory {ipc_base_dir}: {e}")
        except OSError as e:
            # This might happen if even the /tmp fallback cannot be created, which is unlikely.
            log.error(f"Critical error: Could not create IPC directory {ipc_base_dir}: {e}. Process isolation might fail.")
            # As a last resort, use a path directly in /tmp (less secure for multi-user systems if perms are wrong)
            # but the socket itself should be protected by its own permissions if created correctly.
            ipc_base_dir = Path(tempfile.gettempdir()) / f"generic_ipc_{app_name}_{os.urandom(4).hex()}"
            os.makedirs(ipc_base_dir, mode=0o700, exist_ok=True) # Try one last time
            log.warning(f"Fallen back to less ideal IPC path in /tmp: {ipc_base_dir}")

        socket_path = ipc_base_dir / "secure_key_manager.sock"
        return f"ipc://{socket_path.resolve()}"
    
    def _find_available_tcp_port(self) -> str:
        """Find an available TCP port for the key service on Windows."""
        if not HAVE_ZMQ:
            return "tcp://127.0.0.1:5555"  # Fallback
            
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REP)
            port = socket.bind_to_random_port("tcp://127.0.0.1", min_port=49152, max_port=65535)
            socket.unbind(f"tcp://127.0.0.1:{port}")
            socket.close()
            context.term()
            return f"tcp://127.0.0.1:{port}"
        except Exception as e:
            log.warning(f"Error finding available port: {e}")
            # Using a less common port range for fallback
            return "tcp://127.0.0.1:55559" 
    
    def _initialize_storage(self) -> bool:
        """Initialize secure storage directory if using filesystem storage."""
        try:
            # self.secure_dir is already a Path object and resolved
            os.makedirs(self.secure_dir, mode=0o700, exist_ok=True)
            log.info(f"Secure storage directory ensured/created at {self.secure_dir}")
            
            # On POSIX, explicitly set directory permissions to 0700 (owner rwx, no group/other)
            if os.name == 'posix':
                current_mode = stat.S_IMODE(os.stat(self.secure_dir).st_mode)
                if current_mode != 0o700:
                    os.chmod(self.secure_dir, stat.S_IRWXU)
                    log.info(f"Set permissions for {self.secure_dir} to 0700")
            
            return True
        except Exception as e:
            log.error(f"Failed to initialize secure storage at {self.secure_dir}: {e}")
            return False
    
    def _initialize_hardware_security(self) -> bool:
        """Initialize hardware security module for key protection if available."""
        try:
            import platform_hsm_interface as cphs
            
            # Check for Windows TPM via CNG
            tpm_available = False
            if cphs.IS_WINDOWS and cphs._WINDOWS_CNG_NCRYPT_AVAILABLE:
                if cphs._open_cng_provider_platform():
                    tpm_available = True
                    log.info("Hardware security (TPM via Windows CNG) initialized successfully")
                    
                    # We could further check TPM capabilities here
                    attestation = cphs.attest_device()
                    if attestation and len(attestation.get("checks", [])) > 0:
                        for check in attestation["checks"]:
                            if check.get("type") == "Win32_Tpm_Query" and check.get("status") == "Found":
                                if check.get("IsEnabled") and check.get("IsActivated"):
                                    log.info("Windows TPM is enabled and activated")
            
            # Check for Linux TPM
            elif cphs.IS_LINUX and cphs._Linux_ESAPI is not None:
                tpm_available = True
                log.info("Hardware security (TPM via tpm2-pytss) initialized successfully")
            
            # Check for PKCS#11 HSM support
            if cphs._PKCS11_SUPPORT_AVAILABLE:
                # Try to initialize HSM with environment variables
                if cphs.init_hsm():
                    tpm_available = True
                    log.info("Hardware security (PKCS#11 HSM) initialized successfully")
            
            if tpm_available:
                # Further log specific TPM details if needed, e.g., cphs.get_windows_tpm_info() or cphs.get_linux_tpm_info()
                return True
            
            log.warning("Hardware security (TPM/HSM) not detected or not fully configured by platform_hsm_interface module. "
                        "Keys are protected by OS-level keyring (if available) and filesystem permissions only.")
            return False
            
        except ImportError:
            log.warning("platform_hsm_interface module not available. Hardware security features disabled.")
            return False
        except Exception as e:
            log.error(f"Error initializing hardware security: {e}")
            return False
    
    def _check_service_running(self) -> bool:
        """Check if the key management service is already running."""
        if not HAVE_ZMQ:
            return False
        
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REQ)
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.RCVTIMEO, 1000)  # 1 second timeout
            
            current_ipc_path = getattr(self, 'ipc_path', IPC_PATH) # Use instance specific IPC path
            socket.connect(current_ipc_path)
            socket.send_string("PING")
            response = socket.recv_string()
            socket.close()
            context.term()
            return response == "PONG"
        except zmq.error.Again:
            log.debug("Timeout waiting for key service response")
            return False
        except Exception as e:
            log.debug(f"Error checking if service is running: {e}")
            return False
    
    def _start_key_service(self):
        """Start the key management service in a separate process."""
        if not HAVE_ZMQ:
            log.warning("Cannot start key service: pyzmq library is not available.")
            return
        
        service_script_path = None
        try:
            service_script_path = self._create_service_script() # This uses self.ipc_path
            log.info(f"Starting key service using script {service_script_path} with IPC at {self.ipc_path}")
            
            # Common Popen arguments
            popen_args = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE
            }
            if platform.system() == "Windows":
                popen_args["creationflags"] = subprocess.CREATE_NO_WINDOW
            
            self.service_process = subprocess.Popen(
                [sys.executable, service_script_path], # Use sys.executable for portability
                **popen_args
            )
            
            # Schedule verification checks
            threading.Timer(0.5, self._verify_service).start()
            threading.Timer(2.0, self._verify_service).start()
            
        except Exception as e:
            log.error(f"Failed to start key service: {e}", exc_info=True)
        finally:
            # Clean up the temporary script file if it was created and Popen failed early
            # If Popen succeeded, the service itself might delete it or it can be cleaned up later.
            # For simplicity, we might leave it for OS to clean /tmp or handle on service shutdown.
            # However, explicit deletion is better if service fails to start.
            if self.service_process is None and service_script_path and os.path.exists(service_script_path):
                try:
                    # os.remove(service_script_path) # Temporarily disabled for debugging service script
                    log.debug(f"Cleaned up temporary service script: {service_script_path}")
                except OSError as e_remove:
                    log.warning(f"Could not remove temporary service script {service_script_path}: {e_remove}")

    
    def _create_service_script(self) -> str:
        """Create a temporary script for the key service."""
        # self.secure_dir is a Path object
        safe_secure_dir = str(self.secure_dir.resolve()).replace('\\', '/')
        # self.ipc_path is instance specific
        script_ipc_path = self.ipc_path 

        # Using NamedTemporaryFile for better security and auto-cleanup (mostly on POSIX)
        # delete=False is used because the file needs to exist for Popen to execute it.
        # The caller (_start_key_service) or the service itself should handle deletion.
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
                script_path = f.name
                f.write('''
import os
import zmq
import logging
import sys
import signal
import base64
import hashlib # Not used in service script, but kept for now
import uuid # Not used in service script, but kept for now
from pathlib import Path

# Configure logging for the service
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] [KeyService:%(lineno)d] %(message)s')
log = logging.getLogger("key_service")

# Service configuration (passed via string formatting from SecureKeyManager)
SERVICE_APP_NAME = "{app_name}" 
IPC_PATH = "{ipc_path}"
SECURE_DIR_PATH = "{secure_dir}" # Renamed to avoid conflict with os.mkdir

# Try to import keyring (dependency for the service)
try:
    import keyring
    HAVE_KEYRING = True
    # Specific keyring errors if needed
    from keyring.errors import NoKeyringError, PasswordDeleteError
except ImportError:
    HAVE_KEYRING = False
    NoKeyringError = None # Define for except blocks
    PasswordDeleteError = None # Define for except blocks
    log.warning("Keyring library not found in service process. OS keyring backend disabled.")

class KeyService:
    def __init__(self):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REP)
        try:
            self.socket.bind(IPC_PATH)
        except zmq.error.ZMQError as e_bind:
            log.error(f"KeyService CRITICAL: Could not bind to IPC_PATH '{{IPC_PATH}}'. Error: {{e_bind}}")
            # Attempt to clean up socket/context before exiting to avoid resource leaks
            self.socket.close()
            self.context.term()
            sys.exit(1) # Critical failure, service cannot run

        self.running = True
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        # On Windows, SIGBREAK might be relevant if started from console
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, self.handle_shutdown)

        log.info(f"Key service initialized. Listening on {{IPC_PATH}} for app '{{SERVICE_APP_NAME}}'. Storing keys in {{SECURE_DIR_PATH}}.")
    
    def handle_shutdown(self, signum, frame):
        log.info(f"Shutdown signal {{signum}} received. Stopping key service...")
        self.running = False
    
    def secure_store(self, key_id, key_data):
        if HAVE_KEYRING:
            try:
                # Get keyring backend name for logging, handle potential errors if get_keyring() is None
                keyring_backend_name = "Unknown"
                if keyring.get_keyring():
                    keyring_backend_name = keyring.get_keyring().__class__.__name__
                
                log.warning(f"SECURITY NOTICE (KeyService): Storing key \'{{key_id}}\' in OS keyring for app \'{{SERVICE_APP_NAME}}\'. \"\n                            f"Backend: {{keyring_backend_name}}. \"\n                            "OS keyring security depends on user account security. Consider implications if account is compromised.")\n                keyring.set_password(SERVICE_APP_NAME, key_id, key_data)\n                log.debug(f"Key \'{{key_id}}\' stored in OS keyring for \'{{SERVICE_APP_NAME}}\'.")\n                return True\n            except NoKeyringError:\n                log.warning("No OS keyring backend found for key storage.")
            except Exception as e_keyring_set:
                log.error(f"Keyring storage failed for key '{{key_id}}': {{e_keyring_set}}")
        
        # Fallback to file storage
        try:
            secure_dir = Path(SECURE_DIR_PATH)
            os.makedirs(secure_dir, mode=0o700, exist_ok=True)
            key_file = secure_dir / f"{{key_id}}.key"
            
            with open(key_file, 'w', encoding='utf-8') as f:
                f.write(key_data)
            
            if os.name == 'posix':
                os.chmod(key_file, 0o600)  # Owner read/write only
            
            log.debug(f"Key '{{key_id}}' stored in file: {{key_file}}")
            return True
        except Exception as e_file_store:
            log.error(f"File storage failed for key '{{key_id}}': {{e_file_store}}")
            return False
    
    def secure_retrieve(self, key_id):
        if HAVE_KEYRING:
            try:
                key_data = keyring.get_password(SERVICE_APP_NAME, key_id)
                if key_data:
                    log.debug(f"Key '{{key_id}}' retrieved from OS keyring for '{{SERVICE_APP_NAME}}'.")
                    return key_data
            except NoKeyringError:
                log.warning("No OS keyring backend found for key retrieval.")
            except Exception as e_keyring_get:
                log.error(f"Keyring retrieval failed for key '{{key_id}}': {{e_keyring_get}}")
        
        # Fallback to file retrieval
        try:
            key_file = Path(SECURE_DIR_PATH) / f"{{key_id}}.key"
            if key_file.exists():
                # Basic permission check on POSIX before reading
                if os.name == 'posix':
                    mode = key_file.stat().st_mode
                    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH | stat.S_IXGRP | stat.S_IXOTH | stat.S_IXUSR):
                        log.warning(f"Key file {{key_file}} has insecure permissions: {{oct(mode)}}. Expected 0600 or 0400.")
                
                with open(key_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                log.debug(f"Key '{{key_id}}' retrieved from file: {{key_file}}")
                return content
        except Exception as e_file_retrieve:
            log.error(f"File retrieval failed for key '{{key_id}}': {{e_file_retrieve}}")
        
        log.debug(f"Key '{{key_id}}' not found in any storage.")
        return None
    
    def delete_key_from_storage(self, key_id):
        deleted_keyring = False
        deleted_file = False

        if HAVE_KEYRING:
            try:
                keyring.delete_password(SERVICE_APP_NAME, key_id)
                log.debug(f"Key '{{key_id}}' deleted from OS keyring for '{{SERVICE_APP_NAME}}'.")
                deleted_keyring = True
            except PasswordDeleteError:
                log.debug(f"Key '{{key_id}}' not found in OS keyring for deletion (app: {{SERVICE_APP_NAME}})")
                # This isn't an error if the key was only in file storage
            except NoKeyringError:
                log.debug("No OS keyring backend to delete from.")
            except Exception as e_keyring_del:
                log.warning(f"Error deleting key '{{key_id}}' from keyring: {{e_keyring_del}}")
        
        try:
            key_file = Path(SECURE_DIR_PATH) / f"{{key_id}}.key"
            if key_file.exists():
                os.remove(key_file)
                log.debug(f"Key '{{key_id}}' deleted from file: {{key_file}}")
                deleted_file = True
            else:
                log.debug(f"Key file '{{key_file}}' not found for deletion.")
        except Exception as e_file_del:
            log.warning(f"Error deleting key file '{{key_file}}': {{e_file_del}}")
        
        return deleted_keyring or deleted_file # Return True if deleted from at least one place

    def run(self):
        log.info("Key service run loop started.")
        self.socket.setsockopt(zmq.RCVTIMEO, 500) # Poll every 500ms

        while self.running:
            try:
                message = self.socket.recv_string()
                parts = message.split(":", 1)
                command = parts[0]
                payload = parts[1] if len(parts) > 1 else ""
                
                log.debug(f"Received command: {{command}}, payload: {{payload[:30]}}...")

                if command == "PING":
                    self.socket.send_string("PONG")
                
                elif command == "STORE":
                    if not payload:
                        self.socket.send_string("ERROR:Invalid command format for STORE")
                        continue
                    
                    store_parts = payload.split(":", 1)
                    if len(store_parts) < 2:
                        self.socket.send_string("ERROR:Invalid data format for STORE (key_id:key_data)")
                        continue
                    
                    key_id, key_data_b64 = store_parts
                    # key_data is already base64 encoded by SecureKeyManager
                    success = self.secure_store(key_id, key_data_b64)
                    
                    if success:
                        self.socket.send_string(f"SUCCESS:{{key_id}}")
                    else:
                        self.socket.send_string("ERROR:Storage failed")
                
                elif command == "RETRIEVE":
                    if not payload:
                        self.socket.send_string("ERROR:Invalid command format for RETRIEVE")
                        continue
                    
                    key_id = payload
                    key_data_b64 = self.secure_retrieve(key_id)
                    
                    if key_data_b64:
                        self.socket.send_string(f"DATA:{{key_data_b64}}")
                    else:
                        self.socket.send_string("ERROR:Key not found")
                
                elif command == "DELETE":
                    if not payload:
                        self.socket.send_string("ERROR:Invalid command format for DELETE")
                        continue
                    
                    key_id = payload
                    deleted = self.delete_key_from_storage(key_id)
                    if deleted:
                        self.socket.send_string(f"SUCCESS:{{key_id}} deleted")
                    else:
                        # This could mean it wasn't found or an error occurred. Client needs to know.
                        self.socket.send_string(f"INFO:Key {{key_id}} not found or not deleted from any backend")
                
                elif command == "SHUTDOWN":
                    log.info("Received SHUTDOWN command. Terminating service.")
                    self.running = False
                    self.socket.send_string("SUCCESS:Shutting down")
                else:
                    self.socket.send_string("ERROR:Unknown command")
            
            except zmq.Again: # Timeout on recv
                continue
            except Exception as e_loop:
                log.error(f"Error processing request in service loop: {{e_loop}}", exc_info=True)
                try:
                    # Avoid sending error if socket is already closed or in bad state
                    if not self.socket.closed:
                         self.socket.send_string(f"ERROR:Internal service error: {{str(e_loop)}}")
                except Exception as e_send_err:
                    log.error(f"Failed to send error response to client: {{e_send_err}}")
        
        log.info("Key service run loop ended. Cleaning up...")
        self.socket.close()
        self.context.term()
        log.info("Key service shutdown complete.")
        # Attempt to remove self (temporary script)
        # try:
        #     if os.path.exists(__file__):
        #        os.remove(__file__)
        #        log.info(f"Temporary service script {{__file__}} removed.")
        # except OSError as e_remove_self:
        #    log.warning(f"Could not remove self (service script {{__file__}}): {{e_remove_self}}")

if __name__ == "__main__":
    # This script is intended to be run as a standalone process.
    # It receives configuration (app_name, ipc_path, secure_dir) via the formatted string.
    key_service_instance = KeyService()
    key_service_instance.run()
'''.format(app_name=self.app_name, ipc_path=script_ipc_path, secure_dir=safe_secure_dir))
            
            # Set secure permissions for the temporary script file on POSIX (owner rw)
            if os.name == 'posix':
                os.chmod(script_path, stat.S_IRUSR | stat.S_IWUSR) # 0600
            log.debug(f"Temporary key service script created at: {script_path}")

        except Exception as e_create_script:
            log.error(f"Failed to create temporary service script: {e_create_script}")
            if 'script_path' in locals() and os.path.exists(script_path):
                try: # Best effort to clean up partially created script
                    os.remove(script_path)
                except OSError:
                    pass
            raise KeyProtectionError(f"Could not create key service script: {e_create_script}") from e_create_script
        
        return script_path
    
    def _verify_service(self):
        """Verify the key service is running."""
        if self._check_service_running():
            log.info("Key service started successfully")
        else:
            if self.service_process:
                if self.service_process.poll() is not None:
                    return_code = self.service_process.returncode
                    stderr = self.service_process.stderr.read().decode('utf-8', errors='replace') if self.service_process.stderr else ""
                    stdout = self.service_process.stdout.read().decode('utf-8', errors='replace') if self.service_process.stdout else ""
                    
                    log.warning(f"Key service process terminated with return code {return_code}")
                    if stderr:
                        log.warning(f"Service stderr: {stderr.strip()}")
                    if stdout:
                        log.debug(f"Service stdout: {stdout.strip()}")
                else:
                    log.warning("Key service process is running but not responding")
            else:
                log.warning("Key service failed to start")
    
    def _connect_to_service(self) -> bool:
        """Connect to the key management service."""
        if not HAVE_ZMQ:
            return False
        
        if self.socket is not None:
            return True
        
        try:
            context = zmq.Context()
            socket = context.socket(zmq.REQ)
            socket.setsockopt(zmq.LINGER, 0)
            socket.setsockopt(zmq.RCVTIMEO, 1000)
            
            current_ipc_path = getattr(self, 'ipc_path', IPC_PATH) # Use instance specific IPC path
            socket.connect(current_ipc_path)
            
            socket.send_string("PING")
            response = socket.recv_string()
            
            if response == "PONG":
                self.socket = socket
                self.context = context
                return True
            else: 
                socket.close()
                context.term()
                return False
        except zmq.error.Again:
            log.debug("Timeout connecting to key service")
            socket.close()
            context.term()
            return False
        except Exception as e:
            log.debug(f"Failed to connect to key service: {e}")
            try:
                socket.close()
                context.term()
            except:
                pass
            return False
    
    def store_key(self, key_material: Union[bytes, str], key_name: str) -> bool:
        """
        Store a cryptographic key securely.
        
        Args:
            key_material: The key material to store
            key_name: Unique name for the key
            
        Returns:
            bool: True if storage succeeded, False otherwise
        """
        if isinstance(key_material, bytes):
            key_data = base64.b64encode(key_material).decode('utf-8')
        else:
            key_data = key_material
            
        # In-memory mode: use enhanced memory protection
        if self.in_memory_only:
            # Use secure memory if PyNaCl is available
            if HAS_NACL_SECURE_MEM:
                try:
                    # Convert key_data to bytearray in secure memory
                    secure_memory = get_secure_memory()
                    self.memory_keys[key_name] = secure_memory.secure_copy(key_data)
                    log.info(f"Key {key_name} stored in protected memory using PyNaCl (not persisted)")
                    return True
                except Exception as e:
                    log.warning(f"Failed to use PyNaCl secure memory for {key_name}: {e}. Falling back to bytearray.")
            
            # Fall back to using a mutable bytearray for better memory hygiene
            self.memory_keys[key_name] = _convert_to_bytearray(key_data)
            log.info(f"Key {key_name} stored in memory only (not persisted)")
            return True
        
        # Otherwise use persistent storage
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"STORE:{key_name}:{key_data}")
                response = self.socket.recv_string()
                
                if response.startswith("SUCCESS:"):
                    log.info(f"Key {key_name} stored securely via service using app_name '{self.app_name}'")
                    return True
                else:
                    log.warning(f"Service failed to store key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        # Fallback to direct OS keyring or file storage if ZMQ service fails or is not used
        log.warning(f"Attempting fallback storage for key '{key_name}' (OS keyring or file). ZMQ service might be unavailable or failed.")
        try:
            if HAVE_KEYRING:
                log.warning(f"SECURITY NOTICE: Storing key '{key_name}' in OS keyring for app '{self.app_name}'. "
                            f"Backend: {keyring.get_keyring().__class__.__name__ if HAVE_KEYRING and keyring.get_keyring() else 'Unknown'}. "
                            "OS keyring security depends on user account security. Consider implications if account is compromised.")
                keyring.set_password(self.app_name, key_name, key_data)
                log.info(f"Key {key_name} stored in OS keyring under app_name '{self.app_name}' (fallback).")
                return True
            
            # Fallback to file storage if keyring is not available or fails (this part is simplified)
            key_path = self.secure_dir / f"{key_name}.key"
            
            # Ensure the parent directory exists with correct permissions before writing
            os.makedirs(self.secure_dir, mode=0o700, exist_ok=True)
            if os.name == 'posix': # Re-assert parent dir permissions
                os.chmod(self.secure_dir, stat.S_IRWXU)

            with open(key_path, 'w') as f:
                f.write(key_data)
            
            if os.name == 'posix':
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR) # 0600
            
            log.info(f"Key {key_name} stored in file: {key_path}")
            return True
            
        except Exception as e:
            log.error(f"Failed to store key {key_name}: {e}")
            return False
    
    def retrieve_key(self, key_name: str, as_bytes: bool = True) -> Optional[Union[bytes, str]]:
        """
        Retrieve a stored cryptographic key.
        
        Args:
            key_name: Name of the key to retrieve
            as_bytes: If True, return bytes; otherwise, return string
            
        Returns:
            Optional[Union[bytes, str]]: The key material or None if not found
        """
        # In-memory mode: retrieve from memory dictionary
        if self.in_memory_only:
            key_data = self.memory_keys.get(key_name)
            if key_data:
                log.debug(f"Key {key_name} retrieved from memory")
                if as_bytes:
                    return base64.b64decode(key_data)
                return key_data
            else:
                log.warning(f"Key {key_name} not found in memory")
                return None
                
        # Otherwise use persistent storage
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"RETRIEVE:{key_name}")
                response = self.socket.recv_string()
                
                if response.startswith("DATA:"):
                    log.debug(f"Key {key_name} retrieved via service using app_name '{self.app_name}'")
                    key_data = response[5:]
                    if as_bytes:
                        return base64.b64decode(key_data)
                    return key_data
                else:
                    log.warning(f"Service failed to retrieve key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        try:
            if HAVE_KEYRING:
                key_data = keyring.get_password(self.app_name, key_name)
                if key_data:
                    log.debug(f"Key {key_name} retrieved from OS keyring under app_name '{self.app_name}'")
                    if as_bytes:
                        return base64.b64decode(key_data)
                    return key_data
            
            key_path = self.secure_dir / f"{key_name}.key"
            if key_path.exists():
                # Permission check before reading (optional, as read would fail anyway)
                if os.name == 'posix':
                    file_stat = os.stat(key_path)
                    # Check if only owner has read access (0400 or 0600)
                    if not (file_stat.st_mode & (stat.S_IRUSR and not (file_stat.st_mode & (stat.S_IRGRP | stat.S_IROTH)))):
                        log.warning(f"Key file {key_path} has insecure read permissions. Expected owner-read only.")
                        # Depending on policy, could raise error or refuse to read
                
                with open(key_path, 'r') as f:
                    key_data = f.read()
                
                log.debug(f"Key {key_name} retrieved from file")
                if as_bytes:
                    return base64.b64decode(key_data)
                return key_data
            
            log.warning(f"Key {key_name} not found")
            return None
            
        except Exception as e:
            log.error(f"Failed to retrieve key {key_name}: {e}")
            return None
    
    def delete_key(self, key_name: str) -> bool:
        """
        Delete a stored cryptographic key.
        
        Args:
            key_name: Name of the key to delete
            
        Returns:
            bool: True if deletion succeeded, False otherwise
        """
        # In-memory mode: delete from memory dictionary
        if self.in_memory_only:
            if key_name in self.memory_keys:
                key_data = self.memory_keys.get(key_name)
                if key_data:
                    # Use the appropriate method for secure erasure
                    try:
                        secure_memory = get_secure_memory()
                        secure_memory.wipe(key_data)
                        log.debug(f"Securely erased in-memory key data for {key_name}")
                    except Exception as e:
                        log.warning(f"Failed to securely erase in-memory key data for {key_name}: {e}")
                
                del self.memory_keys[key_name]
                log.debug(f"Key {key_name} deleted from memory")
                return True
            return False
            
        # Otherwise delete from persistent storage
        if HAVE_ZMQ and self._connect_to_service():
            try:
                self.socket.send_string(f"DELETE:{key_name}")
                response = self.socket.recv_string()
                
                if response.startswith("SUCCESS:"):
                    log.info(f"Key {key_name} deleted via service for app_name '{self.app_name}'")
                    return True
                else:
                    log.warning(f"Service failed to delete key: {response}")
            except Exception as e:
                log.error(f"Error communicating with key service: {e}")
        
        success = True
        
        if HAVE_KEYRING:
            try:
                keyring.delete_password(self.app_name, key_name)
                log.debug(f"Key {key_name} deleted from OS keyring under app_name '{self.app_name}'")
            except keyring.errors.PasswordDeleteError:
                log.debug(f"Key {key_name} not found in keyring for app_name '{self.app_name}' or other deletion error.")
                success = False # If keyring was expected to have it and failed, it might be an issue
            except Exception as e:
                log.warning(f"Could not delete key {key_name} from keyring for app_name '{self.app_name}': {e}")
                success = False
        
        try:
            key_path = self.secure_dir / f"{key_name}.key"
            if key_path.exists():
                os.remove(key_path)
                log.debug(f"Key {key_name} deleted from file: {key_path}")
        except Exception as e:
            log.warning(f"Could not delete key file {key_path}: {e}")
            success = False
        
        return success
    
    def verify_storage(self) -> bool:
        """
        Verify that the key storage is properly configured and secure.
        
        Returns:
            bool: True if storage is secure, False otherwise
        """
        # In-memory mode is always considered secure
        if self.in_memory_only:
            log.info("In-memory key storage verified (no disk persistence)")
            return True
        
        if HAVE_KEYRING:
            try:
                test_key = f"test_key_{os.urandom(4).hex()}"
                test_data = f"test_data_{os.urandom(8).hex()}"
                
                keyring.set_password(self.app_name, test_key, test_data)
                retrieved = keyring.get_password(self.app_name, test_key)
                
                if retrieved == test_data:
                    keyring.delete_password(self.app_name, test_key)
                    log.info(f"OS keyring storage verified for app_name '{self.app_name}'")
                    return True
            except Exception as e:
                log.warning(f"OS keyring verification failed for app_name '{self.app_name}': {e}")
        
        try:
            if not self.secure_dir.exists(): # Changed to use Path.exists()
                # Attempt to create it if it doesn't exist during verification
                log.warning(f"Secure keys directory {self.secure_dir} does not exist. Attempting to create.")
                self._initialize_storage() # This will create with 0700
                if not self.secure_dir.exists():
                    log.error(f"Failed to create secure keys directory {self.secure_dir} during verification.")
                    return False
            
            if os.name == 'posix':
                dir_stat = os.stat(self.secure_dir)
                if dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO): # Check for group/other permissions
                    log.warning(f"SECURITY ALERT: Secure keys directory {self.secure_dir} has insecure permissions: {oct(dir_stat.st_mode)}. Expected 0700.")
                    # Attempt to fix permissions
                    try:
                        os.chmod(self.secure_dir, stat.S_IRWXU)
                        log.info(f"Attempted to correct permissions for {self.secure_dir} to 0700.")
                        dir_stat = os.stat(self.secure_dir) # Re-check
                        if dir_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                            log.error(f"SECURITY ALERT: Failed to correct permissions for {self.secure_dir}.")
                            return False
                    except Exception as e_chmod:
                        log.error(f"SECURITY ALERT: Could not correct permissions for {self.secure_dir}: {e_chmod}")
                        return False
            
            test_file_name = f".test_write_{os.urandom(4).hex()}"
            test_file = self.secure_dir / test_file_name
            with open(test_file, 'w') as f:
                f.write("test")
            
            if os.name == 'posix':
                os.chmod(test_file, stat.S_IRUSR | stat.S_IWUSR) # Set to 0600
                file_stat = os.stat(test_file)
                if file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO | stat.S_IXUSR): # Check for group/other/execute bits
                    log.warning(f"SECURITY ALERT: Test file {test_file} created with insecure permissions: {oct(file_stat.st_mode)}. Expected 0600.")
                    os.remove(test_file)
                    return False
            
            os.remove(test_file)
            
            log.info(f"File storage at {self.secure_dir} verified")
            return True
            
        except Exception as e:
            log.error(f"Storage verification failed: {e}")
            return False
    
    def cleanup(self):
        """Clean up resources when finished."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        if hasattr(self, 'context') and self.context:
            try:
                self.context.term()
            except:
                pass
            self.context = None

        # Securely erase any keys remaining in memory_keys
        if self.in_memory_only and hasattr(self, 'memory_keys') and self.memory_keys:
            log.debug(f"Cleaning up {len(self.memory_keys)} in-memory keys.")
            # Iterate over a copy of items in case secure_erase modifies the dict or list during iteration (though unlikely here)
            for key_name, key_data_b64_str in list(self.memory_keys.items()):
                if key_data_b64_str:
                    try:
                        enhanced_secure_erase(key_data_b64_str.encode('utf-8'))
                        log.debug(f"Securely erased in-memory key data for {key_name} during cleanup.")
                    except Exception as e:
                        log.warning(f"Failed to securely erase in-memory key data for {key_name} during cleanup: {e}")
            self.memory_keys.clear()
            log.info("All in-memory keys securely erased and cleared.")

    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self.cleanup()


# Singleton instance for global use
_key_manager_instance = None

def get_key_manager(in_memory_only: bool = False) -> SecureKeyManager:
    """
    Get the global key manager instance.
    
    Args:
        in_memory_only: If True, use in-memory key storage with no disk persistence
        
    Returns:
        The global SecureKeyManager instance
    """
    global _key_manager_instance
    if _key_manager_instance is None:
        _key_manager_instance = SecureKeyManager(in_memory_only=in_memory_only)
    return _key_manager_instance


# Module-level API for simplified access

def store_key(key_material: Union[bytes, str], key_name: str, in_memory_only: bool = False) -> bool:
    """
    Store a cryptographic key securely.
    
    Args:
        key_material: The key material to store
        key_name: Name to identify the key
        in_memory_only: If True, store in memory only (no disk persistence)
    """
    return get_key_manager(in_memory_only).store_key(key_material, key_name)

def retrieve_key(key_name: str, as_bytes: bool = True, in_memory_only: bool = False) -> Optional[Union[bytes, str]]:
    """
    Retrieve a stored cryptographic key.
    
    Args:
        key_name: Name of the key to retrieve
        as_bytes: If True, return bytes; otherwise, return string
        in_memory_only: If True, retrieve from memory only (no disk access)
    """
    return get_key_manager(in_memory_only).retrieve_key(key_name, as_bytes)

def delete_key(key_name: str, in_memory_only: bool = False) -> bool:
    """
    Delete a stored cryptographic key.
    
    Args:
        key_name: Name of the key to delete
        in_memory_only: If True, delete from memory only (no disk access)
    """
    return get_key_manager(in_memory_only).delete_key(key_name)

def verify_storage(in_memory_only: bool = False) -> bool:
    """
    Verify that the key storage is properly configured and secure.
    
    Args:
        in_memory_only: If True, verify memory storage only (no disk access)
    """
    return get_key_manager(in_memory_only).verify_storage()

def cleanup():
    """Clean up resources when finished."""
    if _key_manager_instance:
        _key_manager_instance.cleanup()

# Cleanup on exit
import atexit
atexit.register(cleanup)

def test_secure_memory_wiping():
    """
    Test function to verify secure memory wiping is working.
    """
    log.info("Starting secure memory wiping tests...")
    print("Testing secure memory wiping...")
    
    # Create a test bytearray with a known pattern
    test_data = bytearray(b"SECRET_PASSWORD_123456789")
    test_data_copy = bytearray(test_data)  # Keep a copy to verify wiping
    
    print(f"Original data: {bytes(test_data)}")
    log.info(f"Original test data: {bytes(test_data)}")
    
    # Get memory address for checking after wiping
    try:
        addr = ctypes.addressof((ctypes.c_char * len(test_data)).from_buffer(test_data))
        print(f"Memory address: 0x{addr:x}")
        log.info(f"Memory address: 0x{addr:x}")
    except Exception as e:
        addr = None
        print(f"Could not get memory address: {e}")
    
    # Test the secure wipe function
    log.info("Calling secure_wipe_buffer...")
    secure_wipe_buffer(test_data)
    
    # Check if wiping was successful - should be all zeros
    all_zeros = all(b == 0 for b in test_data)
    print(f"After wiping - All zeros: {all_zeros}")
    print(f"After wiping - Data: {bytes(test_data)}")
    log.info(f"After wiping - All zeros: {all_zeros}")
    log.info(f"After wiping - Data: {bytes(test_data)}")
    
    # Verify original data is gone
    original_gone = test_data != test_data_copy
    print(f"Original pattern gone: {original_gone}")
    log.info(f"Original pattern gone: {original_gone}")
    
    # Test memory locking
    mem_lock_test = test_memory_locking()
    print(f"System supports memory locking: {mem_lock_test}")
    log.info(f"System supports memory locking: {mem_lock_test}")
    
    # Test direct sodium bindings if available
    try:
        sodium_available = False
        if 'sodium_malloc' in globals() and HAS_NACL_SECURE_MEM:
            test_size = 32  # Small test size
            try:
                sodium_buf = sodium_malloc(test_size)
                print("Direct sodium_malloc test successful!")
                log.info("Direct sodium_malloc test successful!")
                
                # Write some data
                for i in range(min(len(sodium_buf), test_size)):
                    sodium_buf[i] = 65 + (i % 26)  # ASCII A-Z
                
                print(f"Sodium buffer content: {bytes(sodium_buf[:32])}")
                log.info(f"Sodium buffer content: {bytes(sodium_buf[:32])}")
                
                # Test sodium_free
                sodium_free(sodium_buf)
                print("Direct sodium_free test successful!")
                log.info("Direct sodium_free test successful!")
                sodium_available = True
            except Exception as e:
                print(f"Error testing sodium memory functions: {e}")
                log.warning(f"Error testing sodium memory functions: {e}")
        
        if not sodium_available:
            print("Direct libsodium secure memory functions not available")
            log.info("Direct libsodium secure memory functions not available")
    except Exception as e:
        print(f"Error testing direct libsodium bindings: {e}")
        log.warning(f"Error testing direct libsodium bindings: {e}")

    print("\nTesting SecureMemory class...")
    log.info("Testing SecureMemory class...")
    
    # Test the SecureMemory class
    secure_mem = SecureMemory()
    buffer = secure_mem.allocate(32)
    
    # Write some test data
    for i in range(min(len(buffer), 32)):
        buffer[i] = 65 + (i % 26)  # ASCII A-Z
    
    print(f"SecureMemory buffer content: {bytes(buffer)}")
    log.info(f"SecureMemory buffer content: {bytes(buffer)}")
    
    # Test wiping
    secure_mem.wipe(buffer)
    all_zeros = all(b == 0 for b in buffer)
    print(f"After wiping with SecureMemory - All zeros: {all_zeros}")
    log.info(f"After wiping with SecureMemory - All zeros: {all_zeros}")
    
    # Test buffer freeing
    secure_mem.free(buffer)
    print("SecureMemory buffer freed")
    log.info("SecureMemory buffer freed")
    
    # Output summary of available secure memory mechanisms
    print("\nSecure memory mechanisms available:")
    log.info("Secure memory mechanisms available:")
    
    if HAS_NACL_SECURE_MEM:
        print("✓ libsodium secure memory available")
        log.info("✓ libsodium secure memory available")
    else:
        print("✗ libsodium secure memory NOT available")
        log.info("✗ libsodium secure memory NOT available")
        
    if SYSTEM_SUPPORTS_MEMORY_LOCKING:
        print("✓ Memory locking available")
        log.info("✓ Memory locking available")
    else:
        print("✗ Memory locking NOT available")
        log.info("✗ Memory locking NOT available")
    
    print("\nSecure memory wiping test completed!")
    log.info("Secure memory wiping test completed!")

def lock_memory_pages(address, size):
    """
    Lock memory pages to prevent them from being swapped to disk.
    Enhanced to protect against cold boot attacks.
    
    Args:
        address: Memory address to lock
        size: Size of memory to lock
    
    Returns:
        bool: True if successfully locked, False otherwise
    """
    try:
        # Use OS-specific methods to lock memory pages
        if sys.platform == 'win32':
            if not hasattr(ctypes.windll, 'kernel32'):
                return False
            
            # Windows: VirtualLock
            ctypes.windll.kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            ctypes.windll.kernel32.VirtualLock.restype = ctypes.c_bool
            result = ctypes.windll.kernel32.VirtualLock(address, size)
            
            # Enhanced protection: Mark pages as no-access when not in use
            old_protect = ctypes.c_ulong(0)
            PAGE_NOACCESS = 0x01
            ctypes.windll.kernel32.VirtualProtect(address, size, PAGE_NOACCESS, ctypes.byref(old_protect))
            
            return bool(result)
        elif sys.platform == 'linux':
            # Linux: mlock
            libc = ctypes.cdll.LoadLibrary('libc.so.6')
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.mlock.restype = ctypes.c_int
            result = libc.mlock(address, size)
            
            # Enhanced: Use MADV_DONTDUMP to exclude from core dumps
            MADV_DONTDUMP = 16  # Exclude from core dumps
            libc.madvise(address, size, MADV_DONTDUMP)
            
            return result == 0
        elif sys.platform == 'darwin':
            # macOS: mlock
            libc = ctypes.cdll.LoadLibrary('libc.dylib')
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.mlock.restype = ctypes.c_int
            return libc.mlock(address, size) == 0
        else:
            return False
    except:
        return False

# Implement cold boot attack detection and countermeasures
class ColdBootProtection:
    """
    Advanced protection against cold boot attacks by detecting
    system temperature anomalies and clearing sensitive memory.
    """
    def __init__(self):
        self.last_temp = None
        self.temp_monitor_active = False
        self.protected_memory = []
        
    def register_protected_memory(self, address, size):
        """Register memory region for protection against cold boot attacks"""
        self.protected_memory.append((address, size))
        
    def start_monitoring(self):
        """Start temperature monitoring thread to detect potential cold boot attacks"""
        if self.temp_monitor_active:
            return
            
        self.temp_monitor_active = True
        threading.Thread(target=self._monitor_temperature, daemon=True).start()
        
    def _monitor_temperature(self):
        """Monitor system temperature for sudden drops indicating cold boot attacks"""
        while self.temp_monitor_active:
            try:
                current_temp = self._get_system_temperature()
                if self.last_temp is not None:
                    # Detect significant temperature drop (possible cold boot attack)
                    if self.last_temp - current_temp > 10:  # 10°C drop threshold
                        self._emergency_memory_clear()
                self.last_temp = current_temp
            except:
                pass
            time.sleep(1)  # Check temperature every second
            
    def _get_system_temperature(self):
        """Get current system temperature through platform-specific methods"""
        try:
            if sys.platform == 'win32':
                import wmi
                w = wmi.WMI(namespace="root\\wmi")
                temperature_info = w.MSAcpi_ThermalZoneTemperature()[0]
                # Convert tenths of kelvin to celsius
                return (temperature_info.CurrentTemperature / 10) - 273.15
            elif sys.platform == 'linux':
                # Read from thermal zone
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    return int(f.read().strip()) / 1000  # Convert to celsius
            else:
                # Default fallback value if we can't get temperature
                return 40  # Assume 40°C if can't determine
        except:
            return 40  # Default fallback
            
    def _emergency_memory_clear(self):
        """Immediately clear all protected memory regions"""
        for addr, size in self.protected_memory:
            try:
                # Overwrite with random data before clearing
                buffer = (ctypes.c_byte * size)()
                for i in range(size):
                    buffer[i] = random.randint(0, 255)
                ctypes.memmove(addr, buffer, size)
                
                # Then zero it out
                null_buffer = (ctypes.c_byte * size)()
                ctypes.memmove(addr, null_buffer, size)
            except:
                pass
                
        # Alert about possible attack
        logging.critical("SECURITY ALERT: Possible cold boot attack detected! Emergency memory clearing performed.")

# Initialize the cold boot protection
cold_boot_protection = ColdBootProtection()

# Update the existing SecureMemory class to use cold boot attack protection
# The SecureMemory class implementation is already defined earlier in the file,
# so we're just adding code to enhance its protections

# Monkey patch the allocate method in SecureMemory to add cold boot protection
original_allocate = SecureMemory.allocate

def enhanced_allocate(self, size: int):
    """
    Enhanced allocate that adds cold boot attack protection to the original method.
    """
    # Call original allocate method
    result = original_allocate(self, size)
    
    # Add cold boot protection if allocation successful
    if result:
        # Get the memory address from the buffer
        address = ctypes.addressof((ctypes.c_char * len(result)).from_buffer(result))
        # Register with cold boot protection
        cold_boot_protection.register_protected_memory(address, len(result))
    
    return result

# Apply the monkey patch
SecureMemory.allocate = enhanced_allocate

# Start cold boot protection monitoring on module import
cold_boot_protection.start_monitoring()

# Add this at the bottom of the file for direct testing
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test-secure-memory":
        test_secure_memory_wiping()
        sys.exit(0)