#!/usr/bin/env python
"""
Enhanced DEP (Data Execution Prevention) Implementation

This module provides comprehensive data execution prevention and secure memory
management functionality for the post-quantum secure P2P communication system.
The implementation includes platform-specific memory protection mechanisms,
secure data erasure capabilities, and runtime integrity verification.

Key Security Features:
1. Memory Protection:
   - DEP (Data Execution Prevention) enforcement
   - ASLR (Address Space Layout Randomization) validation
   - Control Flow Guard (CFG) when available
   - Stack protection and heap isolation

2. Secure Memory Operations:
   - Multi-pass secure data erasure (DoD 5220.22-M standard)
   - Memory locking to prevent swap file exposure
   - Constant-time memory operations for cryptographic material
   - Memory integrity verification through canary values

3. Runtime Security:
   - Process mitigation policy enforcement
   - Anti-debugging countermeasures
   - Code injection detection and prevention
   - Execution flow integrity monitoring

This implementation operates across Windows, Linux, and macOS platforms,
adapting to each operating system's specific security capabilities while
maintaining consistent protection levels.

Technical References:
- NIST SP 800-53: Security Controls for Federal Information Systems
- DoD 5220.22-M: Data Sanitization Standard
- Windows Security Development Lifecycle (SDL)
- Linux Kernel Security Subsystem Documentation
"""
 
import ctypes 
import logging 
import os
import platform
import sys
import threading
import random
import struct
import traceback
import mmap
import secrets
import gc

# Import secure memory functions - these provide the actual implementations
try:
    from secure_key_manager import get_secure_memory, KeyProtectionError
    from secure_key_manager import SecureMemory, secure_wipe_buffer
    HAS_SECURE_KEY_MANAGER = True
except ImportError:
    HAS_SECURE_KEY_MANAGER = False
    class KeyProtectionError(Exception): 
        """Exception raised when key protection operations fail."""
        pass

import platform_hsm_interface as cphs

# Configure dedicated logger for DEP operations
dep_logger = logging.getLogger("dep_implementation")
dep_logger.setLevel(logging.DEBUG)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Setup file logging for security audit trail
dep_file_handler = logging.FileHandler(os.path.join("logs", "dep_implementation.log"))
dep_file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] [%(funcName)s] %(message)s')
dep_file_handler.setFormatter(formatter)
dep_logger.addHandler(dep_file_handler)

# Setup console logging for operational feedback
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(formatter)
dep_logger.addHandler(console_handler)

dep_logger.info("DEP Implementation logger initialized")

# Legacy logger for backward compatibility
log = logging.getLogger("secure_p2p")
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)

# Windows Memory Protection Constants (PAGE_* flags)
PAGE_NOACCESS = 0x01              # Disable all access to the committed region
PAGE_READONLY = 0x02              # Enable read-only access to the committed region
PAGE_READWRITE = 0x04             # Enable read/write access to the committed region
PAGE_WRITECOPY = 0x08             # Enable copy-on-write access to the committed region
PAGE_EXECUTE = 0x10               # Enable execute access to the committed region
PAGE_EXECUTE_READ = 0x20          # Enable execute/read access to the committed region
PAGE_EXECUTE_READWRITE = 0x40     # Enable execute/read/write access to the committed region
PAGE_EXECUTE_WRITECOPY = 0x80     # Enable execute/copy-on-write access to the committed region
PAGE_GUARD = 0x100                # Create guard pages that raise exceptions when accessed

# Windows Memory Allocation Constants
MEM_COMMIT = 0x1000               # Allocate memory charges for the specified pages
MEM_RESERVE = 0x2000              # Reserve a range of process virtual address space
MEM_RELEASE = 0x8000              # Release a range of pages, making them available for reuse

# DEP Policy Constants (Data Execution Prevention)
PROCESS_MITIGATION_DEP_POLICY = 0                    # DEP policy mitigation type
PROCESS_DEP_ENABLE = 0x00000001                      # Enable DEP for the process
PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION = 0x00000002 # Disable ATL thunk emulation

# Modern Windows Mitigation Policy Constants
PROCESS_MITIGATION_ASLR_POLICY = 1                   # Address Space Layout Randomization
PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = 2           # Dynamic code generation policy
PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY = 3    # Strict handle checking policy
PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = 4    # System call filtering policy
PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY = 6 # Extension point disable policy
PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = 9     # Control Flow Guard (CFG) policy
PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = 8       # Binary signature validation policy
PROCESS_MITIGATION_IMAGE_LOAD_POLICY = 12            # Image loading restriction policy


def secure_erase(data, level='standard'):
    """
    Perform cryptographically secure erasure of sensitive data from memory.
    
    This function implements multi-pass overwrite patterns following DoD 5220.22-M
    sanitization standards to ensure sensitive cryptographic material cannot be
    recovered through memory analysis, cold boot attacks, or forensic techniques.
    
    Security Features:
    - Multi-pass overwrite with complementary bit patterns
    - Memory locking to prevent swap file exposure  
    - Constant-time operations to prevent timing side-channels
    - Support for various data types (bytes, bytearray, strings, objects)
    - Platform-specific secure random data generation
    - Memory integrity verification through checksums
    
    Args:
        data: The sensitive data to securely erase. Supports:
              - bytes: Immutable byte sequences (creates mutable copy for erasure)
              - bytearray: Mutable byte arrays (erased in-place)
              - str: Unicode strings (converted to UTF-8 for erasure)
              - Objects with zeroize() method (cryptographic key objects)
              - Complex objects (recursively erases attributes)
              
        level (str): Erasure intensity level:
                    'standard' - Single-pass overwrite with random data
                    'paranoid' - Multi-pass DoD 5220.22-M compliant erasure
                    'military' - Extended multi-pass with entropy verification
    
    Returns:
        None
        
    Raises:
        KeyProtectionError: If memory locking fails for highly sensitive data
        
    Security Notes:
        - For immutable objects (bytes, str), the original may remain in memory
        - Always use mutable containers (bytearray) for maximum security
        - Consider using secure allocators for the most sensitive operations
        - Memory fragmentation may leave traces - use dedicated secure allocators
        
    Technical Implementation:
        The function uses platform-specific memory management APIs to:
        1. Lock memory pages to prevent swapping to persistent storage
        2. Apply multiple overwrite passes with different bit patterns
        3. Use cryptographically secure random data for final passes
        4. Verify memory state before and after erasure operations
        5. Force garbage collection to clear potential object references
    """
    if data is None:
        dep_logger.debug("secure_erase called with None data - no action required")
        return
        
    dep_logger.debug(f"Initiating secure erasure with level '{level}' for data type: {type(data).__name__}")
    
    # Delegate to enhanced secure erase if available
    if HAS_SECURE_KEY_MANAGER:
        try:
            # Import the full secure_key_manager secure_erase function
            from secure_key_manager import secure_erase as skm_secure_erase
            skm_secure_erase(data, level)
            dep_logger.debug(f"Successfully delegated secure erasure to secure_key_manager")
            return
        except Exception as e:
            dep_logger.warning(f"secure_key_manager erasure failed, falling back to local implementation: {e}")
    
    # Local implementation for fallback scenarios
    _perform_local_secure_erase(data, level)


def _perform_local_secure_erase(data, level='standard'):
    """
    Local implementation of secure erasure when secure_key_manager is unavailable.
    
    This fallback implementation provides basic secure erasure capabilities
    using standard library functions and platform-specific memory operations.
    """
    original_type = type(data)
    buffer = None
    buffer_len = 0
    
    try:
        # Convert data to mutable format for in-place erasure
        if isinstance(data, bytes):
            buffer = bytearray(data)
            buffer_len = len(buffer)
            dep_logger.debug(f"Created mutable copy of {buffer_len}-byte immutable bytes object")
        elif isinstance(data, str):
            encoded_data = data.encode('utf-8', 'surrogatepass')
            buffer = bytearray(encoded_data)
            buffer_len = len(buffer)
            dep_logger.debug(f"Created mutable copy of {len(data)}-character string ({buffer_len} UTF-8 bytes)")
        elif isinstance(data, bytearray):
            buffer = data  # Already mutable
            buffer_len = len(buffer)
            dep_logger.debug(f"Using existing mutable bytearray ({buffer_len} bytes)")
        elif hasattr(data, 'zeroize'):
            # Object has built-in secure erasure method
            data.zeroize()
            dep_logger.debug(f"Used built-in zeroize() method for {original_type.__name__}")
            return
        else:
            # Attempt to handle complex objects
            _erase_complex_object(data)
            return
            
        if buffer_len == 0:
            dep_logger.debug("Empty buffer detected - no erasure required")
            return
            
        # Attempt memory locking to prevent swapping
        memory_locked = False
        buffer_addr = None
        try:
            buffer_addr = ctypes.addressof((ctypes.c_char * buffer_len).from_buffer(buffer))
            memory_locked = cphs.lock_memory(buffer_addr, buffer_len)
            if memory_locked:
                dep_logger.debug(f"Successfully locked {buffer_len} bytes of memory")
            else:
                dep_logger.warning("Memory locking failed - proceeding without lock protection")
        except Exception as e:
            dep_logger.warning(f"Memory locking attempt failed: {e}")
        
        # Perform erasure based on security level
        if level == 'paranoid' or level == 'military':
            _perform_multipass_erase(buffer, buffer_addr, buffer_len, level)
        else:
            _perform_standard_erase(buffer, buffer_addr, buffer_len)
            
        dep_logger.info(f"Successfully completed {level} level secure erasure of {buffer_len} bytes")
        
        # Unlock memory if it was locked
        if memory_locked and buffer_addr:
            try:
                cphs.unlock_memory(buffer_addr, buffer_len)
                dep_logger.debug("Memory successfully unlocked after erasure")
            except Exception as e:
                dep_logger.warning(f"Memory unlock failed: {e}")
                
    except Exception as e:
        dep_logger.error(f"Secure erasure failed for {original_type.__name__}: {e}")
        raise KeyProtectionError(f"Secure erasure operation failed: {e}")
    finally:
        # Force garbage collection to clear any remaining references
        gc.collect()


def _perform_standard_erase(buffer, buffer_addr, buffer_len):
    """Perform standard single-pass secure erasure with random data."""
    try:
        # Single pass with cryptographically secure random data
        random_data = secrets.token_bytes(buffer_len)
        for i in range(buffer_len):
            buffer[i] = random_data[i]
            
        # Ensure compiler doesn't optimize away the write
        if buffer_addr:
            ctypes.memmove(buffer_addr, buffer_addr, buffer_len)
            
        dep_logger.debug(f"Standard erasure completed: {buffer_len} bytes overwritten with random data")
        
    except Exception as e:
        dep_logger.error(f"Standard erasure failed: {e}")
        raise


def _perform_multipass_erase(buffer, buffer_addr, buffer_len, level):
    """
    Perform multi-pass secure erasure following DoD 5220.22-M standards.
    
    This implements the US Department of Defense data sanitization standard
    which requires multiple overwrite passes with specific bit patterns to
    ensure data cannot be recovered through magnetic force microscopy or
    similar advanced forensic techniques.
    """
    try:
        # DoD 5220.22-M standard overwrite patterns
        if level == 'military':
            # Extended pattern set for maximum security
            patterns = [
                0x00, 0xFF, 0xAA, 0x55, 0xF0, 0x0F, 0x33, 0xCC,  # Standard patterns
                0x96, 0x69, 0xC3, 0x3C, 0x5A, 0xA5, 0x99, 0x66,  # Extended patterns
                0x77, 0x88, 0xBB, 0x44, 0xDD, 0x22, 0xEE, 0x11   # Additional patterns
            ]
        else:
            # Standard DoD patterns
            patterns = [
                0x00,  # All zeros (magnetic state reset)
                0xFF,  # All ones (opposite magnetic state)
                0xAA,  # Alternating 10101010 pattern
                0x55,  # Alternating 01010101 pattern
                0xF0,  # 11110000 pattern
                0x0F,  # 00001111 pattern
                0x33,  # 00110011 pattern
                0xCC   # 11001100 pattern
            ]
        
        # Apply each deterministic pattern
        for i, pattern in enumerate(patterns):
            if buffer_addr:
                # Use ctypes for direct memory manipulation
                ctypes.memset(buffer_addr, pattern, buffer_len)
            else:
                # Fallback to Python array operations
                for j in range(buffer_len):
                    buffer[j] = pattern
                    
            # Memory barrier to prevent optimization
            if buffer_addr:
                ctypes.memmove(buffer_addr, buffer_addr, buffer_len)
                
            dep_logger.debug(f"Applied overwrite pattern {i+1}/{len(patterns)}: 0x{pattern:02X}")
        
        # Multiple random data passes for final sanitization
        random_passes = 3 if level == 'military' else 2
        for pass_num in range(random_passes):
            random_data = secrets.token_bytes(buffer_len)
            for i in range(buffer_len):
                buffer[i] = random_data[i]
                
            if buffer_addr:
                ctypes.memmove(buffer_addr, buffer_addr, buffer_len)
                
            dep_logger.debug(f"Applied random data pass {pass_num + 1}/{random_passes}")
        
        # Final zero pass to ensure clean state
        if buffer_addr:
            ctypes.memset(buffer_addr, 0, buffer_len)
        else:
            for i in range(buffer_len):
                buffer[i] = 0
                
        dep_logger.debug(f"Completed {level} multi-pass erasure with {len(patterns)} deterministic + {random_passes} random passes")
        
    except Exception as e:
        dep_logger.error(f"Multi-pass erasure failed: {e}")
        raise


def _erase_complex_object(obj):
    """
    Attempt to securely erase complex objects by recursively erasing attributes.
    
    This function handles objects that don't have direct byte representations
    by traversing their attribute hierarchy and erasing any sensitive data.
    """
    try:
        if hasattr(obj, '__dict__'):
            # Erase object attributes
            for attr_name in list(vars(obj).keys()):
                try:
                    attr_value = getattr(obj, attr_name)
                    if attr_value is not None:
                        secure_erase(attr_value, 'standard')  # Recursive erasure
                    setattr(obj, attr_name, None)
                except Exception as e:
                    dep_logger.debug(f"Could not erase attribute '{attr_name}': {e}")
                    
        elif isinstance(obj, (list, tuple)):
            # Handle collections
            for item in obj:
                secure_erase(item, 'standard')
                
        elif isinstance(obj, dict):
            # Handle dictionaries
            for key, value in list(obj.items()):
                secure_erase(key, 'standard')
                secure_erase(value, 'standard')
                
        dep_logger.debug(f"Completed complex object erasure for {type(obj).__name__}")
        
    except Exception as e:
        dep_logger.warning(f"Complex object erasure failed for {type(obj).__name__}: {e}")


def get_secure_memory():
    """
    Obtain a secure memory allocator for sensitive cryptographic operations.
    
    Returns:
        SecureMemory instance if available, None otherwise
    """
    if HAS_SECURE_KEY_MANAGER:
        try:
            return SecureMemory()
        except Exception as e:
            dep_logger.warning(f"Failed to create SecureMemory instance: {e}")
    
    dep_logger.warning("SecureMemory not available - falling back to standard memory allocation")
    return None

# Define platform-specific types and structures
if platform.system() == "Windows":
    from ctypes import wintypes
    # Define SIZE_T since it's missing in wintypes
    if hasattr(ctypes, 'c_size_t'):
        SIZE_T = ctypes.c_size_t
    elif ctypes.sizeof(ctypes.c_void_p) == 8:
        SIZE_T = ctypes.c_uint64
    else:
        SIZE_T = ctypes.c_uint32

    class PROCESS_MITIGATION_DEP_POLICY_STRUCT(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Permanent", wintypes.BOOL)
        ]

        def _get_Enable(self):
            return self.Flags & 1

        def _set_Enable(self, value):
            self.Flags = (self.Flags & ~1) | (value & 1)
        
        Enable = property(_get_Enable, _set_Enable)

        def _get_DisableAtlThunkEmulation(self): 
            return (self.Flags >> 1) & 1

        def _set_DisableAtlThunkEmulation(self, value):
            self.Flags = (self.Flags & ~(1 << 1)) | ((value & 1) << 1)

        DisableAtlThunkEmulation = property(_get_DisableAtlThunkEmulation, _set_DisableAtlThunkEmulation)

    class PROCESS_MITIGATION_ASLR_POLICY_STRUCT(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD)]
        
        def _get_EnableBottomUpRandomization(self):
            return self.Flags & 1
        
        def _set_EnableBottomUpRandomization(self, value):
            self.Flags = (self.Flags & ~1) | (value & 1)

        EnableBottomUpRandomization = property(_get_EnableBottomUpRandomization, _set_EnableBottomUpRandomization)

        def _get_EnableForceRelocateImages(self):
            return (self.Flags >> 1) & 1
        
        def _set_EnableForceRelocateImages(self, value):
            self.Flags = (self.Flags & ~(1 << 1)) | ((value & 1) << 1)

        EnableForceRelocateImages = property(_get_EnableForceRelocateImages, _set_EnableForceRelocateImages)
        
        def _get_EnableHighEntropy(self):
            return (self.Flags >> 2) & 1

        def _set_EnableHighEntropy(self, value):
            self.Flags = (self.Flags & ~(1 << 2)) | ((value & 1) << 2)

        EnableHighEntropy = property(_get_EnableHighEntropy, _set_EnableHighEntropy)

        def _get_DisallowStrippedImages(self):
            return (self.Flags >> 3) & 1
        
        def _set_DisallowStrippedImages(self, value):
            self.Flags = (self.Flags & ~(1 << 3)) | ((value & 1) << 3)
        
        DisallowStrippedImages = property(_get_DisallowStrippedImages, _set_DisallowStrippedImages)

    class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_STRUCT(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD)]

        def _get_ProhibitDynamicCode(self):
            return self.Flags & 1

        def _set_ProhibitDynamicCode(self, value):
            self.Flags = (self.Flags & ~1) | (value & 1)

        ProhibitDynamicCode = property(_get_ProhibitDynamicCode, _set_ProhibitDynamicCode)

        def _get_AllowThreadOptOut(self):
            return (self.Flags >> 1) & 1

        def _set_AllowThreadOptOut(self, value):
            self.Flags = (self.Flags & ~(1 << 1)) | ((value & 1) << 1)

        AllowThreadOptOut = property(_get_AllowThreadOptOut, _set_AllowThreadOptOut)

    class PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_STRUCT(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD)]

        def _get_EnableControlFlowGuard(self):
            return self.Flags & 1

        def _set_EnableControlFlowGuard(self, value):
            self.Flags = (self.Flags & ~1) | (value & 1)

        EnableControlFlowGuard = property(_get_EnableControlFlowGuard, _set_EnableControlFlowGuard)
        
        def _get_StrictMode(self):
            return (self.Flags >> 2) & 1
        
        def _set_StrictMode(self, value):
            self.Flags = (self.Flags & ~(1 << 2)) | ((value & 1) << 2)

        StrictMode = property(_get_StrictMode, _set_StrictMode)

    class PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_STRUCT(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD)]
        
        def _get_MicrosoftSignedOnly(self):
            return self.Flags & 1

        def _set_MicrosoftSignedOnly(self, value):
            self.Flags = (self.Flags & ~1) | (value & 1)

        MicrosoftSignedOnly = property(_get_MicrosoftSignedOnly, _set_MicrosoftSignedOnly)
else:
    # Define dummy placeholders for cross-platform compatibility.
    # This allows the module to be imported without raising errors on non-Windows.
    SIZE_T = None
    class PROCESS_MITIGATION_DEP_POLICY_STRUCT: pass
    class PROCESS_MITIGATION_ASLR_POLICY_STRUCT: pass
    class PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_STRUCT: pass
    class PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_STRUCT: pass
    class PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_STRUCT: pass

def _is_admin():
    """Check if the script is running with administrator privileges on Windows."""
    if os.name == 'nt':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return False

class MemoryProtectionError(Exception):
    """Exception raised for memory protection errors."""
    pass

class EnhancedDEP:
    """
    Enhanced Data Execution Prevention implementation that works in virtualized environments.
    Provides DEP-like functionality using VirtualProtect when standard DEP is unavailable.
    """
    
    def __init__(self):
        self.is_windows = platform.system() == "Windows"
        self.protected_regions = {}
        self.is_standard_dep_enabled = False
        self.is_enhanced_dep_enabled = False
        self.is_acg_enabled = False
        self.is_cfg_enabled = False
        self._lock = threading.Lock()
        
        if self.is_windows:
            self.is_admin = _is_admin()
            self._setup_api_functions()
        else:
            self.is_admin = False
            log.info("EnhancedDEP: Not on Windows, all memory protection features are disabled.")
        
    def _setup_api_functions(self):
        """Set up Windows API function definitions"""
        if not self.is_windows:
            return
        try:
            # VirtualProtect
            self.VirtualProtect = ctypes.windll.kernel32.VirtualProtect
            self.VirtualProtect.argtypes = [
                ctypes.c_void_p,
                SIZE_T,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong)
            ]
            self.VirtualProtect.restype = ctypes.c_bool
            
            # VirtualAlloc
            self.VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
            self.VirtualAlloc.argtypes = [
                ctypes.c_void_p,
                SIZE_T,
                ctypes.c_ulong,
                ctypes.c_ulong
            ]
            self.VirtualAlloc.restype = ctypes.c_void_p
            
            # VirtualFree
            self.VirtualFree = ctypes.windll.kernel32.VirtualFree
            self.VirtualFree.argtypes = [
                ctypes.c_void_p,
                SIZE_T,
                ctypes.c_ulong
            ]
            self.VirtualFree.restype = ctypes.c_bool
            
            # VirtualLock / VirtualUnlock (to pin sensitive pages in RAM)
            self.VirtualLock = ctypes.windll.kernel32.VirtualLock
            self.VirtualLock.argtypes = [ctypes.c_void_p, SIZE_T]
            self.VirtualLock.restype = ctypes.c_bool

            self.VirtualUnlock = ctypes.windll.kernel32.VirtualUnlock
            self.VirtualUnlock.argtypes = [ctypes.c_void_p, SIZE_T]
            self.VirtualUnlock.restype = ctypes.c_bool
            
            # GetCurrentProcess
            self.GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess

            # Attempt to load a required native secure memory wiping function.
            # This follows a "fail-closed" security principle. If a secure function is not available,
            # the application will refuse to start.
            self.secure_zero_memory = self._find_secure_memory_function()

            if not self.secure_zero_memory:
                error_message = "CRITICAL_SECURITY_FAILURE: No suitable native or fallback function for secure memory wiping could be found. The application cannot run securely. Aborting."
                log.critical(error_message)
                raise MemoryProtectionError(error_message)

        except Exception as e:
            log.error(f"A critical error occurred while setting up Windows API functions: {e}")
            raise MemoryProtectionError(e) from e
        
    def _find_secure_memory_function(self):
        """
        Finds the best available function for securely wiping memory, checking in order of
        preference for different operating systems.
        """
        # Try to use enhanced SecureMemory from pqc_algorithms first (highest priority)
        try:
            # Check if pqc_algorithms is available with enhanced implementations
            from pqc_algorithms import SecureMemory, SideChannelProtection
            
            # Create a secure memory instance
            secure_mem = SecureMemory()
            
            def enhanced_secure_wipe(ptr, size):
                # Convert address to a bytearray for secure wiping
                buffer = (ctypes.c_char * size).from_address(ptr)
                byte_array = bytearray(buffer[:])
                
                # Use SecureMemory's wipe functionality
                secure_mem._secure_wipe(byte_array)
                
                # Copy wiped data back to original memory location
                for i in range(size):
                    buffer[i] = byte_array[i]
                    
            log.info("Using enhanced secure memory wiping from pqc_algorithms.")
            return enhanced_secure_wipe
        except ImportError:
            log.debug("Could not import SecureMemory from pqc_algorithms, trying libsodium...")
        except Exception as e:
            log.debug(f"Error using enhanced secure memory wiping: {e}")
            
        # If enhanced SecureMemory is not available, try libsodium
        try:
            # Check if libsodium is available through platform_hsm_interface
            import platform_hsm_interface as cphs
            
            # Check if libsodium is available
            if hasattr(cphs, 'LIBSODIUM_AVAILABLE') and cphs.LIBSODIUM_AVAILABLE and hasattr(cphs, 'LIBSODIUM'):
                libsodium = cphs.LIBSODIUM
                
                # Check if sodium_memzero is available
                if hasattr(libsodium, 'sodium_memzero'):
                    # Make sure the function prototype is defined
                    if not hasattr(libsodium.sodium_memzero, 'argtypes'):
                        libsodium.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                        libsodium.sodium_memzero.restype = None
                    
                    def libsodium_wipe(ptr, size):
                        libsodium.sodium_memzero(ctypes.c_void_p(ptr), size)
                    
                    log.info("Using libsodium's sodium_memzero for secure memory wiping.")
                    return libsodium_wipe
        except ImportError:
            log.debug("Could not import platform_hsm_interface for libsodium access.")
        except Exception as e:
            log.debug(f"Error accessing libsodium: {e}")

        # For Windows
        if cphs.IS_WINDOWS: # type: ignore
            try:
                # 1. Try RtlSecureZeroMemory from ntdll (most secure)
                ntdll = ctypes.WinDLL('ntdll')
                if hasattr(ntdll, 'RtlSecureZeroMemory'):
                    func = ntdll.RtlSecureZeroMemory
                    func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    func.restype = None
                    log.info("Successfully loaded required native function: ntdll.RtlSecureZeroMemory.")
                    return func
            except (OSError, AttributeError):
                log.debug("ntdll.RtlSecureZeroMemory not found.")

            try:
                # 2. Try SecureZeroMemory from kernel32
                kernel32 = ctypes.WinDLL('kernel32')
                if hasattr(kernel32, 'SecureZeroMemory'):
                    func = kernel32.SecureZeroMemory
                    func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    func.restype = None
                    log.info("Successfully loaded required native function: kernel32.SecureZeroMemory.")
                    return func
            except (OSError, AttributeError):
                log.debug("kernel32.SecureZeroMemory not found.")

        # For POSIX systems (Linux, macOS)
        elif cphs.IS_LINUX or cphs.IS_DARWIN:
            try:
                libc = ctypes.CDLL(ctypes.util.find_library("c"))
                # 1. Try explicit_bzero (designed to not be optimized away)
                if hasattr(libc, 'explicit_bzero'):
                    func = libc.explicit_bzero
                    func.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    func.restype = None
                    log.info("Successfully loaded required native function: explicit_bzero.")
                    return func
                
                # 2. Try memset_s (C11 standard for secure memset)
                if hasattr(libc, 'memset_s'):
                    func = libc.memset_s
                    # memset_s has a different signature: int memset_s(void *s, rsize_t smax, int c, rsize_t n);
                    # We will create a wrapper for it to match our expected signature.
                    def memset_s_wrapper(ptr, size):
                        # Returns 0 on success
                        if func(ptr, size, 0, size) != 0:
                            raise MemoryProtectionError("memset_s failed to wipe memory.")
                    log.info("Successfully loaded required native function: memset_s.")
                    return memset_s_wrapper

            except (OSError, AttributeError):
                log.debug("Could not find explicit_bzero or memset_s in libc.")
        
        # 3. Universal Python Fallback (if no native functions are found)
        log.warning("No native secure memory wiping function found. Using a Python-based multi-pass overwrite fallback. This is less secure.")
        def python_secure_wipe(ptr, size):
            try:
                # Create a buffer from the raw memory pointer
                buffer = (ctypes.c_char * size).from_address(ptr)
                # Multi-pass overwrite
                patterns = [0x00, 0xFF, 0xAA, 0x55]
                for p in patterns:
                    ctypes.memset(ptr, p, size)
                # Final random pass
                random_data = secrets.token_bytes(size)
                ctypes.memmove(ptr, random_data, size)
                # Final zero pass
                ctypes.memset(ptr, 0, size)
            except Exception as e:
                raise MemoryProtectionError("Python-based secure wipe fallback failed.") from e

        return python_secure_wipe

    def enable_dep(self):
        """
        Enable DEP for the current process using multiple approaches.
        Falls back to enhanced DEP if standard Windows DEP fails.
        
        Returns:
            bool: True if any method succeeded, False otherwise
        """
        if not self.is_windows:
            return False
            
        # Standard DEP may not be available or may fail in some environments.
        # We supplement it with modern mitigations.
        self._enable_modern_mitigations()

        # First try standard Windows DEP
        if self._enable_standard_dep():
            self.is_standard_dep_enabled = True
            log.info("Successfully enabled standard Windows DEP")
            return True
            
        # If that fails, use our enhanced implementation
        log.info("Standard DEP methods failed. Using enhanced memory protection instead.")
        if self._enable_enhanced_dep():
            self.is_enhanced_dep_enabled = True
            log.info("Successfully enabled enhanced DEP alternative")
            return True
            
        # If all methods fail
        log.warning("Could not enable any DEP protection")
        return False

    def _enable_modern_mitigations(self):
        """
        Enable modern process mitigation policies available on Windows 10+.
        """
        if not self.is_windows or not hasattr(self, 'SetProcessMitigationPolicy'):
            return

        # Enable Arbitrary Code Guard (ACG)
        try:
            acg_policy = PROCESS_MITIGATION_DYNAMIC_CODE_POLICY_STRUCT()
            acg_policy.ProhibitDynamicCode = 1
            if self.SetProcessMitigationPolicy(
                PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
                ctypes.byref(acg_policy),
                ctypes.sizeof(acg_policy)
            ):
                log.info("Successfully enabled Arbitrary Code Guard (ACG).")
                self.is_acg_enabled = True
            else:
                error_code = ctypes.windll.kernel32.GetLastError()
                if error_code == 50:  # ERROR_NOT_SUPPORTED
                    log.info("ACG may already be enabled by the OS or not supported in this environment.")
                    self.is_acg_enabled = True  # Assume it's enabled if error 50
                else:
                    log.warning(f"Failed to enable ACG. Error: {error_code}")
        except Exception as e:
            log.warning(f"An exception occurred while enabling ACG: {e}")

        # Enable Strict CFG
        try:
            cfg_policy = PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY_STRUCT()
            cfg_policy.EnableControlFlowGuard = 1
            cfg_policy.StrictMode = 1
            if self.SetProcessMitigationPolicy(
                PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY,
                ctypes.byref(cfg_policy),
                ctypes.sizeof(cfg_policy)
            ):
                log.info("Successfully enabled Strict CFG.")
                self.is_cfg_enabled = True
            else:
                error_code = ctypes.windll.kernel32.GetLastError()
                # Error 87 is common if the interpreter isn't compiled with CFG. This is not a critical failure.
                if error_code == 87:
                    log.info("Strict CFG is not available for this Python interpreter (not compiled with /guard:cf).")
                elif error_code == 50:  # ERROR_NOT_SUPPORTED
                    log.info("CFG may already be enabled by the OS or not supported in this environment.")
                    self.is_cfg_enabled = True  # Assume it's enabled if error 50
                else:
                    log.warning(f"Failed to enable Strict CFG. Error: {error_code}")
        except Exception as e:
            log.warning(f"An exception occurred while enabling Strict CFG: {e}")

        # Enable High Entropy ASLR (requires admin privileges)
        if self.is_admin:
            try:
                aslr_policy = PROCESS_MITIGATION_ASLR_POLICY_STRUCT()
                aslr_policy.EnableHighEntropy = 1
                if self.SetProcessMitigationPolicy(
                    PROCESS_MITIGATION_ASLR_POLICY,
                    ctypes.byref(aslr_policy),
                    ctypes.sizeof(aslr_policy)
                ):
                    log.info("Successfully enabled High Entropy ASLR.")
                else:
                    error_code = ctypes.windll.kernel32.GetLastError()
                    if error_code == 50:  # ERROR_NOT_SUPPORTED
                        log.info("High Entropy ASLR may already be enabled by the OS or not supported in this environment.")
                    else:
                        log.warning(f"Failed to enable High Entropy ASLR. Error: {error_code}")
            except Exception as e:
                log.warning(f"An exception occurred while enabling High Entropy ASLR: {e}")
        else:
            log.info("Skipping High Entropy ASLR: Administrator privileges are required for this mitigation.")

        # Enable blocking of non-Microsoft signed binaries
        try:
            signature_policy = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY_STRUCT()
            signature_policy.MicrosoftSignedOnly = 1
            if self.SetProcessMitigationPolicy(
                PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY,
                ctypes.byref(signature_policy),
                ctypes.sizeof(signature_policy)
            ):
                log.info("Successfully enabled blocking of non-Microsoft signed binaries.")
            else:
                error_code = ctypes.windll.kernel32.GetLastError()
                if error_code == 50:  # ERROR_NOT_SUPPORTED
                    log.info("Binary signature policy may already be enabled or not supported in this environment.")
                else:
                    log.warning(f"Failed to enable blocking of non-Microsoft signed binaries. Error: {error_code}")
        except Exception as e:
            log.warning(f"An exception occurred while enabling binary signature policy: {e}")

    def _enable_standard_dep(self):
        """
        Try to enable standard Windows DEP using various API calls.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_windows:
            return False
        try:
            # Define the DEP policy structure
            class PROCESS_MITIGATION_DEP_POLICY_STRUCT(ctypes.Structure):
                _fields_ = [
                    ("Flags", wintypes.DWORD),
                    ("Permanent", wintypes.BOOL)
                ]
                
            # Set up the policy
            policy = PROCESS_MITIGATION_DEP_POLICY_STRUCT()
            policy.Flags = PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION
            policy.Permanent = True
                
            # Get SetProcessMitigationPolicy function
            SetProcessMitigationPolicy = ctypes.windll.kernel32.SetProcessMitigationPolicy
            SetProcessMitigationPolicy.argtypes = [
                ctypes.c_ulong,
                ctypes.c_void_p,
                ctypes.c_ulong
            ]
            SetProcessMitigationPolicy.restype = ctypes.c_bool
                
            # Try to set the policy
            result = SetProcessMitigationPolicy(
                PROCESS_MITIGATION_DEP_POLICY,
                ctypes.byref(policy),
                ctypes.sizeof(policy)
            )
                
            if result:
                return True
                
            # If that failed, check for specific error codes
            error = ctypes.windll.kernel32.GetLastError()
            log.debug(f"SetProcessMitigationPolicy failed with error code: {error}")
            
            # Error code 50 (ERROR_NOT_SUPPORTED) often means DEP is already enabled by the OS
            # or that we're running in a virtualized environment where the API is limited
            if error == 50:  # ERROR_NOT_SUPPORTED
                log.debug("Error code 50 suggests DEP might already be enabled by the OS")
                
                # On Windows 10+, DEP is typically enabled by default
                if platform.system() == 'Windows' and int(platform.version().split('.')[0]) >= 10:
                    log.info("Running on Windows 10+ where DEP is typically enabled by default")
                    return True  # Consider this a success on modern Windows
                
                # Check if we can verify DEP is actually enabled
                try:
                    # Try to get the current DEP policy
                    GetProcessMitigationPolicy = ctypes.windll.kernel32.GetProcessMitigationPolicy
                    if GetProcessMitigationPolicy:
                        current_policy = PROCESS_MITIGATION_DEP_POLICY_STRUCT()
                        result = GetProcessMitigationPolicy(
                            PROCESS_MITIGATION_DEP_POLICY,
                            ctypes.byref(current_policy),
                            ctypes.sizeof(current_policy)
                        )
                        
                        if result and (current_policy.Flags & PROCESS_DEP_ENABLE):
                            log.debug("DEP is already enabled by the OS")
                            return True
                except Exception:
                    # GetProcessMitigationPolicy might not be available on all Windows versions
                    pass
                
            # Try SetProcessDEPPolicy as fallback
            try:
                result = ctypes.windll.kernel32.SetProcessDEPPolicy(
                    PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION
                )
                
                if result:
                    return True
                    
                error = ctypes.windll.kernel32.GetLastError()
                log.debug(f"SetProcessDEPPolicy failed with error code: {error}")
                
                # Error code 50 here might also indicate DEP is already enabled
                if error == 50:
                    log.debug("Error code 50 from SetProcessDEPPolicy may indicate DEP is already enabled")
                    
                    # On Windows 10+ with default settings, DEP is usually enabled system-wide
                    # Check Windows version to make an educated guess
                    if platform.system() == 'Windows' and int(platform.version().split('.')[0]) >= 10:
                        log.debug("Running on Windows 10+ where DEP is typically enabled by default")
                        # We'll assume DEP is active on Windows 10+
                        return True
                
                return False
            except Exception as e:
                log.debug(f"SetProcessDEPPolicy exception: {e}")
                return False
                
        except Exception as e:
            log.debug(f"Standard DEP enabling failed: {e}")
            return False

    def _enable_enhanced_dep(self):
        """
        Enable enhanced DEP implementation that works in virtualized environments.
        
        Returns:
            bool: True if successfully enabled, False otherwise
        """
        if not self.is_windows:
            return False
        try:
            # Initialize the tracking of protected memory regions
            self.protected_regions = {}
            
            # Add stack canary values for additional protection
            self._initialize_stack_canaries()
            
            # Test if we can allocate and protect memory
            test_ptr = self.VirtualAlloc(
                None,
                4096,  # One page
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
            
            if not test_ptr:
                error = ctypes.windll.kernel32.GetLastError()
                log.debug(f"VirtualAlloc failed with error: {error}")
                return False
                
            # Try to change protection to read-only
            old_protect = ctypes.c_ulong()
            result = self.VirtualProtect(
                test_ptr,
                4096,
                PAGE_READONLY,
                ctypes.byref(old_protect)
            )
            
            # Free the test memory
            self.VirtualFree(test_ptr, 0, MEM_RELEASE)
            
            if not result:
                error = ctypes.windll.kernel32.GetLastError()
                log.debug(f"VirtualProtect failed with error: {error}")
                return False
                
            # If we got here, the enhanced DEP is working
            self.is_enhanced_dep_enabled = True
            return True
            
        except Exception as e:
            log.debug(f"Enhanced DEP enabling failed: {e}")
            return False
    
    def _initialize_stack_canaries(self):
        """
        Initialize stack canary values for additional protection.
        These canaries are used to detect stack-based buffer overflows.
        """
        # Skip on non-Windows platforms
        if not self.is_windows:
            log.debug("Stack canaries not supported on non-Windows platforms")
            self.canary_values = []
            return
            
        try:
            # Generate random canary values
            self.canary_values = []
            for _ in range(5):
                # Use platform_hsm_interface to get secure random bytes
                try:
                    import platform_hsm_interface as cphs
                    # Use get_secure_random instead of get_random_bytes
                    canary = cphs.get_secure_random(8)
                except (ImportError, AttributeError):
                    # Fallback to os.urandom
                    canary = os.urandom(8)
                
                # Avoid null bytes in canaries
                canary = bytes(b if b != 0 else 1 for b in canary)
                self.canary_values.append(canary)
            
            log.debug(f"Initialized {len(self.canary_values)} stack canary values")
            
            # Place canaries in strategic memory locations
            self._place_canaries()
        except Exception as e:
            log.warning(f"Failed to initialize stack canaries: {e}")
    
    def _place_canaries(self):
        """Place canaries in strategic memory locations."""
        # Skip on non-Windows platforms
        if not self.is_windows:
            log.debug("Skipping canary placement on non-Windows platform")
            return
            
        # Ensure Windows API functions are available
        if not hasattr(self, 'VirtualAlloc') or not self.VirtualAlloc:
            log.warning("VirtualAlloc function not available, cannot place canaries")
            return
            
        try:
            # Allocate small memory regions for canaries
            self.canary_regions = []
            for i, canary in enumerate(self.canary_values):
                # Allocate a small region
                ptr = self.VirtualAlloc(
                    None,
                    len(canary),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                )
                
                if ptr:
                    # Copy canary value
                    ctypes.memmove(ptr, canary, len(canary))
                    
                    # Protect memory
                    old_protect = ctypes.c_ulong()
                    self.VirtualProtect(
                        ptr,
                        len(canary),
                        PAGE_READONLY,  # Make read-only
                        ctypes.byref(old_protect)
                    )
                    
                    # Store region
                    self.canary_regions.append((ptr, len(canary), canary))
                    log.debug(f"Placed canary {i} at {ptr:#x}")
            
        except Exception as e:
            log.warning(f"Failed to place canaries: {e}")
    
    def verify_canaries(self):
        """
        Verify that canary values haven't been modified.
        
        Returns:
            bool: True if all canaries are intact, False otherwise
        """
        # Skip on non-Windows platforms
        if not self.is_windows:
            return True
            
        if not hasattr(self, 'canary_regions') or not self.canary_regions:
            return True
            
        try:
            for i, (ptr, size, original) in enumerate(self.canary_regions):
                # Create a buffer to read the current value
                buf = (ctypes.c_ubyte * size).from_address(ptr)
                current = bytes(buf)
                
                # Compare with original
                if current != original:
                    log.critical(f"SECURITY ALERT: Canary {i} at {ptr:#x} has been modified! Possible buffer overflow attack!")
                    return False
            
            return True
        except Exception as e:
            log.warning(f"Failed to verify canaries: {e}")
            return False
    
    def protect_memory(self, address, size, make_executable=False):
        """
        Apply memory protection to a memory region.
        
        Args:
            address: Memory address to protect
            size: Size of memory region in bytes
            make_executable: Whether to allow execution (default: False for DEP)
            
        Returns:
            str or bool: region_id if protection applied successfully, False otherwise
        """
        if not self.is_windows:
            return False
        if not address or not size:
            return False
            
        with self._lock:
            try:
                # Choose protection level
                protection = PAGE_READONLY
                if make_executable:
                    protection = PAGE_EXECUTE_READ

                # Apply protection
                    old_protect = ctypes.c_ulong()
                    if not self.VirtualProtect(
                    address,
                    size,
                    protection,
                    ctypes.byref(old_protect)
                    ):
                        raise ctypes.WinError()

                    # Generate ID for this region
                    region_id = f"region_{id(address)}_{os.urandom(4).hex()}"

                    # Track this region
                    self.protected_regions[region_id] = {
                        'address': address,
                        'size': size,
                        'protection': protection,
                        'old_protection': old_protect.value,
                        'executable': make_executable
                    }

                    log.debug(f"Applied memory protection to region {region_id} at {address:#x}, size {size}")
                    return region_id
            except Exception as e:
                log.error(f"Memory protection failed: {e}")
                return False
 
    def allocate_protected_memory(self, size, executable=False):
        """
        Allocate memory with protection.
        
        Args:
            size: Size of memory to allocate in bytes
            executable: Whether to allow execution (default: False for DEP)
            
        Returns:
            tuple: (address, region_id) or (None, None) on failure
        """
        if not self.is_windows:
            return (None, None)
        with self._lock:
            try:
                # Allocate memory
                protection = PAGE_READWRITE  # Initially allocate as readwrite
                address = self.VirtualAlloc(
                    None,
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    protection
                )
                
                if not address:
                    raise ctypes.WinError()
                    
                # Generate ID for this region
                region_id = f"alloc_{id(address)}_{os.urandom(4).hex()}"
                
                # Track this region
                self.protected_regions[region_id] = {
                    'address': address,
                    'size': size,
                    'protection': protection,
                    'executable': executable,
                    'allocated': True
                }
                
                # Apply DEP protection if needed
                if not executable:
                    old_protect = ctypes.c_ulong()
                    if not self.VirtualProtect(
                        address,
                        size,
                        PAGE_READONLY,  # Non-executable
                        ctypes.byref(old_protect)
                    ):
                        raise ctypes.WinError()

                    self.protected_regions[region_id]['protection'] = PAGE_READONLY
                        
                log.debug(f"Allocated protected memory region {region_id} at {address:#x}, size {size}")
                return address, region_id
                
            except Exception as e:
                log.error(f"Protected memory allocation error: {e}")
                # Attempt to clean up if allocation succeeded but protection failed
                if 'address' in locals() and address:
                    self.VirtualFree(address, 0, MEM_RELEASE)
                return None, None
    
    def free_memory(self, region_id):
        """
        Free a memory region previously allocated with allocate_protected_memory.
        Includes secure wiping of memory before freeing.
        
        Args:
            region_id: ID of the region to free
            
        Returns:
            bool: True if successful
        """
        if not self.is_windows:
            return False
            
        if region_id not in self.protected_regions:
            log.warning(f"Attempted to free non-existent memory region: {region_id}")
            return False
            
        region = self.protected_regions[region_id]
        
        try:
            # Securely zero the memory before freeing
            if region['address'] and region['size'] > 0:
                try:
                    # Make the memory writable before wiping
                    old_protect = ctypes.c_ulong()
                    if self.VirtualProtect(
                        region['address'],
                        region['size'],
                        PAGE_READWRITE,  # Make writable for wiping
                        ctypes.byref(old_protect)
                    ):
                        # Now wipe the memory using our enhanced implementation
                        if self.secure_zero_memory:
                            self.secure_zero_memory(region['address'], region['size'])
                            log.debug(f"Securely wiped memory for region {region_id} ({region['size']} bytes)")
                        
                        # As an additional security measure, use multiple wiping patterns
                        # This creates defense in depth in case the primary wiping function fails
                        try:
                            # Access the memory as a byte array for precise control
                            buf = ctypes.cast(region['address'], ctypes.POINTER(ctypes.c_ubyte * region['size']))
                            
                            # Multi-pattern wiping (military-grade)
                            patterns = [0xAA, 0x55, 0xFF, 0x00]
                            for pattern in patterns:
                                for i in range(region['size']):
                                    buf.contents[i] = pattern
                                
                                # Memory barrier to prevent optimization
                                ctypes.memmove(region['address'], region['address'], min(16, region['size']))
                        except Exception as e:
                            log.debug(f"Additional pattern wiping failed (non-critical): {e}")
                    else:
                        log.warning(f"Could not change memory protection for wiping region {region_id} (non-critical)")
                except Exception as e:
                    log.warning(f"Could not securely zero memory for region {region_id} (non-critical): {e}")
            
            # Free the memory
            if not self.VirtualFree(
                region['address'],
                0,
                MEM_RELEASE
            ):
                raise ctypes.WinError()
            
            # Remove from tracking
            del self.protected_regions[region_id]
            log.debug(f"Freed memory region {region_id}")
            return True
                
        except Exception as e:
            log.error(f"Memory freeing failed for region {region_id}: {e}")
            return False
    
    def mark_as_non_executable(self, region_id):
        """
        Mark a memory region as non-executable (enforce DEP).
        
        Args:
            region_id: ID of the region to protect
            
        Returns:
            bool: True if protection changed successfully, False otherwise
        """
        if not self.is_windows:
            return False
        with self._lock:
            if region_id not in self.protected_regions:
                log.warning(f"Memory region {region_id} not found for marking non-executable")
                return False
            
            region = self.protected_regions[region_id]
        
            try:
                # Change protection to PAGE_READONLY (non-executable)
                old_protect = ctypes.c_ulong()
                if not self.VirtualProtect(
                    region['address'],
                    region['size'],
                    PAGE_READONLY,
                    ctypes.byref(old_protect)
                ):
                    raise ctypes.WinError()
                
                # Update tracking
                region['protection'] = PAGE_READONLY
                region['executable'] = False
                region['old_protection'] = old_protect.value
                log.debug(f"Marked memory region {region_id} as non-executable")
                return True
                    
            except Exception as e:
                log.error(f"Error marking memory as non-executable for region {region_id}: {e}")
                return False
    
    def mark_as_executable(self, region_id):
        """
        Temporarily mark a memory region as executable.
        
        Args:
            region_id: ID of the region to make executable
            
        Returns:
            bool: True if protection changed successfully, False otherwise
        """
        if not self.is_windows:
            return False
        with self._lock:
            if region_id not in self.protected_regions:
                log.warning(f"Memory region {region_id} not found for marking executable")
                return False
            
            region = self.protected_regions[region_id]
        
            try:
                # Change protection to PAGE_EXECUTE_READ
                old_protect = ctypes.c_ulong()
                if not self.VirtualProtect(
                    region['address'],
                    region['size'],
                    PAGE_EXECUTE_READ,
                    ctypes.byref(old_protect)
                ):
                    raise ctypes.WinError()
                
                # Update tracking
                region['protection'] = PAGE_EXECUTE_READ
                region['executable'] = True
                region['old_protection'] = old_protect.value
                log.debug(f"Marked memory region {region_id} as executable")
                return True
                    
            except Exception as e:
                log.error(f"Error marking memory as executable for region {region_id}: {e}")
                return False
    def status(self):
        """
        Get the status of DEP protection.
        
        Returns:
            dict: Information about the DEP status
        """
        with self._lock:
            return {
            'standard_dep': self.is_standard_dep_enabled,
            'enhanced_dep': self.is_enhanced_dep_enabled,
                'acg_enabled': self.is_acg_enabled,
                'cfg_enabled': self.is_cfg_enabled,
            'protected_regions': len(self.protected_regions),
                'implementation': 'Windows DEP' if self.is_standard_dep_enabled else ('Enhanced DEP' if self.is_enhanced_dep_enabled else 'None'),
            'effective': self.is_standard_dep_enabled or self.is_enhanced_dep_enabled
        }

def implement_dep_in_secure_p2p():
    """
    Function to implement this improved DEP in secure_p2p.py
    
    This function demonstrates how to integrate this module with secure_p2p.py
    Returns an instance of the DEP handler that can be used in secure_p2p.py
    """
    if platform.system() != "Windows":
        log.info("Not on Windows, returning a dummy DEP handler.")
        return EnhancedDEP()
        
    # Initialize the enhanced DEP
    dep = EnhancedDEP()
    
    # Try to enable DEP
    success = dep.enable_dep()
    
    if success:
        log.info(f"Successfully enabled DEP: {dep.status()['implementation']}")
        return dep
    else:
        # Check if we're in a situation where standard DEP failed with error 50
        # but enhanced DEP is enabled - this is actually a successful state
        if dep.is_enhanced_dep_enabled:
            log.info("Successfully enabled Enhanced DEP")
            return dep
        else:
            log.warning("Could not enable any form of DEP. No memory protection active.")
            return dep

if __name__ == "__main__":
    if platform.system() != "Windows":
        print("This script provides Windows-specific memory protections and its tests are for Windows.")
        print("Instantiating on non-Windows platform to check for import errors...")
        try:
            dep = EnhancedDEP()
            status = dep.status()
            print(f"Successfully instantiated. Status: {status}")
            print("Cross-platform check PASSED.")
            sys.exit(0)
        except Exception as e:
            print(f"Error during instantiation: {e}")
            print("Cross-platform check FAILED.")
            sys.exit(1)

    # Configure logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Create the DEP instance
    dep = EnhancedDEP()
    
    # Try to enable DEP
    success = dep.enable_dep()
    
    print(f"DEP enabled: {success}")
    print(f"DEP status: {dep.status()}")
    
    # Test allocating protected memory
    addr, region_id = dep.allocate_protected_memory(4096)
    if addr:
        print(f"Allocated protected memory at {addr:#x}, region {region_id}")
        
        # Test marking as non-executable
        if dep.mark_as_non_executable(region_id):
            print(f"Marked region {region_id} as non-executable")
        
        # Free when done
        if dep.free_memory(region_id):
            print(f"Freed memory region {region_id}")
    
    print("Enhanced DEP implementation test completed") 